"""Exercise the real example launcher processes with a controlled child."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LauncherLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.tmp = self.base / 'temp files'
        self.tmp.mkdir()
        self.bin = self.base / 'fixture'
        self.bin.write_text('''#!/usr/bin/env python3
import json, os, pathlib, signal, sys, time
if sys.argv[1] == 'signing':
    sys.exit(23)
config = pathlib.Path(sys.argv[sys.argv.index('--config') + 1])
record = {'argv': sys.argv[1:], 'config': str(config), 'text': config.read_text(),
          'mode': config.parent.stat().st_mode & 0o777,
          'cert': os.environ.get('SSL_CERT_FILE'), 'pid': os.getpid()}
def stop(sig, frame):
    pathlib.Path(os.environ['SIGNAL_RECORD']).write_text(str(sig))
    # The config must remain available until shutdown finishes.
    assert config.exists()
    sys.exit(int(os.environ.get('SIGNAL_EXIT', '37')))
if not os.environ.get('DEFAULT_SIGNALS'):
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
record_path = pathlib.Path(os.environ['RECORD'])
record_tmp = record_path.with_suffix('.tmp')
record_tmp.write_text(json.dumps(record))
record_tmp.replace(record_path)
if os.environ.get('READ_STDIN'):
    pathlib.Path(os.environ['STDIN_RECORD']).write_text(sys.stdin.read())
if os.environ.get('HOLD'):
    while True:
        time.sleep(.01)
sys.exit(int(os.environ.get('CHILD_EXIT', '0')))
''')
        self.bin.chmod(0o700)
        # Independent BSD-style template control: reject suffixes after Xs,
        # delegate creation to the installed utility only after that check.
        self.mktemp = self.base / 'mktemp'
        self.mktemp.write_text('''#!/usr/bin/env python3
import os, re, sys
args = sys.argv[1:]
if not args or not re.search(r'X{6}$', args[-1]):
    sys.exit(64)
os.execv('/usr/bin/mktemp', ['mktemp', *args])
''')
        self.mktemp.chmod(0o700)
        self.env = dict(os.environ, TMPDIR=str(self.tmp),
                        PATH=str(self.base) + os.pathsep + os.environ['PATH'],
                        RECORD=str(self.base / 'record'), SIGNAL_RECORD=str(self.base / 'signal'),
                        AEB_PROXY_ADDR='127.0.0.1:0', AEB_SCAN_ADDR='127.0.0.1:0',
                        AEB_TLS_CA_FILE='fixture cert.pem', AEB_TLS_CA_KEY_FILE='fixture key.pem',
                        AEB_MCP_HTTP_ADDR='127.0.0.1:0', AEB_MCP_HTTP_FIXTURE_URL='http://fixture.example')
        for key in ('AEB_RECEIPT_EVIDENCE_DIR', 'PIPELOCK_BENCH_CONFIG'):
            self.env.pop(key, None)

    def launch(self, script='start-proxy-for-benchmark.sh', **extra):
        proc = subprocess.Popen(['bash', str(ROOT / 'examples/pipelock' / script), str(self.bin)],
                                cwd=ROOT, env=dict(self.env, **extra),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(self.stop, proc)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=3)
        else:
            # An exited launcher may have left a child holding the pipes.
            try:
                proc.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=3)

    def finish(self, proc, expected):
        _, err = proc.communicate(timeout=5)
        self.assertEqual(proc.returncode, expected, err.decode())
        self.assertEqual(list(self.tmp.iterdir()), [])

    def ready(self, proc):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if Path(self.env['RECORD']).exists():
                return json.loads(Path(self.env['RECORD']).read_text())
            if proc.poll() is not None:
                self.fail(proc.communicate()[1].decode())
            time.sleep(.01)
        self.fail('child did not become ready')

    def test_bsd_template_control(self):
        for template, code in [('bad-XXXXXX.yaml', 64), ('good.XXXXXX', 0)]:
            result = subprocess.run([str(self.mktemp), '-d', str(self.tmp / template)],
                                    capture_output=True, timeout=3)
            self.assertEqual(result.returncode, code)
            if code == 0:
                Path(result.stdout.decode().strip()).rmdir()

    def test_repeat_restart_and_exit_status(self):
        configs = []
        for code in (0, 19, 0):
            Path(self.env['RECORD']).unlink(missing_ok=True)
            proc = self.launch(CHILD_EXIT=str(code))
            self.finish(proc, code)
            record = json.loads(Path(self.env['RECORD']).read_text())
            configs.append(record['config'])
            self.assertEqual(record['mode'], 0o700)
            self.assertEqual(record['cert'], self.env['AEB_TLS_CA_FILE'])
            self.assertEqual(record['argv'], ['run', '--config', record['config'], '--listen', self.env['AEB_PROXY_ADDR']])
            self.assertIn('fixture cert.pem', record['text'])
        self.assertEqual(len(set(configs)), 3)

    def test_signals_and_restart(self):
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            Path(self.env['RECORD']).unlink(missing_ok=True)
            proc = self.launch(HOLD='1')
            record = self.ready(proc)
            proc.send_signal(sig)
            self.finish(proc, 37)
            self.assertEqual(Path(self.env['SIGNAL_RECORD']).read_text(), str(sig.value))
            self.assertFalse(Path(record['config']).exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(record['pid'], 0)
        self.finish(self.launch(), 0)

    def test_child_exit_during_signal_trap(self):
        # Keep the forwarding trap active until the child has exited. This makes
        # an interrupted wait distinct from the child's final status.
        startup = self.base / 'startup.bash'
        startup.write_text("""kill() {
  if [[ "$1" == "-s" ]]; then
    builtin kill "$@"
    while builtin kill -0 "$3" 2>/dev/null; do sleep .01; done
  else
    builtin kill "$@"
  fi
}
""")
        proc = self.launch(HOLD='1', BASH_ENV=str(startup))
        self.ready(proc)
        proc.terminate()
        self.finish(proc, 37)

    def test_signal_during_child_handoff(self):
        startup = self.base / 'handoff.bash'
        startup.write_text("""handoff_debug() {
  if [[ "$BASH_COMMAND" == 'child_pid=$!' ]]; then
    while [[ ! -f "$RECORD" ]]; do sleep .01; done
    builtin kill -TERM "$$"
  fi
}
trap handoff_debug DEBUG
""")
        proc = self.launch(HOLD='1', BASH_ENV=str(startup))
        self.addCleanup(self.kill_group, proc.pid)
        self.finish(proc, 37)

    @staticmethod
    def kill_group(pid):
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_default_signal_status(self):
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            Path(self.env['RECORD']).unlink(missing_ok=True)
            proc = self.launch(HOLD='1', DEFAULT_SIGNALS='1')
            self.ready(proc)
            proc.send_signal(sig)
            self.finish(proc, 128 + sig.value)

    def test_stdin_preserved(self):
        record = self.base / 'stdin'
        proc = self.launch(READ_STDIN='1', STDIN_RECORD=str(record), CHILD_EXIT='5')
        _, err = proc.communicate(input=b'hello-stdin', timeout=5)
        self.assertEqual(proc.returncode, 5, err.decode())
        self.assertEqual(record.read_text(), 'hello-stdin')
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_missing_executable_cleanup(self):
        self.bin.unlink()
        self.finish(self.launch(), 127)

    def test_term_during_setup(self):
        awk = self.base / 'awk'
        awk.write_text('#!/usr/bin/env python3\nimport os, signal, sys\nos.kill(os.getppid(), signal.SIGTERM)\nsys.exit(0)\n')
        awk.chmod(0o700)
        self.finish(self.launch(), 143)
        self.assertFalse(Path(self.env['RECORD']).exists())

    def test_prelaunch_failures_cleanup(self):
        self.finish(self.launch(PIPELOCK_BENCH_CONFIG=str(self.base / 'absent')), 2)
        self.finish(self.launch(AEB_RECEIPT_EVIDENCE_DIR=str(self.base / 'receipts')), 23)
        self.finish(self.launch(AEB_PROXY_ADDR=''), 2)

    def test_mcp_sibling_contract(self):
        self.finish(self.launch('start-mcp-http-for-benchmark.sh', CHILD_EXIT='19'), 19)
        record = json.loads(Path(self.env['RECORD']).read_text())
        self.assertEqual(record['argv'], ['mcp', 'proxy', '--config', 'examples/pipelock/pipelock-benchmark.yaml', '--listen', self.env['AEB_MCP_HTTP_ADDR'], '--upstream', self.env['AEB_MCP_HTTP_FIXTURE_URL']])
        Path(self.env['RECORD']).unlink()
        proc = self.launch('start-mcp-http-for-benchmark.sh', HOLD='1')
        self.ready(proc)
        proc.terminate()
        self.finish(proc, 37)


if __name__ == '__main__':
    unittest.main()
