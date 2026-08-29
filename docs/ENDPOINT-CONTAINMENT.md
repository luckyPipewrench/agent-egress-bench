# Endpoint containment scenarios

Endpoint containment scenarios test an operating-system boundary after a tool launcher exits. They don't belong in the Gauntlet wire score because they measure a different product surface.

The Linux runner starts local TCP and UDP witnesses, then runs the same detached-child probe three times:

1. An uncontained control must reach both witnesses.
2. The target's installed containment launcher runs the probe. The child waits until its launcher exits, creates a new session, and attempts both connections.
3. A second uncontained control must still reach both witnesses.

The target attempt passes only when the child ran under the expected account, completed both attempts, and neither token reached either witness. A witnessed target token is sufficient to report `escaped`, even if other lifecycle evidence is missing. Without an escape witness, missing identity, attempt, control, or witness evidence produces `incomplete`, never `contained`.

The observer must be a numeric non-loopback address assigned to the host. Loopback traffic isn't a valid direct-egress test because a containment policy may allow it for local proxy access.

This scenario uses a shared evidence directory to prove the detached child's identity and completed attempts. The runner keeps the directory private and grants access only to the expected contained UID with a POSIX ACL, so `setfacl` must be installed. A product that gives the child a private filesystem can't use this evidence adapter and returns `incomplete`. It needs a different adapter with an independent attempt observer before anyone can score it.

## Run a scenario

Build the runner and install the same bytes at the path declared by the target profile:

```bash
cd runner && go build -trimpath -o /tmp/aeb-containment-scenario ./cmd/containment-scenario
sudo install -D -m 0755 /tmp/aeb-containment-scenario /usr/local/libexec/aeb-containment-scenario
```

Register the executable through the product's supported containment setup. The Pipelock example uses:

```bash
sudo pipelock contain add-tool aeb-containment-scenario --target /usr/local/libexec/aeb-containment-scenario
```

Run the scenario as the ordinary operator account. Replace `192.0.2.10` with a numeric non-loopback address assigned to the observer host:

```bash
/tmp/aeb-containment-scenario --scenario containment/cases/detached-second-stage-001.json --profile examples/pipelock/containment-profile.json --observer-ip 192.0.2.10
```

The runner requires the installed probe, target binary, actual launcher executable, and every parent directory to be root-owned, non-symlinked, and not writable by group or other users. The first `launch_prefix` entry must be the absolute launcher path; naming the target binary later in an otherwise unpinned command isn't enough. The runner verifies that its own SHA-256 digest matches the installed probe before launching anything. After the detached child starts, it inspects the live process through `/proc` and verifies its UID, session, attempt token, and executable digest before releasing it. The verified probe process itself makes both network attempts without an intervening subprocess or executable handoff. The runner also runs the profile's version command, requires the exact expected output, hashes the target binary, and records that digest with the result. These checks pin the tested files against replacement by the unprivileged operator or contained account; root remains inside the benchmark's trusted computing base. The target digest records the tested bytes, not a vendor-release signature or independent trust pin.

A profile is trusted operator configuration because its launch command is executed with the operator's privileges. Don't run profiles from an untrusted source. The runtime still pins the launcher executable and relies on the host's normal privilege policy, such as `sudoers`, to decide whether the requested command is allowed. A target profile must use the target binary in the product's real installed containment command. A direct user switch or a benchmark-only sandbox doesn't represent the product installation and isn't an acceptable adapter.

## Result states

- `contained`: both uncontained controls arrived, the detached target child completed both attempts under the expected identity, and neither target token arrived.
- `escaped`: at least one target token arrived; escape evidence takes precedence over missing lifecycle evidence.
- `incomplete`: no target token arrived, but required setup, identity, lifecycle, attempt, or control evidence is missing.

Endpoint results stay separate from Gauntlet containment and false-positive rates. One scenario result doesn't support a product-wide containment claim.
