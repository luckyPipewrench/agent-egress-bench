// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case parentCommand:
			err = runProbeParent(os.Args[2:])
		case childCommand:
			err = runProbeChild(os.Args[2:])
		case "__early_launcher":
			err = writeEarlyStartedMarker(os.Args[2:])
		case "__blocking_launcher":
			<-make(chan struct{})
		default:
			os.Exit(m.Run())
		}
		if err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func writeEarlyStartedMarker(args []string) error {
	var dir, attemptID string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--marker-dir":
			dir = args[i+1]
		case "--token":
			attemptID = args[i+1]
		}
	}
	return writeMarker(dir, attemptID, "started")
}

func TestValidateScenario(t *testing.T) {
	t.Parallel()
	valid := scenario{SchemaVersion: 1, ID: "case", Title: "title", Description: "description", ExpectedOutcome: "contained", Platform: "linux", Lifecycle: "detached_descendant", Attempts: []string{"tcp_non_loopback", "udp_non_loopback"}, TimeoutMS: 5000}
	if err := validateScenario(valid); err != nil {
		t.Fatalf("valid scenario rejected: %v", err)
	}
	invalid := valid
	invalid.ExpectedOutcome = "escaped"
	if err := validateScenario(invalid); err == nil {
		t.Fatal("scenario with fail-open expected outcome was accepted")
	}
}

func TestValidateProfile(t *testing.T) {
	t.Parallel()
	valid := targetProfile{SchemaVersion: 1, Tool: "example", ToolVersion: "1.0.0", Mode: "contain", ExpectedUser: "nobody", ProbePath: "/opt/probe", TargetBinary: "/opt/tool", VersionCommand: []string{"/opt/tool", "--version"}, ExpectedVersionOutput: "tool 1.0.0", LaunchPrefix: []string{"/opt/tool", "contain", "run"}}
	if err := validateProfile(valid); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	invalid := valid
	invalid.ProbePath = "relative/probe"
	if err := validateProfile(invalid); err == nil {
		t.Fatal("relative probe path was accepted")
	}
	invalid = valid
	invalid.LaunchPrefix = []string{"sudo", "/opt/tool", "contain", "run"}
	if err := validateProfile(invalid); err == nil {
		t.Fatal("relative launcher path was accepted")
	}
}

func TestValidateObserverRequiresHostIPv4(t *testing.T) {
	for _, observer := range []string{"2001:db8::1", "192.0.2.10", "224.0.0.1", "255.255.255.255", "169.254.1.1"} {
		if err := validateObserver(observer); err == nil {
			t.Fatalf("invalid observer %q was accepted", observer)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ip, _, parseErr := net.ParseCIDR(addr.String())
		if parseErr == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			if err := validateObserver(ip.String()); err != nil {
				t.Fatalf("host IPv4 observer rejected: %v", err)
			}
			return
		}
	}
	t.Skip("host has no non-loopback IPv4 address")
}

func TestIncompleteNeverPasses(t *testing.T) {
	t.Parallel()
	sc := scenario{ID: "case", ExpectedOutcome: "contained"}
	p := targetProfile{Tool: "example", ToolVersion: "1.0.0", Mode: "contain"}
	got := incomplete(sc, p, "missing witness", attempt{})
	if got.ActualOutcome != "incomplete" || got.Score != "fail" {
		t.Fatalf("incomplete evidence produced %#v", got)
	}
}

func TestParseParentArgsPreservesChildFlags(t *testing.T) {
	t.Parallel()
	executable, childArgs, err := parseParentArgs([]string{"--executable", "/opt/probe", "--marker-dir", "/tmp/evidence", "--token", "token"})
	if err != nil {
		t.Fatal(err)
	}
	if executable != "/opt/probe" || len(childArgs) != 4 || childArgs[0] != "--marker-dir" || childArgs[3] != "token" {
		t.Fatalf("arguments changed: executable=%q child=%q", executable, childArgs)
	}
}

func TestSameFileHashRejectsDifferentProbe(t *testing.T) {
	t.Parallel()
	a := t.TempDir() + "/a"
	b := t.TempDir() + "/b"
	if err := os.WriteFile(a, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sameFileHash(a, b); err == nil {
		t.Fatal("different probe bytes were accepted")
	}
}

func TestRunAttemptProvesDetachedLifecycle(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	got, err := runAttempt([]string{self}, self, dir, "127.0.0.1", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TCP || !got.UDP || !got.Started || !got.TCPAttempted || !got.UDPAttempted || !got.Finished {
		t.Fatalf("incomplete lifecycle evidence: %#v", got)
	}
	if got.UID != os.Geteuid() || got.PID == 0 || got.PID != got.SID {
		t.Fatalf("wrong detached identity: %#v", got)
	}
}

func TestRunAttemptRejectsChildStartedBeforeLauncherExit(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = runAttempt([]string{self, "__early_launcher"}, self, t.TempDir(), "127.0.0.1", 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "started before launcher exited") {
		t.Fatalf("early child start was not rejected: %v", err)
	}
}

func TestRunAttemptBoundsBlockingLauncher(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = runAttempt([]string{self, "__blocking_launcher"}, self, t.TempDir(), "127.0.0.1", 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "launcher timed out") {
		t.Fatalf("blocking launcher was not rejected: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocking launcher exceeded deadline: %v", elapsed)
	}
}

func TestTerminateDetachedProcess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), self, "__blocking_launcher")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	detached, err := openDetachedProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer detached.close()
	detached.terminate()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("detached session survived cleanup")
	}
}

func TestWriteAtomicReadableReceipt(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomicReadableReceipt(dir, "attempt", []byte("receipt")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(markerPath(dir, "attempt", "identity"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "receipt" {
		t.Fatalf("receipt = %q", got)
	}
}

func TestVerifyTargetIdentityRejectsVersionMismatch(t *testing.T) {
	path := t.TempDir() + "/tool"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'tool 2.0.0\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := targetProfile{TargetBinary: path, VersionCommand: []string{path, "--version"}, ExpectedVersionOutput: "tool 1.0.0"}
	if _, err := verifyTargetIdentity(p, time.Second); err == nil {
		t.Fatal("mismatched target version was accepted")
	}
}

func TestVerifyTargetIdentityTimesOutProcessGroup(t *testing.T) {
	path := t.TempDir() + "/tool"
	if err := os.WriteFile(path, []byte("#!/bin/sh\n(sleep 30) &\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := targetProfile{TargetBinary: path, VersionCommand: []string{path, "--version"}, ExpectedVersionOutput: "tool 1.0.0"}
	started := time.Now()
	_, err := verifyTargetIdentity(p, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("hanging version command error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("hanging version command returned after %v", elapsed)
	}
}

func TestRequireRootPinnedExecutable(t *testing.T) {
	if err := requireRootPinnedExecutable("/usr/bin/true"); err != nil {
		t.Fatalf("root-owned executable rejected: %v", err)
	}
	userOwned := t.TempDir() + "/tool"
	if err := os.WriteFile(userOwned, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requireRootPinnedExecutable(userOwned); err == nil {
		t.Fatal("user-replaceable executable accepted")
	}
}

func TestWitnessReceiversIgnoreFloodWithoutBlocking(t *testing.T) {
	tcpLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcpLn.Close() }()
	tcpIn := receiveTCP(tcpLn, "wanted")
	for i := range 32 {
		conn, dialErr := (&net.Dialer{}).DialContext(context.Background(), "tcp4", tcpLn.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		_, _ = conn.Write([]byte("noise-" + strconv.Itoa(i)))
		_ = conn.Close()
	}
	assertNoWitness(t, tcpIn, "TCP")
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp4", tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("wanted\n"))
	_ = conn.Close()
	select {
	case got := <-tcpIn:
		if got != "wanted" {
			t.Fatalf("TCP witness = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP witness blocked after unsolicited traffic")
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpConn.Close() }()
	udpIn := receiveUDP(udpConn, "wanted")
	sender, err := net.DialUDP("udp4", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	for i := range 32 {
		_, _ = sender.Write([]byte("noise-" + strconv.Itoa(i)))
	}
	assertNoWitness(t, udpIn, "UDP")
	_, _ = sender.Write([]byte("wanted"))
	select {
	case got := <-udpIn:
		if got != "wanted" {
			t.Fatalf("UDP witness = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP witness blocked after unsolicited traffic")
	}
}

func TestTCPWitnessDoesNotSerializeSilentConnections(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	in := receiveTCP(ln, "wanted")
	for range 4 {
		conn, dialErr := (&net.Dialer{}).DialContext(context.Background(), "tcp4", ln.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		defer func() { _ = conn.Close() }()
	}
	valid, err := (&net.Dialer{}).DialContext(context.Background(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = valid.Write([]byte("wanted\n"))
	_ = valid.Close()
	select {
	case got := <-in:
		if got != "wanted" {
			t.Fatalf("TCP witness = %q", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("valid TCP witness blocked behind silent connections")
	}
}

func assertNoWitness(t *testing.T, in <-chan string, protocol string) {
	t.Helper()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case got := <-in:
		t.Fatalf("%s accepted unsolicited witness %q", protocol, got)
	case <-timer.C:
	}
}

func TestCheckedInFixturesMatchRunnerContract(t *testing.T) {
	t.Parallel()
	var sc scenario
	if err := decodeStrictJSON("../../../containment/cases/detached-second-stage-001.json", &sc); err != nil {
		t.Fatal(err)
	}
	if err := validateScenario(sc); err != nil {
		t.Fatal(err)
	}
	var p targetProfile
	if err := decodeStrictJSON("../../../examples/pipelock/containment-profile.json", &p); err != nil {
		t.Fatal(err)
	}
	if err := validateProfile(p); err != nil {
		t.Fatal(err)
	}
}
