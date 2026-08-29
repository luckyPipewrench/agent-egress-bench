// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"strings"
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
}

func TestValidateObserverRejectsIPv6(t *testing.T) {
	t.Parallel()
	if err := validateObserver("2001:db8::1"); err == nil {
		t.Fatal("IPv6 observer was accepted by IPv4-only witnesses")
	}
	if err := validateObserver("192.0.2.10"); err != nil {
		t.Fatalf("valid IPv4 observer rejected: %v", err)
	}
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
	if _, err := verifyTargetIdentity(p); err == nil {
		t.Fatal("mismatched target version was accepted")
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
	tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	tcpIn := receiveTCP(tcpLn, "wanted")
	for i := range 32 {
		conn, dialErr := net.Dial("tcp4", tcpLn.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		_, _ = conn.Write([]byte("noise-" + strconv.Itoa(i)))
		_ = conn.Close()
	}
	assertNoWitness(t, tcpIn, "TCP")
	conn, err := net.Dial("tcp4", tcpLn.Addr().String())
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
	defer udpConn.Close()
	udpIn := receiveUDP(udpConn, "wanted")
	sender, err := net.DialUDP("udp4", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
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
