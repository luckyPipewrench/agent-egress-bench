// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import "golang.org/x/sys/unix"

const nativeAuditArch = unix.AUDIT_ARCH_X86_64

// x32SyscallFloor is __X32_SYSCALL_BIT: x32 syscalls reuse AUDIT_ARCH_X86_64 but
// carry this bit, so any syscall number at or above it is an x32 compat call and
// is killed. Native amd64 syscall numbers are far below it.
const x32SyscallFloor = 0x40000000
