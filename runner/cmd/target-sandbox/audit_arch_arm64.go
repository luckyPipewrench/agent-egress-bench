// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && arm64

package main

import "golang.org/x/sys/unix"

const nativeAuditArch = unix.AUDIT_ARCH_AARCH64

// x32SyscallFloor disables the x32 compat check on arm64: there is no ABI that
// shares AUDIT_ARCH_AARCH64 with a flagged syscall range (32-bit AArch32 uses a
// different AUDIT_ARCH value and is already killed), so this sentinel is chosen
// above every real syscall number and never matches.
const x32SyscallFloor = 0xFFFFFFFF
