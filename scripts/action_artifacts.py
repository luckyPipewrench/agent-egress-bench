#!/usr/bin/env python3
"""Create and publish Action artifacts without following workspace symlinks."""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path


ARTIFACT_NAMES = ("results.jsonl", "summary.json", "run-metadata.json")


class ArtifactError(RuntimeError):
    pass


def open_output_dir(workspace: Path, output_dir: str, *, create: bool) -> int:
    parts = Path(output_dir).parts
    if not parts or Path(output_dir).is_absolute() or any(part in ("", ".", "..") for part in parts):
        raise ArtifactError("output-dir must be a non-empty relative path without '.' or '..'")
    current = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except Exception:
        os.close(current)
        raise


def prepare(workspace: Path, output_dir: str) -> None:
    output_fd = open_output_dir(workspace, output_dir, create=True)
    try:
        for name in ARTIFACT_NAMES:
            try:
                os.unlink(name, dir_fd=output_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(output_fd)
    print(workspace.resolve() / output_dir)


def regular_source(path: Path) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ArtifactError(f"artifact is not a no-follow regular file: {path}: {exc}") from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ArtifactError(f"artifact is not a regular file: {path}")
    return descriptor, info


def copy_regular(source: Path, output_fd: int, destination_name: str) -> None:
    source_fd, _ = regular_source(source)
    temporary_name = f".aeb-{destination_name}.{os.getpid()}.{secrets.token_hex(8)}"
    destination_fd = -1
    try:
        destination_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o644,
            dir_fd=output_fd,
        )
        while chunk := os.read(source_fd, 1024 * 1024):
            remaining = memoryview(chunk)
            while remaining:
                remaining = remaining[os.write(destination_fd, remaining):]
        os.fsync(destination_fd)
        os.close(destination_fd)
        destination_fd = -1
        os.replace(temporary_name, destination_name, src_dir_fd=output_fd, dst_dir_fd=output_fd)
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        try:
            os.unlink(temporary_name, dir_fd=output_fd)
        except FileNotFoundError:
            pass


def publish(workspace: Path, output_dir: str, results: Path, metadata: Path, summary: Path | None) -> None:
    output_fd = open_output_dir(workspace, output_dir, create=False)
    try:
        copy_regular(results, output_fd, "results.jsonl")
        if summary is not None:
            copy_regular(summary, output_fd, "summary.json")
        copy_regular(metadata, output_fd, "run-metadata.json")
    finally:
        os.close(output_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--workspace", type=Path, required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--workspace", type=Path, required=True)
    publish_parser.add_argument("--output-dir", required=True)
    publish_parser.add_argument("--results", type=Path, required=True)
    publish_parser.add_argument("--summary", type=Path)
    publish_parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.workspace.resolve(), args.output_dir)
        else:
            publish(args.workspace.resolve(), args.output_dir, args.results, args.metadata, args.summary)
    except (ArtifactError, OSError) as exc:
        print(f"Action artifact handling failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
