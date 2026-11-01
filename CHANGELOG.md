# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- `golang.org/x/crypto` 0.47.0 → 0.58.0 (GO-2026-5005, -5006, -5017, -5019, -5020, -5021, -5023, -6354, -6355: SSH agent constraints, knownhosts `@revoked` bypass, FIDO touch bypass, `VerifiedPublicKeyCallback` permissions, SSH server deadlocks and DoS). This needs Go 1.26, so the minimum Go version, Devenv and CI move to Go 1.26.

### Added

- Symlink detection on runtime and access directories (`ensureSecureDir`).
- Atomic file writes for session and access state files.
- Shell mode risk warnings in README and agent skill guide.
- SSH option risk documentation in README.
- `SECURITY.md` with vulnerability reporting instructions.
- `CHANGELOG.md` following Keep a Changelog format.
- `go vet` and `golangci-lint` steps in CI pipeline.
- `go mod tidy` check in CI pipeline.
- `sshgate close` listed in agent-allowed commands.
- Public module path (`github.com/jeprecated/sshgate`) for `go install` support.
- Supported-platform documentation for Linux and macOS.
- Pinned devbox Go package for reproducible local builds.

### Fixed

- `umask 0077` now set in `main()` instead of only in `runOpen`, protecting all file writes.
- Signal handler now loops to forward repeated signals instead of dropping them.
- README `run` example corrected to use `--` for shell mode.
- `go.mod` dependencies marked as direct instead of indirect.
- README devbox and quick-start examples updated for repository usage.
- Devbox package list aligned with the committed lockfile.

### Removed

- Windows/Scoop release targets until Windows support is implemented and tested.

### Security

- Runtime and access directories reject symlinks to prevent symlink attacks.
- File writes use atomic rename to prevent data corruption on crash.
- Process-wide umask ensures restrictive permissions on all created files.
