# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-04-25

### Added

- **JWT_ERROR rule**: Detect `jwt.Parse` calls with a nil key function, which misses signature validation entirely.
- **HARDCODED_SECRET rule**: Detect hardcoded tokens, passwords, API keys, and long base64 strings that may be secrets.
- **Deduplication of issues**: Issues are now deduplicated by file:line after all rules run, eliminating duplicate findings.
- **GoReleaser setup**: Multi-platform release pipeline configured (linux/amd64, darwin/amd64, darwin/arm64, windows).
- **Install script**: `curl -L https://git.io/goreview | sh` installer for quick setup on macOS/Linux.

### Changed

- Improved issue scoring and severity classification across all rules.

### Fixed

- Resolved static analysis bugs in analyzer engine.

## [0.2.0] - 2026-04-19

### Added

- Complete GoReview CLI with static analysis engine.
- Context leak detection (`CONTEXT_LEAK`).
- SQL injection detection (`SQL_INJECTION`).
- Goroutine leak detection (`GOROUTINE_LEAK`).
- Resource leak detection (`RESOURCE_LEAK`).
- Sensitive info logging detection (`SENSITIVE_INFO`).
- Initial test suite for analyzer package.

### Changed

- Initial project setup with Cobra CLI framework.
