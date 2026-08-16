# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-08-16

### Added

- Installable `lordms-recon` Python package and console command.
- HTML and JSON reports with technology and server metadata.
- Explicit `--run-nuclei` and `--screenshots` integrations.
- External-tool timeout and error reporting.
- Unit tests, GitHub Actions CI, security policy, and contribution guide.

### Changed

- Split domain validation, external tools, scoring, reporting, dashboard, and CLI orchestration into focused modules.
- Made active integrations opt-in.
- Added automatic `httpx`/`httpx-toolkit` executable detection.

### Fixed

- Prevented malformed httpx lines from desynchronizing target records and scoring results.
- Replaced broad exception handling with actionable failures.
- Updated Gowitness invocation to its current `scan file` command structure.

