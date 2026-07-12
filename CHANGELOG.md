# Changelog

All notable changes to **deadpoint** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] — 2026-07-11
### Added
- Demo GIF in the README (absolute raw URL so it renders on GitHub and PyPI).

## [0.3.0] — 2026-07-11
### Added
- **Optional Textual TUI** (`pip install deadpoint[tui]`, `deadpoint tui <input>`):
  an interactive detect → exploit → remediate dashboard with a live
  forward/backward prediction table. A thin, read-only view over the library;
  the core keeps no Textual dependency.
- README badges (CI, PyPI, Python versions, license), a demo section with a
  `vhs` tape (`docs/demo.tape`), and a `CHANGELOG.md`.
### Changed
- CI now runs `mypy` (type-checking); the project is mypy-clean.
### Fixed
- 12 type errors surfaced by mypy (notably a wrong CLI return annotation and
  `int.from_bytes` endianness types).

## [0.2.3] — 2026-07-11
### Fixed
- Detect stage: base the `STRONG` verdict on a stable min-entropy discriminator
  instead of the all-pass of threshold-crossing p-value tests. A genuine CSPRNG
  independently fails each `p < 0.01` test ~1% of the time, so requiring all five
  to pass mislabelled ~5% of CSPRNG streams as `UNKNOWN`. A weak stream is still
  never classified `STRONG`.

## [0.2.2] — 2026-07-11
### Changed
- README: make explicit that `pip install deadpoint` is pure Python; the Rust
  accelerator is strictly opt-in (`cd native && maturin develop --release`).

## [0.2.1] — 2026-07-11
### Fixed
- `randint`/`randrange` bit width now matches CPython's `randbelow`
  (`width.bit_length()`); the state solve reports failure cleanly rather than
  returning a false success when rejection breaks word alignment.
- Property test bit-width regression; `random()` observations no longer coerced
  to `int` (which zeroed them).

## [0.2.0] — 2026-07-11
### Added
- **Exact `randint`/`randrange` recovery** via small/Unix-time seed recovery and
  real-generator replay — handles rejection sampling ("the subtle case") exactly.
- **Additional generators:** V8 `Math.random` (xorshift128+), Java `Math.random`
  / `nextDouble`, PHP `mt_rand`.
- **Capture on-ramps:** pcap token/nonce extraction (`deadpoint.pcap`) and live
  endpoint sampling (`deadpoint.web`).
- **Optional Rust/PyO3 accelerator** (`native/`), auto-selected when built.
- **diff-against-secrets** demo mode + `deadpoint demo` CLI subcommand.
- Second case study (web session-token prediction).

## [0.1.0] — 2026-07-10
### Added
- Initial release: MT19937 untemper + state recovery, forward/backward
  prediction, Z3 partial-output solver (`random()`, `getrandbits(k)`), LCG +
  Java `Random` recovery, seed recovery, detect stage, remediate stage
  (CSPRNG mappings + vetted-library wrappers + patch codegen), CLI, reporting.

[Unreleased]: https://github.com/Londopy/deadpoint/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Londopy/deadpoint/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Londopy/deadpoint/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/Londopy/deadpoint/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Londopy/deadpoint/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Londopy/deadpoint/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Londopy/deadpoint/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Londopy/deadpoint/releases/tag/v0.1.0
