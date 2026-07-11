# native/ — optional Rust accelerator

Optional Rust + PyO3 acceleration for deadpoint's hottest MT19937 primitives.
**Not required**: the pure-Python implementation in `deadpoint/exploit/` is the
reference and is complete on its own. This is a drop-in speed path.

## What it provides

A compiled module `deadpoint_native` exposing, behind the *same* interface as the
Python code:

- `untemper(y: u32) -> u32` — invert MT19937 output tempering.
- `untemper_batch(ys) -> list` — batched untempering (amortises the FFI cost).
- `recover_state_words(outputs) -> list` — the clean-case 624-word state solve.

`deadpoint/exploit/untemper.py` imports `deadpoint_native` automatically when it
is present and transparently uses it; otherwise it stays on pure Python. So
installing this changes performance, never behaviour — and the Rust-parity test
(`tests/test_native_parity.py`) asserts the two produce identical results.

## Build

Requires a Rust toolchain (`rustup`) and `maturin`:

```bash
pip install maturin
cd native
maturin develop --release      # builds and installs deadpoint_native into the active venv
```

Then, from the repo root:

```bash
python -c "from deadpoint.exploit import untemper; print('native:', untemper.NATIVE)"
pytest tests/test_native_parity.py       # runs (instead of skipping) once built
```

To ship wheels with the native module bundled, build from `native/` with
`maturin build --release` and publish those alongside the pure-Python wheel.

## Layout

- `Cargo.toml` — crate manifest (`cdylib`, PyO3 with `extension-module`).
- `pyproject.toml` — maturin build config (`module-name = "deadpoint_native"`).
- `src/lib.rs` — the implementation (a 1:1 port of the tested Python `untemper`).
