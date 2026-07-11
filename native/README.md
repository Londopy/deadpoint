# native/ — optional Rust accelerator (not required)

This directory is reserved for the **optional** native acceleration path
described in the spec (milestone M9, explicitly a bonus). The pure-Python
implementation in `deadpoint/exploit/` is the reference and is complete on its
own; nothing here is on the critical path.

## Design

A Rust + PyO3 crate (built with `maturin`) would expose the two hottest
primitives behind the *same* Python interface the pure-Python code already uses:

- `untemper(y: u32) -> u32` — GF(2) inversion of MT19937 tempering.
- `solve_state(words: &[u32]) -> Vec<u32>` — the linear-algebra state solve.

The Python layer would select the compiled module automatically when present and
fall back to pure Python otherwise, mirroring the "Rust core under a Python API"
pattern. Rust-parity tests would assert both cores produce identical results.

Build the pure-Python version first (done); the Rust module is a drop-in
accelerator, not a rewrite.
