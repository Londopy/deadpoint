//! Optional Rust acceleration for deadpoint.
//!
//! Exposes the two hot MT19937 primitives — output *untempering* and the
//! clean-case *state solve* — behind the same interface as the pure-Python
//! implementation in `deadpoint/exploit/`.  The Python layer imports this module
//! automatically when it is compiled and falls back to pure Python otherwise, so
//! behaviour is identical; this is only a speed path.  The logic is a 1:1 port of
//! the tested Python `untemper`.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

const MASK32: u32 = 0xFFFF_FFFF;

// Standard MT19937 tempering parameters (match CPython / the Python port).
const U: u32 = 11;
const S: u32 = 7;
const B: u32 = 0x9D2C_5680;
const T: u32 = 15;
const C: u32 = 0xEFC6_0000;
const L: u32 = 18;

#[inline]
fn undo_right_shift_xor(y: u32, shift: u32, mask: u32) -> u32 {
    let mut x = y;
    let mut i = 0;
    while i < 32 {
        x = y ^ ((x >> shift) & mask);
        i += shift;
    }
    x
}

#[inline]
fn undo_left_shift_xor(y: u32, shift: u32, mask: u32) -> u32 {
    let mut x = y;
    let mut i = 0;
    while i < 32 {
        x = y ^ ((x << shift) & mask);
        i += shift;
    }
    x
}

#[inline]
fn untemper_word(y: u32) -> u32 {
    let mut v = y;
    v = undo_right_shift_xor(v, L, MASK32);
    v = undo_left_shift_xor(v, T, C);
    v = undo_left_shift_xor(v, S, B);
    v = undo_right_shift_xor(v, U, MASK32);
    v
}

/// Untemper a single tempered 32-bit output back to its raw state word.
#[pyfunction]
fn untemper(y: u32) -> u32 {
    untemper_word(y)
}

/// Untemper many outputs at once (amortises the FFI boundary).
#[pyfunction]
fn untemper_batch(ys: Vec<u32>) -> Vec<u32> {
    ys.into_iter().map(untemper_word).collect()
}

/// Recover the 624-word MT19937 state block from >=624 consecutive
/// `getrandbits(32)` outputs (the clean-case state solve).
#[pyfunction]
fn recover_state_words(outputs: Vec<u32>) -> PyResult<Vec<u32>> {
    if outputs.len() < 624 {
        return Err(PyValueError::new_err("need at least 624 outputs"));
    }
    Ok(outputs[..624].iter().map(|&y| untemper_word(y)).collect())
}

#[pymodule]
fn deadpoint_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(untemper, m)?)?;
    m.add_function(wrap_pyfunction!(untemper_batch, m)?)?;
    m.add_function(wrap_pyfunction!(recover_state_words, m)?)?;
    Ok(())
}
