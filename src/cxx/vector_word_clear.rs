//! `vector_word_clear` — original: `FUN_083e4884` @ **0x083e4884**.
//!
//! Raw `osos.dec` establishes the exact 84-byte body at
//! `0x083e4884..0x083e48d8`: it starts with `push {r4,lr}`, returns through
//! `pop {r4,pc}` at `0x083e48d4`, and `ldr r2,[r0,#8]` at `0x083e48d8` starts
//! the next independently entered function. A complete raw A32 decode finds
//! no body `bl` instructions and no inbound direct plain or predicated `bl`
//! instructions; Ghidra's three apparent callers are therefore not direct
//! BL edges.
//!
//! # Algorithm
//!
//! This is the 4-byte-element `std::vector::clear()` specialization. For a
//! nonempty vector it leaves element storage intact and makes the vector empty
//! by assigning `begin` to `end`. The stock copy and cursor loops have equal
//! initial bounds and execute zero iterations; they reduce to that assignment.
//!
//! # Deliberate deviations
//!
//! Rust directly performs the observable final assignment rather than retaining
//! the stock's unreachable loops. `VectorBounds` uses native pointers for host
//! fixtures while retaining adjacent target words on ARM.

use crate::cxx::templates::VectorBounds;

/// Empties a vector of opaque 4-byte elements without releasing its storage.
///
/// Original: `FUN_083e4884` @ `0x083e4884` (84 bytes, zero body BL calls and
/// zero inbound direct BL calls, raw-binary verified).
///
/// # Safety
///
/// `vector` must point to a readable and writable retailOS vector head.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_word_clear(vector: *mut VectorBounds) {
    let begin = unsafe { (*vector).begin };
    if begin != unsafe { (*vector).end } {
        unsafe { (*vector).end = begin };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vector_remains_empty() {
        let mut vector = VectorBounds { begin: core::ptr::null_mut(), end: core::ptr::null_mut() };

        unsafe { vector_word_clear(&mut vector) };

        assert_eq!(vector.begin, vector.end);
    }

    #[test]
    fn nonempty_vector_discards_all_elements_without_touching_storage() {
        let mut words = [0x1122_3344u32, 0x5566_7788];
        let begin = words.as_mut_ptr().cast::<u8>();
        let mut vector = VectorBounds { begin, end: unsafe { begin.add(core::mem::size_of_val(&words)) } };

        unsafe { vector_word_clear(&mut vector) };

        assert_eq!(vector.end, begin);
        assert_eq!(words, [0x1122_3344, 0x5566_7788]);
    }

    #[test]
    fn reversed_bounds_are_still_cleared() {
        let mut words = [0u32; 2];
        let end = words.as_mut_ptr().cast::<u8>();
        let mut vector = VectorBounds { begin: unsafe { end.add(4) }, end };

        unsafe { vector_word_clear(&mut vector) };

        assert_eq!(vector.end, vector.begin);
    }
}
