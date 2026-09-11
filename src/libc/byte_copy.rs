//! byte_copy — original: `FUN_080005fc` @ 0x080005fc (24 bytes).
//!
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/000/080005fc_FUN_080005fc.c`.
//! The six-instruction ARM leaf decrements `len`, tests it against -1, then
//! post-increments a byte load and store while the count remains nonzero. It
//! is therefore a forward, byte-at-a-time copy with a `void` return; zero
//! length performs no reads or writes. Overlap is deliberately not repaired:
//! it retains the original forward-copy behavior rather than becoming
//! `memmove`.
//!
//! Deviation: volatile byte accesses prevent LLVM from replacing the loop with
//! an unavailable freestanding memcpy intrinsic; for valid, nonvolatile
//! buffers this preserves the original reads and writes.

/// Copies `len` bytes from `src` to `dst` in ascending address order.
///
/// # Safety
/// For a nonzero `len`, both ranges must be valid for `len` bytes. The source
/// and destination may overlap, with the original's forward-copy semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_copy(mut dst: *mut u8, mut src: *const u8, mut len: u32) {
    while len != 0 {
        dst.write_volatile(src.read_volatile());
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }
}

/// iram_byte_copy_veneer — original: `thunk_EXT_FUN_220005fc` @
/// 0x08038260 (Ghidra reports 4 bytes; raw osos.dec proves the full **8**
/// bytes are `ldr pc, [pc, #-4]` / `0xe51ff004` at 0x08038260 and the
/// literal target `0x220005fc` at 0x08038264; the next veneer starts at
/// 0x08038268).
///
/// Every ARM `B`/`BL` word in osos.dec was decoded: this veneer has **10
/// direct `bl` callers, all unconditional** (0x082e1b2c, 0x082e1b3c,
/// 0x082e1b4c, 0x082e1b5c, 0x082e1b6c, 0x082e1b84, 0x082e1bb0,
/// 0x082e1bd0, 0x082e1bf0, and 0x082e1c08), with no predicated calls or
/// aligned data word containing the thunk address. The relocator @
/// 0x080046e0 copies osos 0x08000000..0x0800aed8 to IRAM 0x22000000, so
/// target 0x220005fc is the already-ported [`byte_copy`] body @
/// 0x080005fc, not a distinct function.
///
/// Algorithm: the retail literal veneer loads PC directly from its adjacent
/// literal, preserving r0-r2 and LR, then the target copies `len` bytes
/// forwards. This Rust hook instead calls the existing body through a
/// volatile function pointer. That deliberate source-level deviation keeps
/// this separately addressable hook seam from being inlined or folded into
/// the body; its memory behavior, argument ABI, and void return are
/// unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iram_byte_copy_veneer")]
#[inline(never)]
pub unsafe extern "C" fn iram_byte_copy_veneer(dst: *mut u8, src: *const u8, len: u32) {
    let body = core::ptr::read_volatile(
        &(byte_copy as unsafe extern "C" fn(*mut u8, *const u8, u32)),
    );
    body(dst, src, len)
}

/// The 0x08038260 IRAM veneer must forward the byte-copy edge cases without
/// changing their forward-overlap behavior or dereferencing zero-length
/// pointers.
#[cfg(test)]
#[test]
fn iram_veneer_matches_byte_copy_edge_cases() {
    const LEN: usize = 64;
    unsafe { iram_byte_copy_veneer(core::ptr::null_mut(), core::ptr::null(), 0) };

    for len in 0..=LEN {
        let mut src = [0u8; LEN + 16];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        let mut dst = [0xa5u8; LEN + 16];

        unsafe {
            iram_byte_copy_veneer(dst.as_mut_ptr().add(4), src.as_ptr().add(8), len as u32);
        }

        assert_eq!(&dst[..4], &[0xa5; 4], "head guard, len={len}");
        assert_eq!(&dst[4..4 + len], &src[8..8 + len], "copied bytes, len={len}");
        assert!(dst[4 + len..].iter().all(|&byte| byte == 0xa5), "tail guard, len={len}");
    }

    let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
    unsafe { iram_byte_copy_veneer(bytes.as_mut_ptr().add(2), bytes.as_ptr(), 5) };
    assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
}

/// The veneer must remain a distinct target from the body it forwards to.
#[cfg(test)]
#[test]
fn iram_veneer_is_a_distinct_call_target_from_byte_copy() {
    let (veneer, body) = unsafe {
        (
            core::ptr::read_volatile(
                &(iram_byte_copy_veneer as unsafe extern "C" fn(*mut u8, *const u8, u32)),
            ),
            core::ptr::read_volatile(
                &(byte_copy as unsafe extern "C" fn(*mut u8, *const u8, u32)),
            ),
        )
    };

    assert_ne!(veneer as usize, 0);
    assert_ne!(veneer as usize, body as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_lengths_without_touching_guards() {
        const LEN: usize = 64;
        let mut src = [0u8; LEN + 16];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for len in 0..=LEN {
            let mut dst = [0xa5u8; LEN + 16];
            unsafe { byte_copy(dst.as_mut_ptr().add(4), src.as_ptr().add(8), len as u32) };
            assert_eq!(&dst[..4], &[0xa5; 4], "head guard, len={len}");
            assert_eq!(
                &dst[4..4 + len],
                &src[8..8 + len],
                "copied bytes, len={len}"
            );
            assert!(
                dst[4 + len..].iter().all(|&byte| byte == 0xa5),
                "tail guard, len={len}"
            );
        }
    }

    #[test]
    fn overlap_retains_forward_copy_behavior() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        unsafe { byte_copy(bytes.as_mut_ptr().add(2), bytes.as_ptr(), 5) };
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }

    #[test]
    fn zero_length_dereferences_neither_pointer() {
        unsafe { byte_copy(core::ptr::null_mut(), core::ptr::null(), 0) };
    }
}
