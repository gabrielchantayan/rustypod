//! memcpy_forward_words — original: `FUN_08000188` @ 0x08000188 (108 bytes).
//!
//! The word-aligned forward-copy body shared by the ARM ADS runtime.  The
//! target ABI receives `dst` in r0, `src` in r1, and `len` in r2; r3 is a
//! scratch register.  It subtracts and streams 32-byte blocks as two
//! `ldmia`/`stmia` 16-byte pairs, then selects 16/8/4-byte blocks and a
//! 0–3-byte tail from the remaining length bits.  Each `ldmia` completes all
//! its loads before its paired `stmia` begins storing.
//!
//! r0 returns the advanced destination (`dst + len`); r1 is likewise advanced
//! but is caller-saved under the ARM ABI and is not a Rust return value.  Both
//! pointers must be word-aligned.  This is forward copy rather than memmove:
//! overlapping `dst > src` ranges can consume earlier stores.  In particular,
//! the implementation preserves the ARM body's grouped-load-before-store
//! behavior, rather than reducing overlap to a byte-by-byte loop.

/// Copy `len` bytes from word-aligned `src` to word-aligned `dst`, returning
/// `dst.add(len)` as the firmware's r0 result.
///
/// # Safety
///
/// `src` and `dst` must be four-byte aligned and valid to read and write,
/// respectively, for `len` bytes.  Overlap is executed as this routine's
/// forward, grouped-load-before-store operation; use [`crate::libc::memmove`]
/// when an overlap-safe copy is required.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memcpy_forward_words(
    mut dst: *mut u8,
    mut src: *const u8,
    mut len: usize,
) -> *mut u8 {
    let mut dst_words = dst as *mut u32;
    let mut src_words = src as *const u32;

    // `subs r2,#32`, then two separate ldmia/stmia pairs per iteration.
    // Keeping each group together also preserves their observable behavior
    // for overlapping raw ranges.
    while len >= 32 {
        let (w0, w1, w2, w3) = (
            src_words.read(),
            src_words.add(1).read(),
            src_words.add(2).read(),
            src_words.add(3).read(),
        );
        dst_words.write(w0);
        dst_words.add(1).write(w1);
        dst_words.add(2).write(w2);
        dst_words.add(3).write(w3);
        src_words = src_words.add(4);
        dst_words = dst_words.add(4);

        let (w0, w1, w2, w3) = (
            src_words.read(),
            src_words.add(1).read(),
            src_words.add(2).read(),
            src_words.add(3).read(),
        );
        dst_words.write(w0);
        dst_words.add(1).write(w1);
        dst_words.add(2).write(w2);
        dst_words.add(3).write(w3);
        src_words = src_words.add(4);
        dst_words = dst_words.add(4);
        len -= 32;
    }

    // The original selects each block from the low bits left after its
    // wrapping initial subtract; those bits are identical to `len` here.
    if len & 16 != 0 {
        let (w0, w1, w2, w3) = (
            src_words.read(),
            src_words.add(1).read(),
            src_words.add(2).read(),
            src_words.add(3).read(),
        );
        dst_words.write(w0);
        dst_words.add(1).write(w1);
        dst_words.add(2).write(w2);
        dst_words.add(3).write(w3);
        src_words = src_words.add(4);
        dst_words = dst_words.add(4);
    }
    if len & 8 != 0 {
        let (w0, w1) = (src_words.read(), src_words.add(1).read());
        dst_words.write(w0);
        dst_words.add(1).write(w1);
        src_words = src_words.add(2);
        dst_words = dst_words.add(2);
    }
    if len & 4 != 0 {
        let word = src_words.read();
        dst_words.write(word);
        src_words = src_words.add(1);
        dst_words = dst_words.add(1);
    }

    dst = dst_words as *mut u8;
    src = src_words as *const u8;
    // The conditional byte loads precede every conditional byte store.
    match len & 3 {
        0 => {}
        1 => {
            let b0 = src.read();
            dst.write(b0);
            dst = dst.add(1);
        }
        2 => {
            let (b0, b1) = (src.read(), src.add(1).read());
            dst.write(b0);
            dst.add(1).write(b1);
            dst = dst.add(2);
        }
        _ => {
            let (b0, b1, b2) = (src.read(), src.add(1).read(), src.add(2).read());
            dst.write(b0);
            dst.add(1).write(b1);
            dst.add(2).write(b2);
            dst = dst.add(3);
        }
    }
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Distinct, non-trivial byte pattern.
    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size)
            .map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8)
            .collect()
    }

    /// Reference one ARM `ldmia`/`stmia`-style group: snapshot all bytes
    /// before writing any of them, so overlap has the target's semantics.
    fn copy_group(buffer: &mut [u8], dst: usize, src: usize, count: usize) {
        let mut loaded = [0u8; 16];
        loaded[..count].copy_from_slice(&buffer[src..src + count]);
        buffer[dst..dst + count].copy_from_slice(&loaded[..count]);
    }

    /// Reference the exact group schedule at 0x08000188, including its tail.
    fn ref_memcpy_forward_words(buffer: &mut [u8], dst: usize, src: usize, mut len: usize) -> usize {
        let mut dst = dst;
        let mut src = src;
        while len >= 32 {
            copy_group(buffer, dst, src, 16);
            dst += 16;
            src += 16;
            copy_group(buffer, dst, src, 16);
            dst += 16;
            src += 16;
            len -= 32;
        }
        for count in [16, 8, 4] {
            if len & count != 0 {
                copy_group(buffer, dst, src, count);
                dst += count;
                src += count;
            }
        }
        if len & 3 != 0 {
            copy_group(buffer, dst, src, len & 3);
            dst += len & 3;
        }
        dst
    }

    /// Word-aligned, non-overlapping copies cover every 32/16/8/4/byte-tail
    /// combination and prove the ARM return convention is the end pointer.
    #[test]
    fn copies_all_lengths_and_returns_advanced_destination() {
        const SIZE: usize = 128;
        for dst_off in (0..16).step_by(4) {
            for src_off in (64..80).step_by(4) {
                for len in 0..=48usize {
                    let mut buffer = pattern(SIZE, 37);
                    let mut reference = buffer.clone();
                    let expected_end = ref_memcpy_forward_words(&mut reference, dst_off, src_off, len);
                    let returned = unsafe {
                        memcpy_forward_words(
                            buffer.as_mut_ptr().add(dst_off),
                            buffer.as_ptr().add(src_off),
                            len,
                        )
                    };
                    assert_eq!(returned, unsafe { buffer.as_mut_ptr().add(expected_end) });
                    assert_eq!(
                        buffer, reference,
                        "mismatch: dst_off={dst_off} src_off={src_off} len={len}"
                    );
                }
            }
        }
    }

    /// `ldmia` loads a complete group before `stmia` stores it.  These
    /// overlapping cases distinguish that hardware schedule from both an
    /// overlap-safe copy and a byte-at-a-time forward loop.
    #[test]
    fn overlap_preserves_grouped_forward_load_store_order() {
        for (dst_off, src_off, len) in [(4, 0, 36), (8, 0, 19), (0, 4, 36), (0, 0, 35)] {
            let mut buffer = pattern(80, 91);
            let mut reference = buffer.clone();
            let expected_end = ref_memcpy_forward_words(&mut reference, dst_off, src_off, len);
            let returned = unsafe {
                memcpy_forward_words(
                    buffer.as_mut_ptr().add(dst_off),
                    buffer.as_ptr().add(src_off),
                    len,
                )
            };
            assert_eq!(returned, unsafe { buffer.as_mut_ptr().add(expected_end) });
            assert_eq!(
                buffer, reference,
                "overlap mismatch: dst_off={dst_off} src_off={src_off} len={len}"
            );
        }
    }

    /// A zero count takes the conditional tail's immediate return path.
    #[test]
    fn zero_length_returns_unadvanced_destination() {
        let mut buffer = pattern(16, 5);
        let before = buffer.clone();
        let returned = unsafe { memcpy_forward_words(buffer.as_mut_ptr(), buffer.as_ptr(), 0) };
        assert_eq!(returned, buffer.as_mut_ptr());
        assert_eq!(buffer, before);
    }
}
