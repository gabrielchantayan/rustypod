//! strcmp — original: `FUN_08391e44` @ 0x08391e44 (68 bytes), reached
//! through the 4-byte entry veneer `thunk_FUN_08391e44` @ 0x08391e38
//! (`b 0x08391e44`).
//!
//! With 756 `bl` call sites (binary-scanned; every one targets the veneer
//! at 0x08391e38, none the body) this is the most-called function in the
//! whole 0x08300000-0x083fffff range. It is *not* the ARM ADS strcmp —
//! that one is absent from osos (see `strlen_safe.rs`) — it belongs to the
//! plain byte-loop string cluster at 0x08391dec..0x083924a0 that also
//! holds `strlen` @ 0x08392478 and the table-driven string hash
//! @ 0x08391dec.
//!
//! Algorithm: walk both strings while the bytes are equal and neither is
//! NUL, then return the *normalized* sign of the difference at the
//! stopping position: `1` / `0` / `-1`, never the raw byte delta. That
//! makes it a `sign(strcmp)` variant — callers that only test against zero
//! are unaffected, callers that use the magnitude would differ from a libc
//! strcmp.
//!
//! The original's continue test is the ADS two-flag idiom
//! `cmp a,#0; cmpne b,#0; bne loop`; since the loop is only entered when
//! `a == b`, testing `a != 0` alone is equivalent, and the port keeps the
//! redundant second test out.
//!
//! Deviation: the byte loads are `read_volatile` so LLVM's loop-idiom pass
//! cannot rewrite the walk into a call to the libc `strcmp`/`bcmp` that
//! does not exist on the target.

/// Three-way string compare returning `-1`, `0` or `1` (not the byte
/// delta) — original @ 0x08391e44.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut a = a;
    let mut b = b;
    loop {
        let byte_a = a.read_volatile();
        let byte_b = b.read_volatile();
        if byte_a != byte_b || byte_a == 0 {
            // Written as an explicit ladder (not `Ord::cmp`) so LLVM emits
            // the original's `movhi #1 / movcs #0 / mvncc #-1` trio instead
            // of materializing an i8 Ordering and sign-extending it.
            return if byte_a > byte_b {
                1
            } else if byte_a == byte_b {
                0
            } else {
                -1
            };
        }
        a = a.add(1);
        b = b.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Reference: normalized sign of the unsigned-byte comparison, exactly
    /// what the original computes.
    fn ref_strcmp(a: &[u8], b: &[u8]) -> i32 {
        let mut i = 0;
        loop {
            let (x, y) = (a[i], b[i]);
            if x != y || x == 0 {
                return match x.cmp(&y) {
                    core::cmp::Ordering::Greater => 1,
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Less => -1,
                };
            }
            i += 1;
        }
    }

    fn call(a: &[u8], b: &[u8]) -> i32 {
        unsafe { strcmp(a.as_ptr(), b.as_ptr()) }
    }

    #[test]
    fn equal_strings_return_zero() {
        assert_eq!(call(b"\0", b"\0"), 0);
        assert_eq!(call(b"abc\0", b"abc\0"), 0);
        assert_eq!(call(b"the quick brown fox\0", b"the quick brown fox\0"), 0);
    }

    #[test]
    fn orders_by_first_difference() {
        assert_eq!(call(b"abc\0", b"abd\0"), -1);
        assert_eq!(call(b"abd\0", b"abc\0"), 1);
        assert_eq!(call(b"ab\0", b"abc\0"), -1);
        assert_eq!(call(b"abc\0", b"ab\0"), 1);
        assert_eq!(call(b"\0", b"a\0"), -1);
        assert_eq!(call(b"a\0", b"\0"), 1);
    }

    /// The result is normalized: a difference of 100 still returns 1.
    #[test]
    fn result_is_normalized_not_the_byte_delta() {
        assert_eq!(call(b"a\0", b"\x01\0"), 1);
        assert_eq!(call(b"\x01\0", b"a\0"), -1);
        assert_eq!(call(b"\xff\0", b"\x01\0"), 1);
    }

    /// High bytes compare as *unsigned* (`ldrb`, not `ldrsb`).
    #[test]
    fn bytes_compare_unsigned() {
        assert_eq!(call(b"\x80\0", b"\x7f\0"), 1);
        assert_eq!(call(b"\xff\0", b"\x00"), 1);
    }

    /// Exhaustive sweep against the reference: every length 0..24, every
    /// mismatch position, both orders, at four start alignments.
    #[test]
    fn matches_reference_over_lengths_and_alignments() {
        for align_a in 0..4usize {
            for align_b in 0..4usize {
                for len in 0..24usize {
                    for mismatch in 0..=len {
                        let mut a: Vec<u8> = std::vec![0u8; align_a + len + 2];
                        let mut b: Vec<u8> = std::vec![0u8; align_b + len + 2];
                        for i in 0..len {
                            let v = (i as u8 % 200) + 1;
                            a[align_a + i] = v;
                            b[align_b + i] = v;
                        }
                        if mismatch < len {
                            b[align_b + mismatch] = b[align_b + mismatch].wrapping_add(7);
                        }
                        let want = ref_strcmp(&a[align_a..], &b[align_b..]);
                        let got = unsafe { strcmp(a.as_ptr().add(align_a), b.as_ptr().add(align_b)) };
                        assert_eq!(got, want, "align={align_a}/{align_b} len={len} mm={mismatch}");
                    }
                }
            }
        }
    }

    /// Sign agrees with the host libc `strcmp` on every ASCII pair of
    /// length <= 3 (magnitude deliberately does not — see the module doc).
    #[test]
    fn sign_agrees_with_std_ordering() {
        let alphabet = [b'\0', b'a', b'b', b'z', 0x80u8, 0xffu8];
        for &c0 in &alphabet {
            for &c1 in &alphabet {
                for &d0 in &alphabet {
                    for &d1 in &alphabet {
                        let a = [c0, c1, 0u8];
                        let b = [d0, d1, 0u8];
                        let want = {
                            let sa: &[u8] = &a[..a.iter().position(|&x| x == 0).unwrap()];
                            let sb: &[u8] = &b[..b.iter().position(|&x| x == 0).unwrap()];
                            match sa.cmp(sb) {
                                core::cmp::Ordering::Greater => 1,
                                core::cmp::Ordering::Equal => 0,
                                core::cmp::Ordering::Less => -1,
                            }
                        };
                        assert_eq!(call(&a, &b), want, "{a:?} vs {b:?}");
                    }
                }
            }
        }
    }
}
