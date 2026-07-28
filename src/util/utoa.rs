//! utoa / variant_compare — retailOS number formatting and the type-tagged
//! variant comparator.
//!
//! `utoa` — original: `FUN_080e799c` @ 0x080e799c (116 bytes). Converts a
//! 32-bit value to a NUL-terminated string in any base 2..=36 using an
//! embedded digit table ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" @
//! 0x080e7a10). A '-' sign is emitted only for base 10 when the value is
//! negative as an i32; for every other base the value is treated as
//! unsigned (so e.g. 0xFFFFFFFF in base 16 is "FFFFFFFF", in base 10 "-1").
//! Digits are generated least-significant-first, then reversed in place
//! (the sign, if any, stays in front). Returns the original `buf` pointer
//! (start of the string), not the end. The original divides via
//! `__rt_udiv` @ 0x08036f14; the port lets LLVM emit `__aeabi_uidivmod`
//! for the same u32 divide (behaviorally identical).
//!
//! `variant_compare` — original: `FUN_080eb6dc` @ 0x080eb6dc (104 bytes).
//! Three-way compare of a C++ type-tagged variant: `{ tag: u32,
//! payload: *const VariantPayload }`. Tags that differ return
//! `tag_a - tag_b` immediately. Equal tags dispatch on the tag:
//!   0 — length-prefixed string: `len` at payload+12, data ptr at +16;
//!       different lengths return `len_a - len_b`, equal lengths tail-call
//!       memcmp @ 0x08030f64 (crate::libc::memcmp) over `len` bytes.
//!   1 — C-string pointer at payload+0.
//!   2 — C-string pointer at payload+4.
//!   3 — signed int at payload+8, returns `int_a - int_b` (wrapping).
//!   _ — returns 0.
//! The C-string tags (1, 2) compare via a normalized three-way strcmp @
//! 0x08391e38/0x08391e44 returning exactly -1/0/+1; a NULL pointer on the
//! left returns -1 (even when both are NULL), a NULL on the right returns
//! +1. That strcmp is now its own module (crate::libc::strcmp), so the
//! C-string tags call it directly.

use crate::libc::memcmp::memcmp;
use crate::libc::strcmp::strcmp;

/// Embedded digit table, byte-identical to the original @ 0x080e7a10.
static DIGITS: [u8; 36] = *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// utoa — original @ 0x080e799c. Writes `value` in `base` (2..=36) as a
/// NUL-terminated string into `buf` and returns `buf`. Sign handling
/// exists only for base 10; all other bases render the raw u32.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn utoa(value: u32, buf: *mut u8, base: u32) -> *mut u8 {
    let mut value = value;
    // Like the original, base is trusted to be in 2..=36: no zero-divisor
    // trap, no digit-table bounds check.
    core::hint::assert_unchecked(base != 0);
    let mut digits = buf;
    if base == 10 && (value as i32) < 0 {
        *digits = b'-';
        digits = digits.add(1);
        value = value.wrapping_neg();
    }

    // Digits are produced least-significant-first.
    let mut end = digits;
    loop {
        let quotient = value / base;
        *end = *DIGITS.get_unchecked((value % base) as usize);
        end = end.add(1);
        value = quotient;
        if value == 0 {
            break;
        }
    }
    *end = 0;

    // Reverse the digit run in place (sign stays put).
    let mut lo = digits;
    let mut hi = end.sub(1);
    while lo < hi {
        let tmp = *lo;
        *lo = *hi;
        *hi = tmp;
        lo = lo.add(1);
        hi = hi.sub(1);
    }
    buf
}

/// Type-tagged variant record compared by `variant_compare`.
/// Layout matches the original: tag at +0, payload pointer at +4.
#[repr(C)]
pub union Variant {
    pub tag: u32,
    pub parts: VariantParts,
}

/// Field view of `Variant` (both words together).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VariantParts {
    pub tag: u32,
    pub payload: *const VariantPayload,
}

/// Tag-dependent payload record pointed to by `Variant::payload`.
/// The active field is selected by the tag:
/// tag 0 = `string`, tags 1/2 = `cstr` (at offset 0 / 4), tag 3 = `int`.
#[repr(C)]
pub union VariantPayload {
    /// Tag 0: length-prefixed string.
    pub string: VariantString,
    /// Tags 1 and 2: NUL-terminated string pointers at offsets 0 and 4.
    pub cstr: VariantCStrs,
    /// Tag 3: signed integer at offset 8.
    pub int: VariantInt,
}

/// Tag 0 payload view: `len` at +12, data pointer at +16.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VariantString {
    pub _unused: [u32; 3],
    pub len: u32,
    pub data: *const u8,
}

/// Tags 1/2 payload view: C-string pointers at +0 and +4.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VariantCStrs {
    pub tag1: *const u8,
    pub tag2: *const u8,
}

/// Tag 3 payload view: signed integer at +8.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VariantInt {
    pub _unused: [u32; 2],
    pub value: i32,
}

/// variant_compare — original @ 0x080eb6dc. See module docs for the
/// per-tag comparison rules and NULL conventions.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn variant_compare(a: *const Variant, b: *const Variant) -> i32 {
    let tag_a = (*a).tag;
    let tag_b = (*b).tag;
    if tag_a != tag_b {
        return (tag_a as i32).wrapping_sub(tag_b as i32);
    }
    let payload_a = (*a).parts.payload;
    let payload_b = (*b).parts.payload;
    match tag_a {
        0 => {
            let str_a = &(*payload_a).string;
            let str_b = &(*payload_b).string;
            if str_a.len != str_b.len {
                (str_a.len as i32).wrapping_sub(str_b.len as i32)
            } else {
                memcmp(str_a.data, str_b.data, str_a.len as usize)
            }
        }
        1 => compare_cstrs((*payload_a).cstr.tag1, (*payload_b).cstr.tag1),
        2 => compare_cstrs((*payload_a).cstr.tag2, (*payload_b).cstr.tag2),
        3 => (*payload_a)
            .int
            .value
            .wrapping_sub((*payload_b).int.value),
        _ => 0,
    }
}

/// NULL conventions of the original: left NULL -> -1 (even if both NULL),
/// right NULL -> +1, otherwise the normalized three-way strcmp.
unsafe fn compare_cstrs(a: *const u8, b: *const u8) -> i32 {
    if a.is_null() {
        return -1;
    }
    if b.is_null() {
        return 1;
    }
    strcmp(a, b)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// Reference conversion: same sign rules as the original (base-10
    /// i32 sign, unsigned otherwise).
    fn reference(value: u32, base: u32) -> String {
        let (negative, mut v) = if base == 10 && (value as i32) < 0 {
            (true, value.wrapping_neg())
        } else {
            (false, value)
        };
        let mut digits = Vec::new();
        loop {
            digits.push(DIGITS[(v % base) as usize]);
            v /= base;
            if v == 0 {
                break;
            }
        }
        let mut s = String::new();
        if negative {
            s.push('-');
        }
        for d in digits.iter().rev() {
            s.push(*d as char);
        }
        s
    }

    fn convert(value: u32, base: u32) -> (String, *mut u8, *mut u8) {
        let mut buf = [0xAAu8; 40];
        let ret = unsafe { utoa(value, buf.as_mut_ptr(), base) };
        let len = buf.iter().position(|&c| c == 0).expect("NUL-terminated");
        (
            String::from_utf8(buf[..len].to_vec()).unwrap(),
            ret,
            buf.as_mut_ptr(),
        )
    }

    #[test]
    fn digit_table_content() {
        assert_eq!(&DIGITS, b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    #[test]
    fn all_bases_match_reference() {
        for value in [0u32, 1, 2, 9, 10, 35, 36, 255, 4096, 123_456_789, u32::MAX] {
            for base in 2..=36u32 {
                let (got, _, _) = convert(value, base);
                assert_eq!(got, reference(value, base), "value={value} base={base}");
            }
        }
    }

    #[test]
    fn zero_every_base() {
        for base in 2..=36u32 {
            assert_eq!(convert(0, base).0, "0", "base={base}");
        }
    }

    #[test]
    fn returns_buf_start() {
        let (_, ret, buf_ptr) = convert(12345, 10);
        assert_eq!(ret, buf_ptr);
    }

    #[test]
    fn base10_signed() {
        assert_eq!(convert(-1i32 as u32, 10).0, "-1");
        assert_eq!(convert(-12345i32 as u32, 10).0, "-12345");
        assert_eq!(convert(i32::MIN as u32, 10).0, "-2147483648");
        assert_eq!(convert(i32::MAX as u32, 10).0, "2147483647");
    }

    #[test]
    fn other_bases_unsigned_wraparound() {
        // Same bit patterns as the negative base-10 cases, but rendered
        // unsigned in non-10 bases.
        assert_eq!(convert(u32::MAX, 16).0, "FFFFFFFF");
        assert_eq!(convert(u32::MAX, 2).0, "11111111111111111111111111111111");
        assert_eq!(convert(u32::MAX, 36).0, "1Z141Z3");
        assert_eq!(convert(i32::MIN as u32, 16).0, "80000000");
        assert_eq!(convert(-12345i32 as u32, 16).0, "FFFFCFC7");
    }

    #[test]
    fn nul_termination_and_no_overrun_past_nul() {
        let mut buf = [0xAAu8; 40];
        unsafe { utoa(0, buf.as_mut_ptr(), 8) };
        assert_eq!(&buf[..3], &[b'0', 0, 0xAA]);
    }

    // --- variant_compare ---

    fn variant(tag: u32, payload: *const VariantPayload) -> Variant {
        Variant {
            parts: VariantParts { tag, payload },
        }
    }

    fn string_payload(s: &[u8]) -> VariantPayload {
        VariantPayload {
            string: VariantString {
                _unused: [0; 3],
                len: s.len() as u32,
                data: s.as_ptr(),
            },
        }
    }

    #[test]
    fn tag_mismatch_returns_tag_difference() {
        let pa = VariantPayload { int: VariantInt { _unused: [0; 2], value: 0 } };
        let pb = VariantPayload { int: VariantInt { _unused: [0; 2], value: 0 } };
        let a = variant(1, &pa);
        let b = variant(3, &pb);
        assert_eq!(unsafe { variant_compare(&a, &b) }, -2);
        assert_eq!(unsafe { variant_compare(&b, &a) }, 2);
    }

    #[test]
    fn tag0_string_compare() {
        let pa = string_payload(b"hello");
        let pb = string_payload(b"hello");
        let pc = string_payload(b"hellp");
        let pd = string_payload(b"hi");
        let (a, b, c, d) = (
            variant(0, &pa),
            variant(0, &pb),
            variant(0, &pc),
            variant(0, &pd),
        );
        unsafe {
            assert_eq!(variant_compare(&a, &b), 0);
            // 'o' - 'p' = -1 via memcmp.
            assert_eq!(variant_compare(&a, &c), -1);
            assert_eq!(variant_compare(&c, &a), 1);
            // Different lengths: len difference, not content compare.
            assert_eq!(variant_compare(&a, &d), 3);
            assert_eq!(variant_compare(&d, &a), -3);
        }
    }

    #[test]
    fn tag1_and_tag2_cstr_compare() {
        for tag in [1u32, 2] {
            let pa = VariantPayload {
                cstr: VariantCStrs {
                    tag1: b"apple\0".as_ptr(),
                    tag2: b"apple\0".as_ptr(),
                },
            };
            let pb = VariantPayload {
                cstr: VariantCStrs {
                    tag1: b"banana\0".as_ptr(),
                    tag2: b"banana\0".as_ptr(),
                },
            };
            let pa2 = VariantPayload {
                cstr: VariantCStrs {
                    tag1: b"apple\0".as_ptr(),
                    tag2: b"apple\0".as_ptr(),
                },
            };
            let a = variant(tag, &pa);
            let b = variant(tag, &pb);
            let a2 = variant(tag, &pa2);
            unsafe {
                assert_eq!(variant_compare(&a, &a2), 0, "tag={tag}");
                assert_eq!(variant_compare(&a, &b), -1, "tag={tag}");
                assert_eq!(variant_compare(&b, &a), 1, "tag={tag}");
            }
        }
    }

    #[test]
    fn cstr_null_conventions() {
        for tag in [1u32, 2] {
            let null_payload = VariantPayload {
                cstr: VariantCStrs {
                    tag1: core::ptr::null(),
                    tag2: core::ptr::null(),
                },
            };
            let str_payload = VariantPayload {
                cstr: VariantCStrs {
                    tag1: b"x\0".as_ptr(),
                    tag2: b"x\0".as_ptr(),
                },
            };
            let null_a = variant(tag, &null_payload);
            let null_b = variant(tag, &null_payload);
            let s = variant(tag, &str_payload);
            unsafe {
                // NULL on the left always loses, even NULL vs NULL.
                assert_eq!(variant_compare(&null_a, &null_b), -1, "tag={tag}");
                assert_eq!(variant_compare(&null_a, &s), -1, "tag={tag}");
                assert_eq!(variant_compare(&s, &null_a), 1, "tag={tag}");
            }
        }
    }

    #[test]
    fn tag3_int_compare() {
        let pa = VariantPayload { int: VariantInt { _unused: [0; 2], value: 7 } };
        let pb = VariantPayload { int: VariantInt { _unused: [0; 2], value: 7 } };
        let pc = VariantPayload { int: VariantInt { _unused: [0; 2], value: -3 } };
        let (a, b, c) = (variant(3, &pa), variant(3, &pb), variant(3, &pc));
        unsafe {
            assert_eq!(variant_compare(&a, &b), 0);
            assert_eq!(variant_compare(&a, &c), 10);
            assert_eq!(variant_compare(&c, &a), -10);
        }
    }

    #[test]
    fn unknown_tag_returns_zero() {
        let pa = VariantPayload { int: VariantInt { _unused: [0; 2], value: 1 } };
        let pb = VariantPayload { int: VariantInt { _unused: [0; 2], value: 2 } };
        let a = variant(4, &pa);
        let b = variant(4, &pb);
        assert_eq!(unsafe { variant_compare(&a, &b) }, 0);
    }

    #[test]
    fn utoa_spot_strings() {
        assert_eq!(convert(255, 16).0, "FF");
        assert_eq!(convert(8, 2).0, "1000");
        assert_eq!(convert(35, 36).0, "Z");
        assert_eq!(convert(36, 36).0, "10");
        assert_eq!(convert(100, 7).0, format!("{}", 202));
    }
}
