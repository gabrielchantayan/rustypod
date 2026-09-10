//! `parse_i32_utf16_range` — original: `FUN_080f01c4` @ 0x080f01c4
//! (**72 bytes**, 0x080f01c4..0x080f0208; the next separately linked
//! function starts at 0x080f020c with `push {r4-r6, lr}`.) **11 plain `bl`
//! call sites, 0 predicated**, verified by decoding every ARM `B`/`BL` word
//! in `osos.dec`.
//!
//! Converts a UTF-16 begin/end range into a temporary StringObject through
//! `string_from_range` @ 0x080f020c, copy-constructs a second StringObject,
//! destroys the conversion temporary, then parses the copy's C string through
//! the signed decimal parser @ 0x080e7904. It always destroys the copied
//! object before returning the parser result. The converter strips surrounding
//! quotes and unescapes backslashes; the decimal parser skips only space, tab,
//! and LF, accepts one optional sign, and accumulates decimal digits with
//! 32-bit wrapping arithmetic.
//!
//! # Deliberate deviations
//!
//! `string_from_range` and the decimal parser are not ported. Their existing
//! firmware entry points are called through [`RANGE_I32_OPS`] on target and
//! injected in host tests. The StringObject copy constructor, C-string
//! accessor, and destructor are already ported and remain direct calls.

use core::mem::MaybeUninit;

use crate::cxx::string_object::{
    string_object_c_str, string_object_copy_construct, string_object_destroy, StringObject,
};

/// `FUN_080f020c(this, range)`: converts a UTF-16 begin/end range to a
/// StringObject, stripping outer quotes and resolving backslash escapes.
pub type Utf16RangeToStringFn = unsafe extern "C" fn(this: *mut StringObject, range: *const u8);

/// `FUN_080e7904(text)`: signed decimal conversion over a NUL-terminated
/// byte string.
pub type DecimalI32ParseFn = unsafe extern "C" fn(text: *const u8) -> i32;

/// Unported direct dependencies of [`parse_i32_utf16_range`].
#[derive(Clone, Copy)]
pub struct RangeI32Ops {
    pub string_from_range: Utf16RangeToStringFn,
    pub parse_decimal: DecimalI32ParseFn,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_from_range(this: *mut StringObject, range: *const u8) {
    let f: Utf16RangeToStringFn = core::mem::transmute(0x080f_020cusize);
    f(this, range)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_parse_decimal(text: *const u8) -> i32 {
    let f: DecimalI32ParseFn = core::mem::transmute(0x080e_7904usize);
    f(text)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_from_range(_this: *mut StringObject, _range: *const u8) {
    panic!("parse_i32_utf16_range requires range converter 0x080f020c")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_parse_decimal(_text: *const u8) -> i32 {
    panic!("parse_i32_utf16_range requires decimal parser 0x080e7904")
}

/// Active unported dependencies. Target defaults preserve the retail entry
/// points; host tests replace them with behavioral fixtures.
pub static mut RANGE_I32_OPS: RangeI32Ops = RangeI32Ops {
    #[cfg(target_os = "none")]
    string_from_range: firmware_string_from_range,
    #[cfg(not(target_os = "none"))]
    string_from_range: missing_string_from_range,
    #[cfg(target_os = "none")]
    parse_decimal: firmware_parse_decimal,
    #[cfg(not(target_os = "none"))]
    parse_decimal: missing_parse_decimal,
};

#[inline(always)]
unsafe fn range_i32_ops() -> RangeI32Ops {
    core::ptr::read_volatile(core::ptr::addr_of!(RANGE_I32_OPS))
}

/// parse_i32_utf16_range — original: `FUN_080f01c4` @ 0x080f01c4
/// (72 bytes; 11 plain `bl` call sites, 0 predicated, binary-scanned).
///
/// Converts `range` to its temporary UTF-8 StringObject form, copy-constructs
/// a second object, releases the conversion temporary, parses the copied C
/// string as a signed wrapping decimal integer, then releases the copy.
///
/// # Safety
///
/// `range` must satisfy `string_from_range`'s UTF-16 range contract. The
/// firmware has no NULL guard: invalid ranges fault in the converter, and
/// neither does this port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_i32_utf16_range(range: *const u8) -> i32 {
    let ops = range_i32_ops();
    let mut converted = MaybeUninit::<StringObject>::uninit();
    (ops.string_from_range)(converted.as_mut_ptr(), range);

    let mut text = MaybeUninit::<StringObject>::uninit();
    string_object_copy_construct(text.as_mut_ptr(), converted.as_ptr());
    string_object_destroy(converted.as_mut_ptr());

    let result = (ops.parse_decimal)(string_object_c_str(text.as_ptr()));
    string_object_destroy(text.as_mut_ptr());
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};

    static RANGE_I32_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SOURCE: [u8; 64] = [0; 64];
    static mut COPY: [u8; 64] = [0; 64];
    static mut CONVERTER_CALLS: usize = 0;
    static mut CONVERTER_RANGE: usize = 0;
    static mut ALLOCATION_CALLS: usize = 0;
    static mut ALLOCATION_SIZE: usize = 0;
    static mut RELEASED: [usize; 2] = [0; 2];
    static mut RELEASE_CALLS: usize = 0;
    static mut PARSER_BYTES: [u8; 64] = [0; 64];

    unsafe extern "C" fn convert_fixture(this: *mut StringObject, range: *const u8) {
        CONVERTER_CALLS += 1;
        CONVERTER_RANGE = range as usize;
        (*this).vtable = &STRING_OBJECT_VTABLE;
        (*this).payload = core::ptr::addr_of_mut!(SOURCE).cast::<u8>();
    }

    unsafe extern "C" fn allocate_copy(
        this: *mut StringObject,
        requested_size: usize,
        flags: u32,
    ) -> *mut u8 {
        assert_eq!(flags, 0);
        assert!(requested_size <= COPY.len());
        ALLOCATION_CALLS += 1;
        ALLOCATION_SIZE = requested_size;
        let copy = core::ptr::addr_of_mut!(COPY).cast::<u8>();
        (*this).payload = copy;
        copy
    }

    unsafe extern "C" fn clear_copy(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }

    unsafe extern "C" fn record_release(this: *mut StringObject) {
        RELEASED[RELEASE_CALLS] = (*this).payload as usize;
        RELEASE_CALLS += 1;
        (*this).payload = core::ptr::null_mut();
    }

    unsafe extern "C" fn parse_fixture(text: *const u8) -> i32 {
        let mut length = 0usize;
        while text.add(length).read() != 0 {
            PARSER_BYTES[length] = text.add(length).read();
            length += 1;
        }
        PARSER_BYTES[length] = 0;
        reference_parse(&PARSER_BYTES[..length])
    }

    /// Independent model of `FUN_080e7904`: it deliberately does not share
    /// the port's dispatch or its pointer flow.
    fn reference_parse(text: &[u8]) -> i32 {
        let mut cursor = 0usize;
        while cursor < text.len() && matches!(text[cursor], b' ' | b'\t' | b'\n') {
            cursor += 1;
        }
        let negative = if text.get(cursor) == Some(&b'-') {
            cursor += 1;
            true
        } else {
            if text.get(cursor) == Some(&b'+') {
                cursor += 1;
            }
            false
        };
        let mut value = 0i32;
        while let Some(&byte) = text.get(cursor) {
            if byte.wrapping_sub(b'0') > 9 {
                break;
            }
            value = value.wrapping_mul(10).wrapping_add((byte - b'0') as i32);
            cursor += 1;
        }
        if negative { value.wrapping_neg() } else { value }
    }

    struct OpsGuard {
        range: RangeI32Ops,
        object: StringObjectOps,
        assign: StringObjectAssignCstrOps,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(self.range);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.object);
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.assign);
            }
        }
    }

    fn install_fixtures() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, OpsGuard) {
        let range_lock = RANGE_I32_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let string_lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let guard = OpsGuard {
                range: core::ptr::addr_of!(RANGE_I32_OPS).read_volatile(),
                object: core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile(),
                assign: core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile(),
            };
            core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(RangeI32Ops {
                string_from_range: convert_fixture,
                parse_decimal: parse_fixture,
            });
            core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(StringObjectOps {
                release_payload: record_release,
            });
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps {
                    allocate_payload: allocate_copy,
                    clear_payload: clear_copy,
                },
            );
            (range_lock, string_lock, guard)
        }
    }

    fn check(input: &[u8]) {
        let (_range_lock, _string_lock, _ops) = install_fixtures();
        let range = [0x1234u16, 0x5678];
        unsafe {
            SOURCE.fill(0);
            COPY.fill(0);
            SOURCE[..input.len()].copy_from_slice(input);
            CONVERTER_CALLS = 0;
            CONVERTER_RANGE = 0;
            ALLOCATION_CALLS = 0;
            ALLOCATION_SIZE = 0;
            RELEASED = [0; 2];
            RELEASE_CALLS = 0;
            PARSER_BYTES.fill(0);

            assert_eq!(parse_i32_utf16_range(range.as_ptr().cast::<u8>()), reference_parse(input));
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_RANGE, range.as_ptr() as usize);
            assert_eq!(&PARSER_BYTES[..input.len()], input);
            assert_eq!(RELEASE_CALLS, 2, "both StringObject temporaries are destroyed");
            assert_eq!(RELEASED[0], SOURCE.as_mut_ptr() as usize);
            if input.is_empty() {
                assert_eq!(ALLOCATION_CALLS, 0);
                assert_eq!(RELEASED[1], 0);
            } else {
                assert_eq!(ALLOCATION_CALLS, 1);
                assert_eq!(ALLOCATION_SIZE, input.len() + 1);
                assert_eq!(RELEASED[1], COPY.as_mut_ptr() as usize);
            }
        }
    }

    #[test]
    fn parses_whitespace_and_signs_after_range_conversion() {
        check(b" \t\n-123tail");
        check(b"+42");
        check(b"  +");
    }

    #[test]
    fn stops_before_non_digits_and_handles_empty_text() {
        check(b"");
        check(b"x123");
        check(b"12\r34");
    }

    #[test]
    fn decimal_accumulation_wraps_like_arm() {
        check(b"2147483648");
        check(b"-2147483648");
        check(b"42949672960");
    }
}
