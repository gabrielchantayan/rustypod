//! `parse_i32_utf16_bounds` — original: `FUN_080e28a4` @ **0x080e28a4**.
//!
//! **32 bytes**, `0x080e28a4..0x080e28c4`; the next independently linked
//! function starts at `0x080e28c4` with `stmdb sp!, {r1-r7,lr}`. Raw words
//! `e92d401c e1a02001 e1a01000 e1a0000d eb036378 e1a0000d eb003640
//! e8bd801c` contain **2 plain `bl` instructions and 0 predicated `bl`
//! instructions**. There are four plain inbound `bl` calls, all from the
//! date/time component parser at `FUN_080bbce8`.
//!
//! Builds the target-width `{ begin, end }` UTF-16 range on its stack, then
//! passes that range to [`parse_i32_utf16_range`]. The parser result remains
//! in `r0` across the epilogue.
//!
//! Deliberate deviation: the two-word stack local is represented explicitly
//! as a `#[repr(C)]` target layout record; the trivial retail range constructor
//! at `0x081bb69c` is inlined rather than introduced as a new seam.

use crate::strto::range_i32::parse_i32_utf16_range;

#[repr(C)]
struct Utf16Range {
    begin: u32,
    end: u32,
}

/// Parses the UTF-16 characters in `[begin, end)` as a signed decimal integer.
///
/// # Safety
///
/// `begin` and `end` must form a range accepted by the retail UTF-16 range
/// converter used by [`parse_i32_utf16_range`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_i32_utf16_bounds(begin: *const u16, end: *const u16) -> i32 {
    let range = Utf16Range {
        begin: begin as usize as u32,
        end: end as usize as u32,
    };

    #[cfg(not(test))]
    unsafe {
        parse_i32_utf16_range(core::ptr::addr_of!(range).cast())
    }

    #[cfg(test)]
    unsafe {
        (PARSE_I32_UTF16_BOUNDS_OPS.parse)(core::ptr::addr_of!(range).cast())
    }
}

#[cfg(test)]
type Parse = unsafe extern "C" fn(*const u8) -> i32;

#[cfg(test)]
#[derive(Clone, Copy)]
struct ParseI32Utf16BoundsOps {
    parse: Parse,
}

#[cfg(test)]
unsafe extern "C" fn default_parse(range: *const u8) -> i32 {
    parse_i32_utf16_range(range)
}

#[cfg(test)]
static mut PARSE_I32_UTF16_BOUNDS_OPS: ParseI32Utf16BoundsOps = ParseI32Utf16BoundsOps {
    parse: default_parse,
};

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_RANGE: [u32; 2] = [0; 2];

    unsafe extern "C" fn record_range(range: *const u8) -> i32 {
        let range = range.cast::<Utf16Range>();
        SEEN_RANGE = [(*range).begin, (*range).end];
        if (*range).begin == (*range).end { 0 } else { -123 }
    }

    struct OpsGuard(ParseI32Utf16BoundsOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(PARSE_I32_UTF16_BOUNDS_OPS).write_volatile(self.0) }
        }
    }

    #[test]
    fn preserves_target_width_bounds_and_parser_result() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let old = unsafe { core::ptr::addr_of!(PARSE_I32_UTF16_BOUNDS_OPS).read_volatile() };
        let _ops = OpsGuard(old);
        unsafe {
            core::ptr::addr_of_mut!(PARSE_I32_UTF16_BOUNDS_OPS).write_volatile(ParseI32Utf16BoundsOps {
                parse: record_range,
            });

            let begin = 0x1234_5678usize as *const u16;
            let end = 0x9abc_def0usize as *const u16;
            assert_eq!(parse_i32_utf16_bounds(begin, end), -123);
            assert_eq!(SEEN_RANGE, [0x1234_5678, 0x9abc_def0]);

            assert_eq!(parse_i32_utf16_bounds(begin, begin), 0);
            assert_eq!(SEEN_RANGE, [0x1234_5678, 0x1234_5678]);
        }
    }
}
