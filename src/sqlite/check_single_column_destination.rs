//! Validate the column count for SQLite SELECT destinations.
//!
//! Original: `FUN_082c254c` at load address `0x082c254c`. True extent is
//! 56 bytes through `0x082c2584`: 52 instruction bytes and the four-byte
//! format-address literal at `0x082c2580`, before the next PUSH prologue.
//! Raw-word decoding verifies one outbound plain BL to `sqlite_error_msg`
//! @ `0x083767a0`, zero predicated BL, and two inbound plain BL sites
//! @ `0x08368954` and `0x08382fa0` (zero predicated inbound BL).
//!
//! Read the destination's first byte unconditionally. When the signed column
//! count exceeds one and the destination kind is 6 (memory) or 7 (set),
//! report an error and return one; otherwise return zero without touching Parse.
//! The raw format pointer is `0x088fe0d4`; its NUL-terminated firmware bytes
//! are UTF-8 U+3002, not the usual SQLite single-result diagnostic.
//!
//! Deliberate deviations: relocate those exact format bytes into Rust rodata,
//! call the already ported reporter with its explicit VaList (NULL because
//! the format has no conversions), and use its repr(C) Parse view on hosts.
//! A volatile byte read retains the original unconditional destination access
//! even for column counts <= 1, unlike the Ghidra short-circuit expression.

//!
//! Verification: host edge tests and ARM release build pass. match.py shows
//! 13 retail instructions versus 18 Rust instructions: LLVM combines kinds
//! 6/7 with an AND mask, preserves the initial LDRB and signed count branch,
//! and supplies the explicit NULL VaList before the reporter call.
//! A standalone test-configured host-library smoke exercised accepted and
//! rejected destinations through the real reporter (default host formatter).
use super::error_msg::{sqlite_error_msg, Parse};

const SINGLE_COLUMN_MESSAGE: &[u8] = b"\xe3\x80\x82\0";

/// Return one after reporting a multi-column memory/set destination error.
///
/// # Safety
/// `destination` must be readable even when `column_count <= 1`. On the
/// rejection path `parse` must point to a valid reporter-compatible context.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn check_single_column_destination(
    parse: *mut Parse, destination: *const u8, column_count: i32,
) -> i32 {
    let kind = core::ptr::read_volatile(destination);
    if column_count > 1 && (kind == 6 || kind == 7) {
        sqlite_error_msg(parse, SINGLE_COLUMN_MESSAGE.as_ptr(), core::ptr::null());
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(rc: i32, n_err: i32) -> Parse {
        Parse {
            db: core::ptr::null_mut(), rc, z_err_msg: core::ptr::null_mut(),
            _gap_0c: [0xa5; 6], check_schema: 0x5a,
            _gap_13: [0xa5; 0x2d], n_err,
        }
    }

    #[test]
    fn all_destination_bytes_and_signed_count_boundaries() {
        for kind in 0..=u8::MAX {
            for count in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
                let mut context = parse(0, 9);
                let rejected = count > 1 && matches!(kind, 6 | 7);
                unsafe {
                    assert_eq!(check_single_column_destination(&mut context, &kind, count), i32::from(rejected));
                }
                assert_eq!(context.n_err, if rejected { 10 } else { 9 });
                assert_eq!(context.rc, i32::from(rejected));
                assert!(context.z_err_msg.is_null());
                assert_eq!(context.check_schema, 0x5a);
                assert_eq!(context._gap_0c, [0xa5; 6]);
                assert_eq!(context._gap_13, [0xa5; 0x2d]);
            }
        }
    }

    #[test]
    fn preserves_prior_error_and_wraps_reporter_count() {
        let mut context = parse(5, i32::MAX);
        unsafe { assert_eq!(check_single_column_destination(&mut context, &7, 2), 1); }
        assert_eq!(context.rc, 5);
        assert_eq!(context.n_err, i32::MIN);
    }

    #[test]
    fn accepted_destination_does_not_require_parse() {
        unsafe {
            assert_eq!(check_single_column_destination(core::ptr::null_mut(), &6, 1), 0);
            assert_eq!(check_single_column_destination(core::ptr::null_mut(), &8, 2), 0);
        }
    }
}
