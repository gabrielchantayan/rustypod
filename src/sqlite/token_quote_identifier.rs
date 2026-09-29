//! SQLite token initialization from an identifier.
//!
//! `sqlite_token_quote_identifier` — original: `FUN_08368fc0` @
//! `0x08368fc0` (120 bytes; 2 plain `bl`, 0 predicated `bl`, binary-scanned).
//! The true body ends at `0x08369038`; its literal pool holds `"\"%w\"\0"`,
//! and `0x08369040` starts the next function.
//!
//! Algorithm: scan `source` for a double quote. An unquoted source is borrowed
//! into `token`, with its byte length packed in bits 1..31 and bit 0 cleared.
//! A quoted source is duplicated through SQLite's `"%w"` formatter, which
//! doubles internal double quotes; on allocation failure it stores NULL and
//! leaves the packed length word unchanged. On success it stores the new text,
//! packs its length, and marks it owned.
//!
//! Deliberate deviation: the retail `sqlite3MPrintf` call at `0x0837d358` is
//! represented by its already-ported `sqlite3VMPrintf` formatter dispatch,
//! with an explicit one-word AAPCS varargs area. This preserves the formatter
//! contract without exposing a Rust C-variadic export.

use crate::libc::strlen::strlen;

use super::error_msg::{vm_printf_op, VaList};
use super::expr_new::Token;

const QUOTED_IDENTIFIER_FORMAT: &[u8] = b"\"%w\"\0";

/// Initialize `token` from an identifier, quoting and owning it when it
/// contains a double quote.
///
/// Original: `FUN_08368fc0` @ `0x08368fc0` (120 bytes; 2 plain direct `bl`
/// calls, 0 predicated direct `bl` calls).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_token_quote_identifier(
    db: *mut u8,
    token: *mut Token,
    source: *const u8,
) {
    let mut text = source;
    while *text != 0 {
        if *text == b'"' {
            let args = [source as usize as u32];
            let quoted = (vm_printf_op())(db, QUOTED_IDENTIFIER_FORMAT.as_ptr(), args.as_ptr() as VaList);
            (*token).z = quoted;
            if quoted.is_null() {
                return;
            }
            (*token).n_dyn = ((*token).n_dyn & 1) | ((strlen(quoted) as u32) << 1) | 1;
            return;
        }
        text = text.add(1);
    }

    (*token).z = source;
    (*token).n_dyn = ((*token).n_dyn & 1) | ((text.offset_from(source) as u32) << 1);
    (*token).n_dyn &= !1;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::error_msg::{missing_vm_printf, SQLITE_VM_PRINTF};
    use crate::testing::{hints, try_map_u32_slab, SQLITE_VM_PRINTF_TEST_LOCK};

    static mut EXPECTED_SOURCE: u32 = 0;
    static mut FORMATTER_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn quote_formatter(_db: *mut u8, format: *const u8, ap: VaList) -> *mut u8 {
        assert_eq!(core::slice::from_raw_parts(format, 5), QUOTED_IDENTIFIER_FORMAT);
        assert_eq!(*ap, EXPECTED_SOURCE);
        FORMATTER_RESULT
    }

    #[test]
    fn borrows_empty_and_unquoted_identifiers_and_clears_ownership() {
        let empty = b"\0";
        let ordinary = b"albums\0";
        let mut token = Token { z: core::ptr::null(), n_dyn: 1 };
        unsafe {
            sqlite_token_quote_identifier(core::ptr::null_mut(), &mut token, empty.as_ptr());
            assert_eq!(token.z, empty.as_ptr());
            assert_eq!(token.n_dyn, 0);
            token.n_dyn = 0xffff_ffff;
            sqlite_token_quote_identifier(core::ptr::null_mut(), &mut token, ordinary.as_ptr());
        }
        assert_eq!(token.z, ordinary.as_ptr());
        assert_eq!(token.n_dyn, (6 << 1));
    }

    #[test]
    fn allocation_failure_stores_null_and_preserves_packed_length() {
        let _guard = SQLITE_VM_PRINTF_TEST_LOCK.lock();
        let source = b"a\"b\0";
        let mut token = Token { z: 1usize as *const u8, n_dyn: 0xfeed_beef };
        unsafe { sqlite_token_quote_identifier(core::ptr::null_mut(), &mut token, source.as_ptr()) };
        assert!(token.z.is_null());
        assert_eq!(token.n_dyn, 0xfeed_beef);
    }

    #[test]
    fn quoted_identifier_uses_percent_w_and_owns_formatter_output() {
        let _guard = SQLITE_VM_PRINTF_TEST_LOCK.lock();
        let Some(source) = try_map_u32_slab(hints::SQLITE_TOKEN_QUOTE_IDENTIFIER, 0x1000) else {
            return;
        };
        let source = unsafe { source.add(0x100) };
        unsafe {
            core::ptr::copy_nonoverlapping(b"a\"b\0".as_ptr(), source, 4);
            let mut formatted = *b"\"a\"\"b\"\0";
            EXPECTED_SOURCE = source as usize as u32;
            FORMATTER_RESULT = formatted.as_mut_ptr();
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), quote_formatter);
            let mut token = Token { z: core::ptr::null(), n_dyn: 0 };
            sqlite_token_quote_identifier(core::ptr::null_mut(), &mut token, source);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), missing_vm_printf);
            assert_eq!(token.z, formatted.as_ptr());
            assert_eq!(token.n_dyn, (6 << 1) | 1);
        }
    }
}
