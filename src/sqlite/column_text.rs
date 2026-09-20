//! SQLite's UTF-8 result-column accessor.
//!
//! `sqlite3_column_text` — original: `FUN_0838fae4` @ `0x0838fae4` (36
//! bytes; true extent `0x0838fae4..0x0838fb08`). Raw ARM words establish
//! three direct inbound `bl` call sites, all plain/unconditional and no
//! predicated forms. The body has three unconditional `bl` calls.
//!
//! # Algorithm
//!
//! Look up a statement result cell with [`super::column_mem::column_mem`],
//! convert that cell to UTF-8 through [`super::value_text::sqlite3_value_text`],
//! then pass the statement's current result code through
//! [`super::api_exit::sqlite_api_exit`]. The returned text pointer is saved
//! before that final API-boundary call and is returned unchanged.
//!
//! On the ARM target, the final call uses the existing word-layout port of
//! `0x082c43d0`. Deliberate host-test deviation: that helper's `u32` fixture
//! layout cannot share typed [`Vdbe`] fields on a 64-bit host, so its
//! result-code refresh is target-only. The text lookup, conversion, ordering,
//! and returned pointer are identical.

use super::column_mem::column_mem;
use super::value_text::sqlite3_value_text;
use super::vdbe::Vdbe;
#[cfg(target_os = "none")]
use crate::util::object_masked_word_refresh::object_masked_word_refresh;

/// SQLite's `sqlite3_column_text` API.
///
/// # Safety
///
/// `statement` must meet [`column_mem`]'s contract. Its selected result cell
/// must meet [`sqlite3_value_text`]'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_column_text(statement: *mut Vdbe, column: i32) -> *mut u8 {
    let value = unsafe { column_mem(statement, column) };
    let text = unsafe { sqlite3_value_text(value.cast()) };
    #[cfg(target_os = "none")]
    unsafe { object_masked_word_refresh(statement.cast()) };
    text
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::error::SQLITE_UTF8;
    use crate::sqlite::value_text::MEM_STR;
    use crate::sqlite::vdbe::Mem;
    use core::mem::MaybeUninit;

    unsafe fn configure_utf8_text(value: *mut Mem, text: *mut u8) {
        let bytes = value.cast::<u8>();
        bytes.add(0x14).cast::<*mut u8>().write_unaligned(text);
        bytes.add(0x1c).cast::<u16>().write_unaligned(MEM_STR);
        bytes.add(0x1f).write(SQLITE_UTF8);
    }
    #[test]
    fn returns_the_selected_utf8_result_before_api_exit() {
        let mut first = *b"first\0";
        let mut second = *b"media\0";
        let mut results = MaybeUninit::<[Mem; 2]>::uninit();
        unsafe {
            configure_utf8_text(results.as_mut_ptr().cast::<Mem>(), first.as_mut_ptr());
            configure_utf8_text(results.as_mut_ptr().cast::<Mem>().add(1), second.as_mut_ptr());
        }
        let mut statement = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
        statement.p_result_set = results.as_mut_ptr().cast();
        statement.n_res_column = 2;
        unsafe {
            assert_eq!(sqlite3_column_text(&mut statement, 0), first.as_mut_ptr());
            assert_eq!(sqlite3_column_text(&mut statement, 1), second.as_mut_ptr());
        }
    }
}
