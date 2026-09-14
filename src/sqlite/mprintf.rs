//! SQLite's connectionless variadic string formatter.
//!
//! - `sqlite_mprintf` — original: `FUN_08390c6c` @ 0x08390c6c (28
//!   bytes; 5 direct `bl` call sites, binary-scanned; no predicated
//!   calls). SQLite 3.5.9's `sqlite3_mprintf` (`char *sqlite3_mprintf(
//!   const char *zFormat, ...)` in `util.c`).
//!
//! Algorithm: spill r0-r3 into the AAPCS varargs home area, reload the
//! format pointer from spilled r0, form `ap` as the address of spilled r1,
//! and call `sqlite3_vmprintf` @ 0x083918a4. Its result is returned
//! unchanged: a heap-owned NUL-terminated formatted string, or NULL on
//! allocation failure. The five unconditional call sites are 0x0837cf60,
//! 0x0837d06c, 0x08390898, 0x083909e0, and 0x08390a2c; they format SQLite
//! extension and parser diagnostics with `%.*s` or `%s`.
//!
//! Deviations:
//! - Stable Rust cannot expose a C-variadic entry point, so `args` is the
//!   house explicit [`VaList`] pointer — exactly the original's
//!   `&spilled-r1`. Firmware callers need the standard variadic trampoline
//!   described in `printf/printf_api.rs`.
//! - `sqlite3_vmprintf` @ 0x083918a4 is not ported. It is behaviorally the
//!   NULL-connection branch of the ported `sqlite_vm_printf`:
//!   `StrAccumInit` with the stock 1,000,000,000-byte limit, then
//!   `sqlite3VXPrintf` and `StrAccumFinish`. Reusing that branch directly
//!   preserves allocation, conversion-engine dispatch, and NULL-result
//!   behavior without adding a duplicate dispatch seam.

use super::error_msg::VaList;
use super::vm_printf::sqlite_vm_printf;

/// `sqlite3_mprintf`: format `format` with the variadic words at `args`.
///
/// Returns the heap-owned NUL-terminated result, or NULL when formatting
/// cannot allocate it.
///
/// Register usage: r0 = format, r1/r2/r3/stack = varargs (the original
/// builds `ap` = &spilled-r1; here `args` is that pointer).
///
/// # Safety
/// `format` and `args` must meet the conversion engine's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_mprintf(format: *const u8, args: VaList) -> *mut u8 {
    sqlite_vm_printf(core::ptr::null_mut(), format, args)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::sqlite::str_accum::StrAccum;
    use crate::sqlite::vm_printf::{missing_vx_printf, VxPrintfFn, SQLITE_VXPRINTF};
    use std::sync::Mutex;

    /// Serializes this module's conversion-engine swaps.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED: Option<(i32, *const u8, VaList, i32, i32)> = None;

    unsafe extern "C" fn recording_vx_printf(
        accum: *mut StrAccum,
        use_malloc: i32,
        format: *const u8,
        args: VaList,
    ) {
        RECORDED = Some((use_malloc, format, args, (*accum).n_alloc, (*accum).mx_alloc));
        (*accum).z_base.write(b'x');
        (*accum).n_char = 1;
    }

    fn with_engine(engine: VxPrintfFn, body: impl FnOnce()) {
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            RECORDED = None;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VXPRINTF), engine);
        }
        body();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_VXPRINTF),
                missing_vx_printf,
            );
        }
    }

    #[test]
    fn forwards_the_format_and_variadic_words_to_the_connectionless_formatter() {
        let mut heap_result = [0xCCu8; 4];
        let _allocator = install_recorder(heap_result.as_mut_ptr());
        let format = b"extension error: %s\0".as_ptr();
        let args = [0x1234_5678];
        let mut result = core::ptr::null_mut();
        with_engine(recording_vx_printf, || unsafe {
            result = sqlite_mprintf(format, args.as_ptr());
            assert_eq!(
                core::ptr::read(core::ptr::addr_of!(RECORDED)),
                Some((1, format, args.as_ptr(), 350, 1_000_000_000)),
                "sqlite_mprintf uses the connectionless formatter's stock StrAccum configuration"
            );
        });
        assert_eq!(result, heap_result.as_mut_ptr(), "the helper's heap result passes through");
        assert_eq!(&heap_result[..2], b"x\0", "finish copies text and its terminator");
        assert_eq!(realloc_log(), std::vec![(0, 2)], "finish allocates n_char + 1 bytes");
    }

    #[test]
    fn allocation_failure_is_returned_as_null() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let result = unsafe { sqlite_mprintf(b"%s\0".as_ptr(), core::ptr::null()) };
        assert!(result.is_null(), "the unallocated finish result passes through unchanged");
        assert_eq!(realloc_log(), std::vec![(0, 1)], "the empty default formatter still requests its NUL");
    }
}
