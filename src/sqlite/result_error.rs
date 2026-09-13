use super::aggregate_context::SqliteContext;
use super::error::SQLITE_UTF8;
use super::vdbe_mem_set_str::vdbe_mem_set_str;
use super::vdbe_set_col_name::SQLITE_TRANSIENT;

/// sqlite3_result_error — original `FUN_08391144` at load address
/// `0x08391144` (36 bytes, `0x08391144..0x08391168`; six direct `bl` call
/// sites, all unconditional: `0x082b5584`, `0x082b55a4`, `0x082c617c`,
/// `0x082d7f38`, `0x082d8130`, and `0x0837cab8`).
///
/// Marks the callback context as failed at `context.is_error`, then installs a
/// transient UTF-8 error string in its embedded scalar-result `Mem`. The
/// function has no NULL checks and ignores `vdbe_mem_set_str`'s result, exactly
/// as the retailOS `str`/`bl` sequence does. Deliberate deviations: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_result_error(
    context: *mut SqliteContext,
    text: *mut u8,
    length: i32,
) {
    (*context).is_error = 1;
    vdbe_mem_set_str(
        core::ptr::addr_of_mut!((*context).s).cast(),
        text,
        length,
        SQLITE_UTF8,
        SQLITE_TRANSIENT,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::Mem;
    use crate::sqlite::vdbe_mem_set_int64::{
        MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS,
    };
    use crate::sqlite::vdbe_mem_set_str::{
        MemHandleBom, VdbeMemGrow, VdbeMemSetStrOps,
        DEFAULT_VDBE_MEM_SET_STR_OPS, VDBE_MEM_SET_STR_OPS,
    };
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GROWN_BYTES: [u8; 16] = [0; 16];

    unsafe extern "C" fn grow(p_mem: *mut Mem, _size: i32, _preserve: i32) -> i32 {
        (*p_mem).z = core::ptr::addr_of_mut!(GROWN_BYTES).cast();
        0
    }

    unsafe extern "C" fn handle_bom(_p_mem: *mut Mem) -> i32 {
        0
    }

    unsafe extern "C" fn release(_p_mem: *mut u8) {}

    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS)
                    .write(DEFAULT_VDBE_MEM_SET_STR_OPS);
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, MutexGuard<'static, ()>, OpsGuard) {
        let result_lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let set_str_lock = super::super::vdbe_mem_set_str::tests::ops_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let release_lock = super::super::vdbe_mem_set_int64::tests::ops_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            GROWN_BYTES.fill(0xcc);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS),
                VdbeMemSetStrOps {
                    grow: grow as VdbeMemGrow,
                    handle_bom: handle_bom as MemHandleBom,
                },
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps { mem_release: release },
            );
        }
        (result_lock, set_str_lock, release_lock, OpsGuard)
    }

    fn empty_mem() -> Mem {
        Mem {
            u: 0,
            r: 0.0,
            db: core::ptr::null_mut(),
            z: core::ptr::null_mut(),
            n: 0,
            flags: 0,
            value_type: 0,
            enc: 0,
            x_del: core::ptr::null_mut(),
            z_malloc: core::ptr::null_mut(),
        }
    }

    fn context() -> SqliteContext {
        SqliteContext {
            p_func: core::ptr::null_mut(),
            _gap_04: [0; 4],
            s: empty_mem(),
            p_mem: core::ptr::null_mut(),
            is_error: 0,
        }
    }

    #[test]
    fn negative_length_marks_error_and_copies_terminated_utf8() {
        let _guards = bench();
        let mut context = context();
        let mut text = *b"error\0";

        unsafe {
            sqlite3_result_error(
                core::ptr::addr_of_mut!(context),
                text.as_mut_ptr(),
                -1,
            );
        }

        assert_eq!(context.is_error, 1);
        assert_eq!(context.s.n, 5);
        assert_eq!(context.s.flags, 0x0022);
        assert_eq!(context.s.enc, SQLITE_UTF8);
        assert_eq!(context.s.value_type, 3);
        assert_eq!(unsafe { &GROWN_BYTES[..6] }, b"error\0");
    }

    #[test]
    fn explicit_length_preserves_embedded_nul_without_a_terminator() {
        let _guards = bench();
        let mut context = context();
        let mut text = *b"a\0b";

        unsafe {
            sqlite3_result_error(
                core::ptr::addr_of_mut!(context),
                text.as_mut_ptr(),
                3,
            );
        }

        assert_eq!(context.is_error, 1);
        assert_eq!(context.s.n, 3);
        assert_eq!(context.s.flags, 0x0002);
        assert_eq!(unsafe { &GROWN_BYTES[..3] }, b"a\0b");
    }
}
