use super::aggregate_context::SqliteContext;
use super::error::SQLITE_UTF8;
use super::vdbe_mem_set_str::vdbe_mem_set_str;
use super::vdbe_set_col_name::SQLITE_TRANSIENT;

/// sqlite3_result_error_toobig — original `FUN_083911d0` at load address
/// `0x083911d0` (44 bytes, `0x083911d0..0x083911fc`; three incoming plain
/// `bl` sites and no predicated incoming `bl` sites, independently counted
/// from the raw ARM words and call-target scan).
///
/// Stores `SQLITE_TOOBIG` (18) in `context.is_error`, then installs the
/// NUL-terminated UTF-8 message `"string or blob too big"` in the embedded
/// result `Mem` using a transient copy. The sole outgoing call is the plain
/// `bl` at `0x083911f4` to `sqlite3VdbeMemSetStr` @ `0x0838c158`; its result
/// is deliberately ignored. Deliberate deviation: the retail literal points
/// into the runtime-skewed read-only pool, so Rust owns an equivalent static
/// message rather than reproducing that image address.
const TOO_BIG_MESSAGE: &[u8] = b"string or blob too big\0";

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_result_error_toobig(context: *mut SqliteContext) {
    (*context).is_error = 18;
    vdbe_mem_set_str(
        core::ptr::addr_of_mut!((*context).s).cast(),
        TOO_BIG_MESSAGE.as_ptr().cast_mut(),
        -1,
        SQLITE_UTF8,
        SQLITE_TRANSIENT,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::Mem;
    use crate::sqlite::vdbe_mem_set_int64::{MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS};
    use crate::sqlite::vdbe_mem_set_str::{
        MemHandleBom, VdbeMemGrow, VdbeMemSetStrOps, DEFAULT_VDBE_MEM_SET_STR_OPS,
        VDBE_MEM_SET_STR_OPS,
    };
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GROWN_BYTES: [u8; 32] = [0; 32];

    unsafe extern "C" fn grow(p_mem: *mut Mem, _size: i32, _preserve: i32) -> i32 {
        (*p_mem).z = core::ptr::addr_of_mut!(GROWN_BYTES).cast();
        0
    }
    unsafe extern "C" fn handle_bom(_p_mem: *mut Mem) -> i32 { 0 }
    unsafe extern "C" fn release(_p_mem: *mut u8) {}

    struct OpsGuard;
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS).write(DEFAULT_VDBE_MEM_SET_STR_OPS);
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    #[test]
    fn marks_toobig_and_copies_the_terminated_message() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _set_str_lock = super::super::vdbe_mem_set_str::tests::ops_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _release_lock = super::super::vdbe_mem_set_int64::tests::ops_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _restore = OpsGuard;
        unsafe {
            GROWN_BYTES.fill(0xcc);
            core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS).write(VdbeMemSetStrOps {
                grow: grow as VdbeMemGrow,
                handle_bom: handle_bom as MemHandleBom,
            });
            core::ptr::addr_of_mut!(MEM_SET_OPS).write(MemSetOps { mem_release: release });
            let mut context: SqliteContext = core::mem::zeroed();
            sqlite3_result_error_toobig(&mut context);
            assert_eq!(context.is_error, 18);
            assert_eq!(context.s.n, 22);
            assert_eq!(context.s.flags, 0x0022);
            assert_eq!(&GROWN_BYTES[..23], TOO_BIG_MESSAGE);
        }
    }
}
