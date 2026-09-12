//! Validate one auto-vacuum pointer-map entry during an integrity check.
//!
//! `ptrmap_check_pages` — original: `FUN_082c27d0` @ `0x082c27d0` (120
//! bytes of code, through `pop {r4-r8,pc}` @ `0x082c2844`; the following
//! `0x082c2848..0x082c289c` bytes are its two diagnostic strings and the next
//! independent function starts at `0x082c28a0`). Decoding every ARM B/BL word
//! in `osos.dec` finds seven direct callers, all unconditional `bl`:
//! `0x082c2650`, `0x082c26c4`, `0x082c2720`, `0x082c2b58`, `0x082c2bb8`,
//! `0x082c2c78`, and `0x083719bc`.
//!
//! This is SQLite 3.5.x's `ptrmapCheckPages`: read `pgno`'s type and parent
//! from `check->pBt`; report a read failure, or report expected and actual
//! fields when either differs. The original has no NULL guards. Deliberate
//! deviations: the unported `ptrmapGet` @ `0x082e85d8` remains a direct
//! load-address call on target; host tests substitute it and the diagnostic
//! append solely to observe the stack-vararg payload. Target builds call the
//! already-ported `integrity_check_append_msg` directly.

use super::integrity_check_append_msg::{integrity_check_append_msg, IntegrityCheck};

#[cfg(target_os = "none")]
const PTRMAP_GET_ADDRESS: usize = 0x082e_85d8;
const READ_FAILURE_FORMAT: &[u8] = b"Failed to read ptrmap key=%d\0";
const MISMATCH_FORMAT: &[u8] =
    b"Bad ptrmap entry key=%d expected=(%d,%d) got=(%d,%d)\0";

type PtrmapGet = unsafe extern "C" fn(*mut u8, u32, *mut u8, *mut u32) -> u32;
#[cfg(not(target_os = "none"))]
type AppendDiagnostic = unsafe extern "C" fn(*mut IntegrityCheck, *const u8, *const u8, *const u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ptrmap_get(
    bt: *mut u8,
    pgno: u32,
    map_type: *mut u8,
    parent_pgno: *mut u32,
) -> u32 {
    let get: PtrmapGet = core::mem::transmute(PTRMAP_GET_ADDRESS);
    get(bt, pgno, map_type, parent_pgno)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn append_diagnostic(
    check: *mut IntegrityCheck,
    prefix: *const u8,
    format: *const u8,
    args: *const u32,
) {
    integrity_check_append_msg(check, prefix, format, args);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PtrmapCheckHostOps {
    get: PtrmapGet,
    append: AppendDiagnostic,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_ptrmap_get(
    _bt: *mut u8,
    _pgno: u32,
    _map_type: *mut u8,
    _parent_pgno: *mut u32,
) -> u32 {
    1
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PTRMAP_CHECK_HOST_OPS: PtrmapCheckHostOps = PtrmapCheckHostOps {
    get: unavailable_ptrmap_get,
    append: integrity_check_append_msg,
};

#[cfg(not(target_os = "none"))]
static mut PTRMAP_CHECK_HOST_OPS: PtrmapCheckHostOps = DEFAULT_PTRMAP_CHECK_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PtrmapCheckHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PTRMAP_CHECK_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ptrmap_get(
    bt: *mut u8,
    pgno: u32,
    map_type: *mut u8,
    parent_pgno: *mut u32,
) -> u32 {
    (host_ops().get)(bt, pgno, map_type, parent_pgno)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn append_diagnostic(
    check: *mut IntegrityCheck,
    prefix: *const u8,
    format: *const u8,
    args: *const u32,
) {
    (host_ops().append)(check, prefix, format, args)
}

/// `ptrmapCheckPages` — original: `FUN_082c27d0` @ `0x082c27d0` (120 bytes;
/// seven direct, plain-`bl` call sites).
///
/// Validates the pointer-map type and parent for `pgno`. A nonzero ptrmap read
/// status reports the key; a mismatch reports `pgno`, expected type and parent,
/// then actual type and parent. Matching values return silently.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ptrmap_check_pages(
    check: *mut IntegrityCheck,
    pgno: u32,
    expected_type: u32,
    expected_parent: u32,
    prefix: *const u8,
) {
    let mut actual_type = 0u8;
    let mut actual_parent = 0u32;
    if ptrmap_get((*check).p_bt, pgno, &mut actual_type, &mut actual_parent) != 0 {
        let args = [pgno];
        append_diagnostic(check, prefix, READ_FAILURE_FORMAT.as_ptr(), args.as_ptr());
        return;
    }

    if u32::from(actual_type) != expected_type || actual_parent != expected_parent {
        let args = [pgno, expected_type, expected_parent, u32::from(actual_type), actual_parent];
        append_diagnostic(check, prefix, MISMATCH_FORMAT.as_ptr(), args.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_BT: *mut u8 = core::ptr::null_mut();
    static mut RETURN_STATUS: u32 = 0;
    static mut RETURN_TYPE: u8 = 0;
    static mut RETURN_PARENT: u32 = 0;
    static mut LOOKUP: Option<(*mut u8, u32)> = None;
    static mut APPEND: Option<(*mut IntegrityCheck, *const u8, std::vec::Vec<u32>)> = None;

    unsafe extern "C" fn recording_ptrmap_get(
        bt: *mut u8,
        pgno: u32,
        map_type: *mut u8,
        parent_pgno: *mut u32,
    ) -> u32 {
        LOOKUP = Some((bt, pgno));
        assert_eq!(bt, EXPECTED_BT, "check->pBt is passed to ptrmapGet");
        map_type.write(RETURN_TYPE);
        parent_pgno.write(RETURN_PARENT);
        RETURN_STATUS
    }

    unsafe extern "C" fn recording_append(
        check: *mut IntegrityCheck,
        prefix: *const u8,
        format: *const u8,
        args: *const u32,
    ) {
        let count = if format == READ_FAILURE_FORMAT.as_ptr() { 1 } else { 5 };
        APPEND = Some((check, prefix, core::slice::from_raw_parts(args, count).to_vec()));
    }

    struct HostOpsGuard {
        old: PtrmapCheckHostOps,
    }

    impl Drop for HostOpsGuard {
        fn drop(&mut self) {
            unsafe { PTRMAP_CHECK_HOST_OPS = self.old; }
        }
    }

    unsafe fn install_recorders() -> HostOpsGuard {
        let old = PTRMAP_CHECK_HOST_OPS;
        PTRMAP_CHECK_HOST_OPS = PtrmapCheckHostOps {
            get: recording_ptrmap_get,
            append: recording_append,
        };
        HostOpsGuard { old }
    }

    fn check(p_bt: *mut u8) -> IntegrityCheck {
        IntegrityCheck {
            p_bt,
            _p_pager: core::ptr::null_mut(),
            _n_page: 0,
            _an_ref: core::ptr::null_mut(),
            mx_err: 3,
            z_err_msg: core::ptr::null_mut(),
            n_err: 9,
        }
    }

    #[test]
    fn matching_entry_is_silent_after_the_ptrmap_lookup() {
        let _lock = TEST_LOCK.lock();
        let _ops = unsafe { install_recorders() };
        let mut state = check(0x1234usize as *mut u8);
        unsafe {
            EXPECTED_BT = state.p_bt;
            RETURN_STATUS = 0;
            RETURN_TYPE = 4;
            RETURN_PARENT = 77;
            LOOKUP = None;
            APPEND = None;
            ptrmap_check_pages(&mut state, 28, 4, 77, b"tree: \0".as_ptr());
            assert_eq!(LOOKUP, Some((state.p_bt, 28)));
            assert!(APPEND.is_none(), "equal type and parent produce no diagnostic");
            assert_eq!((state.mx_err, state.n_err), (3, 9));
        }
    }

    #[test]
    fn read_failure_reports_only_the_key() {
        let _lock = TEST_LOCK.lock();
        let _ops = unsafe { install_recorders() };
        let mut state = check(0x4321usize as *mut u8);
        let prefix = b"leaf: \0".as_ptr();
        unsafe {
            EXPECTED_BT = state.p_bt;
            RETURN_STATUS = 11;
            RETURN_TYPE = 0xff;
            RETURN_PARENT = 0xffff_ffff;
            LOOKUP = None;
            APPEND = None;
            ptrmap_check_pages(&mut state, 91, 2, 12, prefix);
            assert_eq!(LOOKUP, Some((state.p_bt, 91)));
            let (check, actual_prefix, args) = APPEND.take().expect("read failure is diagnosed");
            assert_eq!(check, (&mut state) as *mut IntegrityCheck);
            assert_eq!(actual_prefix, prefix);
            assert_eq!(args, std::vec![91]);
        }
    }

    #[test]
    fn mismatch_reports_expected_fields_before_actual_fields() {
        let _lock = TEST_LOCK.lock();
        let _ops = unsafe { install_recorders() };
        let mut state = check(0x6789usize as *mut u8);
        unsafe {
            EXPECTED_BT = state.p_bt;
            RETURN_STATUS = 0;
            RETURN_TYPE = 5;
            RETURN_PARENT = 44;
            LOOKUP = None;
            APPEND = None;
            ptrmap_check_pages(&mut state, 30, 3, 40, core::ptr::null());
            let (check, prefix, args) = APPEND.take().expect("mismatch is diagnosed");
            assert_eq!(check, (&mut state) as *mut IntegrityCheck);
            assert!(prefix.is_null());
            assert_eq!(args, std::vec![30, 3, 40, 5, 44]);
        }
    }
}
