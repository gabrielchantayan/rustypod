//! Track a page reference during an SQLite integrity check.
//!
//! `integrity_check_ref` — original: `FUN_082c2938` @ `0x082c2938` (92 bytes,
//! ending at `pop {r4,pc}` @ `0x082c2990`; diagnostic literals begin at
//! `0x082c2994`). Raw ARM decoding finds three inbound direct calls, all plain
//! `bl` (`0x082c25c4`, `0x082c26d4`, `0x082c2a10`), and one outbound plain
//! `bl` to `integrity_check_append_msg` @ `0x082c2438`.
//!
//! SQLite's `checkRef`: page zero and invalid page numbers report success;
//! otherwise index `anRef` backwards from `nPage`. A first reference becomes
//! one and succeeds; later references are diagnosed and return failure. The
//! counter increments with ARM's wrapping arithmetic. Deliberate deviation:
//! the C variadic diagnostic's r3 word is a one-word explicit `VaList`, the
//! established Rust ABI for `integrity_check_append_msg`.

use super::integrity_check_append_msg::{integrity_check_append_msg, IntegrityCheck};

const INVALID_PAGE_FORMAT: &[u8] = b"invalid page number %d\0";
const SECOND_REFERENCE_FORMAT: &[u8] = b"2nd reference to page %d\0";

#[cfg(not(target_os = "none"))]
type AppendDiagnostic = unsafe extern "C" fn(*mut IntegrityCheck, *const u8, *const u8, *const u32);

#[cfg(not(target_os = "none"))]
static mut APPEND_DIAGNOSTIC: AppendDiagnostic = integrity_check_append_msg;

#[inline(always)]
unsafe fn append_diagnostic(check: *mut IntegrityCheck, context: *const u8, format: *const u8, args: *const u32) {
    #[cfg(target_os = "none")]
    integrity_check_append_msg(check, context, format, args);
    #[cfg(not(target_os = "none"))]
    (core::ptr::read_volatile(core::ptr::addr_of!(APPEND_DIAGNOSTIC)))(check, context, format, args);
}

/// `checkRef` — original: `FUN_082c2938` @ `0x082c2938` (92 bytes; three
/// plain-`bl` call sites).
///
/// Records `page` in `check->_an_ref[check->_n_page - page]`, preserving the
/// stock diagnostic and return convention for zero, out-of-range, and repeated
/// references. `check`, `_an_ref`, and `context` are deliberately unguarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn integrity_check_ref(check: *mut IntegrityCheck, page: i32, context: *const u8) -> i32 {
    if page == 0 {
        return 1;
    }

    let check_ref = &mut *check;
    let index = check_ref._n_page.wrapping_sub(page);
    if check_ref._n_page < page || index < 0 {
        let args = [page as u32];
        append_diagnostic(check, context, INVALID_PAGE_FORMAT.as_ptr(), args.as_ptr());
        return 1;
    }

    let reference = check_ref._an_ref.add(index as usize);
    let count = reference.read();
    if count == 1 {
        let args = [page as u32];
        append_diagnostic(check, context, SECOND_REFERENCE_FORMAT.as_ptr(), args.as_ptr());
        return 1;
    }

    reference.write(count.wrapping_add(1));
    i32::from(count > 1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut APPEND: Option<(*mut IntegrityCheck, *const u8, *const u8, std::vec::Vec<u32>)> = None;

    unsafe extern "C" fn recording_append(check: *mut IntegrityCheck, context: *const u8, format: *const u8, args: *const u32) {
        APPEND = Some((check, context, format, core::slice::from_raw_parts(args, 1).to_vec()));
    }

    struct AppendGuard(AppendDiagnostic);
    impl Drop for AppendGuard {
        fn drop(&mut self) { unsafe { APPEND_DIAGNOSTIC = self.0; } }
    }

    unsafe fn install_recorder() -> AppendGuard {
        let old = APPEND_DIAGNOSTIC;
        APPEND_DIAGNOSTIC = recording_append;
        AppendGuard(old)
    }

    fn check(refs: &mut [i32]) -> IntegrityCheck {
        IntegrityCheck {
            p_bt: core::ptr::null_mut(), _p_pager: core::ptr::null_mut(),
            _n_page: refs.len() as i32, _an_ref: refs.as_mut_ptr(), mx_err: 3,
            z_err_msg: core::ptr::null_mut(), n_err: 0,
        }
    }

    #[test]
    fn zero_page_is_silent_and_preserves_references() {
        let _lock = TEST_LOCK.lock();
        let _append = unsafe { install_recorder() };
        let mut refs = [4, 3, 2];
        let mut state = check(&mut refs);
        unsafe {
            APPEND = None;
            assert_eq!(integrity_check_ref(&mut state, 0, core::ptr::null()), 1);
            assert_eq!(refs, [4, 3, 2]);
            assert!(APPEND.is_none());
        }
    }

    #[test]
    fn invalid_page_reports_its_original_number() {
        let _lock = TEST_LOCK.lock();
        let _append = unsafe { install_recorder() };
        let mut refs = [0, 0, 0];
        let mut state = check(&mut refs);
        let context = b"root: \0".as_ptr();
        unsafe {
            APPEND = None;
            assert_eq!(integrity_check_ref(&mut state, 4, context), 1);
            let (check, actual_context, format, args) = APPEND.take().expect("invalid page is diagnosed");
            assert_eq!(check, (&mut state) as *mut IntegrityCheck);
            assert_eq!(actual_context, context);
            assert_eq!(format, INVALID_PAGE_FORMAT.as_ptr());
            assert_eq!(args, std::vec![4]);
            assert_eq!(refs, [0, 0, 0]);
        }
    }

    #[test]
    fn first_and_repeated_references_follow_reverse_page_indexing() {
        let _lock = TEST_LOCK.lock();
        let _append = unsafe { install_recorder() };
        let mut refs = [0, 1, i32::MAX];
        let mut state = check(&mut refs);
        unsafe {
            APPEND = None;
            assert_eq!(integrity_check_ref(&mut state, 3, core::ptr::null()), 0);
            assert_eq!(refs[0], 1);
            assert!(APPEND.is_none());
            assert_eq!(integrity_check_ref(&mut state, 2, core::ptr::null()), 1);
            let (_, _, format, args) = APPEND.take().expect("second reference is diagnosed");
            assert_eq!(format, SECOND_REFERENCE_FORMAT.as_ptr());
            assert_eq!(args, std::vec![2]);
            assert_eq!(refs[1], 1);
            assert_eq!(integrity_check_ref(&mut state, 1, core::ptr::null()), 1);
            assert_eq!(refs[2], i32::MIN);
        }
    }

    #[test]
    fn wrapped_reverse_index_is_invalid_before_touching_the_reference_array() {
        let _lock = TEST_LOCK.lock();
        let _append = unsafe { install_recorder() };
        let mut state = IntegrityCheck {
            p_bt: core::ptr::null_mut(), _p_pager: core::ptr::null_mut(),
            _n_page: i32::MAX, _an_ref: core::ptr::null_mut(), mx_err: 3,
            z_err_msg: core::ptr::null_mut(), n_err: 0,
        };
        unsafe {
            APPEND = None;
            assert_eq!(integrity_check_ref(&mut state, -1, core::ptr::null()), 1);
            let (_, _, format, args) = APPEND.take().expect("wrapped index is diagnosed");
            assert_eq!(format, INVALID_PAGE_FORMAT.as_ptr());
            assert_eq!(args, std::vec![u32::MAX]);
        }
    }
}
