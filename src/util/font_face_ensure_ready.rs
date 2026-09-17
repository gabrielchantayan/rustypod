//! font_face_ensure_ready — original: `FUN_082a6e84` @ 0x082a6e84 (76
//! bytes; zero plain `bl`, one predicated `bleq`).
//!
//! The true extent is 0x082a6e84..0x082a6ed0: the closing `pop {r4,pc}` is
//! at 0x082a6ecc and the next separately entered function pushes registers at
//! 0x082a6ed0. When the face's +0x89 ready byte is clear, it calls the
//! unported loader at 0x0828fbac only if the +0x91 deferred-load byte is also
//! clear, then returns the ready byte. A ready face returns one without a
//! refresh request; with one, it tail-dispatches vtable slot +0x2c and returns
//! that method's result.
//!
//! Deliberate deviation: the direct loader call and the virtual tail dispatch
//! are ordinary calls through one operation table so host tests can observe
//! them. The target defaults call 0x0828fbac and the target-width vtable slot
//! exactly; return values and call predicates are unchanged.

/// Byte which reports whether the face has completed loading.
const READY: usize = 0x89;
/// Byte which suppresses the synchronous loader call while loading is deferred.
const DEFERRED_LOAD: usize = 0x91;
/// Target-width vtable slot used to refresh an already-ready face.
const REFRESH_SLOT: usize = 0x2c;

type EnsureLoaded = unsafe extern "C" fn(face: *mut u8);
type RefreshFace = unsafe extern "C" fn(face: *mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ensure_loaded(face: *mut u8) {
    let ensure_loaded: EnsureLoaded = core::mem::transmute(0x0828_fbacusize);
    ensure_loaded(face);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ensure_loaded(_face: *mut u8) {
    panic!("font_face_ensure_ready requires loader 0x0828fbac");
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_refresh(face: *mut u8) -> u32 {
    let vtable = (face as *const u32).read() as usize as *const u8;
    let refresh: RefreshFace = core::mem::transmute((vtable.add(REFRESH_SLOT) as *const u32).read());
    refresh(face)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_face: *mut u8) -> u32 {
    panic!("font_face_ensure_ready requires vtable slot +0x2c");
}

#[derive(Clone, Copy)]
struct FontFaceEnsureOps {
    ensure_loaded: EnsureLoaded,
    refresh: RefreshFace,
}

#[cfg(target_os = "none")]
const DEFAULT_FONT_FACE_ENSURE_OPS: FontFaceEnsureOps = FontFaceEnsureOps {
    ensure_loaded: firmware_ensure_loaded,
    refresh: firmware_refresh,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_FONT_FACE_ENSURE_OPS: FontFaceEnsureOps = FontFaceEnsureOps {
    ensure_loaded: missing_ensure_loaded,
    refresh: missing_refresh,
};

/// Unported loader and virtual refresh operations. Target defaults preserve the
/// original targets; host tests replace these operations to observe the branch
/// predicates without representing target function pointers as host pointers.
static mut FONT_FACE_ENSURE_OPS: FontFaceEnsureOps = DEFAULT_FONT_FACE_ENSURE_OPS;

/// font_face_ensure_ready — original: `FUN_082a6e84` @ 0x082a6e84 (76 bytes).
///
/// Returns the face's ready byte after loading it when neither the ready nor
/// deferred-load byte is set. For a ready face, `refresh != 0` dispatches its
/// vtable method at +0x2c; otherwise this returns one.
///
/// # Safety
///
/// `face` must point to readable bytes through +0x91. When ready and
/// `refresh != 0`, it must also satisfy the target vtable dispatch contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn font_face_ensure_ready(face: *mut u8, refresh: u32) -> u32 {
    if face.add(READY).read() == 0 {
        if face.add(DEFERRED_LOAD).read() == 0 {
            (FONT_FACE_ENSURE_OPS.ensure_loaded)(face);
        }
        return face.add(READY).read() as u32;
    }
    if refresh != 0 {
        return (FONT_FACE_ENSURE_OPS.refresh)(face);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOAD_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REFRESH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REFRESH_RESULT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn load_face(face: *mut u8) {
        LOAD_CALLS.fetch_add(1, Ordering::SeqCst);
        face.add(READY).write(0xa5);
    }

    unsafe extern "C" fn refresh_face(_face: *mut u8) -> u32 {
        REFRESH_CALLS.fetch_add(1, Ordering::SeqCst);
        REFRESH_RESULT.load(Ordering::SeqCst)
    }

    fn install_test_ops() {
        unsafe {
            FONT_FACE_ENSURE_OPS = FontFaceEnsureOps {
                ensure_loaded: load_face,
                refresh: refresh_face,
            };
        }
        LOAD_CALLS.store(0, Ordering::SeqCst);
        REFRESH_CALLS.store(0, Ordering::SeqCst);
    }

    fn restore_default_ops() {
        unsafe { FONT_FACE_ENSURE_OPS = DEFAULT_FONT_FACE_ENSURE_OPS; }
    }

    #[test]
    fn loads_only_when_not_ready_or_deferred() {
        let _lock = TEST_LOCK.lock();
        install_test_ops();
        let mut face = [0u8; DEFERRED_LOAD + 1];
        assert_eq!(unsafe { font_face_ensure_ready(face.as_mut_ptr(), 0) }, 0xa5);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(REFRESH_CALLS.load(Ordering::SeqCst), 0);
        restore_default_ops();
    }

    #[test]
    fn deferred_unready_face_returns_its_zero_ready_byte() {
        let _lock = TEST_LOCK.lock();
        install_test_ops();
        let mut face = [0u8; DEFERRED_LOAD + 1];
        face[DEFERRED_LOAD] = 1;
        assert_eq!(unsafe { font_face_ensure_ready(face.as_mut_ptr(), 1) }, 0);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(REFRESH_CALLS.load(Ordering::SeqCst), 0);
        restore_default_ops();
    }

    #[test]
    fn ready_face_refreshes_only_when_requested() {
        let _lock = TEST_LOCK.lock();
        install_test_ops();
        let mut face = [0u8; DEFERRED_LOAD + 1];
        face[READY] = 1;
        REFRESH_RESULT.store(0xfeed_beef, Ordering::SeqCst);
        assert_eq!(unsafe { font_face_ensure_ready(face.as_mut_ptr(), 0) }, 1);
        assert_eq!(unsafe { font_face_ensure_ready(face.as_mut_ptr(), 7) }, 0xfeed_beef);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(REFRESH_CALLS.load(Ordering::SeqCst), 1);
        restore_default_ops();
    }
}
