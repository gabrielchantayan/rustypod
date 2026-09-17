//! `callback_owner_release` — original: `FUN_08214410` @ `0x08214410`.
//!
//! The true extent is 92 bytes (`0x08214410..0x0821446c`): raw ARM decoding
//! reaches the next separately entered `push {r3,r4,r5,r6,r7,lr}` at
//! `0x0821446c`. It has two unconditional calls (`blx` vtable slot `+0x58`
//! and `bl 0x081f02c0`) and one predicated call (`blxne` slot `+0x5c`). Four
//! plain `bl` callers enter this function; none are predicated.
//!
//! If the target word at owner `+0x14` is nonzero, bit zero of owner `+0x24`
//! selects the target's `+0x5c` callback with `(target, owner)`. The target's
//! `+0x58` finalizer then receives the target, followed by retailOS
//! `FUN_081f02c0(target)`. Finally, owner `+0x20` and byte `+0x24` become
//! zero and the function returns one.
//!
//! Deliberate deviation: `FUN_081f02c0` is not ported. Target builds dispatch
//! to its verified fixed address; host tests install the same operation through
//! a seam. Host virtual dispatch uses explicit operations because target
//! pointers are 32-bit while host function pointers are wider.

#[cfg(test)]
extern crate std;

const TARGET_VTABLE_FINALIZE_WORD: usize = 0x58 / 4;
const TARGET_VTABLE_FLAGGED_CLEANUP_WORD: usize = 0x5c / 4;
const RETAIL_TARGET_RELEASE: usize = 0x081f_02c0;

/// Target-sized prefix through the state byte at `+0x24`.
#[repr(C)]
pub struct CallbackOwner {
    /// +0x00..+0x10: untouched words.
    pub unresolved_00: [u32; 5],
    /// +0x14: target object pointer.
    pub target: u32,
    /// +0x18..+0x1c: untouched words.
    pub unresolved_18: [u32; 2],
    /// +0x20: cleared after releasing the target.
    pub state: u32,
    /// +0x24: bit zero requests cleanup; the entire byte is cleared.
    pub flags: u8,
}

const _: () = assert!(core::mem::size_of::<CallbackOwner>() == 0x28);
const _: () = assert!(core::mem::offset_of!(CallbackOwner, target) == 0x14);
const _: () = assert!(core::mem::offset_of!(CallbackOwner, state) == 0x20);
const _: () = assert!(core::mem::offset_of!(CallbackOwner, flags) == 0x24);

type FlaggedCleanup = unsafe extern "C" fn(u32, *mut CallbackOwner);
type Finalize = unsafe extern "C" fn(u32);
type ReleaseTarget = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_flagged_cleanup(target: u32, owner: *mut CallbackOwner) {
    let vtable = core::ptr::read_volatile(target as usize as *const u32);
    let function = core::ptr::read_volatile(
        (vtable as usize as *const u32).add(TARGET_VTABLE_FLAGGED_CLEANUP_WORD),
    );
    core::mem::transmute::<usize, FlaggedCleanup>(function as usize)(target, owner);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_finalize(target: u32) {
    let vtable = core::ptr::read_volatile(target as usize as *const u32);
    let function = core::ptr::read_volatile((vtable as usize as *const u32).add(TARGET_VTABLE_FINALIZE_WORD));
    core::mem::transmute::<usize, Finalize>(function as usize)(target);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_target(target: u32) {
    core::mem::transmute::<usize, ReleaseTarget>(RETAIL_TARGET_RELEASE)(target);
}

/// Host equivalents of the two vtable calls and the unported release.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CallbackOwnerReleaseOps {
    pub flagged_cleanup: FlaggedCleanup,
    pub finalize: Finalize,
    pub release: ReleaseTarget,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_flagged_cleanup(_target: u32, _owner: *mut CallbackOwner) {
    panic!("install callback-owner release host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finalize(_target: u32) { panic!("install callback-owner release host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_target: u32) { panic!("install callback-owner release host operations") }

#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_OWNER_RELEASE_OPS: CallbackOwnerReleaseOps = CallbackOwnerReleaseOps {
    flagged_cleanup: missing_flagged_cleanup,
    finalize: missing_finalize,
    release: missing_release,
};

/// Releases the optional callback target and clears owner state.
///
/// # Safety
///
/// `owner` must be readable and writable. A nonzero target must satisfy each
/// selected retail vtable entry and the unported release operation's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_owner_release(owner: *mut CallbackOwner) -> u32 {
    let target = (*owner).target;
    if target != 0 {
        #[cfg(target_os = "none")]
        {
            if (*owner).flags & 1 != 0 { dispatch_flagged_cleanup(target, owner); }
            dispatch_finalize(target);
            release_target(target);
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_OWNER_RELEASE_OPS));
            if (*owner).flags & 1 != 0 { (ops.flagged_cleanup)(target, owner); }
            (ops.finalize)(target);
            (ops.release)(target);
        }
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*owner).state), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*owner).flags), 0);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static CLEANUP_OWNER: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn cleanup(_target: u32, owner: *mut CallbackOwner) {
        assert_eq!(CALLS.swap(1, Ordering::Relaxed), 0);
        CLEANUP_OWNER.store(owner as usize as u32, Ordering::Relaxed);
    }
    unsafe extern "C" fn finalize(_target: u32) {
        assert!(CALLS.swap(2, Ordering::Relaxed) <= 1);
    }
    unsafe extern "C" fn release(_target: u32) {
        assert_eq!(CALLS.swap(3, Ordering::Relaxed), 2);
    }

    fn install_ops() {
        unsafe { CALLBACK_OWNER_RELEASE_OPS = CallbackOwnerReleaseOps { flagged_cleanup: cleanup, finalize, release }; }
    }

    #[test]
    fn releases_flagged_target_in_retail_order_and_clears_owner() {
        let _lock = LOCK.lock();
        install_ops();
        CALLS.store(0, Ordering::Relaxed);
        let mut owner = CallbackOwner { unresolved_00: [0; 5], target: 0x1234, unresolved_18: [0; 2], state: 0xabcd, flags: 1 };
        assert_eq!(unsafe { callback_owner_release(&mut owner) }, 1);
        assert_eq!(CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(CLEANUP_OWNER.load(Ordering::Relaxed), &mut owner as *mut _ as usize as u32);
        assert_eq!(owner.state, 0);
        assert_eq!(owner.flags, 0);
    }

    #[test]
    fn unflagged_target_skips_cleanup_but_finalizes_and_releases() {
        let _lock = LOCK.lock();
        install_ops();
        CALLS.store(0, Ordering::Relaxed);
        CLEANUP_OWNER.store(0, Ordering::Relaxed);
        let mut owner = CallbackOwner { unresolved_00: [0; 5], target: 0x1234, unresolved_18: [0; 2], state: 1, flags: 2 };
        assert_eq!(unsafe { callback_owner_release(&mut owner) }, 1);
        assert_eq!(CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(CLEANUP_OWNER.load(Ordering::Relaxed), 0);
        assert_eq!(owner.flags, 0);
    }

    #[test]
    fn null_target_only_clears_owner_state() {
        let _lock = LOCK.lock();
        CALLS.store(0, Ordering::Relaxed);
        let mut owner = CallbackOwner { unresolved_00: [0; 5], target: 0, unresolved_18: [0; 2], state: 9, flags: 0xff };
        assert_eq!(unsafe { callback_owner_release(&mut owner) }, 1);
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(owner.state, 0);
        assert_eq!(owner.flags, 0);
    }
}
