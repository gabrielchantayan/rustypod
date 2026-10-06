//! Own-target notifier destructor — FUN_08167250 @ 0x08167250.
//! True extent: 48 bytes through 0x08167280 (44 code + 4-byte vtable
//! literal); next real function starts with push {r4,lr} at 0x08167280.
//! Two inbound plain BLs (0x08167244, 0x081e6718), zero predicated BLs.
//! One outbound plain BL to 0x08093ca0, zero predicated BLs, then a tail
//! B to 0x08111190. Install vtable 0x08987f18, delete the dual-mutex owner
//! at +0x18 without a NULL guard, clear that field, and destroy the base.
//! Ghidra incorrectly incorporates the tail-called base destructor here.
//! Deliberate deviations: repr(C) member pointer widens on hosts; the
//! verified, unported base destructor uses a retail-address seam on ARM
//! and an explicitly installed host operation. Volatile writes preserve
//! teardown ordering; no firmware behavioral deviations.

use crate::kernel::sync_mutex::{DualMutexOwner, dual_mutex_owner_delete};

#[repr(C)]
pub struct OwnTargetNotifierOwner {
    pub vtable: u32,
    pub base_words: [u32; 5],
    pub mutex_owner: *mut DualMutexOwner,
}

#[cfg(target_os = "none")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(OwnTargetNotifierOwner, mutex_owner)];

type BaseDestruct = unsafe extern "C" fn(*mut OwnTargetNotifierOwner) -> *mut OwnTargetNotifierOwner;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut OwnTargetNotifierOwner) -> *mut OwnTargetNotifierOwner {
    panic!("install notifier base destructor (0x08111190)")
}
#[cfg(not(target_os = "none"))]
pub static mut OWN_TARGET_NOTIFIER_BASE_DESTRUCT: BaseDestruct = missing_base;

/// Destroy the notifier's owned mutex pair before its base teardown.
///
/// # Safety
/// `owner` and its non-NULL mutex owner must be live; base fields must meet
/// the retail base destructor's requirements. Hosts must install that seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn own_target_notifier_destruct(owner: *mut OwnTargetNotifierOwner) -> *mut OwnTargetNotifierOwner {
    core::ptr::addr_of_mut!((*owner).vtable).write_volatile(0x0898_7f18);
    dual_mutex_owner_delete((*owner).mutex_owner);
    core::ptr::addr_of_mut!((*owner).mutex_owner).write_volatile(core::ptr::null_mut());
    #[cfg(target_os = "none")]
    let base: BaseDestruct = core::mem::transmute(0x0811_1190usize);
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::addr_of!(OWN_TARGET_NOTIFIER_BASE_DESTRUCT).read();
    base(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    unsafe extern "C" fn base(owner: *mut OwnTargetNotifierOwner) -> *mut OwnTargetNotifierOwner {
        assert_eq!((*owner).vtable, 0x0898_7f18);
        assert!((*owner).mutex_owner.is_null());
        assert_eq!((*owner).base_words, [0, 1, u32::MAX, 0x1234, 0x5678]);
        assert_eq!(crate::heap::veneers::tests::free_log().0, 1);
        (*owner).vtable = 0x0898_1958;
        owner
    }

    #[test]
    fn empty_mutex_members_still_release_owner_before_base_and_preserve_base_fields() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut mutexes = DualMutexOwner {
            primary: Mutex { sem_cell: core::ptr::null_mut(), unused: 17 },
            opaque: [0xa5a5; 9],
            secondary: Mutex { sem_cell: core::ptr::null_mut(), unused: 29 },
        };
        let mut owner = OwnTargetNotifierOwner {
            vtable: 0, base_words: [0, 1, u32::MAX, 0x1234, 0x5678],
            mutex_owner: &mut mutexes,
        };
        unsafe {
            let old = OWN_TARGET_NOTIFIER_BASE_DESTRUCT;
            OWN_TARGET_NOTIFIER_BASE_DESTRUCT = base;
            assert_eq!(own_target_notifier_destruct(&mut owner), &mut owner as *mut _);
            OWN_TARGET_NOTIFIER_BASE_DESTRUCT = old;
        }
        assert_eq!(owner.vtable, 0x0898_1958);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, (&mut mutexes as *mut DualMutexOwner).cast(), 10));
        assert_eq!(mutexes.primary.unused, 17);
        assert_eq!(mutexes.secondary.unused, 29);
        assert_eq!(mutexes.opaque, [0xa5a5; 9]);
    }
}
