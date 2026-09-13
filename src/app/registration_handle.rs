//! `registration_handle_destroy` — original: `FUN_081d9734` @ `0x081d9734`
//! (40 bytes, `0x081d9734..0x081d975c`; the literal vtable word is at
//! `0x081d975c`, and the separately linked next function opens at
//! `0x081d9760`).
//!
//! Restores the registration handle's base vtable, then releases its claimed
//! manager-table slot unless `slot_index` is exactly -1. The original invokes
//! `FUN_081d9918(owner, slot_index)` with no owner NULL guard and returns
//! `this` regardless of the release result.
//!
//! **18 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`; there
//! are no direct `b` tail callers and no aligned data words containing this
//! address. The call sites are 0x081af5e8, 0x081af5f8, 0x081af6c8,
//! 0x081af6e4, 0x081c8394, 0x081c83a8, 0x081c851c, 0x081c8538,
//! 0x081c85a4, 0x081c85b8, 0x081c8624, 0x081c8638, 0x081c8730,
//! 0x081c87d0, 0x081c8830, 0x081c8854, 0x081c8934, and 0x081c8948.
//!
//! Deliberate deviation: the manager's slot-release helper `FUN_081d9918`
//! is not ported. Firmware builds dispatch to its fixed retailOS address;
//! host tests install a volatile seam. `RegistrationHandle` uses named fields
//! so its ARM layout remains the three target words while its host pointer
//! field stays naturally wide.
//!
//! `registration_handle_init` — original: `FUN_081d96a0` @ `0x081d96a0`
//! (144 bytes, `0x081d96a0..0x081d9730`; its `0x089a74bc` vtable literal is
//! the following word at `0x081d9730`, and the separately linked sibling
//! opens at `0x081d9734`).
//!
//! It installs the base vtable, owner, and `-1` slot sentinel. A non-NULL
//! owner selects a slot either by resolving two selector words (kind one) or
//! directly from the first selector word (kinds two and three); it retains
//! only a resolved slot in the unsigned range 0 through 31. The unported
//! finder and acquirer retain their exact retailOS calls on firmware and have
//! volatile host seams. Deliberate deviation: named `RegistrationHandle`
//! fields preserve target word layout while making its owner pointer naturally
//! wide on the host.
//!
//! **10 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`; there
//! are no direct `b` tail callers. The call sites are 0x081af5d0, 0x081af628,
//! 0x081c8364, 0x081c84ec, 0x081c8574, 0x081c85f4, 0x081c86e0, 0x081c87b4,
//! 0x081c8818, and 0x081c8900.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Vtable written before the optional manager-slot release.
pub const REGISTRATION_HANDLE_VTABLE: u32 = 0x089a_74bc;
const REGISTRATION_SLOT_RELEASE_ADDRESS: usize = 0x081d_9918;
const REGISTRATION_SLOT_FIND_ADDRESS: usize = 0x081d_95e4;
const REGISTRATION_SLOT_ACQUIRE_ADDRESS: usize = 0x081d_98b8;

/// ABI of the manager-table slot finder used by registration initialization.
pub type RegistrationSlotFind =
    unsafe extern "C" fn(*mut u8, u32, u32, u32, *mut u32) -> i32;

/// ABI of the manager-table slot acquirer used by registration initialization.
pub type RegistrationSlotAcquire = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

/// Host seams for the unported manager-table slot helpers.
#[derive(Clone, Copy)]
pub struct RegistrationHandleInitOps {
    pub find_slot: RegistrationSlotFind,
    pub acquire_slot: RegistrationSlotAcquire,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_find_slot(
    owner: *mut u8,
    sentinel_slot: u32,
    selector_first: u32,
    selector_second: u32,
    slot_out: *mut u32,
) -> i32 {
    let find_slot: RegistrationSlotFind = core::mem::transmute(REGISTRATION_SLOT_FIND_ADDRESS);
    find_slot(owner, sentinel_slot, selector_first, selector_second, slot_out)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_acquire_slot(owner: *mut u8, slot_index: u32) -> *mut u8 {
    let acquire_slot: RegistrationSlotAcquire =
        core::mem::transmute(REGISTRATION_SLOT_ACQUIRE_ADDRESS);
    acquire_slot(owner, slot_index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find_slot(
    _owner: *mut u8,
    _sentinel_slot: u32,
    _selector_first: u32,
    _selector_second: u32,
    _slot_out: *mut u32,
) -> i32 {
    panic!("install registration-handle initialization host operations before finding a slot")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_acquire_slot(_owner: *mut u8, _slot_index: u32) -> *mut u8 {
    panic!("install registration-handle initialization host operations before acquiring a slot")
}

/// Host default before a test installs the retail helper equivalents.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTRATION_HANDLE_INIT_OPS: RegistrationHandleInitOps =
    RegistrationHandleInitOps {
        find_slot: missing_find_slot,
        acquire_slot: missing_acquire_slot,
    };

/// Host-side manager-table helper seams. Firmware builds call
/// `FUN_081d95e4` and `FUN_081d98b8` at their fixed retailOS addresses.
#[cfg(not(target_os = "none"))]
pub static mut REGISTRATION_HANDLE_INIT_OPS: RegistrationHandleInitOps =
    DEFAULT_REGISTRATION_HANDLE_INIT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_find_slot(
    owner: *mut u8,
    sentinel_slot: u32,
    selector_first: u32,
    selector_second: u32,
    slot_out: *mut u32,
) -> i32 {
    let find_slot = core::ptr::read_volatile(addr_of!(REGISTRATION_HANDLE_INIT_OPS.find_slot));
    find_slot(owner, sentinel_slot, selector_first, selector_second, slot_out)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_acquire_slot(owner: *mut u8, slot_index: u32) -> *mut u8 {
    let acquire_slot =
        core::ptr::read_volatile(addr_of!(REGISTRATION_HANDLE_INIT_OPS.acquire_slot));
    acquire_slot(owner, slot_index)
}

/// Initializes a registration handle from an owner and slot selector.
///
/// A selector kind of one resolves the two selector words through the
/// manager-table finder. Kinds two and three use the first selector word as
/// the slot directly. A resolved slot is stored only after the manager-table
/// acquirer returns non-NULL.
///
/// # Safety
///
/// `registration` must be valid and aligned. When `owner` is non-NULL,
/// `selector` must point to two readable `u32` values for kind one, or one
/// readable `u32` value for kinds two and three. The owner and selector must
/// meet the unported helper requirements; stock code provides no further
/// validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_init(
    registration: *mut RegistrationHandle,
    owner: *mut u8,
    selector_kind: u32,
    selector: *const u32,
) -> *mut RegistrationHandle {
    (*registration).vtable = REGISTRATION_HANDLE_VTABLE;
    (*registration).owner = owner;
    (*registration).slot_index = -1;

    if owner.is_null() {
        return registration;
    }

    let slot_index = match selector_kind {
        1 => {
            let mut found_slot = u32::MAX;
            let find_result = {
                #[cfg(target_os = "none")]
                {
                    retail_find_slot(
                        owner,
                        u32::MAX,
                        selector.read(),
                        selector.add(1).read(),
                        &mut found_slot,
                    )
                }
                #[cfg(not(target_os = "none"))]
                {
                    host_find_slot(
                        owner,
                        u32::MAX,
                        selector.read(),
                        selector.add(1).read(),
                        &mut found_slot,
                    )
                }
            };
            if find_result != 0 {
                return registration;
            }
            found_slot
        }
        2 | 3 => selector.read(),
        _ => return registration,
    };

    if slot_index >= 32 {
        return registration;
    }

    let acquired = {
        #[cfg(target_os = "none")]
        {
            retail_acquire_slot(owner, slot_index)
        }
        #[cfg(not(target_os = "none"))]
        {
            host_acquire_slot(owner, slot_index)
        }
    };
    if !acquired.is_null() {
        (*registration).slot_index = slot_index as i32;
    }
    registration
}


/// A manager-table registration represented by its owning manager and slot.
///
/// On ARM these fields are respectively at offsets +0, +4, and +8.
#[repr(C)]
pub struct RegistrationHandle {
    pub vtable: u32,
    pub owner: *mut u8,
    pub slot_index: i32,
}

/// ABI of the unported manager-table slot-release helper.
pub type RegistrationSlotRelease = unsafe extern "C" fn(*mut u8, u32) -> i32;

/// Host seam for the unported manager-table slot-release helper.
#[derive(Clone, Copy)]
pub struct RegistrationHandleOps {
    pub release_slot: RegistrationSlotRelease,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_release_slot(owner: *mut u8, slot_index: u32) -> i32 {
    let release_slot: RegistrationSlotRelease = core::mem::transmute(REGISTRATION_SLOT_RELEASE_ADDRESS);
    release_slot(owner, slot_index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_slot(_owner: *mut u8, _slot_index: u32) -> i32 {
    panic!("install registration-handle host operations before releasing a slot")
}

/// Host default before a test installs the retail helper equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTRATION_HANDLE_OPS: RegistrationHandleOps = RegistrationHandleOps {
    release_slot: missing_release_slot,
};

/// Host-side manager slot-release seam. Firmware builds always call
/// `FUN_081d9918` at `0x081d9918`.
#[cfg(not(target_os = "none"))]
pub static mut REGISTRATION_HANDLE_OPS: RegistrationHandleOps = DEFAULT_REGISTRATION_HANDLE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_release_slot(owner: *mut u8, slot_index: u32) -> i32 {
    let release_slot = core::ptr::read_volatile(addr_of!(REGISTRATION_HANDLE_OPS.release_slot));
    release_slot(owner, slot_index)
}

/// Restores the registration-handle vtable and releases its claimed slot.
///
/// Only the exact `-1` sentinel skips the release. Other negative values are
/// passed to the helper as their raw `u32` bit patterns, matching `cmn r1,#1`
/// and the untouched `r1` argument in the ARM body.
///
/// # Safety
///
/// `registration` must be valid and aligned. When `slot_index != -1`, its
/// `owner` must meet `FUN_081d9918`'s requirements; stock code has no NULL
/// guard for it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_destroy(
    registration: *mut RegistrationHandle,
) -> *mut RegistrationHandle {
    (*registration).vtable = REGISTRATION_HANDLE_VTABLE;
    let slot_index = (*registration).slot_index;
    if slot_index != -1 {
        #[cfg(target_os = "none")]
        retail_release_slot((*registration).owner, slot_index as u32);
        #[cfg(not(target_os = "none"))]
        host_release_slot((*registration).owner, slot_index as u32);
    }
    registration
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use crate::app::registration_handle_wrapper::{
        registration_handle_wrapper_init, RegistrationHandleWrapper,
        REGISTRATION_HANDLE_WRAPPER_VTABLE,
    };
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALL: Option<(*mut u8, u32)> = None;
    static INIT_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FIND_CALL: Option<(*mut u8, u32, u32, u32)> = None;
    static mut ACQUIRE_CALL: Option<(*mut u8, u32)> = None;
    static mut FIND_RESULT: i32 = 0;
    static mut FIND_SLOT: u32 = 0;
    static mut ACQUIRE_SUCCEEDS: bool = true;


    unsafe extern "C" fn record_release(owner: *mut u8, slot_index: u32) -> i32 {
        addr_of_mut!(RELEASE_CALL).write(Some((owner, slot_index)));
        0x7f
    }

    unsafe extern "C" fn record_find(
        owner: *mut u8,
        sentinel_slot: u32,
        selector_first: u32,
        selector_second: u32,
        slot_out: *mut u32,
    ) -> i32 {
        addr_of_mut!(FIND_CALL).write(Some((
            owner,
            sentinel_slot,
            selector_first,
            selector_second,
        )));
        slot_out.write(addr_of!(FIND_SLOT).read());
        addr_of!(FIND_RESULT).read()
    }

    unsafe extern "C" fn record_acquire(owner: *mut u8, slot_index: u32) -> *mut u8 {
        addr_of_mut!(ACQUIRE_CALL).write(Some((owner, slot_index)));
        if addr_of!(ACQUIRE_SUCCEEDS).read() {
            1usize as *mut u8
        } else {
            core::ptr::null_mut()
        }
    }


    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RELEASE_CALL).write(None);
            REGISTRATION_HANDLE_OPS = RegistrationHandleOps { release_slot: record_release };
        }
        guard
    }

    fn install_init_recorder() -> MutexGuard<'static, ()> {
        let guard = INIT_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(FIND_CALL).write(None);
            addr_of_mut!(ACQUIRE_CALL).write(None);
            addr_of_mut!(FIND_RESULT).write(0);
            addr_of_mut!(FIND_SLOT).write(0);
            addr_of_mut!(ACQUIRE_SUCCEEDS).write(true);
            REGISTRATION_HANDLE_INIT_OPS = RegistrationHandleInitOps {
                find_slot: record_find,
                acquire_slot: record_acquire,
            };
        }
        guard
    }


    #[test]
    fn zero_index_reinstalls_vtable_releases_owner_and_returns_this() {
        let _guard = install_recorder();
        let owner = 0x1234_5678usize as *mut u8;
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner,
            slot_index: 0,
        };

        let returned = unsafe { registration_handle_destroy(&mut registration) };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, Some((owner, 0)));
    }

    #[test]
    fn minus_one_sentinel_reinstalls_vtable_without_releasing() {
        let _guard = install_recorder();
        let mut registration = RegistrationHandle {
            vtable: 0xdead_beef,
            owner: core::ptr::null_mut(),
            slot_index: -1,
        };

        let returned = unsafe { registration_handle_destroy(&mut registration) };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, None);
    }

    #[test]
    fn other_negative_indices_reach_the_release_helper_unchanged() {
        let _guard = install_recorder();
        let owner = 0x8765_4321usize as *mut u8;
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner,
            slot_index: -2,
        };

        unsafe { registration_handle_destroy(&mut registration) };

        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, Some((owner, u32::MAX - 1)));
    }
    #[test]
    fn init_with_null_owner_sets_fields_without_touching_selector_or_helpers() {
        let _guard = install_init_recorder();
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner: 1usize as *mut u8,
            slot_index: 27,
        };

        let returned = unsafe {
            registration_handle_init(
                &mut registration,
                core::ptr::null_mut(),
                1,
                core::ptr::null(),
            )
        };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert!(registration.owner.is_null());
        assert_eq!(registration.slot_index, -1);
        assert_eq!(unsafe { addr_of!(FIND_CALL).read() }, None);
        assert_eq!(unsafe { addr_of!(ACQUIRE_CALL).read() }, None);
    }

    #[test]
    fn init_direct_selector_acquires_in_range_slot() {
        let _guard = install_init_recorder();
        let owner = 0x1234_5678usize as *mut u8;
        let selector = [31u32];
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner: core::ptr::null_mut(),
            slot_index: 0,
        };

        let returned = unsafe { registration_handle_init(&mut registration, owner, 2, selector.as_ptr()) };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(registration.owner, owner);
        assert_eq!(registration.slot_index, 31);
        assert_eq!(unsafe { addr_of!(FIND_CALL).read() }, None);
        assert_eq!(unsafe { addr_of!(ACQUIRE_CALL).read() }, Some((owner, 31)));
    }

    #[test]
    fn init_resolved_slot_rejects_failed_lookup_and_out_of_range_results() {
        let _guard = install_init_recorder();
        let owner = 0x8765_4321usize as *mut u8;
        let selector = [0xaabb_ccdd, 0x1122_3344];
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner: core::ptr::null_mut(),
            slot_index: 0,
        };

        unsafe {
            addr_of_mut!(FIND_RESULT).write(1);
        }
        unsafe { registration_handle_init(&mut registration, owner, 1, selector.as_ptr()) };
        assert_eq!(registration.slot_index, -1);
        assert_eq!(
            unsafe { addr_of!(FIND_CALL).read() },
            Some((owner, u32::MAX, selector[0], selector[1]))
        );
        assert_eq!(unsafe { addr_of!(ACQUIRE_CALL).read() }, None);

        unsafe {
            addr_of_mut!(FIND_RESULT).write(0);
            addr_of_mut!(FIND_SLOT).write(32);
            addr_of_mut!(FIND_CALL).write(None);
        }
        unsafe { registration_handle_init(&mut registration, owner, 1, selector.as_ptr()) };
        assert_eq!(registration.slot_index, -1);
        assert_eq!(
            unsafe { addr_of!(FIND_CALL).read() },
            Some((owner, u32::MAX, selector[0], selector[1]))
        );
        assert_eq!(unsafe { addr_of!(ACQUIRE_CALL).read() }, None);
    }

    #[test]
    fn init_keeps_sentinel_when_slot_cannot_be_acquired() {
        let _guard = install_init_recorder();
        let owner = 0x4242usize as *mut u8;
        let selector = [0u32];
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner: core::ptr::null_mut(),
            slot_index: 9,
        };
        unsafe {
            addr_of_mut!(ACQUIRE_SUCCEEDS).write(false);
        }

        unsafe { registration_handle_init(&mut registration, owner, 3, selector.as_ptr()) };

        assert_eq!(registration.slot_index, -1);
        assert_eq!(unsafe { addr_of!(ACQUIRE_CALL).read() }, Some((owner, 0)));
    }

    #[test]
    fn wrapper_init_offsets_context_and_acquires_first_selector_word() {
        let _guard = install_init_recorder();
        let mut context = [0u8; 0xa0d];
        let mut wrapper = RegistrationHandleWrapper {
            vtable: 0,
            registration: RegistrationHandle {
                vtable: 0,
                owner: core::ptr::null_mut(),
                slot_index: 9,
            },
        };

        let returned = unsafe {
            registration_handle_wrapper_init(&mut wrapper, context.as_mut_ptr(), 31, 0xfeed_face)
        };
        let expected_owner = unsafe { context.as_mut_ptr().add(0xa0c) };

        assert!(core::ptr::eq(returned, &mut wrapper));
        assert_eq!(wrapper.vtable, REGISTRATION_HANDLE_WRAPPER_VTABLE);
        assert_eq!(wrapper.registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(wrapper.registration.owner, expected_owner);
        assert_eq!(wrapper.registration.slot_index, 31);
        assert_eq!(unsafe { addr_of!(FIND_CALL).read() }, None);
        assert_eq!(
            unsafe { addr_of!(ACQUIRE_CALL).read() },
            Some((expected_owner, 31))
        );
    }

}
