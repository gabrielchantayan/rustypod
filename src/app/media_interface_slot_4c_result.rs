//! `refresh_media_interface_slot_4c_result` — original: `FUN_081fe2f0` @
//! **0x081fe2f0** (**56 bytes**, exactly `0x081fe2f0..0x081fe328`; the next
//! separately linked function begins at `0x081fe328`).
//!
//! Raw ARM calls `lazy_singleton_0x8c_interface_get`, invokes the returned
//! interface's vtable slot `+0x4c` with that interface in `r0`, then stores the
//! result at `state+0x2d4`. It stores whether the result equals `0x100` at
//! `state+0x2d8`; only for that sentinel it overwrites the cached result with
//! `0xff`. The disk image's static descriptor has a zero at this slot, so the
//! dynamic callee has no recoverable static identity and is named only by its
//! verified vtable offset.
//!
//! Full-image decoding of every ARM B/BL immediate finds **seven direct inbound
//! `bl` sites**, all unconditional (zero predicated forms and zero plain-`b`
//! tails): `0x081ff814`, `0x081ffbdc`, `0x081ffc3c`, `0x08200af4`,
//! `0x08200c0c`, `0x08200c2c`, and `0x08200c98`. No aligned image word equals
//! `0x081fe2f0`.
//!
//! Deliberate deviation: host fixtures use a native-width virtual function
//! pointer and a getter seam; the target build directly calls the existing
//! `lazy_singleton_0x8c_interface_get` port and preserves the ARM vtable slot
//! offset.

use core::ptr::addr_of;

const RESULT_OFFSET: usize = 0x2d4;
const SENTINEL_FLAG_OFFSET: usize = 0x2d8;
const SLOT_4C_INDEX: usize = 0x4c / 4;
const SENTINEL_RESULT: u32 = 0x100;
const REPLACEMENT_RESULT: u32 = 0xff;

/// The media interface object recovered as far as its slot `+0x4c` operation.
#[repr(C)]
pub struct MediaInterfaceSlot4c {
    pub vtable: *const MediaInterfaceSlot4cVtable,
}

/// Target layout for the one observed virtual operation.
#[repr(C)]
pub struct MediaInterfaceSlot4cVtable {
    /// Slots `+0x00..+0x48`; no static identity has been recovered for them.
    pub unresolved_00_48: [usize; SLOT_4C_INDEX],
    /// `+0x4c`: returns the value cached by this routine.
    pub query_result: unsafe extern "C" fn(*mut MediaInterfaceSlot4c) -> u32,
}

#[cfg(target_os = "none")]
const _: [u8; SLOT_4C_INDEX * 4] =
    [0; core::mem::offset_of!(MediaInterfaceSlot4cVtable, query_result)];

/// Host-only replacement for the firmware-owned singleton accessor.
#[derive(Clone, Copy)]
pub struct MediaInterfaceSlot4cResultOps {
    pub get_interface: unsafe extern "C" fn() -> *mut MediaInterfaceSlot4c,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_media_interface() -> *mut MediaInterfaceSlot4c {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_INTERFACE_SLOT_4C_RESULT_OPS: MediaInterfaceSlot4cResultOps =
    MediaInterfaceSlot4cResultOps { get_interface: missing_media_interface };

/// Host seam for the existing target singleton accessor.
#[cfg(not(target_os = "none"))]
pub static mut MEDIA_INTERFACE_SLOT_4C_RESULT_OPS: MediaInterfaceSlot4cResultOps =
    DEFAULT_MEDIA_INTERFACE_SLOT_4C_RESULT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn media_interface() -> *mut MediaInterfaceSlot4c {
    unsafe { core::ptr::read_volatile(addr_of!(MEDIA_INTERFACE_SLOT_4C_RESULT_OPS.get_interface))() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn media_interface() -> *mut MediaInterfaceSlot4c {
    unsafe { super::singletons::lazy_singleton_0x8c_interface_get().cast() }
}

/// Refreshes the state cache from the media interface's vtable slot `+0x4c`.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and writable through `+0x2d8`.
/// The singleton accessor must return a non-NULL interface with a readable
/// vtable and callable `+0x4c` slot. RetailOS supplies no NULL guard for any
/// of these accesses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refresh_media_interface_slot_4c_result(state: *mut u8) {
    let interface = unsafe { media_interface() };
    let vtable = unsafe { core::ptr::read_volatile(addr_of!((*interface).vtable)) };
    let result = unsafe { ((*vtable).query_result)(interface) };

    unsafe {
        state.add(RESULT_OFFSET).cast::<u32>().write_volatile(result);
        state
            .add(SENTINEL_FLAG_OFFSET)
            .cast::<u32>()
            .write_volatile(u32::from(result == SENTINEL_RESULT));
        if result == SENTINEL_RESULT {
            state
                .add(RESULT_OFFSET)
                .cast::<u32>()
                .write_volatile(REPLACEMENT_RESULT);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::{Mutex, MutexGuard};
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INTERFACE: *mut MediaInterfaceSlot4c = core::ptr::null_mut();
    static mut QUERY_RESULT: u32 = 0;
    static mut QUERY_INTERFACE: *mut MediaInterfaceSlot4c = core::ptr::null_mut();
    static mut QUERY_CALLS: u32 = 0;

    #[repr(align(4))]
    struct State([u8; SENTINEL_FLAG_OFFSET + 4]);

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        previous_ops: MediaInterfaceSlot4cResultOps,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(MEDIA_INTERFACE_SLOT_4C_RESULT_OPS).write_volatile(self.previous_ops);
                INTERFACE = core::ptr::null_mut();
                QUERY_INTERFACE = core::ptr::null_mut();
                QUERY_CALLS = 0;
            }
        }
    }

    unsafe extern "C" fn get_interface() -> *mut MediaInterfaceSlot4c {
        unsafe { INTERFACE }
    }

    unsafe extern "C" fn query_result(interface: *mut MediaInterfaceSlot4c) -> u32 {
        unsafe {
            QUERY_INTERFACE = interface;
            QUERY_CALLS += 1;
            QUERY_RESULT
        }
    }

    unsafe fn install(interface: *mut MediaInterfaceSlot4c) -> Fixture {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let previous_ops = unsafe { addr_of!(MEDIA_INTERFACE_SLOT_4C_RESULT_OPS).read_volatile() };
        unsafe {
            INTERFACE = interface;
            QUERY_RESULT = 0;
            QUERY_INTERFACE = core::ptr::null_mut();
            QUERY_CALLS = 0;
            addr_of_mut!(MEDIA_INTERFACE_SLOT_4C_RESULT_OPS).write_volatile(
                MediaInterfaceSlot4cResultOps { get_interface },
            );
        }
        Fixture { _guard: guard, previous_ops }
    }

    #[test]
    fn caches_ordinary_result_and_clears_sentinel_flag() {
        let vtable = MediaInterfaceSlot4cVtable {
            unresolved_00_48: [0; SLOT_4C_INDEX],
            query_result,
        };
        let mut interface = MediaInterfaceSlot4c { vtable: &vtable };
        let _fixture = unsafe { install(&mut interface) };
        let mut state = State([0xa5; SENTINEL_FLAG_OFFSET + 4]);
        unsafe { QUERY_RESULT = 0x37 };

        unsafe { refresh_media_interface_slot_4c_result(state.0.as_mut_ptr()) };

        assert_eq!(unsafe { state.0.as_ptr().add(RESULT_OFFSET).cast::<u32>().read() }, 0x37);
        assert_eq!(unsafe { state.0.as_ptr().add(SENTINEL_FLAG_OFFSET).cast::<u32>().read() }, 0);
        assert_eq!(unsafe { QUERY_INTERFACE }, &mut interface as *mut _);
        assert_eq!(unsafe { QUERY_CALLS }, 1);
    }

    #[test]
    fn converts_sentinel_result_to_ff_and_records_it() {
        let vtable = MediaInterfaceSlot4cVtable {
            unresolved_00_48: [0; SLOT_4C_INDEX],
            query_result,
        };
        let mut interface = MediaInterfaceSlot4c { vtable: &vtable };
        let _fixture = unsafe { install(&mut interface) };
        let mut state = State([0; SENTINEL_FLAG_OFFSET + 4]);
        unsafe { QUERY_RESULT = SENTINEL_RESULT };

        unsafe { refresh_media_interface_slot_4c_result(state.0.as_mut_ptr()) };

        assert_eq!(unsafe { state.0.as_ptr().add(RESULT_OFFSET).cast::<u32>().read() }, REPLACEMENT_RESULT);
        assert_eq!(unsafe { state.0.as_ptr().add(SENTINEL_FLAG_OFFSET).cast::<u32>().read() }, 1);
        assert_eq!(unsafe { QUERY_CALLS }, 1);
    }
}
