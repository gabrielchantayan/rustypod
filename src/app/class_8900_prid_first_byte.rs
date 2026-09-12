//! First-byte accessor for the `"prID"` resource: `FUN_081ec2ec` @
//! 0x081ec2ec.
//!
//! # Raw extent and call sites
//!
//! Ghidra's 40-byte size is the ten-instruction code extent
//! (`0x081ec2ec..0x081ec314`). Two literal words follow — resource id
//! `0x60f0` and kind `0x70724944` (`"prID"` read big-endian) — so the true
//! extent is 48 bytes through `0x081ec31c`, where `FUN_081ec31c` begins.
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly **8 direct,
//! unconditional `bl` call sites** (0x0812b098, 0x0817adec, 0x0817f5d8,
//! 0x08186d14, 0x081997f4, 0x08199830, 0x0819a648, and 0x081ccf40), with no
//! predicated or tail-branch callers. No aligned data word in the image is
//! 0x081ec2ec, so it is not dispatched virtually.
//!
//! # Algorithm
//!
//! Load class-0x8900's class-0x6000 store at +0x378, look up resource
//! `(kind "prID", id 0x60f0)` through `resource_chain_find`, and return its
//! first byte sign-extended to `i32`. A missing entry returns zero; the
//! returned resource itself is not otherwise interpreted.
//!
//! # Deliberate deviations
//!
//! The existing `Class8900` layout names the +0x378 field. Its `Class6000`
//! store is passed through the resource-provider-chain ABI, just as the ARM
//! code does. The `"prID"` resource's meaning is not recovered, so the symbol
//! describes only its verified operation.

use crate::app::class_8900::Class8900;
use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};

/// Resource kind literal @ 0x081ec318: `"prID"` read big-endian.
const RESOURCE_KIND_PRID: ResourceKind = ResourceKind(0x7072_4944);
/// Resource id literal @ 0x081ec314.
const RESOURCE_ID_PRID: u32 = 0x60f0;


/// class_8900_prid_first_byte — original: `FUN_081ec2ec` @ 0x081ec2ec
/// (**40 bytes of code plus an 8-byte literal pool; 8 unconditional `bl`
/// call sites, binary-scanned**).
///
/// Looks up `(kind "prID", id 0x60f0)` in the class-0x8900 object's
/// class-0x6000 store. Returns the first byte of a found resource as a
/// sign-extended `i32`, or zero when the chain does not answer. As in the ARM
/// code, `this` itself is not NULL-guarded; it must point to a valid
/// [`Class8900`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_prid_first_byte(this: *const Class8900) -> i32 {
    let resource = resource_chain_find(
        (*this).store as *mut ResourceProvider,
        RESOURCE_KIND_PRID,
        RESOURCE_ID_PRID,
    );
    if resource.is_null() {
        0
    } else {
        *(resource as *const i8) as i32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut ANSWER: *mut u8 = ptr::null_mut();
    static mut OBSERVED_KIND: ResourceKind = ResourceKind(0);
    static mut OBSERVED_ID: u32 = 0;

    unsafe extern "C" fn find_prid(
        _provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        OBSERVED_KIND = kind;
        OBSERVED_ID = id;
        if ANSWER.is_null() {
            0
        } else {
            *found = ANSWER;
            1
        }
    }

    unsafe extern "C" fn read_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn replacement_permits(
        _provider: *mut ResourceProvider,
        _replacement: *mut ResourceProvider,
    ) -> u32 {
        1
    }

    unsafe extern "C" fn write_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    const VTABLE: crate::app::resource_chain::ResourceProviderVTable =
        crate::app::resource_chain::ResourceProviderVTable {
            slots_below: [None; 22],
            read: read_not_called,
            slot_5c: None,
            replacement_allowed: replacement_permits,
            find: find_prid,
            write: write_not_called,
        };

    #[repr(C)]
    struct ResourceBackedClass6000 {
        class: crate::app::class_8900::Class6000,
        state_below_next: [*mut u8; 4],
        next: *mut ResourceProvider,
    }

    fn resource_owner(provider: &mut ResourceBackedClass6000) -> Class8900 {
        Class8900 {
            state_below_cache: [0; 12],
            cached_6031: 0,
            state_below_store: [0; 209],
            store: &mut provider.class,
        }
    }

    #[test]
    fn returns_signed_first_byte_of_prid_resource() {
        let _guard = TEST_LOCK.lock();
        let mut provider = ResourceBackedClass6000 {
            class: crate::app::class_8900::Class6000 {
                vtable: &VTABLE as *const _ as *const crate::app::class_8900::Class6000VTable,
            },
            state_below_next: [ptr::null_mut(); 4],
            next: ptr::null_mut(),
        };
        let owner = resource_owner(&mut provider);
        let mut values = [0_u8, 1, 0x7f, 0x80, 0xff];

        for (value, expected) in values.iter_mut().zip([0, 1, 127, -128, -1]) {
            unsafe {
                ANSWER = value;
                assert_eq!(class_8900_prid_first_byte(&owner), expected);
                assert_eq!(OBSERVED_KIND, RESOURCE_KIND_PRID);
                assert_eq!(OBSERVED_ID, RESOURCE_ID_PRID);
            }
        }
    }

    #[test]
    fn returns_zero_when_no_provider_answers() {
        let _guard = TEST_LOCK.lock();
        let mut provider = ResourceBackedClass6000 {
            class: crate::app::class_8900::Class6000 {
                vtable: &VTABLE as *const _ as *const crate::app::class_8900::Class6000VTable,
            },
            state_below_next: [ptr::null_mut(); 4],
            next: ptr::null_mut(),
        };
        let owner = resource_owner(&mut provider);

        unsafe {
            ANSWER = ptr::null_mut();
            assert_eq!(class_8900_prid_first_byte(&owner), 0);
            assert_eq!(OBSERVED_KIND, RESOURCE_KIND_PRID);
            assert_eq!(OBSERVED_ID, RESOURCE_ID_PRID);
        }
    }
}
