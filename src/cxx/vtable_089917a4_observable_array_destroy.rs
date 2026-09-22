//! Destroy the observable-array member of the vtable-0x089917a4 object.
//!
//! `vtable_089917a4_observable_array_destroy` — original: `FUN_08204464` @
//! **0x08204464**.
//!
//! **24 bytes**, `0x08204464..0x0820447c`; the next real function starts at
//! `0x08204480` with `bx lr` (`e12fff1e`). Raw ARM words contain **1 plain
//! `bl`** (to `0x083e749c`) and no predicated `bl`; raw-firmware inbound
//! scanning finds **3 plain `bl`** callers and no predicated callers.
//!
//! ```text
//! 08204464: ldr r1, [pc,#16]       ; 0x089917a4
//! 08204468: push {r4,lr}
//! 0820446c: str r1, [r0],#20
//! 08204470: bl  0x083e749c
//! 08204474: sub r0,r0,#20
//! 08204478: pop {r4,pc}
//! ```
//!
//! # Algorithm
//!
//! Install vtable `0x089917a4`, destroy and delete the nullable owned
//! [`ObservableArray`] member at target offset `+0x14`, then return the
//! enclosing object. This is the temporary object's destructor used after its
//! payload has been consumed by all three callers.
//!
//! Deliberate deviations: the vtable is represented as a `u32`, rather than a
//! host pointer, and `repr(C)` preserves the target's 4-byte member-word
//! layout on ARM while allowing host tests to use widened pointers.

use super::observable_array::ObservableArray;
use super::observable_array_owned_destroy::observable_array_owned_destroy;

const VTABLE_089917A4: u32 = 0x0899_17a4;

/// The known fields of the temporary object destroyed at `0x08204464`.
#[repr(C)]
pub struct Vtable089917a4ObservableArray {
    pub vtable: u32,
    pub opaque_words: [u32; 4],
    /// Target offset `+0x14`: nullable, owned observable-array member.
    pub array: *mut ObservableArray,
}

/// Installs the destructor vtable, releases the owned array member, and
/// returns `this`.
///
/// Original: `FUN_08204464` @ `0x08204464` (24 bytes; 3 inbound unconditional
/// `bl` call sites, no predicated callers; the body has one direct `bl`).
///
/// # Safety
///
/// `this` must point to a live object whose `array`, when non-NULL, meets
/// [`observable_array_owned_destroy`]'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089917a4_observable_array_destroy(
    this: *mut Vtable089917a4ObservableArray,
) -> *mut Vtable089917a4ObservableArray {
    (*this).vtable = VTABLE_089917A4;
    observable_array_owned_destroy(core::ptr::addr_of_mut!((*this).array));
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::observable_array_construct;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn object(array: *mut ObservableArray) -> Vtable089917a4ObservableArray {
        Vtable089917a4ObservableArray { vtable: 0, opaque_words: [0; 4], array }
    }

    #[test]
    fn null_array_installs_vtable_and_returns_object() {
        let _lock = TEST_LOCK.lock();
        let mut value = object(core::ptr::null_mut());

        let returned = unsafe { vtable_089917a4_observable_array_destroy(&mut value) };

        assert!(core::ptr::eq(returned, &mut value));
        assert_eq!(value.vtable, VTABLE_089917A4);
        assert!(value.array.is_null());
    }

    #[test]
    fn live_array_is_deleted_without_clearing_member_word() {
        let _lock = TEST_LOCK.lock();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut array = ObservableArray {
            base: crate::cxx::observable_array::FrameworkObject { vtable: 0 },
            len: 0,
            storage: 0,
            observers: 0,
        };
        unsafe { observable_array_construct(&mut array) };
        let mut value = object(&mut array);

        let returned = unsafe { vtable_089917a4_observable_array_destroy(&mut value) };

        assert!(core::ptr::eq(returned, &mut value));
        assert_eq!(value.vtable, VTABLE_089917A4);
        assert!(core::ptr::eq(value.array, &mut array));
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, core::ptr::addr_of_mut!(array).cast::<u8>(), 2),
            "the owned array is released under heap tag 2"
        );
    }
}
