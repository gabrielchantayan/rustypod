//! `derived_observable_array_construct` — original: `FUN_0839eba4` @
//! 0x0839eba4 (32 bytes: 28 bytes of code plus the 4-byte vtable literal at
//! 0x0839ebc0).
//!
//! # Extent and reachability, binary-verified
//!
//! The seven ARM instructions span 0x0839eba4..0x0839ebbc; literal-pool word
//! 0x0898872c at 0x0839ebc0 completes the function, and the next separately
//! linked sibling begins at 0x0839ebc4. Decoding every immediate ARM B/BL word
//! in `osos.dec` finds exactly five direct callers: all unconditional `bl`
//! (0x080f02f0, 0x0813ed40, 0x08148658, 0x081d179c, and 0x081dead4), with no
//! predicated calls. There are no aligned data-word references, so the
//! constructor is not directly virtual-dispatched.
//!
//! # Algorithm
//!
//! Construct the 16-byte `ObservableArray` base, overwrite its vtable with
//! literal 0x0898872c, then clear the derived object's word at +0x10. The
//! literal points into a type-name string region in this image rather than a
//! statically decodable vtable; the derived class identity is therefore not
//! invented here. There is no NULL or alignment guard. Deliberate deviations:
//! none.

use super::observable_array::{observable_array_construct, ObservableArray, OBSERVABLE_ARRAY_SIZE};

/// Vtable-like literal the ARM constructor installs at offset +0x00.
pub const DERIVED_OBSERVABLE_ARRAY_VTABLE: u32 = 0x0898_872c;

/// An observable-array base followed by the constructor's cleared derived
/// word. All fields are target-width words, including on 64-bit hosts.
#[repr(C)]
pub struct DerivedObservableArray {
    pub array: ObservableArray,
    pub word_at_10: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(DerivedObservableArray, array)];
const _: [u8; OBSERVABLE_ARRAY_SIZE] = [0; core::mem::offset_of!(DerivedObservableArray, word_at_10)];
const _: [u8; 0x14] = [0; core::mem::size_of::<DerivedObservableArray>()];

/// Constructs the observed derived observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must point to at least 20 writable, word-aligned bytes. The stock
/// constructor has no NULL or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.derived_observable_array_construct")]
pub unsafe extern "C" fn derived_observable_array_construct(
    this: *mut DerivedObservableArray,
) -> *mut DerivedObservableArray {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<DerivedObservableArray>();

    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable).write_volatile(DERIVED_OBSERVABLE_ARRAY_VTABLE);
        core::ptr::addr_of_mut!((*object).word_at_10).write_volatile(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{FrameworkObject, FRAMEWORK_OBJECT_VTABLE};

    #[repr(C)]
    struct Fixture {
        object: DerivedObservableArray,
        trailing: u32,
    }

    #[test]
    fn constructs_base_overwrites_vtable_and_clears_only_derived_word() {
        let mut fixture = Fixture {
            object: DerivedObservableArray {
                array: ObservableArray {
                    base: FrameworkObject { vtable: 0xdead_beef },
                    len: 0x1111_1111,
                    storage: 0x2222_2222,
                    observers: 0x3333_3333,
                },
                word_at_10: u32::MAX,
            },
            trailing: 0xa5a5_a5a5,
        };
        let object = core::ptr::addr_of_mut!(fixture.object);

        let returned = unsafe { derived_observable_array_construct(object) };

        assert_eq!(returned, object);
        assert_eq!(fixture.object.array.base.vtable, DERIVED_OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(fixture.object.array.len, 0);
        assert_eq!(fixture.object.array.storage, 0);
        assert_eq!(fixture.object.array.observers, 0);
        assert_eq!(fixture.object.word_at_10, 0);
        assert_eq!(fixture.trailing, 0xa5a5_a5a5);
    }

    #[test]
    fn base_constructor_does_not_leave_its_root_vtable_installed() {
        let mut object = DerivedObservableArray {
            array: ObservableArray {
                base: FrameworkObject { vtable: FRAMEWORK_OBJECT_VTABLE },
                len: 1,
                storage: 2,
                observers: 3,
            },
            word_at_10: 4,
        };

        unsafe { derived_observable_array_construct(core::ptr::addr_of_mut!(object)) };

        assert_ne!(object.array.base.vtable, FRAMEWORK_OBJECT_VTABLE);
        assert_eq!(object.array.base.vtable, DERIVED_OBSERVABLE_ARRAY_VTABLE);
    }
}
