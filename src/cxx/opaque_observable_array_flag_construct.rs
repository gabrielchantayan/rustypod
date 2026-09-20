//! `opaque_observable_array_flag_construct` — original: `FUN_083d0ac8` @
//! 0x083d0ac8 (40 bytes: 36 bytes of code plus the 4-byte literal
//! 0x089a4638 at 0x083d0aec).
//!
//! # Extent and reachability, binary-verified
//!
//! The nine ARM instructions span 0x083d0ac8..0x083d0ae8. The `ldr r1,
//! [pc,#0x10]` at 0x083d0ad4 reads the literal at 0x083d0aec; the next
//! independently entered function begins at 0x083d0af0. Whole-image decoding
//! finds three inbound plain unconditional `bl` instructions (0x08291e9c,
//! 0x08291ebc, and 0x08291f3c), and no predicated direct `bl` callers. The
//! body makes one plain direct `bl`, to the ported `observable_array_construct`
//! @ 0x08271cec; it has no predicated direct call.
//!
//! # Algorithm
//!
//! Construct the 16-byte `ObservableArray` base, overwrite its vtable with the
//! literal, copy the incoming byte to +0x10, and clear the word at +0x14. The
//! literal has no verified class identity, so this module deliberately uses an
//! opaque role name rather than inventing one. Deliberate deviations: none.

use super::observable_array::{observable_array_construct, ObservableArray, OBSERVABLE_ARRAY_SIZE};

/// Literal installed by the ARM constructor at offset +0x00.
pub const OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE: u32 = 0x089a_4638;

/// Target layout initialized by [`opaque_observable_array_flag_construct`].
#[repr(C)]
pub struct OpaqueObservableArrayFlag {
    pub array: ObservableArray,
    pub flag_at_10: u8,
    pub padding_11_13: [u8; 3],
    pub word_at_14: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, array)];
const _: [u8; OBSERVABLE_ARRAY_SIZE] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, flag_at_10)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, word_at_14)];
const _: [u8; 0x18] = [0; core::mem::size_of::<OpaqueObservableArrayFlag>()];

/// Constructs the observed opaque observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must point to at least 24 writable, word-aligned bytes. The stock
/// constructor has no NULL or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_observable_array_flag_construct")]
pub unsafe extern "C" fn opaque_observable_array_flag_construct(
    this: *mut OpaqueObservableArrayFlag,
    flag: u8,
) -> *mut OpaqueObservableArrayFlag {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<OpaqueObservableArrayFlag>();

    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable)
            .write_volatile(OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE);
        core::ptr::addr_of_mut!((*object).flag_at_10).write_volatile(flag);
        core::ptr::addr_of_mut!((*object).word_at_14).write_volatile(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::FrameworkObject;

    #[repr(C)]
    struct Fixture {
        object: OpaqueObservableArrayFlag,
        trailing: u32,
    }

    #[test]
    fn constructs_base_preserves_each_flag_value_and_clears_only_word_at_14() {
        for flag in [0, 1, u8::MAX] {
            let mut fixture = Fixture {
                object: OpaqueObservableArrayFlag {
                    array: ObservableArray {
                        base: FrameworkObject { vtable: 0xdead_beef },
                        len: u32::MAX,
                        storage: 0x1111_1111,
                        observers: 0x2222_2222,
                    },
                    flag_at_10: !flag,
                    padding_11_13: [0xa5; 3],
                    word_at_14: u32::MAX,
                },
                trailing: 0xcafe_babe,
            };
            let object = core::ptr::addr_of_mut!(fixture.object);

            let returned = unsafe { opaque_observable_array_flag_construct(object, flag) };

            assert_eq!(returned, object);
            assert_eq!(fixture.object.array.base.vtable, OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE);
            assert_eq!(fixture.object.array.len, 0);
            assert_eq!(fixture.object.array.storage, 0);
            assert_eq!(fixture.object.array.observers, 0);
            assert_eq!(fixture.object.flag_at_10, flag);
            assert_eq!(fixture.object.padding_11_13, [0xa5; 3]);
            assert_eq!(fixture.object.word_at_14, 0);
            assert_eq!(fixture.trailing, 0xcafe_babe);
        }
    }
}
