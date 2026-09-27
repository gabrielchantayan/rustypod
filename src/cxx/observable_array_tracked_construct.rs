//! `observable_array_tracked_construct` — retailOS `FUN_083d0e5c` @
//! **0x083d0e5c** (36 bytes: 32 bytes of code plus the 4-byte vtable literal
//! `0x089a48c0` at `0x083d0e80`).
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the complete body: `push {r4,lr}` at
//! `0x083d0e5c` through `pop {r4,pc}` at `0x083d0e7c`, followed by the literal
//! loaded by `ldr r1,[pc,#0x10]`; `0x083d0e84` is the next independently
//! entered function. The body has one plain direct `bl`, to the ported
//! [`observable_array_construct`] at `0x08271cec`, and no predicated `bl`.
//! Whole-image A32 decoding finds two inbound plain `bl` sites (`0x0812b250`
//! and `0x0812b43c`) and no predicated direct callers.
//!
//! ## Algorithm
//!
//! Construct the 16-byte `ObservableArray` base, install the vtable shared by
//! its tracked-array destructor, store the byte flag at `+0x10`, and clear the
//! tracked-items word at `+0x14`. Deliberate deviations: none.

use super::observable_array::{observable_array_construct, ObservableArray, OBSERVABLE_ARRAY_SIZE};

/// Vtable literal installed by the ARM constructor at offset `+0x00`.
pub const OBSERVABLE_ARRAY_TRACKED_VTABLE: u32 = 0x089a_48c0;

/// Target layout initialized by [`observable_array_tracked_construct`].
#[repr(C)]
pub struct ObservableArrayTracked {
    pub array: ObservableArray,
    pub enabled: u8,
    pub padding_11_13: [u8; 3],
    pub tracked_items: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(ObservableArrayTracked, array)];
const _: [u8; OBSERVABLE_ARRAY_SIZE] = [0; core::mem::offset_of!(ObservableArrayTracked, enabled)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ObservableArrayTracked, tracked_items)];
const _: [u8; 0x18] = [0; core::mem::size_of::<ObservableArrayTracked>()];

/// Constructs a tracked observable array and returns `this`.
///
/// # Safety
///
/// `this` must point to at least 24 writable, word-aligned bytes. The stock
/// constructor has no NULL or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.observable_array_tracked_construct")]
pub unsafe extern "C" fn observable_array_tracked_construct(
    this: *mut ObservableArrayTracked,
    enabled: u8,
) -> *mut ObservableArrayTracked {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<ObservableArrayTracked>();

    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable)
            .write_volatile(OBSERVABLE_ARRAY_TRACKED_VTABLE);
        core::ptr::addr_of_mut!((*object).enabled).write_volatile(enabled);
        core::ptr::addr_of_mut!((*object).tracked_items).write_volatile(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::FrameworkObject;

    #[repr(C)]
    struct Fixture {
        object: ObservableArrayTracked,
        trailing: u32,
    }

    #[test]
    fn constructs_base_preserves_flag_and_padding_and_clears_tracked_items() {
        for enabled in [0, 1, u8::MAX] {
            let mut fixture = Fixture {
                object: ObservableArrayTracked {
                    array: ObservableArray {
                        base: FrameworkObject { vtable: 0xdead_beef },
                        len: u32::MAX,
                        storage: 0x1111_1111,
                        observers: 0x2222_2222,
                    },
                    enabled: !enabled,
                    padding_11_13: [0xa5; 3],
                    tracked_items: u32::MAX,
                },
                trailing: 0xcafe_babe,
            };
            let object = core::ptr::addr_of_mut!(fixture.object);

            let returned = unsafe { observable_array_tracked_construct(object, enabled) };

            assert_eq!(returned, object);
            assert_eq!(fixture.object.array.base.vtable, OBSERVABLE_ARRAY_TRACKED_VTABLE);
            assert_eq!(fixture.object.array.len, 0);
            assert_eq!(fixture.object.array.storage, 0);
            assert_eq!(fixture.object.array.observers, 0);
            assert_eq!(fixture.object.enabled, enabled);
            assert_eq!(fixture.object.padding_11_13, [0xa5; 3]);
            assert_eq!(fixture.object.tracked_items, 0);
            assert_eq!(fixture.trailing, 0xcafe_babe);
        }
    }
}
