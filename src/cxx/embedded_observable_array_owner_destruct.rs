//! `embedded_observable_array_owner_destruct` — `FUN_0820b8b0` @ 0x0820b8b0.
//!
//! True extent: 32 bytes (28 code bytes plus vtable literal 0x08992200 at
//! 0x0820b8cc); the next real function starts at 0x0820b8d0. Whole-image
//! aligned A32 decoding finds two inbound plain BLs (0x081dcdf8, 0x081dceac)
//! and zero predicated BLs. The body has one plain BL, zero predicated BLs,
//! and a tail B to 0x081fae30.
//!
//! Install the derived vtable, destroy the embedded observable array at
//! +0x54, subtract 0x54 from its returned receiver, then destruct the base
//! owner through `vtable_08990af8_destruct`. Return that base destructor's
//! result. Ghidra incorrectly folds the tail callee into this function.
//! Deliberate deviations: the class is named by its verified ownership
//! behavior; Rust expresses the tail branch as a direct returning call.

use super::observable_array::{observable_array_destruct, ObservableArray};
use super::vtable_08990af8_destruct::{vtable_08990af8_destruct, Vtable08990af8Object};

/// Target-width owner with the embedded array at byte offset 0x54.
#[repr(C)]
pub struct EmbeddedObservableArrayOwner {
    pub base: Vtable08990af8Object,
    pub words_40_to_50: [u32; 5],
    pub array: ObservableArray,
}

const _: [u8; 0x54] = [0; core::mem::offset_of!(EmbeddedObservableArrayOwner, array)];
const _: [u8; 0x64] = [0; core::mem::size_of::<EmbeddedObservableArrayOwner>()];

/// Destroy the embedded array before the base owner's owned members.
///
/// # Safety
/// `this` must point to a live writable owner. Its embedded array and base
/// must satisfy the respective callees' destruction contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_observable_array_owner_destruct(
    this: *mut EmbeddedObservableArrayOwner,
) -> *mut EmbeddedObservableArrayOwner {
    core::ptr::addr_of_mut!((*this).base.vtable).write_volatile(0x0899_2200);
    let array = observable_array_destruct(core::ptr::addr_of_mut!((*this).array));
    let base = array.cast::<u8>().sub(0x54).cast::<Vtable08990af8Object>();
    vtable_08990af8_destruct(base).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observable_array::{FrameworkObject, OBSERVABLE_ARRAY_VTABLE};
    use super::super::vtable_08990af8_destruct::VTABLE_08990AF8_DESTRUCT_VTABLE;

    #[test]
    fn clears_embedded_length_without_overwriting_owner_state_or_guards() {
        for length in [0, 1, u32::MAX] {
            let mut guarded = (0x12345678u32, EmbeddedObservableArrayOwner {
                base: Vtable08990af8Object {
                    vtable: 0xdeadbeef,
                    words_04_to_20: [0xa5a5a5a5; 8],
                    owned_outer: 0,
                    owned_arrays: [0; 6],
                },
                words_40_to_50: [0x5a5a5a5a; 5],
                array: ObservableArray {
                    base: FrameworkObject { vtable: 0xdeadbeef },
                    len: length,
                    storage: 0,
                    observers: 0,
                },
            }, 0x87654321u32);
            let owner = &mut guarded.1 as *mut EmbeddedObservableArrayOwner;
            unsafe { assert_eq!(embedded_observable_array_owner_destruct(owner), owner); }
            assert_eq!(guarded.0, 0x12345678);
            assert_eq!(guarded.2, 0x87654321);
            assert_eq!(guarded.1.base.vtable, VTABLE_08990AF8_DESTRUCT_VTABLE);
            assert_eq!(guarded.1.base.words_04_to_20, [0xa5a5a5a5; 8]);
            assert_eq!(guarded.1.words_40_to_50, [0x5a5a5a5a; 5]);
            assert_eq!(guarded.1.array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(guarded.1.array.len, 0);
            assert_eq!(guarded.1.array.storage, 0);
            assert_eq!(guarded.1.array.observers, 0);
        }
    }
}
