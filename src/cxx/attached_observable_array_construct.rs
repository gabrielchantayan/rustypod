//! Attached observable-array constructor — `FUN_083d0c2c` @ **0x083d0c2c**.
//!
//! True extent: **40 bytes**: nine A32 instructions (36 bytes), then the
//! vtable literal `0x089a4710` at `0x083d0c50`. The next real function starts
//! at `0x083d0c54`. Whole-image word decoding verifies one inbound plain BL
//! at `0x081fbd8c`, zero predicated inbound BLs, and one outbound plain BL
//! to `observable_array_construct` @ `0x08271cec`, zero predicated BLs.
//!
//! Constructs the observable-array base, installs the derived vtable, writes
//! the low byte of the supplied flag at +0x10, and clears the attached-object
//! word at +0x14. Returns the base constructor result unchanged. The matching
//! destructor at `0x083d0c54` releases that attached object through slot +0x1c.
//! The sole caller constructs an embedded array with flag zero. The flag's
//! stronger meaning is unresolved. Deliberate deviations: none; target-width
//! fields and volatile stores preserve bytes +0x11..+0x13 on hosts as well.

use super::observable_array::{observable_array_construct, ObservableArray};

pub const ATTACHED_OBSERVABLE_ARRAY_VTABLE: u32 = 0x089a_4710;

#[repr(C)]
pub struct AttachedObservableArray {
    pub array: ObservableArray,
    pub flag: u8,
    pub padding_11_13: [u8; 3],
    pub attached_object: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(AttachedObservableArray, flag)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(AttachedObservableArray, attached_object)];
const _: [u8; 0x18] = [0; core::mem::size_of::<AttachedObservableArray>()];

/// Initializes an empty attached observable array, truncating the flag to a byte.
///
/// # Safety
/// `this` must point to at least 24 writable, word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn attached_observable_array_construct(
    this: *mut AttachedObservableArray,
    flag: u32,
) -> *mut AttachedObservableArray {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<AttachedObservableArray>();
    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable)
            .write_volatile(ATTACHED_OBSERVABLE_ARRAY_VTABLE);
        core::ptr::addr_of_mut!((*object).flag).write_volatile(flag as u8);
        core::ptr::addr_of_mut!((*object).attached_object).write_volatile(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        leading: u32,
        object: [u32; 6],
        trailing: u32,
    }

    #[test]
    fn truncates_flag_resets_dirty_state_and_preserves_padding_and_neighbors() {
        for seed in [0u32, u32::MAX, 0xa5c3_7e92, 0x0102_0304] {
            for flag in [0u32, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234_5680, u32::MAX] {
                let mut fixture = Fixture {
                    leading: 0x1234_5678,
                    object: [seed; 6],
                    trailing: 0x8765_4321,
                };
                let pointer = fixture.object.as_mut_ptr().cast::<AttachedObservableArray>();
                let mut expected = [seed; 6];
                expected[0] = ATTACHED_OBSERVABLE_ARRAY_VTABLE;
                expected[1..4].fill(0);
                let mut flag_word = seed.to_ne_bytes();
                flag_word[0] = flag as u8;
                expected[4] = u32::from_ne_bytes(flag_word);
                expected[5] = 0;

                for _ in 0..2 {
                    let returned = unsafe { attached_observable_array_construct(pointer, flag) };
                    assert_eq!(returned, pointer);
                    assert_eq!(fixture.object, expected);
                    assert_eq!(fixture.leading, 0x1234_5678);
                    assert_eq!(fixture.trailing, 0x8765_4321);
                }
            }
        }
    }
}
