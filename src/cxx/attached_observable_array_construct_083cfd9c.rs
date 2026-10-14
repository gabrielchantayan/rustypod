//! Attached observable-array constructor — `FUN_083cfd9c` @ **0x083cfd9c**.
//!
//! True extent: **40 bytes**: nine A32 instructions (36 bytes), then the
//! vtable literal `0x089a3a68` at `0x083cfdc0`. The next real function starts
//! at `0x083cfdc4`. Whole-image word decoding verifies one inbound plain BL
//! at `0x080fe840`, zero predicated inbound BLs, and one outbound plain BL
//! to `observable_array_construct` @ `0x08271cec`, zero predicated BLs.
//!
//! Constructs the observable-array base, installs the derived vtable, writes
//! the low byte of the supplied flag at +0x10, and clears the attached-object
//! word at +0x14. Returns the base constructor result unchanged. The matching
//! destructor at `0x083cfdc4` releases the attached object through slot +0x1c.
//! The sole caller embeds this array at +8 and supplies flag one; stronger
//! flag semantics remain unresolved. Deliberate deviations: none. Reuses the
//! target-width attached-array layout; bytes +0x11..+0x13 remain untouched.

use super::attached_observable_array_construct::AttachedObservableArray;
use super::observable_array::observable_array_construct;

pub const ATTACHED_OBSERVABLE_ARRAY_VTABLE_083CFD9C: u32 = 0x089a_3a68;

/// Initializes an empty attached observable array, truncating the flag to a byte.
///
/// # Safety
/// `this` must point to at least 24 writable, word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn attached_observable_array_construct_083cfd9c(
    this: *mut AttachedObservableArray,
    flag: u32,
) -> *mut AttachedObservableArray {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<AttachedObservableArray>();
    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable)
            .write_volatile(ATTACHED_OBSERVABLE_ARRAY_VTABLE_083CFD9C);
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
    fn truncates_flag_clears_dirty_state_and_preserves_untouched_bytes() {
        for seed in [0u32, u32::MAX, 0xa5c3_7e92, 0x0102_0304] {
            for flag in [0u32, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234_5680, u32::MAX] {
                let mut fixture = Fixture {
                    leading: 0x1234_5678,
                    object: [seed; 6],
                    trailing: 0x8765_4321,
                };
                let pointer = fixture.object.as_mut_ptr().cast::<AttachedObservableArray>();
                let mut expected = [seed; 6];
                expected[0] = ATTACHED_OBSERVABLE_ARRAY_VTABLE_083CFD9C;
                expected[1..4].fill(0);
                let mut flag_word = seed.to_ne_bytes();
                flag_word[0] = flag as u8;
                expected[4] = u32::from_ne_bytes(flag_word);
                expected[5] = 0;

                let returned = unsafe { attached_observable_array_construct_083cfd9c(pointer, flag) };
                assert_eq!(returned, pointer);
                assert_eq!(fixture.object, expected);
                assert_eq!(fixture.leading, 0x1234_5678);
                assert_eq!(fixture.trailing, 0x8765_4321);
            }
        }
    }
}
