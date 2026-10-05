//! Embedded-array word accessor — `FUN_081d5e90` @ 0x081d5e90.
//! True extent: 20 bytes, ending before the push at 0x081d5ea4.
//! Verified inbound calls: 2 plain BL (0x08137560, 0x0820bbdc), 0 predicated.
//! Body: push; add r0,r0,#8; bl 0x082a4cf8; ldr r0,[r0]; pop.
//! Select an element of the array embedded at +8 using the unchanged signed
//! index, then read its first aligned word. No bounds or NULL checks.
//! Deliberate deviation: reuse the existing accessor's host-widened vtable
//! layout; repr(C) preserves the embedded member offset on host and target.
//! ARM codegen retains add +8, one BL to array_element_at, and one word load;
//! LLVM adds its frame-pointer setup (24 bytes versus the original's 20).

use super::array_element_at::{array_element_at, StridedArray};

/// Only the owner prefix and embedded array accessed by this function.
#[repr(C)]
pub struct EmbeddedWordArray {
    pub prefix: [u32; 2],
    pub elements: StridedArray,
}

const _: [u8; 8] = [0; core::mem::offset_of!(EmbeddedWordArray, elements)];

/// Read the first word of an indexed element of the array at owner +8.
/// Original: 0x081d5e90, 20 bytes, 2 plain BL callers, no predicated callers.
///
/// # Safety
/// `this` must contain a readable array satisfying `array_element_at`'s
/// contract. The resulting element address must be aligned and readable
/// for one u32, including when the index is negative or the last sentinel.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_array_word_at(
    this: *const EmbeddedWordArray,
    index: i32,
) -> u32 {
    let address = array_element_at(core::ptr::addr_of!((*this).elements), index);
    (address as usize as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::array_element_at::{StridedArrayVtable, LAST_ELEMENT_INDEX};

    unsafe extern "C" fn stride(_: *const StridedArray) -> u32 { 8 }

    static VTABLE: StridedArrayVtable = StridedArrayVtable {
        unresolved_00_14: [0; 6],
        element_stride: stride,
    };

    #[test]
    fn reads_signed_indices_and_last_element_with_padded_stride() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::EMBEDDED_ARRAY_WORD_AT, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/embedded_array_word_at"));
            return;
        };
        unsafe {
            let words = slab.cast::<u32>();
            let values = [0x8000_0000, 0xffff_ffff, 0, 0x1234_5678];
            for (i, value) in values.iter().enumerate() {
                words.add(i * 2).write(*value);
                words.add(i * 2 + 1).write(0xdead_beef);
            }
            let mut owner = EmbeddedWordArray {
                prefix: [0xaabb_ccdd, 0x5566_7788],
                elements: StridedArray {
                    vtable: &VTABLE, count: 3,
                    storage: words.add(2) as usize as u32,
                },
            };
            for (index, expected) in [(-1, values[0]), (0, values[1]),
                (1, values[2]), (2, values[3]), (LAST_ELEMENT_INDEX, values[3])] {
                assert_eq!(embedded_array_word_at(&owner, index), expected);
            }
            // With stride 8, MAX * 8 wraps to -8. Nonpositive counts
            // must not clamp the sentinel; both resolve to the prefix word.
            for count in [0, -1] {
                owner.elements.count = count;
                assert_eq!(embedded_array_word_at(&owner, LAST_ELEMENT_INDEX), values[0]);
            }
            assert_eq!(owner.prefix, [0xaabb_ccdd, 0x5566_7788]);
            for i in 0..4 {
                assert_eq!(words.add(i * 2 + 1).read(), 0xdead_beef);
            }
        }
    }
}
