//! Auto-hinter edge position translation.

/// Translate an edge using a reference edge's fitted displacement.
///
/// Original: `FUN_080cc500` at load address `0x080cc500`, true extent
/// `0x080cc500..0x080cc51c` (28 bytes; next function begins at `0x080cc51c`).
/// Whole-image aligned A32 decoding verifies two plain inbound BLs at
/// `0x080a108c` and `0x080a1138`, zero predicated inbound BLs, and zero
/// outgoing plain or predicated BLs.
///
/// Read edge+4, reference+4 and reference+8 before writing edge+8:
/// `position = original_position - reference_original + reference_position`,
/// with 32-bit wrapping arithmetic. The caller walks 48-byte auto-hinter
/// edge records and marks translated edges fitted (bit 4 at +12).
///
/// Deliberate representation deviation: aligned word pointers expose only
/// the accessed prefix, not an invented full edge type. Return the computed
/// position to preserve raw r0, despite Ghidra's void signature. No algorithmic
/// deviations, validation, or allocation.
///
/// # Safety
/// `reference` and `edge` must each have three readable aligned u32 words;
/// edge word 2 must also be writable. They may alias. `hints` is ignored and
/// may be null. No references are formed, so overlapping records are allowed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn af_edge_translate_position(
    _hints: *mut u32,
    reference: *const u32,
    edge: *mut u32,
) -> i32 {
    let original = *edge.add(1);
    let reference_original = *reference.add(1);
    let reference_position = *reference.add(2);
    let position = original.wrapping_sub(reference_original).wrapping_add(reference_position);
    *edge.add(2) = position;
    position as i32
}

#[cfg(test)]
mod tests {
    use super::af_edge_translate_position;

    #[test]
    fn translates_signed_and_wrapping_positions_without_touching_other_words() {
        let cases: [(i32, i32, i32); 7] = [
            (120, 100, 128), (80, 100, 128), (-80, -100, -128),
            (100, 100, 128), (i32::MAX, -1, 1),
            (i32::MIN, 1, -1), (0, i32::MIN, i32::MAX),
        ];
        for (original, reference_original, reference_position) in cases {
            let reference = [0x12345678, reference_original as u32, reference_position as u32, 0x87654321];
            let mut edge = [0xabcdef01, original as u32, 0xdeadbeef, 0x13579bdf];
            let expected = ((original as i64 - reference_original as i64 + reference_position as i64) as u32) as i32;
            let result = unsafe {
                af_edge_translate_position(core::ptr::null_mut(), reference.as_ptr(), edge.as_mut_ptr())
            };
            assert_eq!(result, expected);
            assert_eq!(edge, [0xabcdef01, original as u32, expected as u32, 0x13579bdf]);
            assert_eq!(reference, [0x12345678, reference_original as u32, reference_position as u32, 0x87654321]);
        }
    }

    #[test]
    fn identical_records_preserve_the_fitted_position() {
        let mut edge = [0x12345678, i32::MIN as u32, i32::MAX as u32, 0xabcdef01];
        let pointer = edge.as_mut_ptr();
        let result = unsafe { af_edge_translate_position(core::ptr::null_mut(), pointer, pointer) };
        assert_eq!(result, i32::MAX);
        assert_eq!(edge, [0x12345678, i32::MIN as u32, i32::MAX as u32, 0xabcdef01]);
    }

    #[test]
    fn overlapping_prefixes_read_before_the_destination_write() {
        let mut words = [10, 20, 31, 45, 50];
        let pointer = words.as_mut_ptr();
        let result = unsafe {
            af_edge_translate_position(core::ptr::null_mut(), pointer.add(1), pointer)
        };
        assert_eq!(result, 34);
        assert_eq!(words, [10, 20, 34, 45, 50]);
        let result = unsafe {
            af_edge_translate_position(core::ptr::null_mut(), pointer, pointer.add(1))
        };
        assert_eq!(result, 48);
        assert_eq!(words, [10, 20, 34, 48, 50]);
    }
}
