//! `rgb8_cursor_write` — original: `FUN_0826056c` @ `0x0826056c` (64 bytes;
//! **5 unconditional `bl` call sites** at `0x0825e6a8`, `0x0825e7a0`,
//! `0x0825f62c`, `0x0825fb24`, and `0x08260044`; no predicated `bl` forms or
//! direct tail branches, binary-scanned by decoding every aligned ARM B/BL word
//! in `osos.dec`.
//!
//! The complete sixteen-word body begins with `ldr r0,[r1]` at `0x0826056c` and
//! ends with `bx lr` at `0x082605a8`; the separately linked next function
//! begins at `0x082605ac`. It emits the three RGB8 components in increasing
//! source order through the destination cursor, advancing that cursor after
//! each byte. Each source byte is loaded only after the previous destination
//! store, so overlapping source and destination ranges retain the ARM-observed
//! order.
//!
//! # Deliberate deviations
//!
//! Volatile accesses prevent LLVM from coalescing or reordering the three
//! load/store pairs; this preserves the observable ordering of the ARM body.

/// Writes one RGB8 triplet through `destination_cursor`.
///
/// # Safety
///
/// `destination_cursor` must point to a writable pointer to at least three
/// writable bytes; `components` must identify three readable bytes. The
/// original has no NULL, alignment, or bounds checks, and the ranges may
/// overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb8_cursor_write(
    _unused: u32,
    destination_cursor: *mut *mut u8,
    components: *const u8,
) {
    for offset in 0..3 {
        let destination = destination_cursor.read_volatile();
        let component = components.add(offset).read_volatile();
        destination_cursor.write_volatile(destination.add(1));
        destination.write_volatile(component);
    }
}

#[cfg(test)]
mod tests {
    use super::rgb8_cursor_write;

    fn reference_rgb8_cursor_write(bytes: &mut [u8], destination: usize, source: usize) -> usize {
        let mut cursor = destination;
        for offset in 0..3 {
            let component = bytes[source + offset];
            cursor += 1;
            bytes[cursor - 1] = component;
        }
        cursor
    }

    #[test]
    fn writes_triplet_and_advances_cursor() {
        let components = [0x12, 0xab, 0xfe];
        let mut destination = [0xde, 0xad, 0xbe, 0xef, 0x55];
        let mut cursor = destination.as_mut_ptr().wrapping_add(1);

        unsafe { rgb8_cursor_write(0xffff_ffff, &mut cursor, components.as_ptr()) };

        assert_eq!(destination, [0xde, 0x12, 0xab, 0xfe, 0x55]);
        assert_eq!(cursor, destination.as_mut_ptr().wrapping_add(4));
    }

    #[test]
    fn matches_ordered_arm_accesses_for_all_triplet_overlaps() {
        for destination in 0..=4 {
            let source = 2;
            let initial = [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76];
            let mut expected = initial;
            let mut actual = initial;
            let expected_cursor = reference_rgb8_cursor_write(&mut expected, destination, source);
            let mut cursor = actual.as_mut_ptr().wrapping_add(destination);

            unsafe { rgb8_cursor_write(0, &mut cursor, actual.as_ptr().wrapping_add(source)) };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(cursor, actual.as_mut_ptr().wrapping_add(expected_cursor));
        }
    }
}
