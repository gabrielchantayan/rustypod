//! Four-byte color setter for the resource-resolved string view.

/// string_view_set_color — `FUN_08290fbc` @ `0x08290fbc`, 36 bytes.
///
/// Raw extent: 0x08290fbc..0x08290fe0, ending in `bx lr`; the next
/// function starts with `push {r4,r5,r6,lr}`. Whole-image ARM decoding
/// finds two incoming plain BL calls (0x0816d398 and 0x0816d3a4), zero
/// predicated incoming BL calls, and no outgoing BL calls. Copies four
/// color bytes, interleaving each load and store, to view +0xf4..+0xf7.
/// The callers supply black or 0xdd gray with a final 0xff byte. Returns
/// view +0xf4, preserving the first store's r0 writeback omitted by Ghidra.
/// Volatile byte accesses preserve the original order even for overlapping
/// source/destination and prevent a widened copy. No semantic deviations.
///
/// # Safety
/// `view` must permit writing bytes +0xf4..+0xf7; `color` must permit
/// reading four bytes. Overlap is allowed; there are no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_view_set_color(view: *mut u8, color: *const u8) -> *mut u8 {
    unsafe {
        let destination = view.add(0xf4);
        destination.write_volatile(color.read_volatile());
        destination.add(1).write_volatile(color.add(1).read_volatile());
        destination.add(2).write_volatile(color.add(2).read_volatile());
        destination.add(3).write_volatile(color.add(3).read_volatile());
        destination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_unaligned_colors_without_touching_surrounding_bytes() {
        for color in [[0, 0, 0, 0xff], [0xdd, 0xdd, 0xdd, 0xff], [1, 0x80, 0xfe, 0]] {
            for alignment in 0..4 {
                let mut storage = [0xa5; 0x100];
                let mut source = [0x5a; 8];
                source[alignment..alignment + 4].copy_from_slice(&color);
                let mut expected = storage;
                expected[alignment + 0xf4..alignment + 0xf8].copy_from_slice(&color);
                unsafe {
                    let view = storage.as_mut_ptr().add(alignment);
                    assert_eq!(string_view_set_color(view, source.as_ptr().add(alignment)), view.add(0xf4));
                }
                assert_eq!(storage, expected);
                assert_eq!(&source[alignment..alignment + 4], &color);
            }
        }
    }

    #[test]
    fn overlapping_color_observes_each_prior_store() {
        for displacement in -3isize..=3 {
            let mut storage = [0u8; 0x100];
            for (index, byte) in storage.iter_mut().enumerate() {
                *byte = index as u8;
            }
            let mut expected = storage;
            let source_offset = (0xf4isize + displacement) as usize;
            for index in 0..4 {
                expected[0xf4 + index] = expected[source_offset + index];
            }
            unsafe {
                let view = storage.as_mut_ptr();
                assert_eq!(string_view_set_color(view, view.add(source_offset)), view.add(0xf4));
            }
            assert_eq!(storage, expected, "source displacement {displacement}");
        }
    }
}
