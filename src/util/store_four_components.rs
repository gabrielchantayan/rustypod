//! Four-component byte store.

/// `store_four_components` — original: `FUN_0824bf5c` @ 0x0824bf5c (24 bytes
/// exactly, `0x0824bf5c..0x0824bf73`; the separately linked zeroing sibling
/// begins at 0x0824bf74).
///
/// Verified call count: four direct, unconditional `bl` call sites; no
/// predicated `bl` call sites. The leaf loads its fifth argument from the
/// caller stack, writes the low bytes of its four component arguments to
/// `destination[0..4]` in ascending order, and returns `destination` unchanged.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `destination` must be valid and writable for four `u8`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn store_four_components(
    destination: *mut u8,
    first: u8,
    second: u8,
    third: u8,
    fourth: u8,
) -> *mut u8 {
    destination.write(first);
    destination.add(1).write(second);
    destination.add(2).write(third);
    destination.add(3).write(fourth);
    destination
}

#[cfg(test)]
mod tests {
    use super::store_four_components;

    #[test]
    fn stores_components_in_ascending_offsets_and_returns_destination() {
        let mut bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let destination = unsafe { bytes.as_mut_ptr().add(1) };

        let returned = unsafe { store_four_components(destination, 0, 0x7f, 0x80, 0xff) };

        assert_eq!(returned, destination);
        assert_eq!(bytes, [0xaa, 0, 0x7f, 0x80, 0xff, 0xff]);
    }

    #[test]
    fn accepts_an_unaligned_destination() {
        let mut bytes = [0xff; 9];

        unsafe { store_four_components(bytes.as_mut_ptr().add(3), 1, 2, 3, 4) };

        assert_eq!(bytes, [0xff, 0xff, 0xff, 1, 2, 3, 4, 0xff, 0xff]);
    }
}
