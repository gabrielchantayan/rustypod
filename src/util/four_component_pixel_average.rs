//! Four-component pixel averaging.

/// average_four_component_pixel — original: `FUN_0824bd98` @ 0x0824bd98
/// (84 verified bytes; Ghidra reports 88 bytes, but the next entry starts at
/// 0x0824bdf0).
///
/// Verified call count: 12 direct, unconditional `bl` call sites; no
/// predicated `bl` call sites. The function loads all four components from
/// both input pixels, computes each component's floor average, then writes the
/// four results in component order. Loading every input before the first write
/// means `dst` may alias either source without changing the sampled values.
///
/// Deliberate deviation: the retail body delegates the four ordered stores to
/// unported `FUN_0824bf5c` @ 0x0824bf5c. This port performs those equivalent
/// stores directly after retaining all source components, avoiding a new
/// dispatch seam for that otherwise trivial helper.
///
/// # Safety
/// `dst` must be valid for four `u8` writes; `first` and `second` must each be
/// valid for four `u8` reads. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn average_four_component_pixel(dst: *mut u8, first: *const u8, second: *const u8) {
    let second_3 = second.add(3).read();
    let first_3 = first.add(3).read();
    let second_2 = second.add(2).read();
    let second_1 = second.add(1).read();
    let first_2 = first.add(2).read();
    let second_0 = second.read();
    let first_1 = first.add(1).read();
    let first_0 = first.read();

    dst.write(((first_0 as u16 + second_0 as u16) >> 1) as u8);
    dst.add(1).write(((first_1 as u16 + second_1 as u16) >> 1) as u8);
    dst.add(2).write(((first_2 as u16 + second_2 as u16) >> 1) as u8);
    dst.add(3).write(((first_3 as u16 + second_3 as u16) >> 1) as u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::average_four_component_pixel;

    fn reference_average(first: [u8; 4], second: [u8; 4]) -> [u8; 4] {
        [
            ((first[0] as u16 + second[0] as u16) >> 1) as u8,
            ((first[1] as u16 + second[1] as u16) >> 1) as u8,
            ((first[2] as u16 + second[2] as u16) >> 1) as u8,
            ((first[3] as u16 + second[3] as u16) >> 1) as u8,
        ]
    }

    #[test]
    fn averages_each_component_with_floor_rounding() {
        let first = [0x00, 0x01, 0xfe, 0xff];
        let second = [0x01, 0x02, 0xff, 0x00];
        let mut destination = [0xaa; 4];

        unsafe {
            average_four_component_pixel(destination.as_mut_ptr(), first.as_ptr(), second.as_ptr());
        }

        assert_eq!(destination, [0x00, 0x01, 0xfe, 0x7f]);
    }

    #[test]
    fn retains_both_inputs_before_an_aliasing_destination_write() {
        let first = [0x11, 0x22, 0x33, 0x44];
        let second = [0xaa, 0xbb, 0xcc, 0xdd];
        let expected = reference_average(first, second);

        let mut second_is_destination = [0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
        unsafe {
            average_four_component_pixel(
                second_is_destination.as_mut_ptr().add(4),
                second_is_destination.as_ptr(),
                second_is_destination.as_ptr().add(4),
            );
        }
        assert_eq!(&second_is_destination[4..], &expected);

        let mut first_is_destination = [0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
        unsafe {
            average_four_component_pixel(
                first_is_destination.as_mut_ptr(),
                first_is_destination.as_ptr(),
                first_is_destination.as_ptr().add(4),
            );
        }
        assert_eq!(&first_is_destination[..4], &expected);
    }

    #[test]
    fn averages_every_possible_component_pair() {
        for first in 0u8..=u8::MAX {
            for second in 0u8..=u8::MAX {
                let source_first = [first; 4];
                let source_second = [second; 4];
                let mut destination = [0; 4];
                unsafe {
                    average_four_component_pixel(
                        destination.as_mut_ptr(),
                        source_first.as_ptr(),
                        source_second.as_ptr(),
                    );
                }
                assert_eq!(destination, [((first as u16 + second as u16) >> 1) as u8; 4]);
            }
        }
    }
}
