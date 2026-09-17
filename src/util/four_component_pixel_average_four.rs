//! Four-input component pixel averaging.

/// average_four_component_pixels — original: `FUN_0824bdf0` @ 0x0824bdf0
/// (172 verified bytes; the next separately linked entry begins at 0x0824be9c).
///
/// Verified call count: six direct, unconditional `bl` call sites; no
/// predicated `bl` call sites. The function retains each component from all
/// four input pixels, computes `(first[i] + second[i] + third[i] + fourth[i])
/// >> 2`, then writes the four floor averages in component order. Retaining
/// every input before the first write means `dst` may alias any source.
///
/// Deliberate deviation: the retail body calls `store_four_components` to
/// write the four computed bytes. This port performs equivalent ordered stores
/// directly, avoiding an unnecessary call.
///
/// # Safety
/// `dst` must be valid for four `u8` writes; each source must be valid for
/// four `u8` reads. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn average_four_component_pixels(
    dst: *mut u8,
    first: *const u8,
    second: *const u8,
    third: *const u8,
    fourth: *const u8,
) {
    let first_3 = first.add(3).read();
    let second_3 = second.add(3).read();
    let third_3 = third.add(3).read();
    let fourth_3 = fourth.add(3).read();
    let first_2 = first.add(2).read();
    let second_2 = second.add(2).read();
    let third_2 = third.add(2).read();
    let fourth_2 = fourth.add(2).read();
    let first_1 = first.add(1).read();
    let second_1 = second.add(1).read();
    let third_1 = third.add(1).read();
    let fourth_1 = fourth.add(1).read();
    let first_0 = first.read();
    let second_0 = second.read();
    let third_0 = third.read();
    let fourth_0 = fourth.read();

    dst.write(((first_0 as u16 + second_0 as u16 + third_0 as u16 + fourth_0 as u16) >> 2) as u8);
    dst.add(1).write(((first_1 as u16 + second_1 as u16 + third_1 as u16 + fourth_1 as u16) >> 2) as u8);
    dst.add(2).write(((first_2 as u16 + second_2 as u16 + third_2 as u16 + fourth_2 as u16) >> 2) as u8);
    dst.add(3).write(((first_3 as u16 + second_3 as u16 + third_3 as u16 + fourth_3 as u16) >> 2) as u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::average_four_component_pixels;

    fn reference_average(inputs: [[u8; 4]; 4]) -> [u8; 4] {
        let mut result = [0; 4];
        for component in 0..4 {
            result[component] = ((inputs[0][component] as u16
                + inputs[1][component] as u16
                + inputs[2][component] as u16
                + inputs[3][component] as u16) >> 2) as u8;
        }
        result
    }

    #[test]
    fn averages_components_with_floor_rounding() {
        let inputs = [
            [0x00, 0x01, 0xfe, 0xff],
            [0x01, 0x02, 0xff, 0x00],
            [0x02, 0x03, 0x00, 0x01],
            [0x03, 0x04, 0x01, 0x02],
        ];
        let mut destination = [0xaa; 4];

        unsafe {
            average_four_component_pixels(
                destination.as_mut_ptr(),
                inputs[0].as_ptr(),
                inputs[1].as_ptr(),
                inputs[2].as_ptr(),
                inputs[3].as_ptr(),
            );
        }

        assert_eq!(destination, [0x01, 0x02, 0x7f, 0x40]);
    }

    #[test]
    fn retains_all_inputs_before_an_aliasing_destination_write() {
        let inputs = [
            [0x11, 0x22, 0x33, 0x44],
            [0x55, 0x66, 0x77, 0x88],
            [0x99, 0xaa, 0xbb, 0xcc],
            [0xdd, 0xee, 0xff, 0x00],
        ];
        let expected = reference_average(inputs);

        for destination_input in 0..4 {
            let mut pixels = inputs;
            unsafe {
                average_four_component_pixels(
                    pixels[destination_input].as_mut_ptr(),
                    pixels[0].as_ptr(),
                    pixels[1].as_ptr(),
                    pixels[2].as_ptr(),
                    pixels[3].as_ptr(),
                );
            }
            assert_eq!(pixels[destination_input], expected);
        }
    }

    #[test]
    fn averages_every_possible_four_input_component_sum() {
        for sum in 0u16..=1020 {
            let first = sum.min(255) as u8;
            let second = (sum - first as u16).min(255) as u8;
            let third = (sum - first as u16 - second as u16).min(255) as u8;
            let fourth = (sum - first as u16 - second as u16 - third as u16) as u8;
            let mut destination = [0; 4];

            unsafe {
                average_four_component_pixels(
                    destination.as_mut_ptr(),
                    [first; 4].as_ptr(),
                    [second; 4].as_ptr(),
                    [third; 4].as_ptr(),
                    [fourth; 4].as_ptr(),
                );
            }

            assert_eq!(destination, [(sum >> 2) as u8; 4]);
        }
    }
}
