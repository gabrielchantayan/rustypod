//! Sum the value words of an object's three child records.

/// Object prefix: on ARM the child pointers occupy +4, +8 and +12.
/// Native pointers keep host fixtures valid without truncating addresses.
#[repr(C)]
pub struct ThreeChildValues {
    pub header: u32,
    pub first: *const u32,
    pub second: *const u32,
    pub third: *const u32,
}

/// retailOS `FUN_0816f32c` @ 0x0816f32c: 52 bytes; the next real
/// function starts at 0x0816f360. Raw words verify zero outgoing BLs
/// (plain or predicated), and two plain incoming BLs at 0x081335c8 and
/// 0x0816f3e8, zero predicated incoming BLs.
///
/// If the first child is null, return zero without reading the other
/// slots. Otherwise add each child's word at +4 modulo 2^32. The caller
/// at 0x0816f3d0 compares this sum to vector_size_elem2 of object+0x68.
/// No deliberate target deviations; repr(C) widens pointer slots only on
/// the host. The meanings of the child headers and values remain unknown.
///
/// # Safety
/// `object` must address a readable prefix. When first is non-null, all
/// three children must address at least two aligned, readable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_child_value_sum(object: *const ThreeChildValues) -> u32 {
    let first = (*object).first;
    if first.is_null() {
        return 0;
    }
    let first_value = *first.add(1);
    let second = (*object).second;
    let third = (*object).third;
    let second_value = *second.add(1);
    let third_value = *third.add(1);
    third_value.wrapping_add(second_value.wrapping_add(first_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_first_ignores_invalid_remaining_children() {
        let object = ThreeChildValues {
            header: u32::MAX,
            first: core::ptr::null(),
            second: 1usize as *const u32,
            third: 3usize as *const u32,
        };
        assert_eq!(unsafe { three_child_value_sum(&object) }, 0);
    }

    #[test]
    fn sums_value_words_with_arm_wrapping() {
        for values in [[0, 0, 0], [7, 11, 19], [u32::MAX, 1, 0],
                       [0x8000_0000, 0x8000_0000, 9], [u32::MAX; 3]] {
            let children = [[0x11111111, values[0]], [0x22222222, values[1]],
                            [0x33333333, values[2]]];
            let object = ThreeChildValues {
                header: 0xdeadbeef,
                first: children[0].as_ptr(),
                second: children[1].as_ptr(),
                third: children[2].as_ptr(),
            };
            let expected = (values.iter().map(|&x| x as u64).sum::<u64>() & 0xffff_ffff) as u32;
            assert_eq!(unsafe { three_child_value_sum(&object) }, expected);
            assert_eq!(children[0], [0x11111111, values[0]]);
            assert_eq!(children[1], [0x22222222, values[1]]);
            assert_eq!(children[2], [0x33333333, values[2]]);
        }
    }

    #[test]
    fn aliased_children_are_counted_three_times() {
        let child = [0xdeadbeef, 0x8000_0001];
        let object = ThreeChildValues {
            header: 0,
            first: child.as_ptr(),
            second: child.as_ptr(),
            third: child.as_ptr(),
        };
        assert_eq!(unsafe { three_child_value_sum(&object) }, 0x8000_0003);
    }
}
