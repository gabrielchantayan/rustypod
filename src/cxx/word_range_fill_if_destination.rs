//! Word-range fill with nullable destination — original thunk:
//! `thunk_FUN_083e9700` at load address `0x083e96e8`.
//!
//! Raw `osos.dec` establishes the thunk's exact four-byte extent: the A32 word
//! `b 0x083e9700` at `0x083e96e8`; the independently entered implementation
//! resumes at `0x083e96ec`, and `0x083e970c` begins the next function. A full
//! raw A32 decode finds two inbound plain direct `bl` calls (`0x083e66d8` and
//! `0x083e678c`) and zero predicated direct `bl` calls. The thunk has no
//! outbound calls.
//!
//! The branch target writes the current `*fill` word to each of `count`
//! consecutive destination words when `destination` is non-null. It reloads
//! `*fill` for every word, so overlapping source and destination preserve the
//! retail mutation order. Deliberate deviation: Rust implements the verified
//! branch target directly rather than retaining the four-byte tail branch;
//! `destination.wrapping_add` models the target's null pointer increment
//! without forming an invalid Rust pointer offset.

/// Fills `count` target-width words from `fill` when `destination` is non-null.
///
/// # Safety
///
/// A non-null `destination` must identify every writable `u32` reached by the
/// loop. `fill` must be readable for every iteration that reaches a non-null
/// destination. In particular, the retail loop increments a null destination,
/// so a null destination is only safe with `count <= 1`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_range_fill_if_destination(
    mut destination: *mut u32,
    mut count: u32,
    fill: *const u32,
) {
    while count != 0 {
        if !destination.is_null() {
            destination.write(fill.read());
        }
        destination = destination.wrapping_add(1);
        count -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::word_range_fill_if_destination;

    #[test]
    fn fills_each_requested_word() {
        let fill = 0x1357_9bdf;
        let mut words = [0_u32; 5];

        unsafe { word_range_fill_if_destination(words.as_mut_ptr().add(1), 3, &fill) };

        assert_eq!(words, [0, fill, fill, fill, 0]);
    }

    #[test]
    fn accepts_null_destination_for_its_first_iteration() {
        let fill = 0x2468_ace0;

        unsafe { word_range_fill_if_destination(core::ptr::null_mut(), 1, &fill) };
    }

    #[test]
    fn reloads_fill_after_an_overlapping_write() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333];
        let fill = words.as_ptr();

        unsafe { word_range_fill_if_destination(words.as_mut_ptr(), 3, fill) };

        assert_eq!(words, [0x1111_1111; 3]);
    }
}
