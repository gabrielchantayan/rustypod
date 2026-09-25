/// pair_range_fill_after_cursor — original: `thunk_FUN_083e9510` @
/// `0x083e94e4` (4-byte branch thunk; its target's loop body occupies
/// `0x083e94e8..0x083e951c`, bounded by `push {r4-r6,lr}` at `0x083e951c`).
/// Two inbound direct calls are unconditional plain `bl`; there are no
/// predicated `bl` calls.
///
/// The entry's branch lands on the loop update at `0x083e9510`, so it first
/// advances `destination` by one eight-byte pair. It then fills each of
/// `count` successive pairs from `fill`: bytes 0..4 and 6..7 are stored,
/// while destination byte 5 remains unchanged. It reloads `fill` for every
/// pair and returns the cursor one pair beyond the final store. A NULL cursor
/// is only checked after that initial advance, matching the raw A32 control
/// flow.
///
/// Deliberate deviation: Rust implements the thunk target directly rather
/// than retaining its internal branch. Volatile byte-granular accesses preserve
/// the observed load/store order against LLVM loop-idiom substitution.
///
/// # Safety
///
/// `destination.wrapping_add(1)` must be writable for `count` pairs unless it
/// is NULL. In that case `fill` must be readable as one aligned pair. The
/// original is forward-only and has no overlap protection.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_range_fill_after_cursor(
    mut destination: *mut [u32; 2],
    mut count: u32,
    fill: *const [u32; 2],
) -> *mut [u32; 2] {
    destination = destination.wrapping_add(1);
    while count != 0 {
        if !destination.is_null() {
            let fill_bytes = fill.cast::<u8>();
            let destination_bytes = destination.cast::<u8>();
            destination_bytes.cast::<u32>().write_volatile(fill_bytes.cast::<u32>().read_volatile());
            destination_bytes.add(4).write_volatile(fill_bytes.add(4).read_volatile());
            destination_bytes.add(6).cast::<u16>().write_volatile(
                fill_bytes.add(6).cast::<u16>().read_volatile(),
            );
        }
        count -= 1;
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::pair_range_fill_after_cursor;

    #[test]
    fn fills_pairs_after_initial_cursor_and_returns_past_range() {
        let fill = [0x0102_0304u32, 0x1112_1314];
        let mut pairs = [
            [0xaaaa_aaaa, 0xbbbb_bbbb],
            [0xcccc_cccc, 0xdddd_dddd],
            [0xeeee_eeee, 0xffff_ffff],
            [0x1234_5678, 0x9abc_def0],
        ];
        let cursor = pairs.as_mut_ptr();

        let returned = unsafe { pair_range_fill_after_cursor(cursor, 2, &fill) };

        assert_eq!(pairs[0], [0xaaaa_aaaa, 0xbbbb_bbbb], "entry skips cursor");
        assert_eq!(pairs[1], [0x0102_0304, 0x1112_dd14]);
        assert_eq!(pairs[2], [0x0102_0304, 0x1112_ff14]);
        assert_eq!(returned, unsafe { cursor.add(3) });
    }

    #[test]
    fn zero_count_advances_once_without_reading_fill() {
        let cursor = 0usize as *mut [u32; 2];

        let returned = unsafe {
            pair_range_fill_after_cursor(cursor, 0, core::ptr::null())
        };

        assert_eq!(returned, 8usize as *mut [u32; 2]);
    }
}
