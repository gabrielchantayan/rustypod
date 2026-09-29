//! `stream_flags_configure` — original: `FUN_082c5d1c` at load address
//! `0x082c5d1c`.
//!
//! True size: 140 bytes (`0x082c5d1c..0x082c5da7`); `0x082c5da8` begins the
//! next real function. Raw A32 decoding finds zero plain and zero predicated
//! outbound `bl` instructions. It derives the stream's byte flags from bits
//! 0, 1, 2, and 3 of `flags`, selects one of two halfword pairs from the
//! target-width configuration pointer at `stream + 0x40`, and records whether
//! a follow-up byte is required. Deliberate deviation: byte and halfword
//! accesses are explicit unaligned Rust accesses, preserving the firmware
//! layout without imposing a host struct layout.

/// Configures a stream's flag-derived decoding state.
///
/// `stream` has target-width pointer storage at +0x40. The selected
/// configuration halfwords are at +0x20/+0x24 when bit 2 is clear and
/// +0x28/+0x2c when it is set.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_flags_configure(stream: *mut u8, flags: u32) {
    let has_flag_0_or_2 = ((flags & 5) != 0) as u8;
    let has_flag_1 = ((flags >> 1) & 1) as u8;
    let has_flag_2 = ((flags >> 2) & 1) as u8;
    let has_flag_3 = ((flags >> 3) & 1) as u8;

    stream.add(3).write_unaligned(has_flag_0_or_2);
    stream.add(5).write_unaligned(has_flag_1);
    stream.add(4).write_unaligned(has_flag_3);
    stream.add(9).write_unaligned((has_flag_3 == 0) as u8 * 4);
    stream.add(6).write_unaligned(has_flag_2);

    let configuration = stream.add(0x40).cast::<u32>().read_unaligned() as usize as *const u8;
    let selected_pair = if has_flag_2 != 0 { 0x28 } else { 0x20 };
    stream.add(10).cast::<u16>().write_unaligned(
        configuration.add(selected_pair).cast::<u16>().read_unaligned(),
    );
    stream.add(12).cast::<u16>().write_unaligned(
        configuration.add(selected_pair + 4).cast::<u16>().read_unaligned(),
    );
    stream.add(7).write_unaligned((has_flag_1 == 0 && (has_flag_3 != 0 || has_flag_2 == 0)) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const STREAM_SIZE: usize = 0x80;
    const CONFIGURATION_OFFSET: usize = 0x100;

    #[test]
    fn configures_every_flag_combination_and_selects_the_matching_pair() {
        let Some(base) = try_map_u32_slab(hints::SQLITE_STREAM_FLAGS_CONFIGURE, 0x1000) else {
            return;
        };
        let stream = base;
        let configuration = unsafe { base.add(CONFIGURATION_OFFSET) };
        unsafe {
            configuration.add(0x20).cast::<u16>().write_unaligned(0x1020);
            configuration.add(0x24).cast::<u16>().write_unaligned(0x1024);
            configuration.add(0x28).cast::<u16>().write_unaligned(0x1028);
            configuration.add(0x2c).cast::<u16>().write_unaligned(0x102c);
            stream.add(0x40).cast::<u32>().write_unaligned(configuration as usize as u32);

            for flags in 0..16u32 {
                stream.write_bytes(0xa5, STREAM_SIZE);
                stream.add(0x40).cast::<u32>().write_unaligned(configuration as usize as u32);
                stream_flags_configure(stream, flags);

                assert_eq!(stream.add(3).read_unaligned(), ((flags & 5) != 0) as u8);
                assert_eq!(stream.add(4).read_unaligned(), ((flags >> 3) & 1) as u8);
                assert_eq!(stream.add(5).read_unaligned(), ((flags >> 1) & 1) as u8);
                assert_eq!(stream.add(6).read_unaligned(), ((flags >> 2) & 1) as u8);
                assert_eq!(stream.add(9).read_unaligned(), ((flags & 8 == 0) as u8) * 4);
                assert_eq!(stream.add(7).read_unaligned(),
                    ((flags & 2 == 0 && (flags & 8 != 0 || flags & 4 == 0)) as u8));
                let pair = if flags & 4 == 0 { 0x20 } else { 0x28 };
                assert_eq!(stream.add(10).cast::<u16>().read_unaligned(), configuration.add(pair).cast::<u16>().read_unaligned());
                assert_eq!(stream.add(12).cast::<u16>().read_unaligned(), configuration.add(pair + 4).cast::<u16>().read_unaligned());
            }
        }
    }
}
