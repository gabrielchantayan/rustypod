//! Advance the start of a two-word byte range while preserving its end.

/// byte_range_offset_copy — retailOS `FUN_083d7360` @ 0x083d7360 (40 bytes).
///
/// Raw words establish the exact A32 extent from `push {r2,r3,lr}` at
/// 0x083d7360 through `pop {r3,ip,pc}` at 0x083d7384; the following `ldr`
/// at 0x083d7388 begins the next real function. There is one unconditional
/// outgoing `bl` to the verified two-word copy helper at 0x083dc0cc and no
/// predicated `bl` instructions. Full-image A32 branch decoding finds two
/// inbound unconditional `bl` sites (0x083d8fdc and 0x083d99c0) and zero
/// predicated sites. The body snapshots a byte range, adds `byte_count` to
/// its start, then copies the resulting pair to `destination`.
///
/// Deliberate deviation: the retail stack-local pair and its helper call are
/// represented directly, preserving the source snapshot before either output
/// store; volatile output accesses prevent LLVM from replacing the ordered
/// two-word copy with a bulk intrinsic.
///
/// # Safety
/// `destination` and `source` must each be valid for two aligned `u32`
/// accesses. They may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.byte_range_offset_copy")]
#[inline(never)]
pub unsafe extern "C" fn byte_range_offset_copy(
    destination: *mut u32,
    source: *const u32,
    byte_count: u32,
) {
    let range = [source.read_volatile().wrapping_add(byte_count), source.add(1).read_volatile()];
    destination.write_volatile(range[0]);
    destination.add(1).write_volatile(range[1]);
}

#[cfg(test)]
mod tests {
    use super::byte_range_offset_copy;

    #[test]
    fn advances_start_and_preserves_end() {
        let source = [0xffff_fff0, 0x0800_4000];
        let mut destination = [0, 0];

        unsafe { byte_range_offset_copy(destination.as_mut_ptr(), source.as_ptr(), 0x30) };

        assert_eq!(destination, [0x20, 0x0800_4000]);
    }

    #[test]
    fn snapshots_both_source_words_before_storing_an_overlapping_destination() {
        let mut words = [0x1000, 0x2000, 0x3000];

        unsafe { byte_range_offset_copy(words.as_mut_ptr().add(1), words.as_ptr(), 0x40) };

        assert_eq!(words, [0x1000, 0x1040, 0x2000]);
    }
}
