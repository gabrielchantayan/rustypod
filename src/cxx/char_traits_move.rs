/// char_traits_move — original: `FUN_082a78b0` @ 0x082a78b0.
/// True size: 20 bytes, ending before the real function at 0x082a78c4.
/// Two inbound plain BLs, zero inbound predicated BLs; one outbound plain
/// BL, zero outbound predicated BLs. Raw words:
/// e92d4010 e1a04000 ebf64150 e1a00004 e8bd8010.
///
/// Move `count` bytes with overlap allowed and return the original destination.
/// Stream-buffer callers at 0x083d9048 and 0x083d95f8 preserve trailing
/// characters using this char_traits::move operation. The call targets
/// 0x08037e00: `ldr pc,[pc,#-4]` with literal 0x220000d4, the IRAM mirror
/// of osos memmove at 0x080000d4. Deliberate deviation: call the existing
/// Rust memmove directly instead of the firmware veneer; behavior unchanged.
///
/// # Safety
/// Source and destination must be valid for `count` bytes, with the padding
/// needed by the existing memmove's aligned funnel reads for misaligned sources.
/// Overlap is permitted. Zero count does not dereference either pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.char_traits_move")]
#[inline(never)]
pub unsafe extern "C" fn char_traits_move(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    crate::libc::memmove::memmove(dst, src, count);
    dst
}

#[cfg(test)]
mod tests {
    use super::char_traits_move;

    #[test]
    fn overlapping_and_disjoint_ranges_match_snapshot_copy() {
        // Word-aligned backing storage and spare words around every source.
        for src_offset in 8..16 {
            for dst_offset in 8..24 {
                for count in 0..=64 {
                    let mut words = [0u32; 32];
                    let bytes = unsafe {
                        core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 128)
                    };
                    for (index, byte) in bytes.iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
                    }
                    let snapshot: [u8; 128] = bytes.try_into().unwrap();
                    let mut expected = snapshot;
                    expected[dst_offset..dst_offset + count]
                        .copy_from_slice(&snapshot[src_offset..src_offset + count]);
                    let dst = unsafe { bytes.as_mut_ptr().add(dst_offset) };
                    let src = unsafe { bytes.as_ptr().add(src_offset) };
                    assert_eq!(unsafe { char_traits_move(dst, src, count) }, dst);
                    assert_eq!(bytes, expected, "src={src_offset} dst={dst_offset} count={count}");
                }
            }
        }
    }

    #[test]
    fn identical_ranges_preserve_all_bytes() {
        let mut bytes = [0x00, 0x80, 0xff, 0x37, 0x00, 0xa5, 0x01, 0xfe];
        let expected = bytes;
        let dst = bytes.as_mut_ptr();
        assert_eq!(unsafe { char_traits_move(dst, dst, bytes.len()) }, dst);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn zero_count_accepts_null_source_and_preserves_destination() {
        let mut byte = 0xa5u8;
        let dst = &mut byte as *mut u8;
        assert_eq!(unsafe { char_traits_move(dst, core::ptr::null(), 0) }, dst);
        assert_eq!(byte, 0xa5);
        assert!(unsafe { char_traits_move(core::ptr::null_mut(), core::ptr::null(), 0) }.is_null());
    }
}
