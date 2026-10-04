use super::string_object::utf8_next_codepoint;

/// Populate a codepoint-to-group byte map — original `FUN_0820b2c4` at
/// 0x0820b2c4. True extent: 120 bytes through 0x0820b33c (116 bytes of
/// instructions and the 0x1ff literal at 0x0820b338). Raw ARM verifies
/// one unconditional BL at 0x0820b2f4 to utf8_next_codepoint, zero predicated
/// BLs; Ghidra's reported two call sites are not present in the bytes.
///
/// Walk a NULL-terminated target-width array of UTF-8 string pointers,
/// writing (first_group + string_index) modulo 256 at embedded_table[codepoint]
/// until the decoder returns zero. Later groups overwrite earlier entries;
/// all other bytes are preserved. Then set header words to 0, 511, and the
/// address of the embedded table at +12. No deliberate deviations.
///
/// # Safety
/// `map` must be word-aligned, writable through +12 plus every decoded
/// codepoint. `groups` points to a readable u32 array-address word; the array
/// and its strings must be readable through their terminators, including the
/// decoder's unchecked multibyte reads. Stored pointers use the target's u32 ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codepoint_group_map_populate(
    map: *mut u32,
    first_group: u32,
    groups: *const u32,
) {
    let mut index = 0usize;
    loop {
        let array = *groups as usize as *const u32;
        let string = *array.add(index);
        if string == 0 { break; }
        let mut cursor = string as usize as *const u8;
        let label = first_group.wrapping_add(index as u32) as u8;
        loop {
            let codepoint = utf8_next_codepoint(&mut cursor);
            if codepoint == 0 { break; }
            map.cast::<u8>().add(12 + codepoint as usize).write(label);
        }
        index += 1;
    }
    map.write(0);
    map.add(1).write(511);
    map.add(2).write(map.cast::<u8>().add(12) as usize as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    #[test]
    fn preserves_unmapped_bytes_overwrites_groups_and_stops_on_decoded_zero() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CODEPOINT_GROUP_MAP, 0x12000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("codepoint_group_map"));
            return;
        };
        unsafe {
            let map = slab.cast::<u32>();
            let array = slab.add(0x11000).cast::<u32>();
            let strings: [&[u8]; 5] = [
                b"A\xc3\xa9\xef\xbf\xbf\0", b"\0", b"AB\0",
                b"C\xf0\x80\x80D\0", b"E\xc0\x80F\0",
            ];
            for (index, text) in strings.iter().enumerate() {
                let dst = slab.add(0x11100 + index * 32);
                core::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
                array.add(index).write(dst as usize as u32);
            }
            array.add(strings.len()).write(0);
            let groups = array as usize as u32;
            slab.write_bytes(0xa5, 0x1000c);
            codepoint_group_map_populate(map, 0x1ff, &groups);
            assert_eq!(core::slice::from_raw_parts(map, 3),
                &[0, 511, slab.add(12) as usize as u32]);
            let mut expected = std::vec![0xa5u8; 65536];
            for (cp, label) in [(65, 1), (66, 1), (67, 2), (69, 3), (233, 255), (65535, 255)] {
                expected[cp] = label;
            }
            assert_eq!(core::slice::from_raw_parts(slab.add(12), 65536), expected);
            // Empty input still initializes the header without clearing the table.
            array.write(0);
            map.write(99);
            map.add(1).write(99);
            map.add(2).write(99);
            codepoint_group_map_populate(map, 42, &groups);
            assert_eq!(core::slice::from_raw_parts(map, 3),
                &[0, 511, slab.add(12) as usize as u32]);
            assert_eq!(core::slice::from_raw_parts(slab.add(12), 65536), expected);
        }
    }
}
