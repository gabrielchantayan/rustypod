//! CFF DICT parser initialization.

/// Initialize a CFF DICT parser — `FUN_0809041c` at `0x0809041c`.
/// True extent: `0x0809041c..0x08090444`, 40 bytes (ten ARM words).
/// Raw-word decoding verifies two inbound plain BLs at `0x0809a30c` and
/// `0x0809a41c`, no predicated BLs; one outbound plain BL at `0x08090430`
/// to the zero-fill veneer `0x08037db8` (IRAM `0x2200027c`).
///
/// Clear all 103 target words, point the stack top at the first operand
/// slot (+12), and store the object-code namespace and destination address
/// at +404 and +408. The DICT consumer uses the namespace to select handlers
/// and the destination as their field-write base.
///
/// Deliberate deviation: call the existing Rust memzero_aligned through a
/// volatile function pointer to prevent LLVM builtin substitution; its
/// differing return pointer is unused. Host records retain 32-bit words.
///
/// # Safety
/// `parser` must address 103 writable, aligned u32 words below 4 GiB.
/// `object_address` is a target-width address, stored without dereferencing.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_parser_init(parser: *mut u32, object_code: u32, object_address: u32) {
    let zero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 =
        crate::memzero::memzero_aligned;
    core::ptr::read_volatile(&zero)(parser.cast(), 0x19c);
    parser.add(100).write(parser.add(3) as usize as u32);
    parser.add(101).write(object_code);
    parser.add(102).write(object_address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use crate::testing::hints::CFF_PARSER_INIT;

    #[test]
    fn initialization_clears_stale_state_and_preserves_neighboring_words() {
        unsafe {
            let Some(slab) = try_map_u32_slab(CFF_PARSER_INIT, 0x1000) else {
                note_missing_u32_fixture("ft/cff_parser_init");
                return;
            };
            let words = slab.cast::<u32>();
            let parser = words.add(1);
            for (code, address) in [(0x1000, 0x1234_5678), (0x2000, 0), (0, u32::MAX)] {
                for i in 0..105 {
                    words.add(i).write(0xa5a5_a5a5);
                }
                cff_parser_init(parser, code, address);
                let mut expected = [0u32; 103];
                expected[100] = parser.add(3) as usize as u32;
                expected[101] = code;
                expected[102] = address;
                assert_eq!(core::slice::from_raw_parts(parser, 103), &expected);
                assert_eq!(words.read(), 0xa5a5_a5a5);
                assert_eq!(words.add(104).read(), 0xa5a5_a5a5);
                // The stored target pointer must really designate the first slot.
                assert_eq!(parser.add(100).read() as usize, parser.add(3) as usize);
            }
        }
    }
}
