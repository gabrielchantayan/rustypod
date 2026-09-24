//! `parser_scan_to_token_boundary` — original: `FUN_080a1ee8` @
//! `0x080a1ee8` (80 bytes, `0x080a1ee8..0x080a1f38`; the next real function
//! starts at `0x080a1f38`).
//!
//! Scans a token using the parser's target-width 256-entry character-class
//! table at offset four. Ordinary bytes advance while any of class bits
//! `0x0307` are set. A byte carrying bit `0x20` uses the following byte's
//! bit `0x08` to select a one- or two-byte advance. The scan stops at the
//! first ordinary byte whose class lacks every `0x0307` bit.
//!
//! **3 direct `bl` call sites, all unconditional; no predicated `bl`**,
//! verified from every ARM B/BL word in `osos.dec`: 0x0807bfc8, 0x0807c070,
//! and 0x0807c0a0. The 80-byte body contains no outgoing `bl` calls.
//!
//! Deliberate deviation: Rust represents the partially recovered parser as
//! raw target-layout storage rather than inventing a parser type from its
//! one observed field.

/// Scans from `characters` to the next parser token boundary.
///
/// # Safety
///
/// `parser` must have an aligned raw `u32` character-class-table pointer at
/// offset four. That table must contain 256 aligned `u16` entries, and
/// `characters` must remain readable through the returned byte plus one more
/// byte after every character whose class has bit `0x20` set.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.parser_scan_to_token_boundary")]
#[inline(never)]
pub unsafe extern "C" fn parser_scan_to_token_boundary(
    parser: *const u8,
    mut characters: *const u8,
) -> *const u8 {
    let class_table = unsafe { parser.add(4).cast::<u32>().read() as usize as *const u16 };

    loop {
        let character = unsafe { characters.read_volatile() };
        let class = unsafe { class_table.add(character as usize).read_volatile() };
        if class & 0x20 != 0 {
            let next_character = unsafe { characters.add(1).read_volatile() };
            let next_class = unsafe { class_table.add(next_character as usize).read_volatile() };
            characters = unsafe { characters.add(if next_class & 0x08 == 0 { 2 } else { 1 }) };
        } else if class & 0x0307 != 0 {
            characters = unsafe { characters.add(1) };
        } else {
            return characters;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const TABLE_OFFSET: usize = 0x100;
    const INPUT_OFFSET: usize = 0x400;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PARSER_SCAN_TO_TOKEN_BOUNDARY, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn scan(class_table: &[u16; 256], input: &[u8]) -> Option<usize> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let table = base.add(TABLE_OFFSET).cast::<u16>();
            for (index, class) in class_table.iter().enumerate() {
                table.add(index).write(*class);
            }
            base.add(4).cast::<u32>().write(table as usize as u32);
            let characters = base.add(INPUT_OFFSET);
            core::ptr::copy_nonoverlapping(input.as_ptr(), characters, input.len());
            Some(parser_scan_to_token_boundary(base, characters).offset_from(characters) as usize)
        }
    }

    #[test]
    fn scans_each_ordinary_acceptance_bit() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[b'a' as usize] = 0x0001;
        classes[b'b' as usize] = 0x0002;
        classes[b'c' as usize] = 0x0004;
        classes[b'd' as usize] = 0x0100;
        classes[b'e' as usize] = 0x0200;
        let Some(offset) = (unsafe { scan(&classes, b"abcde:") }) else {
            assert!(note_missing_u32_fixture("app/parser_scan_to_token_boundary"));
            return;
        };
        assert_eq!(offset, 5);
    }

    #[test]
    fn stops_when_no_ordinary_acceptance_bit_is_set() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[b'a' as usize] = 0x0001;
        let Some(offset) = (unsafe { scan(&classes, b"a:") }) else {
            assert!(note_missing_u32_fixture("app/parser_scan_to_token_boundary"));
            return;
        };
        assert_eq!(offset, 1);
    }

    #[test]
    fn advances_two_bytes_for_a_lead_class_before_non_delimiter() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[0x80] = 0x0020;
        classes[b'x' as usize] = 0x0001;
        let Some(offset) = (unsafe { scan(&classes, &[0x80, b'x', b':'] ) }) else {
            assert!(note_missing_u32_fixture("app/parser_scan_to_token_boundary"));
            return;
        };
        assert_eq!(offset, 2);
    }

    #[test]
    fn advances_one_byte_for_a_lead_class_before_delimiter() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[0x80] = 0x0020;
        classes[b':' as usize] = 0x0008;
        let Some(offset) = (unsafe { scan(&classes, &[0x80, b':'] ) }) else {
            assert!(note_missing_u32_fixture("app/parser_scan_to_token_boundary"));
            return;
        };
        assert_eq!(offset, 1);
    }
}
