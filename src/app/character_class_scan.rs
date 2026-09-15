//! `parser_scan_to_class_boundary` — original: `FUN_080e8eb0` @
//! `0x080e8eb0` (52 bytes, `0x080e8eb0..0x080e8ee4`; the next real function
//! starts at `0x080e8ee4`).
//!
//! Reads the parser's target-width character-class table at offset four and
//! advances over bytes whose class word has bit `0x10` set, stopping before a
//! byte without that bit or one also carrying bit `0x08`. The returned pointer
//! is therefore the first class boundary; the input is otherwise untouched.
//!
//! **5 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified from every ARM B/BL word in `osos.dec`: 0x0807bf8c, 0x0807bfb8,
//! 0x0807bfd8, 0x0807c0b0, and 0x0807c0dc.
//!
//! Deliberate deviation: Rust exposes the parser as raw target-layout storage,
//! rather than inventing a parser type from its single observed field.

/// Scans from `characters` to the next parser character-class boundary.
///
/// # Safety
///
/// `parser` must have an aligned raw `u32` character-class-table pointer at
/// offset four. That table must contain 256 aligned `u16` entries, and
/// `characters` must remain readable through the returned byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.parser_scan_to_class_boundary")]
#[inline(never)]
pub unsafe extern "C" fn parser_scan_to_class_boundary(
    parser: *const u8,
    mut characters: *const u8,
) -> *const u8 {
    let class_table = unsafe { parser.add(4).cast::<u32>().read() as usize as *const u16 };

    loop {
        let character = unsafe { characters.read_volatile() };
        let class = unsafe { class_table.add(character as usize).read_volatile() };
        if class & 0x10 == 0 || class & 0x08 != 0 {
            return characters;
        }
        characters = unsafe { characters.add(1) };
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
        try_map_u32_slab(hints::PARSER_SCAN_TO_CLASS_BOUNDARY, FIXTURE_LEN)
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
            Some(parser_scan_to_class_boundary(base, characters).offset_from(characters) as usize)
        }
    }

    #[test]
    fn stops_at_first_non_scannable_character() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[b' ' as usize] = 0x10;
        let Some(offset) = (unsafe { scan(&classes, b"  word") }) else {
            assert!(note_missing_u32_fixture("app/character_class_scan"));
            return;
        };
        assert_eq!(offset, 2);
    }

    #[test]
    fn delimiter_bit_overrides_the_scan_bit() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[b'a' as usize] = 0x10;
        classes[b':' as usize] = 0x18;
        let Some(offset) = (unsafe { scan(&classes, b"aa:tail") }) else {
            assert!(note_missing_u32_fixture("app/character_class_scan"));
            return;
        };
        assert_eq!(offset, 2);
    }

    #[test]
    fn indexes_the_full_unsigned_byte_range() {
        let _guard = LOCK.lock();
        let mut classes = [0u16; 256];
        classes[0xff] = 0x10;
        let Some(offset) = (unsafe { scan(&classes, &[0xff, 0]) }) else {
            assert!(note_missing_u32_fixture("app/character_class_scan"));
            return;
        };
        assert_eq!(offset, 1);
    }
}
