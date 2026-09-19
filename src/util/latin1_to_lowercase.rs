//! `latin1_to_lowercase` — original: `FUN_08077284` @ 0x08077284.
//!
//! True extent: 124 instruction bytes, 0x08077284..0x08077300; the next function begins
//! at 0x08077308 after the two-word literal pool. Whole-image A32 decoding
//! finds three inbound plain `bl` calls (0x080693f0, 0x08069414, 0x0806945c)
//! and one predicated `blne` call (0x08069470). It lazily fills a 223-entry
//! u16 Latin-1 lowercase table: ASCII A..Z and Latin-1 C0..DE except D7 gain
//! 0x20; all other entries retain their code. Inputs above DE return unchanged.
//!
//! Deliberate deviation: the retail table at 0x08a774e8 is initialized on its
//! first call behind byte 1 of 0x089cb1a8. This port uses an immutable,
//! compile-time equivalent table because the table and its initialization flag
//! are not observable through this function's ABI.

const TABLE_LEN: usize = 0xdf;

const fn make_lowercase_table() -> [u16; TABLE_LEN] {
    let mut table = [0u16; TABLE_LEN];
    let mut code = 0;
    while code < TABLE_LEN {
        table[code] = if (code >= b'A' as usize && code <= b'Z' as usize)
            || (code >= 0xc0 && code <= 0xde && code != 0xd7) {
            (code + 0x20) as u16
        } else {
            code as u16
        };
        code += 1;
    }
    table
}

static LOWERCASE_TABLE: [u16; TABLE_LEN] = make_lowercase_table();

/// Converts a Latin-1 code point to lowercase through the retailOS mapping.
/// Inputs above 0xde are not table-indexed and pass through unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn latin1_to_lowercase(code: u32) -> u32 {
    if code <= 0xde {
        LOWERCASE_TABLE[code as usize] as u32
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(code: u32) -> u32 {
        if code <= 0xde
            && ((b'A' as u32..=b'Z' as u32).contains(&code)
                || (0xc0..=0xde).contains(&code) && code != 0xd7)
        {
            code + 0x20
        } else {
            code
        }
    }

    #[test]
    fn maps_every_table_entry_like_retailos() {
        for code in 0..=0xde {
            assert_eq!(latin1_to_lowercase(code), reference(code), "code {code:#x}");
        }
    }

    #[test]
    fn preserves_latin1_exceptions_and_out_of_range_words() {
        for code in [0xd7, 0xdf, 0x100, 0x0000_0141, u32::MAX] {
            assert_eq!(latin1_to_lowercase(code), code);
        }
    }
}
