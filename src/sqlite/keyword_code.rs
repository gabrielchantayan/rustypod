//! Classify an SQLite identifier as a parser keyword.
//!
//! `keyword_code` — original: `FUN_082d7740` at load address `0x082d7740`.
//! Raw A32 decoding establishes a 192-byte extent, `0x082d7740..0x082d7800`:
//! 172 bytes of instructions followed by five literal words; the next `push`
//! starts an independent function. The body has two plain unconditional `bl`
//! instructions (`__rt_sdiv` @ `0x08031568` and `str_nicmp` @ `0x08384fa0`),
//! and no predicated `bl`; a whole-image direct-call scan finds its two plain
//! inbound calls at `0x082d4adc` and `0x0837aa8c`.
//!
//! It folds the first and final input bytes through SQLite's ASCII table,
//! hashes them with the length modulo 127, then follows the generated keyword
//! chain until a same-length case-insensitive entry matches. The captured
//! table is the 1,250-byte decrypted-image range `0x08908290..0x08908772`,
//! which is the runtime literals' `+0xaed8` image location. Deliberate
//! deviation: Rust's `% 127` replaces the ADS quotient/remainder call; this
//! non-negative hash has the identical remainder.

use super::stricmp::{str_nicmp, UPPER_TO_LOWER};

const TABLE: &[u8; 1250] = include_bytes!("keyword_code_data.bin");
const TEXT: usize = 0x000;
const HASH: usize = 0x20e;
const NEXT: usize = 0x28d;
const LENGTH: usize = 0x301;
const OFFSET: usize = 0x376;
const CODE: usize = 0x45e;
const KEYWORD_COUNT: usize = 116;
const UNKNOWN_TOKEN: u8 = 0x17;

#[inline(always)]
fn little_u16(at: usize) -> usize {
    TABLE[at] as usize | ((TABLE[at + 1] as usize) << 8)
}

/// `sqlite3KeywordCode`: return the parser token for `text`, or `TK_ID`.
///
/// # Safety
/// `text` must point to `len` readable bytes. As in retailOS, it is only read
/// when `len >= 2`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn keyword_code(text: *const u8, len: i32) -> u8 {
    if len < 2 {
        return UNKNOWN_TOKEN;
    }

    let len = len as usize;
    let first = UPPER_TO_LOWER[text.read_volatile() as usize] as usize;
    let last = UPPER_TO_LOWER[text.add(len - 1).read_volatile() as usize] as usize;
    let hash = ((last * 3) ^ (first << 2) ^ len) % 127;
    let mut index = TABLE[HASH + hash] as i32 - 1;

    while index >= 0 {
        let candidate = index as usize;
        if TABLE[LENGTH + candidate] as usize == len {
            let keyword = TABLE.as_ptr().add(TEXT + little_u16(OFFSET + candidate * 2));
            if str_nicmp(keyword, text, len as i32) == 0 {
                return TABLE[CODE + candidate];
            }
        }
        index = TABLE[NEXT + candidate] as i32 - 1;
        if index as usize >= KEYWORD_COUNT {
            break;
        }
    }

    UNKNOWN_TOKEN
}

#[cfg(test)]
mod tests {
    use super::keyword_code;

    #[test]
    fn recognizes_select_with_ascii_case_folding() {
        unsafe {
            assert_eq!(keyword_code(b"SELECT".as_ptr(), 6), 110);
            assert_eq!(keyword_code(b"sElEcT".as_ptr(), 6), 110);
        }
    }

    #[test]
    fn rejects_short_and_non_keyword_identifiers() {
        unsafe {
            assert_eq!(keyword_code(b"x".as_ptr(), 1), 0x17);
            assert_eq!(keyword_code(b"SELECTED".as_ptr(), 8), 0x17);
            assert_eq!(keyword_code(b"iPod".as_ptr(), 4), 0x17);
        }
    }
}
