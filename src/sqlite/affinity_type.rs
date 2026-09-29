//! SQLite declared-type affinity classification.

use super::expr_affinity::Token;

const AFFINITY_TEXT: u8 = b'a';
const AFFINITY_BLOB: u8 = b'b';
const AFFINITY_NUMERIC: u8 = b'c';
const AFFINITY_INTEGER: u8 = b'd';
const AFFINITY_REAL: u8 = b'e';

/// `sqlite3AffinityType` — original: `FUN_0836e90c` @ `0x0836e90c` (192 bytes).
///
/// Raw `osos.dec` words establish the exact body at
/// `0x0836e90c..0x0836e9cb`; its literal pool occupies
/// `0x0836e9cc..0x0836e9ef`, and the next function starts with `push` at
/// `0x0836e9f0`. Decoding all direct ARM branches finds two inbound plain
/// `bl` calls (`0x080ddcdc` and `0x080e680e`) and zero predicated `bl` calls.
/// SQLite 3.5.9's `sqlite3AffinityType` folds the bounded declared type name
/// through the recovered ASCII upper-to-lower map and recognizes `char`,
/// `clob`, and `text` as text; `blob`; `real`, `floa`, and `doub`; and an
/// `int` suffix as integer. The first matching category wins under the same
/// state gates as retail. Deliberate deviations: the firmware loads its
/// skewed 256-byte table at runtime; this equivalent uses direct ASCII folding.
///
/// # Safety
/// `token` must name a valid SQLite token whose `text` field names at least
/// `token.n_and_dyn >> 1` readable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_affinity_type(token: *const Token) -> u8 {
    let mut affinity = AFFINITY_NUMERIC;
    let mut rolling = 0_u32;
    let text = (*token).text;
    let length = ((*token).n_and_dyn >> 1) as usize;

    for index in 0..length {
        let byte = *text.add(index);
        let lower = if byte >= b'A' && byte <= b'Z' { byte + (b'a' - b'A') } else { byte };
        rolling = (rolling << 8).wrapping_add(lower as u32);

        match rolling {
            0x6368_6172 | 0x636c_6f62 | 0x7465_7874 => affinity = AFFINITY_TEXT,
            0x626c_6f62 if affinity == AFFINITY_NUMERIC || affinity == AFFINITY_REAL => {
                affinity = AFFINITY_BLOB;
            }
            0x7265_616c | 0x666c_6f61 | 0x646f_7562 if affinity == AFFINITY_NUMERIC => {
                affinity = AFFINITY_REAL;
            }
            _ if rolling & 0x00ff_ffff == 0x0069_6e74 => return AFFINITY_INTEGER,
            _ => {}
        }
    }

    affinity
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn classify(type_name: &[u8], n_and_dyn: u32) -> u8 {
        let token = Token { text: type_name.as_ptr(), n_and_dyn };
        sqlite3_affinity_type(core::ptr::addr_of!(token))
    }

    #[test]
    fn classifies_case_insensitive_declared_types() {
        unsafe {
            assert_eq!(classify(b"VARCHAR", 7 << 1), AFFINITY_TEXT);
            assert_eq!(classify(b"cLoB", 4 << 1), AFFINITY_TEXT);
            assert_eq!(classify(b"BLOB", 4 << 1), AFFINITY_BLOB);
            assert_eq!(classify(b"DOUBLE PRECISION", 16 << 1), AFFINITY_REAL);
            assert_eq!(classify(b"UNSIGNED", 8 << 1), AFFINITY_NUMERIC);
        }
    }

    #[test]
    fn integer_match_overrides_an_earlier_affinity_and_respects_length() {
        unsafe {
            assert_eq!(classify(b"FLOATING POINT", 14 << 1), AFFINITY_INTEGER);
            assert_eq!(classify(b"INTX", (3 << 1) | 1), AFFINITY_INTEGER);
            assert_eq!(classify(b"BLOBINT", 4 << 1), AFFINITY_BLOB);
            assert_eq!(classify(b"", 0), AFFINITY_NUMERIC);
        }
    }
}
