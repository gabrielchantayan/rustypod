//! Quote-state handling for the character-driven markup parser.
//!
//! `parser_quoted_character` — `FUN_0818c85c` @ `0x0818c85c`, 144 bytes
//! (`0x0818c85c..0x0818c8ec`, next function starts with push at 0x0818c8ec).
//! Raw ARM words contain zero plain BL and two predicated BLNE calls, both
//! to `string_object_append_code_unit` @ 0x082768e8.
//!
//! Outside quotes, only a double quote is consumed and sets bit 16. Inside
//! quotes, an unescaped quote clears bit 16 and returns 1; other characters
//! are appended when output is non-NULL and return 2. Backslashes are also
//! appended and set bit 17, making the next character literal; that character
//! clears bit 17 before append. Unrelated flags remain untouched. Return 0
//! means the caller must handle the character outside a quoted region.
//!
//! No algorithm deviations. The existing StringObject allocator boundary
//! remains unported, so output allocation must be wired before hooking this.

use crate::cxx::string_object::{string_object_append_code_unit, StringObject};

const IN_QUOTES: u32 = 1 << 16;
const ESCAPED: u32 = 1 << 17;

/// Only the parser prefix through the flags word is accessed here.
#[repr(C)]
pub struct ParserQuoteState {
    pub opaque_words: [u32; 10],
    pub flags: u32,
}

/// Process a full-width input value; only the append callee truncates to u16.
/// `state` must be writable; non-NULL `output` must be a valid StringObject.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_quoted_character(
    state: *mut ParserQuoteState, character: u32, output: *mut StringObject,
) -> u32 {
    let flags = core::ptr::addr_of_mut!((*state).flags);
    let initial = flags.read();
    if initial & IN_QUOTES == 0 {
        if character == b'"' as u32 {
            flags.write(initial | IN_QUOTES);
            return 2;
        }
        return 0;
    }
    if initial & ESCAPED != 0 {
        flags.write(initial & !ESCAPED);
        if !output.is_null() {
            string_object_append_code_unit(output, character);
        }
    } else {
        if character == b'"' as u32 {
            flags.write(initial & !IN_QUOTES);
            return 1;
        }
        if !output.is_null() {
            string_object_append_code_unit(output, character);
        }
        if character == b'\\' as u32 {
            flags.write(flags.read() | ESCAPED);
        }
    }
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_preserve_unrelated_flags_and_full_width_comparisons() {
        let unrelated = 0xa5a4_1234 & !(IN_QUOTES | ESCAPED);
        for mode in [0, IN_QUOTES, ESCAPED, IN_QUOTES | ESCAPED] {
            for character in [0, 34, 92, 65, 0x10022, 0x1005c, u32::MAX] {
                let mut state = ParserQuoteState { opaque_words: [0xdead_beef; 10], flags: unrelated | mode };
                let (expected_result, expected_mode) = if mode & IN_QUOTES == 0 {
                    if character == 34 { (2, mode | IN_QUOTES) } else { (0, mode) }
                } else if mode & ESCAPED != 0 {
                    (2, mode & !ESCAPED)
                } else if character == 34 {
                    (1, mode & !IN_QUOTES)
                } else if character == 92 {
                    (2, mode | ESCAPED)
                } else {
                    (2, mode)
                };
                assert_eq!(unsafe { parser_quoted_character(&mut state, character, core::ptr::null_mut()) }, expected_result);
                assert_eq!(state.flags, unrelated | expected_mode);
                assert_eq!(state.opaque_words, [0xdead_beef; 10]);
            }
        }
    }

    #[test]
    fn escaped_quote_does_not_close_and_double_backslash_does_not_rearm() {
        let mut state = ParserQuoteState { opaque_words: [0; 10], flags: 0 };
        let input = [34, 92, 34, 92, 92, 34, 65];
        let results = [2, 2, 2, 2, 2, 1, 0];
        let modes = [IN_QUOTES, IN_QUOTES | ESCAPED, IN_QUOTES, IN_QUOTES | ESCAPED, IN_QUOTES, 0, 0];
        for i in 0..input.len() {
            assert_eq!(unsafe { parser_quoted_character(&mut state, input[i], core::ptr::null_mut()) }, results[i]);
            assert_eq!(state.flags, modes[i]);
        }
    }

    #[test]
    fn output_keeps_escape_characters_but_omits_quote_delimiters() {
        use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};
        unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, _: u32) -> *mut u8 {
            assert!(size <= 64);
            (*this).payload
        }
        unsafe extern "C" fn clear(_: *mut StringObject) { panic!("unexpected clear"); }
        struct Restore(StringObjectAssignCstrOps);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; } }
        }
        unsafe {
            let _restore = Restore(core::ptr::read(core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS)));
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            let mut bytes = [0u8; 64];
            let mut out = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
            let mut state = ParserQuoteState { opaque_words: [0; 10], flags: 0 };
            for (character, result) in [(34, 2), (65, 2), (92, 2), (34, 2), (0x10042, 2), (34, 1), (90, 0)] {
                assert_eq!(parser_quoted_character(&mut state, character, &mut out), result);
            }
            assert_eq!(&bytes[..5], b"A\\\"B\0");
            assert_eq!(state.flags, 0);
        }
    }
}
