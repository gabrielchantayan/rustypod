//! Selected-entry state used by the retailOS FreeType-facing loaders.
//!
//! The callers at 0x08041ae4 and 0x08041d48 use the word at +4 as an
//! index passed to their selected-entry lookup helper.  When that lookup
//! cannot be used, they reset this index and take their unselected path.

/// The two-word prefix whose selected-entry index is reset by
/// [`ft_clear_selected_entry_index`].
///
/// The word at +0 is deliberately opaque: the target never reads or writes
/// it.  It is retained to pin the +4 offset on ARM and to make the function's
/// non-interference contract explicit.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtSelectionPrefix {
    pub leading_word: u32,
    pub selected_entry_index: u32,
}

const _: () = assert!(core::mem::size_of::<FtSelectionPrefix>() == 8);
const _: () = assert!(core::mem::offset_of!(FtSelectionPrefix, selected_entry_index) == 4);

/// The ARM `mvneq r0, #49` at 0x080413e8: `0xffff_ffce` (`-50`).
pub const FT_SELECTION_INVALID_ARGUMENT: i32 = -50;

/// ft_clear_selected_entry_index — original: `FUN_080413dc` @ 0x080413dc
/// (24 bytes).
///
/// Returns [`FT_SELECTION_INVALID_ARGUMENT`] without dereferencing a null
/// prefix.  Otherwise it writes zero to `selected_entry_index` (+4) and
/// returns zero; `leading_word` and all bytes beyond this two-word prefix are
/// untouched.  This is the exact `cmp`/conditional-store shape recovered
/// from ARM and used by the selection-fallback paths at 0x08041ae4 and
/// 0x08041d48.
///
/// # Safety
/// When non-null, `selection` must point to a writable [`FtSelectionPrefix`]
/// prefix.  The caller owns any surrounding record.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_clear_selected_entry_index(
    selection: *mut FtSelectionPrefix,
) -> i32 {
    if selection.is_null() {
        FT_SELECTION_INVALID_ARGUMENT
    } else {
        (*selection).selected_entry_index = 0;
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(C)]
    struct SelectionRecord {
        prefix: FtSelectionPrefix,
        trailing_words: [u32; 2],
    }

    unsafe fn reference_clear_selected_entry_index(selection: *mut u32) -> i32 {
        if selection.is_null() {
            FT_SELECTION_INVALID_ARGUMENT
        } else {
            *selection.add(1) = 0;
            0
        }
    }

    #[test]
    fn null_returns_the_exact_arm_failure_code() {
        let actual = unsafe { ft_clear_selected_entry_index(core::ptr::null_mut()) };
        let expected = unsafe { reference_clear_selected_entry_index(core::ptr::null_mut()) };
        assert_eq!(actual, expected);
        assert_eq!(actual as u32, 0xffff_ffce);
    }

    #[test]
    fn non_null_clears_only_the_selected_entry_index() {
        let mut actual = SelectionRecord {
            prefix: FtSelectionPrefix {
                leading_word: 0x1122_3344,
                selected_entry_index: 0xaabb_ccdd,
            },
            trailing_words: [0x5566_7788, 0x99aa_bbcc],
        };
        let mut expected = SelectionRecord {
            prefix: actual.prefix,
            trailing_words: actual.trailing_words,
        };

        let actual_return = unsafe { ft_clear_selected_entry_index(&mut actual.prefix) };
        let expected_return = unsafe {
            reference_clear_selected_entry_index((&mut expected.prefix as *mut FtSelectionPrefix).cast())
        };

        assert_eq!(actual_return, expected_return);
        assert_eq!(actual.prefix, expected.prefix);
        assert_eq!(actual.trailing_words, expected.trailing_words);
        assert_eq!(actual.prefix.leading_word, 0x1122_3344);
        assert_eq!(actual.prefix.selected_entry_index, 0);
    }
}
