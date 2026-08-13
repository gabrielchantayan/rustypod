//! Display indexed-resource flags.
//!
//! `display_index_flags` — original: `FUN_0800483c` @ `0x0800483c`
//! (40 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/0800483c_FUN_0800483c.c`;
//! raw ARM is `0x0800483c..0x08004864`.
//!
//! The display-command builders at `0x080048fc` and `0x08004a20` pass two
//! resource selectors through this helper before either looking a selector up
//! in a display resource table or retaining it directly. Each selector below
//! the 28-entry table limit contributes an independent hardware command flag:
//! the first contributes `0x1000`, and the second contributes `0x0800`.

/// Number of entries in each display resource table.
pub const DISPLAY_RESOURCE_TABLE_ENTRIES: u32 = 0x1c;
/// Command flag for a first selector that names a display-table entry.
pub const DISPLAY_FIRST_RESOURCE_INDEXED: u32 = 0x1000;
/// Command flag for a second selector that names a display-table entry.
pub const DISPLAY_SECOND_RESOURCE_INDEXED: u32 = 0x0800;

/// display_index_flags — original: `FUN_0800483c` @ `0x0800483c` (40 bytes).
///
/// Returns the bitwise combination describing which of the two display
/// resource selectors is an index into its 28-entry resource table. Comparisons
/// are unsigned, exactly as the ARM `bcc` paths require: values at or above
/// `0x1c`, including words with bit 31 set, contribute no flag.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn display_index_flags(first_resource: u32, second_resource: u32) -> u32 {
    let mut flags = 0;
    if first_resource < DISPLAY_RESOURCE_TABLE_ENTRIES {
        flags |= DISPLAY_FIRST_RESOURCE_INDEXED;
    }
    if second_resource < DISPLAY_RESOURCE_TABLE_ENTRIES {
        flags |= DISPLAY_SECOND_RESOURCE_INDEXED;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_selector_contributes_its_flag_independently_at_the_table_boundary() {
        assert_eq!(display_index_flags(0x1b, 0x1b), 0x1800);
        assert_eq!(display_index_flags(0x1b, 0x1c), 0x1000);
        assert_eq!(display_index_flags(0x1c, 0x1b), 0x0800);
        assert_eq!(display_index_flags(0x1c, 0x1c), 0);
    }

    #[test]
    fn high_unsigned_words_are_not_resource_indices() {
        assert_eq!(display_index_flags(u32::MAX, 0), DISPLAY_SECOND_RESOURCE_INDEXED);
        assert_eq!(display_index_flags(0, u32::MAX), DISPLAY_FIRST_RESOURCE_INDEXED);
    }
}
