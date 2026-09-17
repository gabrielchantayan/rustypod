//! predicate_for_kind — original: `FUN_082432c8` @ **0x082432c8** (88 bytes,
//! `0x082432c8..0x0824331f`; the following literal pool ends at 0x08243334,
//! and the next separately linked function begins at 0x08243338).
//!
//! A complete aligned A32 B/BL-immediate decode of `osos.dec` finds four direct
//! inbound call sites, all unconditional plain `bl` (0x082435f0, 0x08243674,
//! 0x08243790, and 0x0824385c); there are no predicated `bl` calls. The jump
//! table maps kinds 2 through 6 to five runtime predicate-object addresses;
//! kinds 0, 1, and all values above 6 select the default object.
//!
//! Deliberate deviations: none. The returned addresses are runtime-initialized
//! objects outside `osos.dec`, but the selector only returns their literal
//! addresses and never dereferences them.

/// Selects the runtime predicate object for `kind`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.predicate_for_kind"]
pub extern "C" fn predicate_for_kind(kind: u32) -> u32 {
    match kind {
        2 => 0x08ac_6cf0,
        3 => 0x08ac_6d14,
        4 => 0x08ac_6d20,
        5 => 0x08ac_6d08,
        6 => 0x089c_c940,
        _ => 0x08ac_6cfc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_jump_table_case() {
        assert_eq!(predicate_for_kind(2), 0x08ac_6cf0);
        assert_eq!(predicate_for_kind(3), 0x08ac_6d14);
        assert_eq!(predicate_for_kind(4), 0x08ac_6d20);
        assert_eq!(predicate_for_kind(5), 0x08ac_6d08);
        assert_eq!(predicate_for_kind(6), 0x089c_c940);
    }

    #[test]
    fn maps_default_and_out_of_range_kinds_to_the_default_object() {
        for kind in [0, 1, 7, u32::MAX] {
            assert_eq!(predicate_for_kind(kind), 0x08ac_6cfc, "kind {kind}");
        }
    }
}
