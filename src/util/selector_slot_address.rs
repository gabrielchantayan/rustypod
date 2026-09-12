//! `selector_slot_address` — original: `FUN_08223aa8` @ `0x08223aa8`
//! (168 bytes; `0x08223aa8..0x08223b4c`).
//!
//! # Algorithm
//!
//! A computed branch table maps a selector to one of the caller-owned object's
//! word-aligned slots. Selectors 3/4 and 5/6 intentionally share slots;
//! selectors 1, 11 through 14, and every value greater than 16 use the
//! default slot. The returned address uses wrapping 32-bit addition exactly as
//! the ARM `add` instructions do.
//!
//! Deliberate deviations: none.
//!
//! Raw osos.dec decoding finds exactly eight direct inbound `bl` call sites,
//! all unconditional (at `0x0822390c`, `0x0822392c`, `0x08223984`,
//! `0x082239c8`, `0x08223a20`, `0x08223a44`, `0x08223a64`, and `0x08223a8c`);
//! there are no predicated calls, plain tail branches, or aligned data-word
//! references to this leaf.

/// selector_slot_address — original: `FUN_08223aa8` @ `0x08223aa8`
/// (168 bytes).
///
/// Returns the 32-bit address of the slot selected from an object base.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.selector_slot_address")]
pub extern "C" fn selector_slot_address(base: u32, selector: u32) -> u32 {
    let offset = match selector {
        0 => 8,
        2 => 16,
        3 | 4 => 20,
        5 | 6 => 24,
        7 => 28,
        8 => 40,
        9 => 44,
        10 => 48,
        15 => 32,
        16 => 36,
        _ => 12,
    };

    base.wrapping_add(offset)
}

#[cfg(test)]
mod tests {
    use super::selector_slot_address;

    fn arm_reference(base: u32, selector: u32) -> u32 {
        let offset = if selector > 16 {
            12
        } else {
            [8, 12, 16, 20, 20, 24, 24, 28, 40, 44, 48, 12, 12, 12, 12, 32, 36]
                [selector as usize]
        };
        base.wrapping_add(offset)
    }

    #[test]
    fn maps_every_computed_branch_table_entry() {
        let expected_offsets = [8, 12, 16, 20, 20, 24, 24, 28, 40, 44, 48, 12, 12, 12, 12, 32, 36];

        for (selector, offset) in expected_offsets.into_iter().enumerate() {
            assert_eq!(selector_slot_address(0x0898_ff00, selector as u32),
                       0x0898_ff00 + offset,
                       "selector={selector}");
            assert_eq!(selector_slot_address(0x0898_ff00, selector as u32),
                       arm_reference(0x0898_ff00, selector as u32));
        }
    }

    #[test]
    fn defaults_for_out_of_range_and_default_table_selectors() {
        for selector in [1, 11, 12, 13, 14, 17, u32::MAX] {
            assert_eq!(selector_slot_address(0x0898_ff00, selector), 0x0898_ff0c);
            assert_eq!(selector_slot_address(0x0898_ff00, selector),
                       arm_reference(0x0898_ff00, selector));
        }
    }

    #[test]
    fn preserves_wrapping_address_addition() {
        for base in [0, 1, 0xffff_ffff, 0xffff_fff8] {
            for selector in [0, 3, 8, 15, 16, 17, u32::MAX] {
                assert_eq!(selector_slot_address(base, selector), arm_reference(base, selector),
                           "base={base:#010x}, selector={selector}");
            }
        }
    }
}
