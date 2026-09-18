//! `ui_three_item_next_index` — original: `FUN_08144830` @ **0x08144830**
//! (44 bytes, `0x08144830..0x08144858`; the distinct next function begins at
//! `0x0814485c`).
//!
//! Raw ARM loads the byte at `owner + 0xa4`, then maps the three valid item
//! indexes in a cycle: 1 becomes 2, 2 becomes 3, and 3 becomes 1. Every other
//! byte produces zero. A complete aligned ARM B/BL-immediate decode of
//! `osos.dec` finds four direct inbound plain, unconditional `bl` calls
//! (0x081456d0, 0x08145768, 0x0814589c, and 0x08145af4), with no predicated
//! `bl` calls. The body is a leaf and has no outgoing calls.
//!
//! Deliberate deviations: none. The enclosing owner layout is unrecovered, so
//! this port accesses only the verified byte field rather than naming a
//! speculative object type.

/// Returns the next index in the owner's three-item cycle, or zero for an
/// index outside that cycle.
///
/// # Safety
///
/// `owner` must point to a readable object containing a byte at offset 0xa4.
/// Stock ARM has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.ui_three_item_next_index"]
pub unsafe extern "C" fn ui_three_item_next_index(owner: *const u8) -> u32 {
    let item_index = *owner.add(0xa4);
    if item_index == 1 {
        2
    } else if item_index == 2 {
        3
    } else if item_index == 3 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_only_the_three_valid_indexes() {
        let mut owner = [0u8; 0xa5];
        for (index, expected) in [(0, 0), (1, 2), (2, 3), (3, 1), (4, 0), (255, 0)] {
            owner[0xa4] = index;
            assert_eq!(unsafe { ui_three_item_next_index(owner.as_ptr()) }, expected);
        }
    }
}
