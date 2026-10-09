//! `controller_event_class` — FUN_080e2054 @ 0x080e2054.
//! True size: 212 bytes, extent 0x080e2054..0x080e2128; the next function
//! begins with an independent PUSH. Zero outgoing plain or predicated BLs;
//! two incoming plain BLs (0x08172570, 0x08172634), zero predicated BLs.
//!
//! Select the controller input-mask class: events 0x8237 and 0x823f return
//! one; every other u32 returns zero. Retail subtracts 0x8214, unsigned-checks
//! the 44-entry branch table, and selects one of two constant returns.
//! Deliberate deviation: replace that table with two equality comparisons;
//! there are no behavioral deviations, memory accesses, or callee seams.

/// Returns the input-mask class for a retail controller event code.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn controller_event_class(event: u32) -> u32 {
    u32::from(event == 0x8237 || event == 0x823f)
}

#[cfg(test)]
mod tests {
    use super::controller_event_class;

    #[test]
    fn every_table_entry_and_unsigned_boundaries() {
        // Destinations decoded independently from the retail branch table.
        const CLASS: [u32; 44] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        for (index, expected) in CLASS.into_iter().enumerate() {
            assert_eq!(controller_event_class(0x8214 + index as u32), expected);
        }
        for event in [0, 1, 0x8213, 0x8240, 0x18237, 0x1823f,
                      0x8000_8237, 0x8000_823f, u32::MAX] {
            assert_eq!(controller_event_class(event), 0, "event {event:#x}");
        }
    }
}
