//! `service_handler_slot_secondary_value_set` — original: `FUN_08193f10` @
//! `0x08193f10` (20 bytes; `0x08193f10..0x08193f24`).
//!
//! # Algorithm
//!
//! Reject signed slots of three or greater, then store `value` in word `+0x14`
//! of the selected 0x20-byte service-handler record. Negative slots are
//! deliberately accepted: ARM's `blge` is a signed comparison, so they select
//! records before the supplied base. A rejected slot takes the predicated fatal
//! path through `heap_panic` and never returns.
//!
//! Deliberate deviations: none.
//!
//! Raw `osos.dec` words establish the exact 20-byte code extent ending in `bx
//! lr`; the next real function begins at `0x08193f24`. There is one outbound
//! predicated BL (`blge 0x08030f44`, `heap_panic`) and no outbound plain BL
//! calls. Full-image A32 decoding finds three inbound plain unconditional BL
//! call sites and no predicated inbound BL forms.

/// Stores the selected service-handler record's secondary value at byte offset
/// `0x14`.
///
/// `slot_table` must be valid at the signed `slot` selected record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_slot_secondary_value_set")]
pub unsafe extern "C" fn service_handler_slot_secondary_value_set(slot_table: *mut u32, slot: i32, value: u32) {
    if slot >= 3 {
        crate::heap::veneers::heap_panic();
    }
    *slot_table.offset((slot as isize) << 3).add(5) = value;
}

#[cfg(test)]
mod tests {
    use super::service_handler_slot_secondary_value_set;

    #[test]
    fn stores_only_the_selected_record_secondary_value() {
        let mut table = [0xfeed_faceu32; 32];
        let base = unsafe { table.as_mut_ptr().add(8) };

        unsafe {
            service_handler_slot_secondary_value_set(base, -1, 0x1111_1111);
            service_handler_slot_secondary_value_set(base, 0, 0x2222_2222);
            service_handler_slot_secondary_value_set(base, 2, 0x3333_3333);
        }

        assert_eq!(table[5], 0x1111_1111);
        assert_eq!(table[13], 0x2222_2222);
        assert_eq!(table[29], 0x3333_3333);
        assert_eq!(table[6], 0xfeed_face);
        assert_eq!(table[12], 0xfeed_face);
        assert_eq!(table[28], 0xfeed_face);
        assert_eq!(table[30], 0xfeed_face);
    }
}
