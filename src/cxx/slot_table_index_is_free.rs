//! `slot_table_index_is_free` — original: `FUN_083b4a9c` @ `0x083b4a9c` (44
//! bytes; true extent `0x083b4a9c..0x083b4ac8`).
//!
//! Raw `osos.dec` words are `e5902008 e1520001 9a000005 e5900000 e7900101
//! e3a01001 e1d10000 13a00001 112fff1e e3a00000 e12fff1e`; `0x083b4ac8`
//! begins the next separately linked function. The body has zero outbound
//! plain BL and zero outbound predicated BL instructions. Independent
//! whole-image branch decoding finds two inbound unconditional plain BL sites
//! (`0x0824ce78` and `0x0824fba0`) and zero predicated inbound BL sites.
//!
//! The function rejects an index outside the slot table's capacity, then
//! returns one precisely when the selected 32-bit slot word has a clear low
//! bit. The target layout keeps the slot-array pointer and capacity at +0x00
//! and +0x08 as 32-bit words. Deliberate deviations: none; the target build
//! uses the verified original A32 body, while the host build exposes the same
//! target-width layout for tests.

#[repr(C)]
pub struct SlotTable {
    slots: u32,
    _reserved: u32,
    capacity: u32,
}

#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", unsafe(naked))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.slot_table_index_is_free")]
pub unsafe extern "C" fn slot_table_index_is_free() {
    core::arch::naked_asm!(
        "ldr r2,[r0,#0x8]",
        "cmp r2,r1",
        "bls 2f",
        "ldr r0,[r0,#0x0]",
        "ldr r0,[r0,r1,lsl #0x2]",
        "mov r1,#0x1",
        "bics r0,r1,r0",
        "movne r0,#0x1",
        "bxne lr",
        "2:",
        "mov r0,#0x0",
        "bx lr",
    );
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn slot_table_index_is_free(table: *const SlotTable, index: u32) -> u32 {
    if index >= (*table).capacity {
        return 0;
    }

    let slots = (*table).slots as usize as *const u32;
    if slots.add(index as usize).read() & 1 == 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::{slot_table_index_is_free, SlotTable};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn accepts_clear_low_bits_only_within_capacity() {
        const WORDS: usize = 8;
        let Some(slab) = try_map_u32_slab(hints::SLOT_TABLE_INDEX_IS_FREE, WORDS * 4) else {
            return;
        };

        unsafe {
            let slots = slab.cast::<u32>();
            slots.write(0);
            slots.add(1).write(0xfeed_beef);
            slots.add(2).write(2);
            slots.add(3).write(1);
            slots.add(4).write(0xffff_fffe);
            slots.add(5).write(0xffff_ffff);
            slots.add(6).write(0xdead_beef);
            let table = SlotTable {
                slots: slab as usize as u32,
                _reserved: 0xa5a5_a5a5,
                capacity: 6,
            };

            for (index, expected) in [(0, 1), (1, 0), (2, 1), (3, 0), (4, 1), (5, 0), (6, 0), (u32::MAX, 0)] {
                assert_eq!(slot_table_index_is_free(&table, index), expected, "index={index}");
            }
        }
    }
}
