//! One-time initialization of two shared slot tables.
//!
//! Original: FUN_08090c48 @ 0x08090c48. True extent is 108 bytes:
//! 96 instruction bytes followed by three literals; next function begins
//! at 0x08090cb4. Two plain outbound BLs to the memzero_aligned IRAM
//! veneer @ 0x08037db8, no predicated BLs. Two plain inbound BLs
//! @ 0x081c1024 and 0x081c178c, no predicated inbound BLs.
//!
//! If the flag byte is nonzero, return 2 without touching either table.
//! Otherwise clear each 72-byte table, set its count to zero and capacity
//! to 16, publish flag = 1, and return 0. Consumer @ 0x0807ba80 drains
//! both tables while their +0x40 counts are positive. Globals are the flag
//! @ 0x08a0e180 and adjacent tables @ 0x08b1c858 / 0x08b1c8a0.
//!
//! Deviations: native host storage replaces fixed RAM globals. A volatile
//! function-pointer read preserves calls to the existing zero-fill port
//! rather than allowing LLVM to substitute a libc builtin. No locking or
//! validation is added; callers retain responsibility for serialization.

use crate::libc::memzero::memzero_aligned;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotTable {
    slots: [u32; 16],
    count: u32,
    capacity: u32,
}

#[cfg(not(target_os = "none"))]
static mut INITIALIZED: u8 = 0;
#[cfg(not(target_os = "none"))]
static mut TABLES: [SlotTable; 2] = [SlotTable {
    slots: [0; 16], count: 0, capacity: 0,
}; 2];

unsafe fn initialize_tables(initialized: *mut u8, tables: *mut SlotTable) -> u32 {
    if initialized.read() != 0 {
        return 2;
    }
    let zero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = memzero_aligned;
    let zero = core::ptr::read_volatile(&zero);
    zero(tables.cast(), 0x48);
    core::ptr::addr_of_mut!((*tables).count).write(0);
    core::ptr::addr_of_mut!((*tables).capacity).write(16);
    let second = tables.add(1);
    zero(second.cast(), 0x48);
    core::ptr::addr_of_mut!((*second).count).write(0);
    core::ptr::addr_of_mut!((*second).capacity).write(16);
    initialized.write(1);
    0
}

/// Initialize the shared tables, or return 2 if already initialized.
/// Requires exclusive access to the firmware's shared table state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn paired_slot_tables_initialize() -> u32 {
    #[cfg(target_os = "none")]
    let (flag, tables) = (0x08a0_e180 as *mut u8, 0x08b1_c858 as *mut SlotTable);
    #[cfg(not(target_os = "none"))]
    let (flag, tables) = (core::ptr::addr_of_mut!(INITIALIZED),
        core::ptr::addr_of_mut!(TABLES).cast::<SlotTable>());
    initialize_tables(flag, tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIRTY: SlotTable = SlotTable {
        slots: [0xa5a5_5a5a; 16], count: 0xffff_ffff, capacity: 0x1234_5678,
    };
    const EMPTY: SlotTable = SlotTable { slots: [0; 16], count: 0, capacity: 16 };

    #[test]
    fn initializes_both_tables_without_touching_neighbors_and_preserves_later_updates() {
        let mut flag = [0xa5, 0, 0x5a];
        let mut tables = [DIRTY; 4];
        unsafe {
            assert_eq!(initialize_tables(flag.as_mut_ptr().add(1), tables.as_mut_ptr().add(1)), 0);
        }
        assert_eq!(flag, [0xa5, 1, 0x5a]);
        assert_eq!(tables, [DIRTY, EMPTY, EMPTY, DIRTY]);
        tables[1].slots[15] = 99;
        tables[2].count = 7;
        let before = tables;
        unsafe {
            assert_eq!(initialize_tables(flag.as_mut_ptr().add(1), tables.as_mut_ptr().add(1)), 2);
        }
        assert_eq!(tables, before);
        assert_eq!(flag, [0xa5, 1, 0x5a]);
    }

    #[test]
    fn every_nonzero_flag_skips_all_table_access() {
        for value in 1..=255u8 {
            let mut flag = value;
            assert_eq!(unsafe { initialize_tables(&mut flag, core::ptr::null_mut()) }, 2);
            assert_eq!(flag, value);
        }
    }
}
