//! Big-endian bit-cell table update.

/// big_endian_bit_cell_store — original: `FUN_0806436c` @ 0x0806436c
/// (**176 bytes exactly**, 44 ARM words from `push {r2-r9,sl,lr}` through
/// `pop {r2-r9,sl,pc}`; the next independently linked function begins at
/// 0x0806441c). Raw decoding finds three inbound direct calls, all
/// unconditional `bl` at 0x0804b3c4, 0x0813b0f4, and 0x0814f72c; no
/// predicated `bl` or direct tail `b` callers exist.
///
/// Converts `bit_index` to the physical bit within its big-endian word, clears
/// two retailOS pending-bit maps for `channel`, then writes the payload, logical
/// bit index, and group value into their corresponding channel-row cells. It
/// sets that physical bit in the fourth table only when `mode == 2`. Deviations:
/// the target calls the already ported `big_endian_word_bit_index` rather than
/// its retailOS address; it has the identical verified contract.
///
/// # Safety
/// The retailOS table getter and its four target-width table-pointer words must
/// be valid. Each selected row and cell pointer must be writable.
use core::ptr::{read_volatile, write_volatile};

use super::big_endian_word_bit_index::big_endian_word_bit_index;

type RetailTableGetter = unsafe extern "C" fn() -> *mut u32;
type RetailChannelUpdate = unsafe extern "C" fn(u32);

const TABLE_GETTER_ADDRESS: usize = 0x0805_1268;
const CLEAR_FIRST_PENDING_ADDRESS: usize = 0x0836_b578;
const CLEAR_SECOND_PENDING_ADDRESS: usize = 0x0836_b5fc;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn table_getter() -> RetailTableGetter {
    unsafe { core::mem::transmute(TABLE_GETTER_ADDRESS) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_first_pending() -> RetailChannelUpdate {
    unsafe { core::mem::transmute(CLEAR_FIRST_PENDING_ADDRESS) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_second_pending() -> RetailChannelUpdate {
    unsafe { core::mem::transmute(CLEAR_SECOND_PENDING_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
pub struct BigEndianBitCellStoreOps {
    pub table_getter: RetailTableGetter,
    pub clear_first_pending: RetailChannelUpdate,
    pub clear_second_pending: RetailChannelUpdate,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_table_getter() -> *mut u32 {
    panic!("big_endian_bit_cell_store requires a table getter fixture")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_channel_update(_: u32) {
    panic!("big_endian_bit_cell_store requires pending-map fixtures")
}

#[cfg(not(target_os = "none"))]
pub static mut BIG_ENDIAN_BIT_CELL_STORE_OPS: BigEndianBitCellStoreOps = BigEndianBitCellStoreOps {
    table_getter: missing_table_getter,
    clear_first_pending: missing_channel_update,
    clear_second_pending: missing_channel_update,
};

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.big_endian_bit_cell_store")]
#[inline(never)]
pub unsafe extern "C" fn big_endian_bit_cell_store(
    channel: u32,
    payload: u32,
    bit_index: u32,
    group: u32,
    mode: u32,
) {
    #[cfg(target_os = "none")]
    let tables = unsafe { table_getter()() };
    #[cfg(not(target_os = "none"))]
    let tables = unsafe { (BIG_ENDIAN_BIT_CELL_STORE_OPS.table_getter)() };

    let row = 6 - (channel >> 5);
    let mut physical_bit = 0;
    unsafe { big_endian_word_bit_index(channel, &mut physical_bit) };

    #[cfg(target_os = "none")]
    unsafe {
        clear_first_pending()(channel);
        clear_second_pending()(channel);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (BIG_ENDIAN_BIT_CELL_STORE_OPS.clear_first_pending)(channel);
        (BIG_ENDIAN_BIT_CELL_STORE_OPS.clear_second_pending)(channel);
    }

    unsafe {
        for (table_index, value) in [(0, payload), (1, bit_index), (2, group)] {
            let rows = read_volatile(tables.add(table_index)) as *mut u32;
            let cells = read_volatile(rows.add(row as usize)) as *mut u32;
            write_volatile(cells.add(physical_bit as usize), value);
        }
        let flag_rows = read_volatile(tables.add(3)) as *mut u32;
        let flags = flag_rows.add(row as usize);
        let mask = 1u32 << physical_bit;
        let old_flags = read_volatile(flags);
        write_volatile(flags, if mode == 2 { old_flags | mask } else { old_flags & !mask });
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab, BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK};
    static mut TABLES: *mut u32 = core::ptr::null_mut();
    static mut CLEARED: [u32; 2] = [u32::MAX; 2];

    unsafe extern "C" fn table_getter() -> *mut u32 { unsafe { TABLES } }
    unsafe extern "C" fn clear_first(channel: u32) { unsafe { CLEARED[0] = channel; } }
    unsafe extern "C" fn clear_second(channel: u32) { unsafe { CLEARED[1] = channel; } }

    unsafe fn fixture() -> Option<*mut u32> {
        let base = try_map_u32_slab(hints::BIG_ENDIAN_BIT_CELL_STORE, 0x200)?.cast::<u32>();
        unsafe {
            base.cast::<u8>().write_bytes(0, 0x200);
            for table in 0..4 {
                let rows = base.add(4 + table * 8);
                let cells = base.add(40 + table * 32);
                base.add(table).write(rows as usize as u32);
                for row in 0..7 { rows.add(row).write(cells as usize as u32); }
            }
        }
        Some(base)
    }

    #[test]
    fn stores_each_value_in_the_big_endian_cell_and_sets_mode_two_flag() {
        let _lock = BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return; };
        unsafe {
            TABLES = base;
            CLEARED = [u32::MAX; 2];
            BIG_ENDIAN_BIT_CELL_STORE_OPS = BigEndianBitCellStoreOps { table_getter, clear_first_pending: clear_first, clear_second_pending: clear_second };
            big_endian_bit_cell_store(8, 0x1122_3344, 0xaabb_cc08, 0x5566_7788, 2);
            assert_eq!(CLEARED, [8, 8]);
            assert_eq!(*base.add(40 + 16), 0x1122_3344);
            assert_eq!(*base.add(72 + 16), 0xaabb_cc08);
            assert_eq!(*base.add(104 + 16), 0x5566_7788);
            assert_eq!(*base.add(28 + 6), 1 << 16);
        }
    }

    #[test]
    fn clears_only_the_selected_flag_for_non_two_modes() {
        let _lock = BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return; };
        unsafe {
            TABLES = base;
            *base.add(28 + 5) = (1 << 24) | (1 << 3);
            BIG_ENDIAN_BIT_CELL_STORE_OPS = BigEndianBitCellStoreOps { table_getter, clear_first_pending: clear_first, clear_second_pending: clear_second };
            big_endian_bit_cell_store(32, 7, 31, 9, 1);
            assert_eq!(*base.add(28 + 5), 1 << 3);
            assert_eq!(*base.add(40 + 24), 7);
        }
    }
}
