//! Big-endian bit-cell store with pending-map updates.

/// `big_endian_bit_cell_store_and_mark_pending` — original: `FUN_0804b3a8`
/// @ `0x0804b3a8` (**60 bytes**, 15 ARM words through the tail `b`
/// @ `0x0804b3e0`; the next independently entered function starts at
/// `0x0804b3e4`). Raw A32 decoding finds **two plain `bl` calls, zero
/// predicated `bl` calls, and one direct tail `b` call**.
///
/// Stores `(group, bit_index, mode)` in the selected channel's big-endian
/// bit-cell tables with `pending` as its mode, then applies `pending` to the
/// `0x0836b740` pending map and ORs `payload` into the three maps rooted at
/// `0x39a000e0`. The retail tail call returns its zero result unchanged.
///
/// # Deliberate deviations
///
/// The first helper is the already ported `big_endian_bit_cell_store`. The
/// two map helpers have no `names.yaml` entries, so ARM calls their verified
/// retail addresses; host tests use explicit callback seams. This preserves
/// the original call order and arguments without assigning unverified helper
/// identities.
use super::big_endian_bit_cell_store::big_endian_bit_cell_store;

type RetailPendingMapUpdate = unsafe extern "C" fn(u32, i32) -> u32;

const SET_PENDING_MAP_ADDRESS: usize = 0x0836_b6fc;
const OR_PENDING_MAPS_ADDRESS: usize = 0x0836_b634;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_pending_map() -> RetailPendingMapUpdate {
    unsafe { core::mem::transmute(SET_PENDING_MAP_ADDRESS) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn or_pending_maps() -> RetailPendingMapUpdate {
    unsafe { core::mem::transmute(OR_PENDING_MAPS_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
pub struct BigEndianBitCellStoreAndMarkPendingOps {
    pub set_pending_map: RetailPendingMapUpdate,
    pub or_pending_maps: RetailPendingMapUpdate,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pending_map_update(_: u32, _: i32) -> u32 {
    panic!("big_endian_bit_cell_store_and_mark_pending requires pending-map fixtures")
}

#[cfg(not(target_os = "none"))]
pub static mut BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING_OPS: BigEndianBitCellStoreAndMarkPendingOps = BigEndianBitCellStoreAndMarkPendingOps {
    set_pending_map: missing_pending_map_update,
    or_pending_maps: missing_pending_map_update,
};

/// Performs the retailOS bit-cell store and its two following pending-map updates.
///
/// # Safety
/// The underlying bit-cell table pointers must be valid as required by
/// [`big_endian_bit_cell_store`]. On ARM the two retail map helpers access
/// their fixed global maps.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.big_endian_bit_cell_store_and_mark_pending")]
#[inline(never)]
pub unsafe extern "C" fn big_endian_bit_cell_store_and_mark_pending(
    channel: u32,
    pending: i32,
    payload: i32,
    group: u32,
    bit_index: u32,
    mode: u32,
) -> u32 {
    unsafe { big_endian_bit_cell_store(channel, group, bit_index, mode, pending as u32) };

    #[cfg(target_os = "none")]
    unsafe {
        set_pending_map()(channel, pending);
        return or_pending_maps()(channel, payload);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING_OPS.set_pending_map)(channel, pending);
        return (BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING_OPS.or_pending_maps)(channel, payload);
    }
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab, BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK};
    use crate::util::big_endian_bit_cell_store::{BigEndianBitCellStoreOps, BIG_ENDIAN_BIT_CELL_STORE_OPS};

    static mut TABLES: *mut u32 = core::ptr::null_mut();
    static mut CALLS: [(u32, i32); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn table_getter() -> *mut u32 { unsafe { TABLES } }
    unsafe extern "C" fn clear_pending(_: u32) {}
    unsafe extern "C" fn set_pending(channel: u32, value: i32) -> u32 {
        unsafe { CALLS[CALL_COUNT] = (channel, value); CALL_COUNT += 1; }
        0
    }

    unsafe fn fixture() -> Option<*mut u32> {
        let base = try_map_u32_slab(hints::BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING, 0x200)?.cast::<u32>();
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
    fn stores_reordered_arguments_then_updates_pending_maps_in_order() {
        let _lock = BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return; };
        unsafe {
            TABLES = base;
            CALLS = [(0, 0); 2];
            CALL_COUNT = 0;
            BIG_ENDIAN_BIT_CELL_STORE_OPS = BigEndianBitCellStoreOps { table_getter, clear_first_pending: clear_pending, clear_second_pending: clear_pending };
            BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING_OPS = BigEndianBitCellStoreAndMarkPendingOps { set_pending_map: set_pending, or_pending_maps: set_pending };

            assert_eq!(big_endian_bit_cell_store_and_mark_pending(8, 2, 0x1122_3344, 0x5566_7788, 0xaabb_cc08, 2), 0);
            assert_eq!(*base.add(40 + 16), 0x5566_7788);
            assert_eq!(*base.add(72 + 16), 0xaabb_cc08);
            assert_eq!(*base.add(104 + 16), 2);
            assert_eq!(*base.add(28 + 6), (base.add(136) as usize as u32) | (1 << 16));
            assert_eq!(CALLS, [(8, 2), (8, 0x1122_3344)]);
            assert_eq!(CALL_COUNT, 2);
        }
    }
}
