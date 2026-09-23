//! `transfer_slot_reconcile` — original: `FUN_081e3950` @ `0x081e3950`
//! (152 bytes; true extent `0x081e3950..0x081e39e7`).
//!
//! # Verified calls and algorithm
//!
//! Raw A32 words establish two outbound plain unconditional `bl` calls, at
//! `0x081e39a8` (`FUN_081e39e8`) and `0x081e39cc`
//! ([`mov_chain_table_next`]); no predicated `bl` forms occur. The following
//! `push` at `0x081e39e8` begins the next real function. The selected 0x50-byte
//! transfer slot accepts status bytes 0 or 1 only. If its current source differs
//! from its saved source, mode 0 resolves the current source through the MOV
//! chain table, mode 1 uses the saved source directly, and either path calls the
//! unported transfer advance routine with the slot state at +0x1240.
//!
//! # Deliberate deviations
//!
//! `mov_chain_table_next`'s status is deliberately ignored: stock invokes it
//! and forwards its output word regardless of the return value. The unported
//! `FUN_081e39e8` remains a target-address seam; host tests install a recording
//! implementation for its verified four-argument ABI.

use crate::mov::chain_table::{mov_chain_table_next, MovChainTable};

type TransferSlotAdvance = unsafe extern "C" fn(*mut u8, u32, u32, *mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe fn transfer_slot_advance(context: *mut u8, source: u32, resolved_source: u32, state: *mut u8) -> u32 {
    const TRANSFER_SLOT_ADVANCE_ADDRESS: usize = 0x081e_39e8;
    let advance: TransferSlotAdvance = unsafe { core::mem::transmute(TRANSFER_SLOT_ADVANCE_ADDRESS) };
    unsafe { advance(context, source, resolved_source, state) }
}

#[cfg(all(not(target_os = "none"), test))]
static mut HOST_TRANSFER_SLOT_ADVANCE: Option<TransferSlotAdvance> = None;

#[cfg(not(target_os = "none"))]
unsafe fn transfer_slot_advance(context: *mut u8, source: u32, resolved_source: u32, state: *mut u8) -> u32 {
    #[cfg(test)]
    if let Some(advance) = unsafe { HOST_TRANSFER_SLOT_ADVANCE } {
        return unsafe { advance(context, source, resolved_source, state) };
    }
    let _ = (context, source, resolved_source, state);
    3
}

/// Reconciles a transfer slot's current and saved MOV-chain sources.
///
/// # Safety
///
/// `context` must point to the retail transfer context. The slot, chain-table
/// pointer, and slot state are dereferenced without validation, matching stock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_reconcile(
    context: *mut u8,
    slot_index: u32,
    mode: u32,
) -> u32 {
    const SLOT_SIZE: usize = 0x50;
    const CHAIN_TABLE: usize = 0x1060;
    const SLOT_STATE: usize = 0x1240;
    const SAVED_SOURCE: usize = 0x1244;
    const SOURCE: usize = 0x125c;
    const STATUS: usize = 0x128e;

    let slot = unsafe { context.add(slot_index as usize * SLOT_SIZE) };
    let status = unsafe { slot.add(STATUS).read() };
    if status > 1 {
        return 3;
    }

    let source = unsafe { slot.add(SOURCE).cast::<u32>().read() };
    let saved_source = unsafe { slot.add(SAVED_SOURCE).cast::<u32>().read() };
    if source == saved_source {
        return 0;
    }

    let resolved_source = if mode == 0 {
        let table = unsafe { context.add(CHAIN_TABLE).cast::<u32>().read() } as usize as *const MovChainTable;
        let mut next_source = 0;
        unsafe { mov_chain_table_next(table, source, &mut next_source) };
        next_source
    } else if mode == 1 {
        saved_source
    } else {
        return 3;
    };

    unsafe { transfer_slot_advance(context, source, resolved_source, slot.add(SLOT_STATE)) }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mov::chain_table::MovChainEntry;

    static mut ADVANCE_ARGS: (*mut u8, u32, u32, *mut u8) = (core::ptr::null_mut(), 0, 0, core::ptr::null_mut());
    static mut ADVANCE_RESULT: u32 = 0;

    unsafe extern "C" fn record_advance(context: *mut u8, source: u32, resolved_source: u32, state: *mut u8) -> u32 {
        unsafe { ADVANCE_ARGS = (context, source, resolved_source, state) };
        unsafe { ADVANCE_RESULT }
    }

    #[test]
    fn reconciles_valid_slots_and_rejects_invalid_inputs() {
        let _lock = crate::testing::TRANSFER_SLOT_RECONCILE_TEST_LOCK.lock();
        let Some(context) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TRANSFER_SLOT_RECONCILE,
            0x3000,
        ) else {
            return;
        };
        let slot_index = 1u32;
        let slot = unsafe { context.add(slot_index as usize * 0x50) };
        let table = unsafe { context.add(0x1800).cast::<MovChainTable>() };
        unsafe {
            (context.add(0x1060) as *mut u32).write(table as usize as u32);
            (*table).entries[7] = MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 23, field_10: 0 };
            HOST_TRANSFER_SLOT_ADVANCE = Some(record_advance);
            ADVANCE_RESULT = 0x51;
            slot.add(0x128e).write(2);
        }
        assert_eq!(unsafe { transfer_slot_reconcile(context, slot_index, 0) }, 3);

        unsafe {
            slot.add(0x128e).write(0);
            (slot.add(0x125c) as *mut u32).write(7);
            (slot.add(0x1244) as *mut u32).write(7);
        }
        assert_eq!(unsafe { transfer_slot_reconcile(context, slot_index, 0) }, 0);

        unsafe { (slot.add(0x1244) as *mut u32).write(31) };
        assert_eq!(unsafe { transfer_slot_reconcile(context, slot_index, 2) }, 3);

        assert_eq!(unsafe { transfer_slot_reconcile(context, slot_index, 0) }, 0x51);
        assert_eq!(unsafe { ADVANCE_ARGS }, (context, 7, 23, unsafe { slot.add(0x1240) }));

        unsafe { ADVANCE_RESULT = 9 };
        assert_eq!(unsafe { transfer_slot_reconcile(context, slot_index, 1) }, 9);
        assert_eq!(unsafe { ADVANCE_ARGS }, (context, 7, 31, unsafe { slot.add(0x1240) }));
        unsafe { HOST_TRANSFER_SLOT_ADVANCE = None };
    }
}
