//! `transfer_slot_process` — original: `FUN_081e46b0` @ `0x081e46b0`
//! (188 bytes; true extent `0x081e46b0..0x081e476b`).
//!
//! # Verified calls and algorithm
//!
//! Raw A32 words establish three outbound plain unconditional `bl` calls,
//! at 0x081e46e4 (`mov_chain_table_find_predecessor`), 0x081e4708
//! (`mov_chain_table_release_range`), and 0x081e4748
//! (`mov_chain_table_set_next`); no outbound predicated `bl` forms occur.
//! The next real function starts with `add r2, r1, r1, lsl #2` at
//! 0x081e476c. The three inbound direct calls are `bleq` at 0x081e4150 and
//! 0x081e4cd4 plus plain `bl` at 0x081e4790; thus two inbound calls are
//! predicated. The selected 0x50-byte transfer slot supplies a chain head,
//! source, and saved source. This routine finds the source's predecessor,
//! releases the chain range, subtracts the released count from the slot and
//! context totals, then relinks the predecessor to the saved source.
//! # Deliberate deviations
//!
//! The fifth stack argument left by the caller at the
//! `mov_chain_table_release_range` call is not consumed by that verified
//! four-argument callee, so it is omitted.

use crate::mov::chain_table::{
    mov_chain_table_release_range, mov_chain_table_set_next, MovChainTableManager,
    MOV_CHAIN_TABLE_OK,
};
use crate::mov::chain_table_find_predecessor::mov_chain_table_find_predecessor;

/// Releases the selected source range and reconnects its predecessor.
///
/// # Safety
///
/// `context` must identify the retail transfer context. Its manager pointer,
/// selected slot, and count fields are dereferenced without validation, as in
/// stock firmware; the MOV chain routines impose their own documented
/// requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_process(
    context: *mut u8,
    slot_index: u32,
    source: u32,
    transferred: *mut u32,
) -> u32 {
    const SLOT_SIZE: usize = 0x50;
    const SLOT_BASE: usize = 0x1240;
    const CHAIN_HEAD: usize = 0;
    const SAVED_SOURCE: usize = 4;
    const REMAINING: usize = 0x14;
    const MANAGER: usize = 0x1060;
    const TOTAL_REMAINING: usize = 0x1074;

    unsafe { core::ptr::write(transferred, 0) };
    let slot = unsafe { context.add(SLOT_BASE + slot_index as usize * SLOT_SIZE) };
    let manager = unsafe { core::ptr::read(context.add(MANAGER).cast::<u32>()) as usize }
        as *mut MovChainTableManager;
    let head = unsafe { core::ptr::read(slot.add(CHAIN_HEAD).cast::<u32>()) };
    let mut predecessor = 0u32;

    if unsafe { mov_chain_table_find_predecessor(manager.cast(), head, source, &mut predecessor) }
        != MOV_CHAIN_TABLE_OK
    {
        return 3;
    }

    let saved_source = unsafe { core::ptr::read(slot.add(SAVED_SOURCE).cast::<u32>()) };
    if unsafe { mov_chain_table_release_range(manager, source, saved_source, transferred) }
        != MOV_CHAIN_TABLE_OK
    {
        return 3;
    }

    let count = unsafe { core::ptr::read(transferred) };
    let remaining = unsafe { core::ptr::read(slot.add(REMAINING).cast::<u32>()) };
    unsafe { core::ptr::write(slot.add(REMAINING).cast::<u32>(), remaining.wrapping_sub(count)) };
    let total_remaining = unsafe { core::ptr::read(context.add(TOTAL_REMAINING).cast::<u32>()) };
    unsafe {
        core::ptr::write(
            context.add(TOTAL_REMAINING).cast::<u32>(),
            total_remaining.wrapping_sub(count),
        )
    };

    if unsafe { mov_chain_table_set_next(manager.cast(), predecessor, saved_source) } != MOV_CHAIN_TABLE_OK {
        return 3;
    }
    unsafe { core::ptr::write(slot.add(8).cast::<u32>(), predecessor) };
    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predecessor_failures_zero_count_without_writing_slot_counts() {
        let Some(context) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TRANSFER_SLOT_PROCESS,
            0x3000,
        ) else {
            return;
        };
        let manager = unsafe { context.add(0x1800) };
        let mut transferred = 0xdead_beef;
        unsafe {
            (context.add(0x1060) as *mut u32).write(manager as usize as u32);
            (context.add(0x1240) as *mut u32).write(17);
            (context.add(0x1244) as *mut u32).write(29);
            (context.add(0x1254) as *mut u32).write(41);
            (context.add(0x1074) as *mut u32).write(43);
        }

        assert_eq!(unsafe { transfer_slot_process(context, 0, 17, &mut transferred) }, 3);
        assert_eq!(transferred, 0);
        assert_eq!(unsafe { (context.add(0x1254) as *const u32).read() }, 41);
        assert_eq!(unsafe { (context.add(0x1074) as *const u32).read() }, 43);

        transferred = 7;
        unsafe { (context.add(0x1240) as *mut u32).write(u32::MAX) };
        assert_eq!(unsafe { transfer_slot_process(context, 0, 5, &mut transferred) }, 3);
        assert_eq!(transferred, 0);
        assert_eq!(unsafe { (context.add(0x1254) as *const u32).read() }, 41);
        assert_eq!(unsafe { (context.add(0x1074) as *const u32).read() }, 43);
    }
}
