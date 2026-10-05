//! `transfer_slot_retire` — original: `FUN_081e40f0` @ `0x081e40f0`.
//! True extent: [0x081e40f0, 0x081e41a4), 180 bytes; next entry is a push.
//! Raw word decoding finds two inbound plain BLs (0x081e40a8, 0x081e49ac),
//! no inbound predicated BLs, three outbound plain BLs (lock, unlock,
//! payload-last-index lookup), and one outbound BLEQ (transfer_slot_process).
//!
//! An absent pending source (-1) is a no-op. Otherwise wait for the slot
//! mutex, immediately unlock it, and optionally process its pending source.
//! Save the pending source and invalidate it, then in normal mode restore
//! the saved chain and its payload's last index. Lookup failure returns 3
//! before clearing the active byte; processing failure is deliberately ignored.
//!
//! Deviations: initialize the scratch count that processing overwrites.
//! The unported 0x081e3e88 helper remains a three-argument target-address
//! seam: raw instructions show r3 is dead (its only callee overwrites it).
//! Hosts execute its verified lookup/subtract algorithm using the existing
//! payload lookup port. Hosts widen only the mutex in a local adapter, keeping
//! every firmware context field at its original word offset.
//! Codegen review: LLVM emits 65 instructions versus ADS's 45, using a
//! branch around processing instead of BLEQ and BLX for the address seam.
//! Sentinel exit, both mode checks, ordered partial writes, and error exit
//! remain intact; dead service loads disappear because lock adapters ignore it.

use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::app::transfer_slot_process::transfer_slot_process;
use crate::kernel::sync_mutex::Mutex;

#[cfg(target_os = "none")]
unsafe fn payload_last_index(context: *mut u8, chain: u32, out: *mut u32) -> u32 {
    let lookup: unsafe extern "C" fn(*mut u8, u32, *mut u32) -> u32 =
        unsafe { core::mem::transmute(0x081e_3e88usize) };
    unsafe { lookup(context, chain, out) }
}

#[cfg(not(target_os = "none"))]
unsafe fn payload_last_index(context: *mut u8, chain: u32, out: *mut u32) -> u32 {
    let mut length = 0;
    if unsafe { crate::mov::chain_table::mov_chain_table_lookup_payload_word(
        context, chain as i32, &mut length, 0,
    ) } != 0 {
        return 3;
    }
    unsafe { out.write(length.wrapping_sub(1)) };
    0
}

/// Retires a selected slot's pending source, preserving stock partial updates.
///
/// # Safety
/// `context` must expose the selected 0x50-byte slot and fields through
/// +0x13b0. Its mutex cell and MOV manager/record pointers must be valid for
/// the lock, processing and payload lookup routines. No bounds are checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_retire(context: *mut u8, slot_index: u32) -> u32 {
    let slot = unsafe { context.add(slot_index as usize * 0x50) };
    let pending = unsafe { slot.add(0x1280).cast::<u32>() };
    if unsafe { pending.read() } == u32::MAX {
        return 0;
    }

    let service = unsafe { context.add(0x1380).cast::<u32>().read() } as usize as *mut core::ffi::c_void;
    #[cfg(target_os = "none")]
    let mutex = unsafe { slot.add(0x1270).cast::<Mutex>() };
    #[cfg(not(target_os = "none"))]
    let mut host_mutex = Mutex {
        sem_cell: unsafe { slot.add(0x1270).cast::<u32>().read() } as usize as *mut u32,
        unused: unsafe { slot.add(0x1274).cast::<u32>().read() },
    };
    #[cfg(not(target_os = "none"))]
    let mutex = &mut host_mutex as *mut Mutex;
    unsafe { lock_service_lock(service, mutex) };
    unsafe { lock_service_unlock(service, mutex) };

    if unsafe { context.add(0x13b0).read() } == 0 {
        let mut transferred = 0;
        unsafe { transfer_slot_process(context, slot_index, pending.read(), &mut transferred) };
    }
    unsafe {
        slot.add(0x1288).cast::<u32>().write(pending.read());
        pending.write(u32::MAX);
    }
    if unsafe { context.add(0x13b0).read() } == 0 {
        let saved_chain = unsafe { slot.add(0x1264).cast::<u32>().read() };
        unsafe { slot.add(0x124c).cast::<u32>().write(saved_chain) };
        if unsafe { payload_last_index(context, saved_chain, slot.add(0x1250).cast()) } != 0 {
            return 3;
        }
    }
    unsafe { slot.add(0x1284).write(0) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mov::chain_table::MovChainTableManager;

    #[test]
    fn retirement_preserves_noop_and_failure_boundaries_and_wraps_zero_length() {
        let Some(context) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TRANSFER_SLOT_RETIRE, 0x90000,
        ) else { return; };
        unsafe {
            core::ptr::write_bytes(context, 0, 0x90000);
            let slot = context.add(0x50);
            let pending = slot.add(0x1280).cast::<u32>();
            let saved = slot.add(0x1288).cast::<u32>();
            let active = slot.add(0x1284);
            pending.write(u32::MAX);
            saved.write(91);
            active.write(7);
            assert_eq!(transfer_slot_retire(context, 1), 0);
            assert_eq!((saved.read(), active.read()), (91, 7));

            // Non-normal mode must not dereference an absent MOV manager.
            context.add(0x13b0).write(2);
            pending.write(17);
            assert_eq!(transfer_slot_retire(context, 1), 0);
            assert_eq!((pending.read(), saved.read(), active.read()), (u32::MAX, 17, 0));
            assert_eq!(context.add(0x1280).cast::<u32>().read(), 0);

            let manager = context.add(0x2000).cast::<MovChainTableManager>();
            context.add(0x1060).cast::<u32>().write(manager as usize as u32);
            context.add(0x13b0).write(0);
            // Invalid chain head makes processing fail; retirement still continues.
            slot.add(0x1240).cast::<u32>().write(u32::MAX);
            slot.add(0x1264).cast::<u32>().write(u32::MAX);
            slot.add(0x1250).cast::<u32>().write(99);
            pending.write(23);
            active.write(5);
            assert_eq!(transfer_slot_retire(context, 1), 3);
            assert_eq!((pending.read(), saved.read(), active.read()), (u32::MAX, 23, 5));
            assert_eq!(slot.add(0x124c).cast::<u32>().read(), u32::MAX);
            assert_eq!(slot.add(0x1250).cast::<u32>().read(), 99);

            let record = context.add(0x4000);
            (*manager).table.entries[7].field_00 = record as usize as u32;
            (*manager).table.entries[7].tag = 3;
            (*manager).table.entries[7].field_10 = 0;
            slot.add(0x1264).cast::<u32>().write(7);
            for length in [0u32, 1, 29, u32::MAX] {
                record.add(0x7fff8).cast::<u32>().write(length);
                pending.write(31);
                active.write(5);
                assert_eq!(transfer_slot_retire(context, 1), 0);
                assert_eq!(slot.add(0x124c).cast::<u32>().read(), 7);
                assert_eq!(slot.add(0x1250).cast::<u32>().read(), length.wrapping_sub(1));
                assert_eq!((pending.read(), saved.read(), active.read()), (u32::MAX, 31, 0));
            }
        }
    }
}
