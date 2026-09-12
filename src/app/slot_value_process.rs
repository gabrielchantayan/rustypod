//! `process_present_slot_values` — original: `FUN_080fc540` @ `0x080fc540`
//! (88 bytes; eight direct callers, all unconditional `bl`).
//!
//! The manager's unsigned `slot_count` at `+0x468` bounds its 60-byte slot
//! table at `+0x484`. The function visits every index below the bound and runs
//! the slot processor only when both the `has_slot_value` byte at `+0x01` and
//! the `slot_value` byte at `+0x00` are nonzero. It gives that processor a
//! stack-local parse-result record, then destroys the record. The destructor
//! is the already-ported no-op `parse_result_destroy`, so the processor's
//! side effects are the sole observable result.
//!
//! The per-slot processor is `FUN_080fa540` @ `0x080fa540`, which is not yet
//! ported. Device builds dispatch directly to its retail entry; host tests
//! install a replacement through the volatile seam. This is the only
//! deliberate deviation from the original direct `bl`.

use crate::app::parse_result::parse_result_destroy;

/// A manager prefix with a zero-length tail beginning at the exact slot-table
/// address reached by the ARM code.
#[repr(C)]
struct SlotManager {
    _before_slot_count: [u8; 0x468],
    slot_count: u32,
    _before_slots: [u8; 0x18],
    slots: [SlotState; 0],
}

/// The two value-state bytes and stride observed by this function.
#[repr(C)]
struct SlotState {
    slot_value: u8,
    has_slot_value: u8,
    _remaining: [u8; 0x3a],
}

/// The four-byte result object the slot processor initializes before its
/// caller immediately destroys it.
#[repr(C, align(4))]
struct ParseResult([u8; 4]);

const _: () = assert!(core::mem::size_of::<SlotState>() == 0x3c);
const _: () = assert!(core::mem::offset_of!(SlotManager, slots) == 0x484);
const _: () = assert!(core::mem::offset_of!(SlotState, has_slot_value) == 0x01);
const _: () = assert!(core::mem::size_of::<ParseResult>() == 4);

/// ABI of the unported per-slot processor `FUN_080fa540` @ `0x080fa540`.
type SlotValueProcessor = unsafe extern "C" fn(*mut u8, *mut SlotManager, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_slot_value_processor(
    out: *mut u8, slot_manager: *mut SlotManager, index: u32,
) {
    let process: SlotValueProcessor = unsafe { core::mem::transmute(0x080f_a540usize) };
    unsafe { process(out, slot_manager, index) };
}

#[cfg(target_os = "none")]
static mut SLOT_VALUE_PROCESSOR: SlotValueProcessor = retail_slot_value_processor;

#[cfg(not(target_os = "none"))]
static mut SLOT_VALUE_PROCESSOR: SlotValueProcessor = missing_slot_value_processor;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot_value_processor(
    _out: *mut u8, _slot_manager: *mut SlotManager, _index: u32,
) {
    panic!("process_present_slot_values requires slot processor 0x080fa540")
}

#[inline(always)]
unsafe fn slot_value_processor() -> SlotValueProcessor {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SLOT_VALUE_PROCESSOR)) }
}

/// Processes every slot whose value-present pair is nonzero — original:
/// `FUN_080fc540` @ `0x080fc540` (88 bytes; eight unconditional direct `bl`
/// call sites, binary-scanned).
///
/// # Safety
///
/// `slot_manager` must point to a writable firmware object containing its
/// declared number of 60-byte slot states at `+0x484`. Every present slot
/// invokes the processor without additional validation, exactly as retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn process_present_slot_values(slot_manager: *mut SlotManager) {
    let slots = unsafe { (*slot_manager).slots.as_mut_ptr() };
    let mut index = 0u32;

    while index < unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*slot_manager).slot_count)) } {
        let slot = unsafe { &mut *slots.add(index as usize) };
        if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(slot.has_slot_value)) } != 0
            && unsafe { core::ptr::read_volatile(core::ptr::addr_of!(slot.slot_value)) } != 0
        {
            let mut result = core::mem::MaybeUninit::<ParseResult>::uninit();
            unsafe { slot_value_processor()(result.as_mut_ptr().cast(), slot_manager, index) };
            unsafe { parse_result_destroy(result.as_mut_ptr().cast()) };
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use super::*;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static CALLED_INDICES: AtomicU32 = AtomicU32::new(0);
    static RESULT_WAS_ALIGNED: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn record_slot_processor(
        out: *mut u8, _slot_manager: *mut SlotManager, index: u32,
    ) {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        CALLED_INDICES.fetch_or(1 << index, Ordering::SeqCst);
        RESULT_WAS_ALIGNED.store((out as usize & 3) == 0, Ordering::SeqCst);
        unsafe { out.cast::<u32>().write(0x1234_5678) };
    }

    #[test]
    fn processes_only_slots_with_both_value_bytes_nonzero() {
        let _guard = SEAM_LOCK.lock();
        let mut storage = std::vec![0u8; 0x484 + 4 * 0x3c];
        let manager = storage.as_mut_ptr().cast::<SlotManager>();

        unsafe {
            (*manager).slot_count = 4;
            let slots = (*manager).slots.as_mut_ptr();
            (*slots.add(0)).slot_value = 0x11;
            (*slots.add(0)).has_slot_value = 1;
            (*slots.add(1)).slot_value = 0;
            (*slots.add(1)).has_slot_value = 1;
            (*slots.add(2)).slot_value = 0x22;
            (*slots.add(2)).has_slot_value = 0;
            (*slots.add(3)).slot_value = 0x33;
            (*slots.add(3)).has_slot_value = 2;

            let previous = core::ptr::read_volatile(core::ptr::addr_of!(SLOT_VALUE_PROCESSOR));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SLOT_VALUE_PROCESSOR),
                record_slot_processor,
            );
            CALL_COUNT.store(0, Ordering::SeqCst);
            CALLED_INDICES.store(0, Ordering::SeqCst);
            RESULT_WAS_ALIGNED.store(false, Ordering::SeqCst);

            process_present_slot_values(manager);

            core::ptr::write_volatile(core::ptr::addr_of_mut!(SLOT_VALUE_PROCESSOR), previous);
        }

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(CALLED_INDICES.load(Ordering::SeqCst), (1 << 0) | (1 << 3));
        assert!(RESULT_WAS_ALIGNED.load(Ordering::SeqCst));

        unsafe {
            let slots = (*manager).slots.as_ptr();
            assert_eq!((*slots.add(0)).slot_value, 0x11);
            assert_eq!((*slots.add(0)).has_slot_value, 1);
            assert_eq!((*slots.add(1)).slot_value, 0);
            assert_eq!((*slots.add(1)).has_slot_value, 1);
            assert_eq!((*slots.add(2)).slot_value, 0x22);
            assert_eq!((*slots.add(2)).has_slot_value, 0);
            assert_eq!((*slots.add(3)).slot_value, 0x33);
            assert_eq!((*slots.add(3)).has_slot_value, 2);

            (*manager).slot_count = 0;
            CALL_COUNT.store(0, Ordering::SeqCst);
            process_present_slot_values(manager);
        }
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 0, "zero count must not touch slots");
    }
}
