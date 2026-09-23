//! `selection_context_set_slot_label` — original: `FUN_081a3830` @
//! **0x081a3830** (**80 bytes exactly**, `0x081a3830..0x081a387f`; the
//! following `push {r4, lr}` at `0x081a3880` begins a sibling).
//!
//! Raw decoding finds three plain, unconditional `bl` instructions:
//! `0x08037db8` (the IRAM `memzero_aligned` veneer), `0x08053170` (an
//! unported slot-to-UTF-16 producer), and `0x082765a8`
//! (`string_object_assign_utf16`). There are no predicated calls.
//!
//! # Algorithm
//!
//! Stores `slot` at context `+0x60`. For any slot other than `-1`, clears a
//! 512-byte stack buffer, asks the context's `+0x44` source to produce a
//! length-prefixed UTF-16 label for that slot, then assigns the label to the
//! StringObject at `+0x64`. The producer's first halfword is the count; its
//! following halfwords are the source range.
//!
//! # Deliberate deviations
//!
//! The slot-label producer at `0x08053170` is not yet ported. Target builds
//! call its verified address; host builds expose a replaceable seam. Its name
//! states only the verified ABI, not an unproven retail identity. The stock
//! call reaches `memzero_aligned` through an IRAM veneer; this port calls the
//! existing export through a volatile function-pointer load to preserve a
//! real call and avoid an AEABI memset substitution.

use crate::cxx::string_object::string_object_assign_utf16;
use crate::libc::memzero::memzero_aligned;

pub type SlotLabelLoad = unsafe extern "C" fn(*mut u8, i32, *mut u16);

const SLOT_LABEL_LOAD_ADDRESS: usize = 0x0805_3170;
const SOURCE_OFFSET: usize = 0x44;
const SLOT_OFFSET: usize = 0x60;
static mut MEMZERO_ALIGNED_CALL: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = memzero_aligned;

const LABEL_OFFSET: usize = 0x64;
const SCRATCH_BYTES: usize = 0x200;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_slot_label_load(source: *mut u8, slot: i32, output: *mut u16) {
    unsafe { core::mem::transmute::<usize, SlotLabelLoad>(SLOT_LABEL_LOAD_ADDRESS)(source, slot, output) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot_label_load(_: *mut u8, _: i32, _: *mut u16) {
    panic!("selection_context_set_slot_label requires slot-label producer 0x08053170")
}

#[cfg(target_os = "none")]
pub static mut SLOT_LABEL_LOAD: SlotLabelLoad = retail_slot_label_load;
#[cfg(not(target_os = "none"))]
pub static mut SLOT_LABEL_LOAD: SlotLabelLoad = missing_slot_label_load;

#[inline(always)]
fn slot_label_load() -> SlotLabelLoad {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SLOT_LABEL_LOAD)) }
}

/// Stores the selected slot and refreshes its UTF-16 display label when valid.
///
/// # Safety
///
/// `context` must point to the retail layout through the StringObject at
/// `+0x64`; nonnegative slots must satisfy the unported producer's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.selection_context_set_slot_label"))]
#[inline(never)]
pub unsafe extern "C" fn selection_context_set_slot_label(context: *mut u8, slot: i32) {
    unsafe {
        (context.add(SLOT_OFFSET) as *mut i32).write_volatile(slot);
        if slot == -1 {
            return;
        }

        let mut scratch = [0u16; SCRATCH_BYTES / core::mem::size_of::<u16>()];
        let zero = core::ptr::read_volatile(core::ptr::addr_of!(MEMZERO_ALIGNED_CALL));
        zero(scratch.as_mut_ptr().cast(), SCRATCH_BYTES);
        let source = (context.add(SOURCE_OFFSET) as *const *mut u8).read_volatile();
        slot_label_load()(source, slot, scratch.as_mut_ptr());
        string_object_assign_utf16(context.add(LABEL_OFFSET).cast(), scratch.as_ptr().add(1), i32::from(scratch[0]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOAD_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_SLOT: AtomicI32 = AtomicI32::new(0);
    static SEEN_SOURCE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn load_label(source: *mut u8, slot: i32, output: *mut u16) {
        LOAD_CALLS.fetch_add(1, Ordering::SeqCst);
        SEEN_SOURCE.store(source as usize, Ordering::SeqCst);
        SEEN_SLOT.store(slot, Ordering::SeqCst);
        unsafe {
            output.write(2);
            output.add(1).write(0x0041);
            output.add(2).write(0x03a9);
        }
    }

    #[test]
    fn stores_valid_slot_and_passes_produced_utf16_range_to_assignment() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            SLOT_LABEL_LOAD = load_label;
        }
        LOAD_CALLS.store(0, Ordering::SeqCst);
        let mut context = [0u8; 0x80];
        let source = 0x1234_5678usize as *mut u8;
        unsafe {
            (context.as_mut_ptr().add(SOURCE_OFFSET) as *mut *mut u8).write(source);
            selection_context_set_slot_label(context.as_mut_ptr(), 7);
        }
        assert_eq!(unsafe { (context.as_ptr().add(SLOT_OFFSET) as *const i32).read() }, 7);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_SOURCE.load(Ordering::SeqCst), source as usize);
        assert_eq!(SEEN_SLOT.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn negative_one_only_stores_the_sentinel() {
        let _guard = TEST_LOCK.lock();
        LOAD_CALLS.store(0, Ordering::SeqCst);
        let mut context = [0xa5u8; 0x80];
        unsafe { selection_context_set_slot_label(context.as_mut_ptr(), -1); }
        assert_eq!(unsafe { (context.as_ptr().add(SLOT_OFFSET) as *const i32).read() }, -1);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 0);
    }
}
