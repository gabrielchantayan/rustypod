//! Service-handler slot initialization.
//!
//! `service_handler_slot_initialize` — original: `FUN_0813858c` @
//! **0x0813858c** (84 bytes; 4 direct incoming, unconditional `bl` call
//! sites; 3 outbound `bl`: 2 unconditional and 1 `blge`).
//!
//! Raw ARM establishes the extent as 0x0813858c..0x081385e0; the word at
//! 0x081385e0 is the slot-table literal and 0x081385e4 starts the next
//! function. Signed slots at least three call `heap_panic`. An uninitialized
//! 0x114-byte slot record is zeroed through the IRAM `memzero_aligned` veneer,
//! then its descriptor word receives the registry entry for handler id zero.
//!
//! Deliberate deviation: this port calls the already ported
//! `memzero_aligned` through a volatile function pointer rather than the IRAM
//! veneer, preserving the required call while preventing LLVM builtin
//! substitution. Host fixtures use the shared slot-table model.

#[cfg(test)]
extern crate std;

use crate::app::service_handler_slot_state_set::{slot_states, SlotStateRecord};
use crate::heap::veneers::heap_panic;
use crate::libc::memzero::memzero_aligned;
use crate::util::table_find::registry_find_for_slot;
use core::ptr;

type MemzeroAligned = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;

static MEMZERO_ALIGNED: MemzeroAligned = memzero_aligned;
/// service_handler_slot_initialize — original: `FUN_0813858c` @ 0x0813858c
/// (84 bytes; 4 direct incoming unconditional `bl` call sites; 2 outbound
/// unconditional and 1 `blge` call sites).
///
/// Clears an inactive service-handler slot and assigns its default registry
/// descriptor.
///
/// # Safety
///
/// `context` must satisfy the registry lookup contract. `slot` must be
/// nonnegative: the original only rejects signed values at least three.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_slot_initialize")]
pub unsafe extern "C" fn service_handler_slot_initialize(context: *mut u8, slot: i32) {
    if slot >= 3 {
        heap_panic();
    }

    let record = unsafe { slot_states().offset(slot as isize) };
    if unsafe { ptr::read_volatile(ptr::addr_of!((*record).initialized)) } != 0 {
        return;
    }

    let zero = unsafe { ptr::read_volatile(ptr::addr_of!(MEMZERO_ALIGNED)) };
    unsafe { zero(record.cast(), core::mem::size_of::<SlotStateRecord>()) };
    let descriptor = unsafe { registry_find_for_slot(context, slot as u32, 0) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*record).descriptor), descriptor as u32) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::service_handler_slot_state_set::{EMPTY_SLOT_STATE_RECORD, HOST_SLOT_STATES, SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK};
    use crate::util::table_find::{SLOT_RECORDS, SLOT_RECORDS_LOCK};

    #[test]
    fn clears_inactive_record_and_assigns_default_descriptor() {
        let _slot_guard = SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _registry_guard = SLOT_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            HOST_SLOT_STATES = [EMPTY_SLOT_STATE_RECORD; 3];
            HOST_SLOT_STATES[1].state = 0xaa;
            HOST_SLOT_STATES[1].descriptor = 0xfeed_beef;
            HOST_SLOT_STATES[1].remainder = [0xcc; 0x104];
            SLOT_RECORDS[0].id = 0;
            SLOT_RECORDS[0].slot_mask = 1 << 1;

            service_handler_slot_initialize(ptr::null_mut(), 1);

            assert_eq!(HOST_SLOT_STATES[1].state, 0);
            assert_eq!(HOST_SLOT_STATES[1].initialized, 0);
            assert_eq!(HOST_SLOT_STATES[1].descriptor, ptr::addr_of!(SLOT_RECORDS[0]) as u32);
            assert_eq!(HOST_SLOT_STATES[1].remainder, [0; 0x104]);
            SLOT_RECORDS[0].slot_mask = 0;
        }
    }
}
