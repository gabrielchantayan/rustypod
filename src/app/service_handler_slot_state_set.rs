//! Service-handler slot state update.
//!
//! `service_handler_slot_state_set` — original: `FUN_08138c80` @
//! **0x08138c80** (172 bytes; 4 direct, unconditional `bl` call sites;
//! no predicated `bl` call sites).
//!
//! Raw ARM establishes the extent as 0x08138c80..0x08138d2c; the two words
//! at 0x08138d2c and 0x08138d30 are its literal pool, and 0x08138d34 begins
//! the next function. The routine requires a live service-manager root, a
//! signed slot below three, and a signed state below seven. It leaves an
//! already-initialized 0x114-byte slot record alone. Otherwise, states -1 and
//! 0 initialize the record; state 6 looks up the manager's u16 handler id and
//! replaces the current descriptor except for ids 0x200..=0x2ff; all other
//! states only stamp the state byte.
//!
//! Deliberate deviation: the two adjacent, unported callees remain explicit
//! firmware-address seams on target and replaceable host seams in tests. The
//! original stores a target pointer at +0x04; this port stores its low u32
//! target representation, including on 64-bit host fixtures.

#[cfg(test)]
extern crate std;

use crate::heap::veneers::heap_panic;
use crate::util::table_find::registry_find_for_slot;
use core::ptr;

const SERVICE_MANAGER_ROOT_ADDRESS: usize = 0x089c_cc30;
const SLOT_STATE_TABLE_ADDRESS: usize = 0x08ad_0f34;
const SLOT_COUNT: usize = 3;

type HandlerIdRead = unsafe extern "C" fn(*mut u8, i32) -> u16;

#[derive(Clone, Copy)]
struct SlotStateOps {
    handler_id_read: HandlerIdRead,
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_id_read(manager_records: *mut u8, slot: i32) -> u16 {
    let function: HandlerIdRead = unsafe { core::mem::transmute(0x0819_3e84usize) };
    unsafe { function(manager_records, slot) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler_id_read(_manager_records: *mut u8, _slot: i32) -> u16 {
    panic!("install a service-handler handler-id-read host seam before calling service_handler_slot_state_set")
}


#[cfg(target_os = "none")]
static mut SLOT_STATE_OPS: SlotStateOps = SlotStateOps {
    handler_id_read: firmware_handler_id_read,
};

#[cfg(not(target_os = "none"))]
static mut SLOT_STATE_OPS: SlotStateOps = SlotStateOps {
    handler_id_read: unavailable_handler_id_read,
};

#[inline(always)]
unsafe fn slot_state_ops() -> SlotStateOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(SLOT_STATE_OPS)) }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SlotStateRecord {
    pub(crate) state: u8,
    _padding_01: [u8; 3],
    pub(crate) descriptor: u32,
    _padding_08: [u8; 4],
    pub(crate) initialized: u32,
    pub(crate) remainder: [u8; 0x104],
}

pub(crate) const EMPTY_SLOT_STATE_RECORD: SlotStateRecord = SlotStateRecord {
    state: 0,
    _padding_01: [0; 3],
    descriptor: 0,
    _padding_08: [0; 4],
    initialized: 0,
    remainder: [0; 0x104],
};

const _: [u8; 0x114] = [0; core::mem::size_of::<SlotStateRecord>()];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SlotStateRecord, initialized)];

#[cfg(target_os = "none")]
#[inline(always)]
pub(crate) unsafe fn slot_states() -> *mut SlotStateRecord {
    SLOT_STATE_TABLE_ADDRESS as *mut SlotStateRecord
}

#[cfg(not(target_os = "none"))]
pub(crate) static mut HOST_SLOT_STATES: [SlotStateRecord; SLOT_COUNT] = [EMPTY_SLOT_STATE_RECORD; SLOT_COUNT];

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_MANAGER: *mut u8 = ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
pub(crate) unsafe fn slot_states() -> *mut SlotStateRecord {
    ptr::addr_of_mut!(HOST_SLOT_STATES).cast()
}

#[inline(always)]
unsafe fn service_manager() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile((SERVICE_MANAGER_ROOT_ADDRESS + 4) as *const *mut u8) }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_MANAGER)) }
    }
}

/// service_handler_slot_state_set — original: `FUN_08138c80` @ 0x08138c80
/// (172 bytes; 4 direct unconditional `bl` call sites).
///
/// Updates the selected slot's state byte, initializing inactive slots and
/// selecting a registry descriptor for state 6 when its handler id is outside
/// the reserved 0x200..=0x2ff range.
///
/// # Safety
///
/// `context` and the installed seams must satisfy their retailOS contracts.
/// The signed bounds checks are faithful; negative slots pass them and index
/// before the fixed slot table, so callers must provide 0..2.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_slot_state_set")]
pub unsafe extern "C" fn service_handler_slot_state_set(context: *mut u8, slot: i32, state: i32) -> u32 {
    let manager = unsafe { service_manager() };
    if manager.is_null() || slot >= 3 || state >= 7 {
        heap_panic();
    }

    let record = unsafe { slot_states().offset(slot as isize) };
    if unsafe { ptr::read_volatile(ptr::addr_of!((*record).initialized)) } == 0 {
        if state == -1 || state == 0 {
            unsafe { super::service_handler_slot_initialize::service_handler_slot_initialize(context, slot) };
        } else if state == 6 {
            let id = unsafe { (slot_state_ops().handler_id_read)(manager.add(4), slot) } as u32;
            if !(0x200..=0x2ff).contains(&id) {
                let descriptor = unsafe { registry_find_for_slot(context, slot as u32, id) };
                if descriptor.is_null() {
                    heap_panic();
                }
                unsafe { ptr::write_volatile(ptr::addr_of_mut!((*record).descriptor), descriptor as u32) };
            }
        }
        unsafe { ptr::write_volatile(ptr::addr_of_mut!((*record).state), state as u8) };
    }
    0
}

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::table_find::{SLOT_RECORDS, SLOT_RECORDS_LOCK};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HANDLER_ID: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fixed_handler_id(_records: *mut u8, _slot: i32) -> u16 {
        HANDLER_ID.load(Ordering::SeqCst) as u16
    }

    unsafe fn install_test_state() -> SlotStateOps {
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(SLOT_STATE_OPS)) };
        unsafe { SLOT_STATE_OPS = SlotStateOps { handler_id_read: fixed_handler_id } };
        unsafe { HOST_SLOT_STATES = [EMPTY_SLOT_STATE_RECORD; SLOT_COUNT] };
        unsafe { HOST_SERVICE_MANAGER = 1usize as *mut u8 };
        previous
    }

    unsafe fn restore_test_state(previous: SlotStateOps) {
        unsafe { SLOT_STATE_OPS = previous };
        unsafe { HOST_SERVICE_MANAGER = ptr::null_mut() };
    }

    #[test]
    fn initialized_slot_is_unchanged() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = install_test_state();
            HOST_SLOT_STATES[1].initialized = 1;
            HOST_SLOT_STATES[1].state = 3;
            assert_eq!(service_handler_slot_state_set(ptr::null_mut(), 1, 6), 0);
            assert_eq!(HOST_SLOT_STATES[1].state, 3);
            restore_test_state(previous);
        }
    }

    #[test]
    fn inactive_state_initializes_then_stamps_state() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = install_test_state();
            service_handler_slot_state_set(0x1234usize as *mut u8, 2, -1);
            assert_eq!(HOST_SLOT_STATES[2].state, 0xff);
            restore_test_state(previous);
        }
    }

    #[test]
    fn state_six_stores_matching_descriptor_but_skips_reserved_ids() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _records_guard = SLOT_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = install_test_state();
            SLOT_RECORDS[0].id = 0x123;
            SLOT_RECORDS[0].slot_mask = 1 << 1;
            HANDLER_ID.store(0x123, Ordering::SeqCst);
            service_handler_slot_state_set(ptr::null_mut(), 1, 6);
            assert_eq!(HOST_SLOT_STATES[1].descriptor, ptr::addr_of!(SLOT_RECORDS[0]) as u32);
            assert_eq!(HOST_SLOT_STATES[1].state, 6);

            HOST_SLOT_STATES[1].descriptor = 0xaabb_ccdd;
            HANDLER_ID.store(0x200, Ordering::SeqCst);
            service_handler_slot_state_set(ptr::null_mut(), 1, 6);
            assert_eq!(HOST_SLOT_STATES[1].descriptor, 0xaabb_ccdd);
            assert_eq!(HOST_SLOT_STATES[1].state, 6);
            SLOT_RECORDS[0].id = 0;
            SLOT_RECORDS[0].slot_mask = 0;
            restore_test_state(previous);
        }
    }
}
