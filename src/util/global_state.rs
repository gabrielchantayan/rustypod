//! Lookup of a global-state record by name.
//!
//! `global_state_get` — original: `FUN_080781b0` @ 0x080781b0 (16 bytes).
//! Raw ARM is:
//!
//! ```text
//! 080781b0: push {r4, lr}
//! 080781b4: bl   0x08077ff0
//! 080781b8: ldr  r0, [r0]
//! 080781bc: pop  {r4, pc}
//! ```
//!
//! The unported helper `FUN_08077ff0` @ 0x08077ff0 is a 140-byte,
//! string-hashed table-slot search. It receives the incoming name in `r0`
//! and opaque state-table pointer in `r1`, then returns a pointer to the
//! matching slot. This wrapper performs no lookup or validation itself: it
//! forwards both incoming arguments unchanged and returns the slot's first
//! word. Direct callers at 0x0807b2fc, 0x0809fc9c, 0x0809fd78, 0x0809fda8,
//! 0x080ae028, and 0x080bfbb4 supply a name plus an in-object table pointer;
//! the first two recovered callers use the result as a global-state record.
//!
//! The state-table layout and the global-state record's ownership remain
//! unported and opaque here. On target the seam calls the original helper;
//! host tests replace it with a recorder.

/// ABI of `FUN_08077ff0`: find the slot for `global_name` in the opaque
/// `global_state_table`. The returned slot's first word is the record that
/// [`global_state_get`] returns.
pub type GlobalStateSlotFind = unsafe extern "C" fn(
    global_name: *const u8,
    global_state_table: *const u8,
) -> *const *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_global_state_slot_find(
    global_name: *const u8,
    global_state_table: *const u8,
) -> *const *mut u8 {
    let find_slot: GlobalStateSlotFind = unsafe { core::mem::transmute(0x0807_7ff0usize) };
    unsafe { find_slot(global_name, global_state_table) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_global_state_slot_find(
    _global_name: *const u8,
    _global_state_table: *const u8,
) -> *const *mut u8 {
    panic!("global_state_get requires table-slot helper 0x08077ff0")
}

#[cfg(target_os = "none")]
const DEFAULT_GLOBAL_STATE_SLOT_FIND: GlobalStateSlotFind = firmware_global_state_slot_find;
#[cfg(not(target_os = "none"))]
const DEFAULT_GLOBAL_STATE_SLOT_FIND: GlobalStateSlotFind = missing_global_state_slot_find;

/// Unported `FUN_08077ff0` table-slot search. Target builds dispatch to its
/// retailOS address; host tests install a recording mock through this seam.
pub static mut GLOBAL_STATE_SLOT_FIND: GlobalStateSlotFind = DEFAULT_GLOBAL_STATE_SLOT_FIND;

/// global_state_get — original: `FUN_080781b0` @ 0x080781b0 (16 bytes).
///
/// Forwards `global_name` and `global_state_table` unchanged to the unported
/// table-slot helper at 0x08077ff0, then loads and returns the resulting
/// slot's first word. As in the raw ARM body, neither the slot nor its first
/// word is checked for null or otherwise validated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_state_get(
    global_name: *const u8,
    global_state_table: *const u8,
) -> *mut u8 {
    let find_slot = unsafe { core::ptr::addr_of_mut!(GLOBAL_STATE_SLOT_FIND).read_volatile() };
    unsafe { *find_slot(global_name, global_state_table) }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{Mutex, MutexGuard};

    static SLOT_FIND_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED_NAME: *const u8 = core::ptr::null();
    static mut RECORDED_TABLE: *const u8 = core::ptr::null();
    static mut RETURNED_SLOT: *const *mut u8 = core::ptr::null();

    unsafe extern "C" fn recording_slot_find(
        global_name: *const u8,
        global_state_table: *const u8,
    ) -> *const *mut u8 {
        unsafe {
            RECORDED_NAME = global_name;
            RECORDED_TABLE = global_state_table;
            RETURNED_SLOT
        }
    }

    struct SlotFindReset;

    impl Drop for SlotFindReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(GLOBAL_STATE_SLOT_FIND)
                    .write(DEFAULT_GLOBAL_STATE_SLOT_FIND);
            }
        }
    }

    fn install_recording_slot_find() -> MutexGuard<'static, ()> {
        let guard = SLOT_FIND_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            RECORDED_NAME = core::ptr::null();
            RECORDED_TABLE = core::ptr::null_mut();
            RETURNED_SLOT = core::ptr::null_mut();
            core::ptr::addr_of_mut!(GLOBAL_STATE_SLOT_FIND).write(recording_slot_find);
        }
        guard
    }

    #[test]
    fn forwards_name_and_table_to_the_slot_helper() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let name = b"volume\0";
        let mut table = [0u8; 16];
        let mut record = [0u8; 8];
        let mut slot = record.as_mut_ptr();
        unsafe {
            RETURNED_SLOT = &mut slot;
            assert_eq!(global_state_get(name.as_ptr(), table.as_mut_ptr()), record.as_mut_ptr());
            assert_eq!(RECORDED_NAME, name.as_ptr());
            assert_eq!(RECORDED_TABLE, table.as_mut_ptr());
        }
    }

    #[test]
    fn returns_the_first_word_loaded_from_the_slot() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let mut first_word_record = [0u8; 4];
        let mut slot = first_word_record.as_mut_ptr();
        unsafe {
            RETURNED_SLOT = &mut slot;
            assert_eq!(
                global_state_get(b"backlight\0".as_ptr(), core::ptr::null_mut()),
                first_word_record.as_mut_ptr(),
            );
            assert_ne!(
                global_state_get(b"backlight\0".as_ptr(), core::ptr::null_mut()),
                &mut slot as *mut *mut u8 as *mut u8,
            );
        }
    }
}
