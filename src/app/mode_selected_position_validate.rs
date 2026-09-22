//! `mode_selected_position_validate` — original: `FUN_0822aee0` @ **0x0822aee0**.
//!
//! **112 bytes**, `0x0822aee0..0x0822af50`: the next separately entered
//! function begins at `0x0822af50`. Raw ARM decoding finds **seven** direct
//! `bl` instructions, all unconditional (`0x0822aef0`, `0x0822af04`,
//! `0x0822af10`, `0x0822af18`, `0x0822af24`, `0x0822af30`, and `0x0822af3c`);
//! there are zero predicated `bl` instructions. It returns false unless the
//! mode-selected byte is zero. On that path it asks the still-unported
//! `0x08143474` helper to prepare a temporary shared-cell handle from the
//! selected position, copy-assigns it into `state+0x890`, drops the temporary,
//! then compares the destination against a newly constructed empty handle.
//! Thus the result is true exactly when the prepared handle is non-empty.
//!
//! Deliberate deviation: the unported preparation helper remains a fixed-address
//! target seam on ARM and an injectable seam on hosts. Host handles use native
//! pointer-width slots so fixtures can retain real pointers; target accesses
//! remain 32-bit words at the recovered offsets.

use crate::app::mode_selected_byte::mode_selected_byte;
use crate::cxx::shared_cell::{shared_cell_assign_secondary, shared_cell_construct_secondary, shared_cell_release_secondary, SharedCell};

pub type PrepareSelectedPositionCell = unsafe extern "C" fn(*mut *mut SharedCell, u32);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn prepare_selected_position_cell() -> PrepareSelectedPositionCell {
    core::mem::transmute(0x0814_3474u32 as usize)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_prepare_selected_position_cell(slot: *mut *mut SharedCell, _position: u32) {
    slot.write(core::ptr::null_mut());
}

#[cfg(not(target_arch = "arm"))]
static mut PREPARE_SELECTED_POSITION_CELL: PrepareSelectedPositionCell = missing_prepare_selected_position_cell;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn prepare_selected_position_cell() -> PrepareSelectedPositionCell {
    core::ptr::addr_of!(PREPARE_SELECTED_POSITION_CELL).read_volatile()
}

/// Validates and retains the shared cell prepared for `selected_position`.
///
/// # Safety
/// `state` must designate the retail state layout, including readable bytes at
/// `+0x2f4`, `+0x5ec`, and `+0x5f8`, plus a writable shared-cell slot at
/// `+0x890`. The selected-position helper and any non-NULL cells must satisfy
/// their respective contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_selected_position_validate(state: *mut u8, selected_position: u32) -> u32 {
    if mode_selected_byte(state) != 0 {
        return 0;
    }

    let mut prepared = core::ptr::null_mut();
    prepare_selected_position_cell()(&mut prepared, selected_position);
    let destination = state.add(0x890).cast::<*mut SharedCell>();
    shared_cell_assign_secondary(destination, &mut prepared);
    shared_cell_release_secondary(&mut prepared);

    let mut empty = core::ptr::null_mut();
    shared_cell_construct_secondary(&mut empty, core::ptr::null_mut());
    let changed = destination.read() != empty;
    shared_cell_release_secondary(&mut empty);
    changed as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static PREPARE_LOCK: Mutex<()> = Mutex::new(());

    fn prepare_lock() -> MutexGuard<'static, ()> {
        PREPARE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }


    const STATE_BYTES: usize = 0x890 + core::mem::size_of::<*mut SharedCell>();
    const DEFAULT_MODE_BYTE: usize = 0x5ec;
    const MODE_FLAGS: usize = 0x5f8;
    static mut PREPARED: *mut SharedCell = core::ptr::null_mut();
    static mut PREPARE_CALLS: usize = 0;

    unsafe extern "C" fn prepare(slot: *mut *mut SharedCell, position: u32) {
        assert_eq!(position, 0x1234_5678);
        PREPARE_CALLS += 1;
        slot.write(PREPARED);
    }

    #[test]
    fn nonzero_mode_skips_preparation_and_leaves_destination() {
        let _lock = prepare_lock();
        let saved = unsafe { core::ptr::addr_of!(PREPARE_SELECTED_POSITION_CELL).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(prepare) };
        let mut state = [0u8; STATE_BYTES];
        let existing = 0x44usize as *mut SharedCell;
        unsafe {
            state[DEFAULT_MODE_BYTE] = 1;
            state[MODE_FLAGS] = 0;
            state.as_mut_ptr().add(0x890).cast::<*mut SharedCell>().write(existing);
            PREPARE_CALLS = 0;
            assert_eq!(mode_selected_position_validate(state.as_mut_ptr(), 0x1234_5678), 0);
            assert_eq!(state.as_ptr().add(0x890).cast::<*mut SharedCell>().read(), existing);
            assert_eq!(PREPARE_CALLS, 0);
            core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(saved);
        }
    }

    #[test]
    fn empty_preparation_is_not_valid() {
        let _lock = prepare_lock();
        let saved = unsafe { core::ptr::addr_of!(PREPARE_SELECTED_POSITION_CELL).read_volatile() };
        unsafe {
            core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(prepare);
            PREPARED = core::ptr::null_mut();
            PREPARE_CALLS = 0;
            let mut state = [0u8; STATE_BYTES];
            assert_eq!(mode_selected_position_validate(state.as_mut_ptr(), 0x1234_5678), 0);
            assert!(state.as_ptr().add(0x890).cast::<*mut SharedCell>().read().is_null());
            assert_eq!(PREPARE_CALLS, 1);
            core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(saved);
        }
    }

    #[test]
    fn prepared_cell_is_retained_in_destination() {
        let _lock = prepare_lock();
        let saved = unsafe { core::ptr::addr_of!(PREPARE_SELECTED_POSITION_CELL).read_volatile() };
        let mut cell = SharedCell { value: 0, refcount: 1 };
        unsafe {
            core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(prepare);
            PREPARED = &mut cell;
            let mut state = [0u8; STATE_BYTES];
            assert_eq!(mode_selected_position_validate(state.as_mut_ptr(), 0x1234_5678), 1);
            assert!(core::ptr::eq(state.as_ptr().add(0x890).cast::<*mut SharedCell>().read(), &mut cell));
            assert_eq!(cell.refcount, 1);
            core::ptr::addr_of_mut!(PREPARE_SELECTED_POSITION_CELL).write_volatile(saved);
        }
    }
}
