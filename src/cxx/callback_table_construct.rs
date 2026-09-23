//! `callback_table_construct` — retailOS `FUN_0818ba34` @ **0x0818ba34**.
//!
//! Raw `osos.dec` establishes the true **48-byte** A32 extent
//! `0x0818ba34..0x0818ba63`; `0x0818ba64` begins the next independently entered
//! function with `push {r1-r11,lr}`. Ghidra's 172-byte extent incorrectly
//! absorbs that sibling. A whole-image A32 decode finds three inbound plain
//! `bl` calls (0x081d60ac, 0x081f1a58, and 0x08267c70) and no predicated
//! `bl` calls. The body has one plain `bl` to `FUN_0818ca9c` and one direct
//! tail `b` to the still-retail sibling at 0x081fd578.
//!
//! It writes `{-2, object}` at object offsets +0x50 and +0x54, then tail-calls
//! the sibling with its embedded callback-table state at +0x48, the record
//! table, and the enclosing object. The sibling initializes that state and
//! invokes enabled 24-byte record callbacks. Deliberate deviation: Rust uses
//! a direct call-and-return instead of ARM's tail branch; device builds call
//! the verified fixed address and host tests install a narrow recording seam.

use core::ptr::{addr_of, read_volatile, write_volatile};

/// Firmware load address of the still-retail callback-table population sibling.
pub const CALLBACK_TABLE_POPULATE_ADDRESS: usize = 0x081f_d578;

/// ABI of `FUN_081fd578`, whose semantic identity is only established by its
/// verified record iteration and callback dispatch.
pub type CallbackTablePopulate = unsafe extern "C" fn(*mut u8, *const u8, *mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_callback_table_populate(
    state: *mut u8,
    records: *const u8,
    object: *mut u8,
) -> u32 {
    let populate: CallbackTablePopulate = unsafe { core::mem::transmute(CALLBACK_TABLE_POPULATE_ADDRESS) };
    unsafe { populate(state, records, object) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_table_populate(_: *mut u8, _: *const u8, _: *mut u8) -> u32 {
    panic!("callback_table_construct requires callback-table population at 0x081fd578")
}

/// Boundary for the still-retail callback-table population sibling.
#[cfg(target_os = "none")]
pub static mut CALLBACK_TABLE_POPULATE: CallbackTablePopulate = firmware_callback_table_populate;
#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_TABLE_POPULATE: CallbackTablePopulate = missing_callback_table_populate;

/// Constructs the callback-table portion of `object` and populates it from
/// `records`, returning the population status.
///
/// # Safety
/// `object` must be writable through +0x57. `records` must satisfy the
/// installed population operation's record-table contract. Neither is checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_table_construct(object: *mut u8, records: *const u8) -> u32 {
    unsafe {
        write_volatile(object.add(0x50).cast::<u32>(), u32::MAX - 1);
        write_volatile(object.add(0x54).cast::<u32>(), object as usize as u32);
        let populate = read_volatile(addr_of!(CALLBACK_TABLE_POPULATE));
        populate(object.add(0x48), records, object)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

    static mut CALL: (*mut u8, *const u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());

    unsafe extern "C" fn record_populate(state: *mut u8, records: *const u8, object: *mut u8) -> u32 {
        unsafe { write_volatile(addr_of_mut!(CALL), (state, records, object)) };
        9
    }

    #[test]
    fn stores_callback_state_and_forwards_target_abi() {
        unsafe {
            CALLBACK_TABLE_POPULATE = record_populate;
            let mut object = [0xa5u8; 0x58];
            let records = [0u8; 24];
            assert_eq!(callback_table_construct(object.as_mut_ptr(), records.as_ptr()), 9);
            assert_eq!(read_volatile(object.as_ptr().add(0x50).cast::<u32>()), u32::MAX - 1);
            assert_eq!(read_volatile(object.as_ptr().add(0x54).cast::<u32>()), object.as_ptr() as usize as u32);
            let (state, table, receiver) = read_volatile(addr_of!(CALL));
            assert_eq!(state, object.as_mut_ptr().add(0x48));
            assert_eq!(table, records.as_ptr());
            assert_eq!(receiver, object.as_mut_ptr());
        }
    }
}
