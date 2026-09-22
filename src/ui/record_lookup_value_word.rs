//! Look up a record and return its value word.
//!
//! `record_lookup_value_word` — original: `FUN_08291d90` @ `0x08291d90`,
//! 20 bytes (`0x08291d90..0x08291da4`; the next independently entered
//! function begins at `0x08291da4`). Raw osos.dec A32 decoding establishes
//! one unconditional internal `bl` to `0x08291da4` and no predicated BL
//! forms. A full-image decode finds three inbound plain BL calls
//! (`0x0816ddec`, `0x081fa620`, and `0x0829b778`) and no predicated BL calls.
//!
//! # Algorithm
//!
//! Call the adjacent record lookup with `context` and `key`. Return zero when
//! it yields NULL; otherwise return the aligned u32 at target offset `+0x58`.
//!
//! # Deliberate deviations
//!
//! The adjacent lookup is not yet ported, so the target calls its verified
//! address directly. Host tests use an explicit dispatch seam. The target
//! field is read with a volatile u32 access; this avoids host pointer-width
//! layout assumptions and preserves the firmware's single aligned load.

use core::ptr;

type RecordLookup = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

const RECORD_LOOKUP_ADDRESS: usize = 0x0829_1da4;
const RECORD_VALUE_WORD_OFFSET: usize = 0x58;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_record_lookup(context: *mut u8, key: u32) -> *mut u8 {
    let lookup: RecordLookup = unsafe { core::mem::transmute(RECORD_LOOKUP_ADDRESS) };
    unsafe { lookup(context, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_lookup(_context: *mut u8, _key: u32) -> *mut u8 {
    panic!("record lookup dispatch seam was not configured")
}

#[cfg(target_os = "none")]
pub static mut RECORD_LOOKUP: RecordLookup = firmware_record_lookup;
#[cfg(not(target_os = "none"))]
pub static mut RECORD_LOOKUP: RecordLookup = missing_record_lookup;

/// Looks up `key` in `context`, returning zero if no record is present.
///
/// # Safety
///
/// `context` and `key` must be valid for the adjacent retailOS lookup. A
/// non-NULL result must have a readable aligned u32 at target offset `+0x58`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_lookup_value_word(context: *mut u8, key: u32) -> u32 {
    let record = unsafe { RECORD_LOOKUP(context, key) };
    if record.is_null() {
        0
    } else {
        unsafe { ptr::read_volatile(record.add(RECORD_VALUE_WORD_OFFSET).cast::<u32>()) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static LOOKUP_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED_CONTEXT: *mut u8 = ptr::null_mut();
    static mut RECEIVED_KEY: u32 = 0;
    static mut LOOKUP_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn fixture_lookup(context: *mut u8, key: u32) -> *mut u8 {
        unsafe {
            RECEIVED_CONTEXT = context;
            RECEIVED_KEY = key;
            LOOKUP_RESULT
        }
    }

    #[test]
    fn returns_value_word_and_forwards_lookup_arguments() {
        let _guard = LOOKUP_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut record = [0u32; (RECORD_VALUE_WORD_OFFSET / 4) + 1];
        record[RECORD_VALUE_WORD_OFFSET / 4] = 0xd00d_cafe;
        let mut context = 0u32;

        unsafe {
            RECORD_LOOKUP = fixture_lookup;
            RECEIVED_CONTEXT = ptr::null_mut();
            RECEIVED_KEY = 0;
            LOOKUP_RESULT = record.as_mut_ptr().cast();

            assert_eq!(record_lookup_value_word(ptr::addr_of_mut!(context).cast(), 0x42), 0xd00d_cafe);
            assert_eq!(RECEIVED_CONTEXT, ptr::addr_of_mut!(context).cast());
            assert_eq!(RECEIVED_KEY, 0x42);
        }
    }

    #[test]
    fn returns_zero_when_lookup_returns_null() {
        let _guard = LOOKUP_LOCK.lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            RECORD_LOOKUP = fixture_lookup;
            LOOKUP_RESULT = ptr::null_mut();

            assert_eq!(record_lookup_value_word(ptr::null_mut(), u32::MAX), 0);
        }
    }
}
