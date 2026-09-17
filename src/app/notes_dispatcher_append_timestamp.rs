//! `notes_dispatcher_append_timestamp` — original: `FUN_0828a3a0` @
//! `0x0828a3a0` (180 bytes, `0x0828a3a0..0x0828a450`).
//!
//! Raw ARM establishes eleven direct calls in the body. A full-image decode
//! finds four incoming unconditional `bl` sites and no predicated incoming
//! `bl` sites. The next separately linked function begins at `0x0828a454`.
//!
//! The notes dispatcher appends a freshly allocated, default-constructed
//! StringObject containing the current normalized datetime when either its
//! byte-source flag at +0x4ec/+4 or its class-0x4a80 field's +0x54/+4 flag is
//! nonzero. It appends the object to the observable array at +0x5b8, then,
//! when the count at +0x5bc exceeds 100, brackets the unported notes-log flush
//! with gateway requests `(16, 1)` and `(16, 250)`.
//!
//! Deliberate deviation: the unported flush at `0x0828b69c` is a direct
//! retailOS call on device and an injectable seam on host. Every other call
//! uses its established Rust port.

use crate::app::byte_source::byte_source_at;
use crate::app::registry::field_dc_as_class_4a80;
use crate::cxx::observable_array::observable_array_append;
use crate::cxx::string_object::{string_default_construct, string_object_assign_cstr, StringObject};
use crate::heap::veneers::operator_new;
use crate::kernel::gateway_request::gateway_request_timed;
use crate::kernel::gateway_request_blocking::gateway_request_blocking;
use crate::time::current_datetime::current_datetime_to_normalized_record;

const OWNER_CLASS_FLAG_OFFSET: usize = 0x4ec;
const CLASS_TIMESTAMP_FLAG_OFFSET: usize = 0x54;
const OWNER_ARRAY_OFFSET: usize = 0x5b8;
const OWNER_ARRAY_COUNT_OFFSET: usize = 0x5bc;
const TIMESTAMP_ALLOCATION_SIZE: usize = 20;
const TIMESTAMP_STRING_OFFSET: usize = 12;
const FLUSH_THRESHOLD: u32 = 100;
const GATEWAY_PAYLOAD: usize = 16;

type FlushNotesLog = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn flush_notes_log(owner: *mut u8) {
    let flush: FlushNotesLog = core::mem::transmute(0x0828_b69cusize);
    flush(owner);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_flush_notes_log(_owner: *mut u8) {}

#[cfg(not(target_os = "none"))]
pub static mut NOTES_DISPATCHER_FLUSH_LOG: FlushNotesLog = missing_flush_notes_log;

#[cfg(not(target_os = "none"))]
unsafe fn flush_notes_log(owner: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(NOTES_DISPATCHER_FLUSH_LOG))(owner);
}

/// Appends a current-time StringObject to `owner`'s notes array when either
/// source flag is set, and flushes a log larger than 100 entries.
///
/// # Safety
/// `owner` must be a retail notes-dispatcher object. Its +0x4ec byte source,
/// +0xdc class field, +0x5b8 observable array, and +0x5bc count must be
/// readable; when either gate is true, its allocation and array vtables must
/// accept the constructed StringObject.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn notes_dispatcher_append_timestamp(owner: *mut u8, timestamp: *const u8) {
    let class_object = field_dc_as_class_4a80(owner);
    let owner_flag = byte_source_at(owner.add(OWNER_CLASS_FLAG_OFFSET).cast(), 4);
    let class_flag = if owner_flag != 0 || class_object.is_null() {
        0
    } else {
        byte_source_at(class_object.add(CLASS_TIMESTAMP_FLAG_OFFSET).cast(), 4)
    };
    if owner_flag == 0 && class_flag == 0 {
        return;
    }

    let allocation = operator_new(TIMESTAMP_ALLOCATION_SIZE);
    let string = string_default_construct(allocation.add(TIMESTAMP_STRING_OFFSET).cast::<StringObject>());
    current_datetime_to_normalized_record(allocation.cast());
    string_object_assign_cstr(string, timestamp);
    observable_array_append(owner.add(OWNER_ARRAY_OFFSET).cast(), allocation);

    let count = core::ptr::read_volatile(owner.add(OWNER_ARRAY_COUNT_OFFSET).cast::<u32>());
    if count > FLUSH_THRESHOLD {
        gateway_request_blocking(GATEWAY_PAYLOAD, 1);
        flush_notes_log(owner);
        gateway_request_timed(GATEWAY_PAYLOAD, 250);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_flush(_owner: *mut u8) {
        CALL_COUNT += 1;
    }

    fn bench() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock()
    }

    #[test]
    fn neither_gate_leaves_owner_untouched() {
        let _bench = bench();
        let mut owner = [0u32; 0x5c0 / 4 + 1];
        unsafe {
            NOTES_DISPATCHER_FLUSH_LOG = record_flush;
            CALL_COUNT = 0;
            notes_dispatcher_append_timestamp(owner.as_mut_ptr().cast(), b"x\0".as_ptr());
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
