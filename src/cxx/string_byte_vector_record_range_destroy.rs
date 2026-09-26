//! `string_byte_vector_record_range_destroy` — original: `FUN_083e3ea8` @
//! 0x083e3ea8 (40 bytes).
//!
//! Raw ARM establishes the exact extent 0x083e3ea8..0x083e3ecf: the following
//! independently linked function begins at 0x083e3ed0. The ten words save r2
//! (end) and r1 (begin), branch into the loop tail, then call
//! `record_string_byte_vector_destroy` @ 0x082678d4 for each record and advance
//! by 0x20. r0 is unused. The body has one unconditional `bl`, no predicated
//! `bl`, and whole-image A32 decoding finds two unconditional inbound `bl` sites
//! (0x082679f8 and 0x083e3f40), with no predicated inbound `bl` sites.
//!
//! Algorithm: destroy the 32-byte `StringByteVectorRecord` values in the
//! half-open target-address range `[begin, end)` in ascending address order.
//!
//! # Deliberate deviation
//!
//! The target stride is retained as raw target bytes rather than Rust's host
//! `size_of::<StringByteVectorRecord>()`, because `StringObject` widens on host.
//! The injected helper makes this target-layout contract testable without
//! dereferencing synthetic records.

use crate::cxx::record_string_byte_vector_destroy::record_string_byte_vector_destroy;
use crate::cxx::string_byte_vector_record::StringByteVectorRecord;

type RecordDestroy = unsafe extern "C" fn(*mut StringByteVectorRecord) -> *mut StringByteVectorRecord;

const RECORD_STRIDE: usize = 0x20;

/// Destroys the target-layout records in `[begin, end)`. The first argument is
/// the ignored r0 argument retained for the retail ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_byte_vector_record_range_destroy")]
#[inline(never)]
pub unsafe extern "C" fn string_byte_vector_record_range_destroy(
    _ignored: *mut u8,
    begin: *mut u8,
    end: *mut u8,
) {
    unsafe { string_byte_vector_record_range_destroy_with(begin, end, record_string_byte_vector_destroy) }
}

#[inline(always)]
unsafe fn string_byte_vector_record_range_destroy_with(
    mut begin: *mut u8,
    end: *mut u8,
    destroy: RecordDestroy,
) {
    while begin != end {
        destroy(begin.cast());
        begin = begin.add(RECORD_STRIDE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DESTROYED: [usize; 3] = [0; 3];
    static mut DESTROY_COUNT: usize = 0;

    unsafe extern "C" fn recording_destroy(record: *mut StringByteVectorRecord) -> *mut StringByteVectorRecord {
        DESTROYED[DESTROY_COUNT] = record as usize;
        DESTROY_COUNT += 1;
        record
    }

    #[test]
    fn skips_an_empty_range() {
        let _lock = LOCK.lock();
        let mut storage = [0u8; RECORD_STRIDE];
        unsafe {
            DESTROY_COUNT = 0;
            let start = storage.as_mut_ptr();
            string_byte_vector_record_range_destroy_with(start, start, recording_destroy);
            assert_eq!(DESTROY_COUNT, 0);
        }
    }

    #[test]
    fn destroys_each_target_sized_record_in_order() {
        let _lock = LOCK.lock();
        let mut storage = [0u8; RECORD_STRIDE * 3];
        unsafe {
            DESTROY_COUNT = 0;
            let start = storage.as_mut_ptr();
            string_byte_vector_record_range_destroy_with(start, start.add(RECORD_STRIDE * 3), recording_destroy);
            assert_eq!(DESTROY_COUNT, 3);
            assert_eq!(DESTROYED, [start as usize, start.add(RECORD_STRIDE) as usize, start.add(RECORD_STRIDE * 2) as usize]);
        }
    }
}
