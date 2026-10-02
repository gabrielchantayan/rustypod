//! User-record constructor — `FUN_082801bc` @ `0x082801bc`.
//! True extent: 60 bytes (56 instruction bytes, vtable literal at
//! 0x082801f4); the next real function starts at 0x082801f8.
//! Raw A32 decoding finds two inbound plain BLs at 0x081364bc and
//! 0x08136760, no predicated BLs. Two outbound plain BLs, no predicated
//! calls: 0x08037db8 and 0x08037dc8, verified IRAM zero-fill veneers.
//!
//! Installs the string-derived record's vtable, clears its payload word,
//! two ten-byte calendar records and 16-bit user ID, and returns this.
//! The Users serializer identifies the record's role; the raw caller at
//! 0x081364a8 allocates 32 bytes and assigns its ID and string payload.
//! Bytes 30..32 are allocation padding and remain untouched.
//!
//! Deliberate deviations: calls existing Rust memzero ports rather than
//! IRAM veneers; their differing return values are ignored here. Target
//! pointers remain u32 words on hosts so all firmware offsets are retained.
//! The exact retail class name and meanings of the two dates are unknown.

use crate::libc::memzero::{memzero, memzero_aligned};

pub const USER_RECORD_VTABLE: u32 = 0x089a_6044;

#[repr(C)]
pub struct UserRecord {
    pub vtable: u32,
    pub payload: u32,
    pub first_datetime: [u8; 10],
    pub second_datetime: [u8; 10],
    pub user_id: u16,
    pub padding: [u8; 2],
}

/// Initialize a word-aligned, writable 32-byte user record in place.
///
/// # Safety
/// `record` must point to valid storage for `UserRecord`. As in retailOS,
/// no NULL check is performed. The target pointer words are not host pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn user_record_construct(record: *mut UserRecord) -> *mut UserRecord {
    core::ptr::addr_of_mut!((*record).vtable).write(USER_RECORD_VTABLE);
    core::ptr::addr_of_mut!((*record).payload).write(0);
    memzero_aligned(core::ptr::addr_of_mut!((*record).first_datetime).cast(), 10);
    memzero(core::ptr::addr_of_mut!((*record).second_datetime).cast(), 10);
    core::ptr::addr_of_mut!((*record).user_id).write(0);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_storage_initialization_preserves_padding_and_neighbors() {
        // Exercise distinct word-aligned object placements in guarded storage.
        for prefix_words in 1..=2 {
            for dirty in [0x00u8, 0x55, 0xa5, 0xff] {
                let mut storage = [u32::from_ne_bytes([dirty; 4]); 12];
                let record = unsafe { storage.as_mut_ptr().add(prefix_words).cast::<UserRecord>() };
                let mut expected = [dirty; 48];
                let start = prefix_words * 4;
                expected[start..start + 4].copy_from_slice(&USER_RECORD_VTABLE.to_ne_bytes());
                expected[start + 4..start + 30].fill(0);
                for _ in 0..2 {
                    assert_eq!(unsafe { user_record_construct(record) }, record);
                    let actual = unsafe {
                        core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 48)
                    };
                    assert_eq!(actual, expected);
                }
            }
        }
    }
}
