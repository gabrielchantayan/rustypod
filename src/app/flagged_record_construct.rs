//! Constructor prefix for a flagged record associated with an opaque source.
//!
//! Original: `FUN_08269010` @ `0x08269010`. True extent: 36 bytes,
//! 32 instruction bytes followed by the vtable literal at `0x08269030`.
//! The next independent function begins at `0x08269034` with a NULL check.
//! Whole-image aligned A32 decoding finds two incoming plain BLs at
//! `0x08269204` and `0x082699dc`, zero predicated BLs, and no outgoing BLs.
//!
//! Installs vtable `0x089a8130`, sets byte +4 to one, stores the source
//! word at +12, clears word +8, and returns storage unchanged in r0.
//! Both callers allocate derived records (0x18 and 0x14 bytes) and replace
//! the vtable after construction. Bytes +5..+7 and derived fields are not
//! initialized. The concrete class and the flag's meaning are unestablished.
//! Deliberate deviations: none; opaque target addresses remain u32 on hosts.

/// # Safety
/// `storage` must be four-byte aligned and writable for four words.
/// `source` is an opaque target word and is not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_record_construct(storage: *mut u32, source: u32) -> *mut u32 {
    storage.write(0x089a_8130);
    storage.add(1).cast::<u8>().write(1);
    storage.add(3).write(source);
    storage.add(2).write(0);
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_prefix_preserving_padding_and_derived_fields() {
        for source in [0, 1, 0x0800_0000, u32::MAX] {
            let mut words = [0xa5a5_5a5au32; 8];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let returned = unsafe { flagged_record_construct(storage, source) };
            assert_eq!(returned, storage);
            let mut flag_bytes = 0xa5a5_5a5au32.to_ne_bytes();
            flag_bytes[0] = 1;
            assert_eq!(words, [0xa5a5_5a5a, 0x089a_8130,
                u32::from_ne_bytes(flag_bytes), 0, source,
                0xa5a5_5a5a, 0xa5a5_5a5a, 0xa5a5_5a5a]);
        }
    }

    #[test]
    fn reconstruction_resets_base_state_without_touching_padding() {
        let mut words = [0x1234_5678u32, u32::from_ne_bytes([0xff, 2, 3, 4]), 99, 7, 8, 9];
        unsafe { flagged_record_construct(words.as_mut_ptr(), 0); }
        assert_eq!(words, [0x089a_8130, u32::from_ne_bytes([1, 2, 3, 4]), 0, 0, 8, 9]);
    }
}
