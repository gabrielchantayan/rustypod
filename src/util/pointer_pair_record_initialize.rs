//! Pointer-pair record initialization — `FUN_0827263c` @ 0x0827263c.
//!
//! Raw `osos.dec` words establish the exact 44-byte A32 body from 0x0827263c
//! through the `bx lr` at 0x08272664; the next independently entered function
//! begins at 0x08272668. A whole-image A32 decode finds three inbound plain
//! unconditional `bl` calls and no predicated `bl` calls. The function clears
//! bytes 5 and 6, stores two target words at offsets 8 and 12, invokes the
//! 7-byte prefix clear at 0x0827259c, and returns its input pointer unchanged.
//!
//! Deliberate deviation: the record's role and its two pointer-like fields are
//! not recoverable from the assigned function, so the fields stay opaque u32
//! target words rather than host pointers.

/// The 16-byte target layout initialized by [`pointer_pair_record_initialize`].
#[repr(C)]
pub struct PointerPairRecord {
    pub cleared_prefix: [u8; 7],
    pub byte_07: u8,
    pub first: u32,
    pub second: u32,
}

#[inline(never)]
unsafe fn clear_record_prefix(record: *mut PointerPairRecord) {
    unsafe {
        for offset in 0..7 {
            (record.cast::<u8>().add(offset)).write_volatile(0);
        }
    }
}

/// Initializes an opaque record containing two target-width pointer-like words.
///
/// # Safety
///
/// `record` must point to at least 16 writable, four-byte-aligned bytes. The
/// retail function does not check it for NULL or alignment.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pointer_pair_record_initialize(
    record: *mut PointerPairRecord,
    first: u32,
    second: u32,
) -> *mut PointerPairRecord {
    unsafe {
        core::ptr::addr_of_mut!((*record).cleared_prefix[5]).write_volatile(0);
        core::ptr::addr_of_mut!((*record).cleared_prefix[6]).write_volatile(0);
        core::ptr::addr_of_mut!((*record).first).write_volatile(first);
        core::ptr::addr_of_mut!((*record).second).write_volatile(second);
        clear_record_prefix(record);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_the_prefix_and_stores_both_words() {
        let mut record = PointerPairRecord {
            cleared_prefix: [0xa5; 7],
            byte_07: 0xa5,
            first: 0xa5a5_a5a5,
            second: 0xa5a5_a5a5,
        };

        let returned = unsafe {
            pointer_pair_record_initialize(&mut record, 0x1122_3344, 0x5566_7788)
        };

        assert!(core::ptr::eq(returned, &mut record));
        assert_eq!(record.cleared_prefix, [0; 7]);
        assert_eq!(record.byte_07, 0xa5);
        assert_eq!(record.first, 0x1122_3344);
        assert_eq!(record.second, 0x5566_7788);
    }

    #[test]
    fn permits_zero_words_without_touching_byte_seven() {
        let mut record = PointerPairRecord {
            cleared_prefix: [0xff; 7],
            byte_07: 0x3c,
            first: 1,
            second: 1,
        };

        unsafe { pointer_pair_record_initialize(&mut record, 0, 0) };

        assert_eq!(record.cleared_prefix, [0; 7]);
        assert_eq!(record.byte_07, 0x3c);
        assert_eq!((record.first, record.second), (0, 0));
    }
}
