//! `tagged_record_init` — original: `FUN_0826fc2c` @ 0x0826fc2c (20 bytes).
//!
//! Raw ARM establishes the true extent as the four instruction words at
//! 0x0826fc2c..0x0826fc3c plus the literal-pool word at 0x0826fc40; the next
//! separately linked function starts at 0x0826fc44. Decoding every ARM B/BL
//! word in `osos.dec` finds exactly 20 direct call sites: all are unconditional
//! plain `bl`, with no predicated forms or plain-B tail calls.
//!
//! # Algorithm
//!
//! Store the incoming payload word at +0x04, install the literal
//! `0x089a5b04` at +0x00, store the low byte of `flag` at +0x08, then return
//! `this` unchanged in r0. There is no NULL or alignment guard.
//!
//! The stored literal does **not** decode as a callable function entry in the
//! static image: it lands at 0x089a5b04, a branch-table case label within a
//! larger body. This initializer never calls through it, so the field remains
//! an opaque 32-bit descriptor and no dispatch seam is invented. Deliberate
//! deviations: none.

/// Literal descriptor the ARM initializer loads from its pool word at
/// 0x0826fc40.
pub const TAGGED_RECORD_DESCRIPTOR: u32 = 0x089a_5b04;

/// A target-width view of the twelve-byte record initialized by
/// [`tagged_record_init`].
#[repr(C)]
pub struct TaggedRecord {
    /// +0x00: opaque descriptor installed by the initializer.
    pub descriptor: u32,
    /// +0x04: incoming payload word.
    pub payload: u32,
    /// +0x08: low byte of the incoming flag register.
    pub flag: u8,
}

/// Initializes a tagged record and returns `this` unchanged.
///
/// # Safety
///
/// `this` must be valid and four-byte aligned for the two word stores and
/// point to at least twelve writable bytes. The original writes every field
/// unconditionally, leaves the three trailing bytes untouched, and discards
/// flag bits 8..31.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_record_init")]
#[inline(never)]
pub unsafe extern "C" fn tagged_record_init(
    this: *mut TaggedRecord,
    payload: u32,
    flag: u32,
) -> *mut TaggedRecord {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).payload), payload);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*this).descriptor),
            TAGGED_RECORD_DESCRIPTOR,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).flag), flag as u8);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_descriptor_payload_and_low_flag_byte_in_store_order() {
        let mut words = [0xfeed_faceu32, 0xa5a5_a5a5, 0x1122_3344, 0xdead_beef];
        let record = unsafe { words.as_mut_ptr().add(1).cast::<TaggedRecord>() };

        let returned = unsafe { tagged_record_init(record, 0x7654_3210, 0xabcd_ef89) };

        assert_eq!(returned, record);
        assert_eq!(words, [0xfeed_face, TAGGED_RECORD_DESCRIPTOR, 0x7654_3210, 0xdead_be89]);
        assert_eq!(unsafe { (*record).flag }, 0x89);
        assert_eq!(unsafe { record.cast::<u8>().add(9).read() }, 0xbe);
        assert_eq!(unsafe { record.cast::<u8>().add(10).read() }, 0xad);
        assert_eq!(unsafe { record.cast::<u8>().add(11).read() }, 0xde);
    }

    #[test]
    fn accepts_zero_payload_and_zero_flag() {
        let mut record = TaggedRecord {
            descriptor: 0xffff_ffff,
            payload: 0xffff_ffff,
            flag: 0xff,
        };

        let returned = unsafe { tagged_record_init(&mut record, 0, 0) };

        assert_eq!(returned, &mut record as *mut TaggedRecord);
        assert_eq!(record.descriptor, TAGGED_RECORD_DESCRIPTOR);
        assert_eq!(record.payload, 0);
        assert_eq!(record.flag, 0);
    }
}
