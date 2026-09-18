//! Optional-pointer record initializer.
//!
//! `optional_pointer_record_init` — original: `FUN_081caf88` @
//! **0x081caf88**. Raw `osos.dec` establishes its 32-byte extent:
//! 0x081caf88..0x081cafa8, ending at `bx lr`; the next independently linked
//! function starts with `cmp r1,#0x2600` at 0x081cafa8. A whole-image A32
//! decode finds four incoming plain `bl` calls and no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Set the first byte to whether `value` is nonzero, store `kind` in the
//! second byte, then write `value`, `context`, and zero to the three following
//! target words. The original has no calls and no NULL or alignment checks.
//!
//! Deliberate deviation: `value` and `context` remain u32 target words on
//! hosts, preserving the retail four-byte field offsets rather than using
//! host-width pointers.

/// The 16-byte target layout initialized by [`optional_pointer_record_init`].
#[repr(C)]
pub struct OptionalPointerRecord {
    pub has_value: u8,
    pub kind: u8,
    pub padding_02: [u8; 2],
    pub value: u32,
    pub context: u32,
    pub reserved: u32,
}

/// Initializes a target-layout optional-pointer record in caller-provided storage.
///
/// # Safety
///
/// `record` must point to at least 16 writable, four-byte-aligned bytes. The
/// retail function does not check it for NULL or alignment.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_pointer_record_init(
    record: *mut OptionalPointerRecord,
    value: u32,
    context: u32,
    kind: u8,
) {
    unsafe {
        core::ptr::addr_of_mut!((*record).has_value).write_volatile((value != 0) as u8);
        core::ptr::addr_of_mut!((*record).kind).write_volatile(kind);
        core::ptr::addr_of_mut!((*record).value).write_volatile(value);
        core::ptr::addr_of_mut!((*record).context).write_volatile(context);
        core::ptr::addr_of_mut!((*record).reserved).write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_nonzero_value_and_preserves_target_offsets() {
        let mut record = OptionalPointerRecord {
            has_value: 0xa5,
            kind: 0xa5,
            padding_02: [0xa5; 2],
            value: 0xa5a5_a5a5,
            context: 0xa5a5_a5a5,
            reserved: 0xa5a5_a5a5,
        };

        unsafe { optional_pointer_record_init(&mut record, 0x1234_5678, 0x9abc_def0, 0x7e) };

        assert_eq!(record.has_value, 1);
        assert_eq!(record.kind, 0x7e);
        assert_eq!(record.padding_02, [0xa5; 2]);
        assert_eq!(record.value, 0x1234_5678);
        assert_eq!(record.context, 0x9abc_def0);
        assert_eq!(record.reserved, 0);
    }

    #[test]
    fn initializes_zero_value_as_absent() {
        let mut record = OptionalPointerRecord {
            has_value: 1,
            kind: 1,
            padding_02: [0; 2],
            value: 1,
            context: 1,
            reserved: 1,
        };

        unsafe { optional_pointer_record_init(&mut record, 0, 0, 0) };

        assert_eq!(record.has_value, 0);
        assert_eq!(record.kind, 0);
        assert_eq!(record.value, 0);
        assert_eq!(record.context, 0);
        assert_eq!(record.reserved, 0);
    }
}
