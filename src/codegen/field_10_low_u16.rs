//! Low-halfword accessor for an opaque codegen-adjacent record.
//!
//! The direct caller `FUN_08295e9c` treats the value at `+0x10` as an
//! event/control code (comparing it with `0x10`, `0x59`, `0x5a`, `0x6e`, and
//! `0x6f`). Its containing record has not been recovered enough to name a
//! Rust type, so this port preserves the retail ABI as an opaque byte pointer.

/// field_10_low_u16 — original: `FUN_082a4f58` @ `0x082a4f58`
/// (16 bytes; 5 direct `bl` call sites).
///
/// Loads the 32-bit word at `this + 0x10` and returns precisely its low 16
/// bits, zero-extended to `u32`. The retail ARM sequence is `ldr; lsl #16;
/// lsr #16; bx lr`; it has no NULL guard and does not modify the record.
///
/// # Safety
///
/// `this` must point to an aligned readable record containing a `u32` at
/// byte offset `0x10`, just as required by the original `ldr`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn field_10_low_u16(this: *const u8) -> u32 {
    ((this.add(0x10) as *const u32).read()) & 0xffff
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIELD_OFFSET: usize = 0x10;

    #[repr(align(4))]
    struct Record([u8; 0x14]);

    impl Record {
        fn with_field(word: u32) -> Self {
            let mut record = Self([0xa5; 0x14]);
            record.0[FIELD_OFFSET..FIELD_OFFSET + 4].copy_from_slice(&word.to_ne_bytes());
            record
        }

        fn field(&self) -> u32 {
            u32::from_ne_bytes(self.0[FIELD_OFFSET..FIELD_OFFSET + 4].try_into().unwrap())
        }
    }

    #[test]
    fn returns_only_the_low_halfword_for_every_high_low_combination() {
        for (high, low) in [(0x0000u16, 0x0000u16), (0xffff, 0xffff), (0x1234, 0xabcd),
                            (0xabcd, 0x1234), (0x8000, 0x7fff), (0x7fff, 0x8000)] {
            let record = Record::with_field((u32::from(high) << 16) | u32::from(low));
            assert_eq!(unsafe { field_10_low_u16(record.0.as_ptr()) }, u32::from(low));
        }
    }

    #[test]
    fn preserves_low_halfword_boundary_patterns() {
        for word in [0x0000_0000u32, 0xffff_0000, 0x0000_ffff, 0xffff_ffff,
                     0xaaaa_5555, 0x5555_aaaa] {
            let record = Record::with_field(word);
            assert_eq!(unsafe { field_10_low_u16(record.0.as_ptr()) }, word & 0xffff);
        }
    }

    #[test]
    fn aliases_observe_the_same_word_without_mutating_the_record() {
        let mut record = Record::with_field(0xdead_beef);
        let read_alias = record.0.as_ptr();
        let write_alias = record.0.as_mut_ptr();
        let before_first_read = record.0;

        assert_eq!(unsafe { field_10_low_u16(read_alias) }, 0xbeef);
        assert_eq!(record.0, before_first_read, "the accessor is read-only");

        unsafe { (write_alias.add(FIELD_OFFSET) as *mut u32).write(0x0123_4567) };
        let before_second_read = record.0;
        assert_eq!(unsafe { field_10_low_u16(read_alias) }, 0x4567);
        assert_eq!(record.0, before_second_read, "the accessor is read-only");
        assert_eq!(record.field(), 0x0123_4567);
    }
}
