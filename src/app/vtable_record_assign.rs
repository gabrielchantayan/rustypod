//! `vtable_record_assign` — original: `FUN_0828308c` @ `0x0828308c`
//! (**152 bytes**, `0x0828308c..0x08283120`; the next separately linked function
//! starts at `0x08283124`).
//!
//! Raw ARM preserves the destination's vtable word at `+0x00`, then copies the
//! byte fields at `+0x04`, `+0x05`, `+0x30`, and `+0x3c` plus the aligned words
//! at `+0x08..+0x2c`, `+0x34..+0x38`, and `+0x40..+0x4c`. Padding is not read or
//! written. Four inbound direct call sites are plain unconditional `bl`; no
//! predicated `bl` reaches this body. It contains no outbound `bl`.
//!
//! Deliberate deviation: the record's class identity is unrecovered, so this
//! module names only its verified vtable-preserving assignment behavior.

/// An 80-byte vtable-headed record whose non-vtable fields are assigned by
/// [`vtable_record_assign`].
#[repr(C)]
pub struct VtableRecord {
    pub vtable: u32,
    byte_04: u8,
    byte_05: u8,
    padding_06: [u8; 2],
    words_08_to_2c: [u32; 10],
    byte_30: u8,
    padding_31: [u8; 3],
    words_34_to_38: [u32; 2],
    byte_3c: u8,
    padding_3d: [u8; 3],
    words_40_to_4c: [u32; 4],
}

/// Assigns every non-vtable field from `source` to `destination` and returns
/// `destination` unchanged.
///
/// Original: `FUN_0828308c` @ `0x0828308c` (152 bytes; four plain unconditional
/// inbound `bl` call sites, no predicated inbound `bl`, and no outbound calls).
///
/// # Safety
///
/// `destination` and `source` must identify readable/writable, aligned
/// [`VtableRecord`] storage. They must not overlap except when equal.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_record_assign")]
#[inline(never)]
pub unsafe extern "C" fn vtable_record_assign(
    destination: *mut VtableRecord,
    source: *const VtableRecord,
) -> *mut VtableRecord {
    macro_rules! copy_byte {
        ($field:ident) => {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*destination).$field),
                core::ptr::read_volatile(core::ptr::addr_of!((*source).$field)),
            );
        };
    }
    macro_rules! copy_word {
        ($field:ident, $index:expr) => {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*destination).$field).cast::<u32>().add($index),
                core::ptr::read_volatile(core::ptr::addr_of!((*source).$field).cast::<u32>().add($index)),
            );
        };
    }

    copy_byte!(byte_04);
    copy_byte!(byte_05);
    copy_word!(words_08_to_2c, 0);
    copy_word!(words_08_to_2c, 1);
    copy_word!(words_08_to_2c, 2);
    copy_word!(words_08_to_2c, 3);
    copy_word!(words_08_to_2c, 4);
    copy_word!(words_08_to_2c, 5);
    copy_word!(words_08_to_2c, 6);
    copy_word!(words_08_to_2c, 7);
    copy_word!(words_08_to_2c, 8);
    copy_word!(words_08_to_2c, 9);
    copy_byte!(byte_30);
    copy_word!(words_34_to_38, 0);
    copy_word!(words_34_to_38, 1);
    copy_byte!(byte_3c);
    copy_word!(words_40_to_4c, 0);
    copy_word!(words_40_to_4c, 1);
    copy_word!(words_40_to_4c, 2);
    copy_word!(words_40_to_4c, 3);
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::size_of;


    #[repr(align(4))]
    struct AlignedBytes([u8; 80]);

    #[test]
    fn copies_fields_but_preserves_vtable_and_padding() {
        assert_eq!(size_of::<VtableRecord>(), 80);

        let source = AlignedBytes(core::array::from_fn(|index| index as u8));
        let mut destination = AlignedBytes(core::array::from_fn(|index| 0xa0 | index as u8));
        let before = destination.0;

        let returned = unsafe {
            vtable_record_assign(
                destination.0.as_mut_ptr().cast(),
                source.0.as_ptr().cast(),
            )
        };
        assert_eq!(returned as usize, destination.0.as_mut_ptr() as usize);

        for index in 0..80 {
            let copied = matches!(index, 4 | 5 | 0x30 | 0x3c)
                || (8..=0x2f).contains(&index)
                || (0x34..=0x3b).contains(&index)
                || (0x40..=0x4f).contains(&index);
            assert_eq!(destination.0[index], if copied { source.0[index] } else { before[index] }, "index {index:#x}");
        }
    }

    #[test]
    fn self_assignment_leaves_every_byte_unchanged() {
        let mut value = AlignedBytes(core::array::from_fn(|index| (0x5a_u8).wrapping_add(index as u8)));
        let before = value.0;
        unsafe {
            vtable_record_assign(value.0.as_mut_ptr().cast(), value.0.as_ptr().cast());
        }
        assert_eq!(value.0, before);
    }
}
