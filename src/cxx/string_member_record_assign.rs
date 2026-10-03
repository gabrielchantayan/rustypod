//! Fieldwise assignment of the polymorphic record with a StringObject member.

use super::string_object::{string_object_assign, StringObject};

/// Target layout: 56 bytes; opaque scalar fields retain their 32-bit widths.
/// Only actual pointers widen on hosts; use fields rather than target offsets.
#[repr(C)]
pub struct StringMemberRecord {
    pub vtable: *const (),
    pub words: [u32; 7],
    pub string: StringObject,
    pub auxiliary: u32,
    pub flag: u8,
    pub padding: [u8; 3],
    pub trailing_words: [u32; 2],
}

/// Original: FUN_08271688 @ 0x08271688, 120 code bytes, ending before
/// the next function at 0x08271700. Raw-word scan: two inbound plain BLs,
/// zero predicated; body has one plain BL and zero predicated BLs.
/// Copies seven words (+4..+28), assigns the embedded StringObject (+32),
/// then copies the +40 word, +44 byte, and +48/+52 words; returns this.
/// Preserves the outer vtable, embedded vtable, and +45..+47 padding.
/// There is no outer self-assignment guard: the embedded assignment owns
/// its own guard. Deliberate deviations: host pointer fields widen under
/// repr(C); string allocation/clear retain the existing callee's seams.
///
/// # Safety
/// Both operands must be aligned, live initialized records. They may be the
/// same object; otherwise their storage must not overlap. Embedded strings
/// must satisfy string_object_assign's payload and dispatch contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_member_record_assign(
    this: *mut StringMemberRecord,
    source: *const StringMemberRecord,
) -> *mut StringMemberRecord {
    for index in 0..7 {
        (*this).words[index] = (*source).words[index];
    }
    string_object_assign(
        core::ptr::addr_of_mut!((*this).string),
        core::ptr::addr_of!((*source).string),
    );
    (*this).auxiliary = (*source).auxiliary;
    (*this).flag = (*source).flag;
    (*this).trailing_words[0] = (*source).trailing_words[0];
    (*this).trailing_words[1] = (*source).trailing_words[1];
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seed: u32) -> StringMemberRecord {
        StringMemberRecord {
            vtable: seed as usize as *const (),
            words: core::array::from_fn(|i| seed.wrapping_add(i as u32)),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            auxiliary: seed ^ u32::MAX,
            flag: seed as u8,
            padding: [seed as u8; 3],
            trailing_words: [seed.rotate_left(5), seed.rotate_right(7)],
        }
    }

    #[test]
    fn assigns_scalars_without_copying_vtable_or_padding() {
        let source = record(0xffff_ff80);
        let mut destination = record(0x1234_5678);
        let vtable = destination.vtable;
        let padding = destination.padding;
        let pointer = &mut destination as *mut _;
        assert_eq!(unsafe { string_member_record_assign(pointer, &source) }, pointer);
        assert_eq!(destination.words, source.words);
        assert_eq!(destination.auxiliary, source.auxiliary);
        assert_eq!(destination.flag, 0x80);
        assert_eq!(destination.trailing_words, source.trailing_words);
        assert_eq!(destination.vtable, vtable);
        assert_eq!(destination.padding, padding);
        assert!(destination.string.vtable.is_null());
    }

    #[test]
    fn self_assignment_preserves_nonempty_payload_without_dispatch() {
        let mut payload = *b"record\0";
        let mut object = record(0x8000_0001);
        object.string.payload = payload.as_mut_ptr();
        let pointer = &mut object as *mut _;
        assert_eq!(unsafe { string_member_record_assign(pointer, pointer) }, pointer);
        assert_eq!(object.words, [0x8000_0001, 0x8000_0002, 0x8000_0003,
            0x8000_0004, 0x8000_0005, 0x8000_0006, 0x8000_0007]);
        assert_eq!(object.string.payload, payload.as_mut_ptr());
        assert_eq!(payload, *b"record\0");
        assert_eq!(object.auxiliary, 0x7fff_fffe);
        assert_eq!(object.flag, 1);
        assert_eq!(object.padding, [1; 3]);
        assert_eq!(object.trailing_words, [0x30, 0x0300_0000]);
    }
}
