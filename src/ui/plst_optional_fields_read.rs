//! Decode the optional five- or eight-byte field prefix of a 'plst' record.
//!
//! `read_plst_optional_fields` is `FUN_080df114` @ `0x080df114` (164 bytes;
//! the next real function starts at `0x080df1b8`). Raw `osos.dec` decoding
//! finds zero direct calls inside it and exactly three incoming direct calls:
//! three plain `bl`, no predicated `bl` forms.
//!
//! It bounds-checks a five-byte prefix, copies it to the parser state's
//! `+0x0c` buffer only before the state becomes latched, optionally extends
//! that prefix to eight bytes, then latches state `+0x10` and advances the
//! cursor. Deliberate deviation: the retail byte-at-a-time stores are retained
//! as an explicit loop rather than relying on a synthesized copy intrinsic.

const DESTINATION_OFFSET: usize = 0x0c;
const LATCH_OFFSET: usize = 0x10;
const SHORT_FIELD_LEN: usize = 5;
const LONG_FIELD_LEN: usize = 8;
const MALFORMED_RECORD: u32 = 6;

/// Read a record's optional field prefix.
///
/// # Safety
///
/// `state` must be readable through `+0x10`; its `+0x0c` target-width pointer
/// must designate at least eight writable bytes when state is not latched.
/// `cursor` and `end` must delimit one readable input allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_plst_optional_fields(
    state: *mut u8,
    cursor: *mut u32,
    end: *const u8,
    include_extra: u32,
) -> u32 {
    let source = unsafe { cursor.read() as usize as *const u8 };
    if unsafe { source.add(SHORT_FIELD_LEN) } > end {
        return MALFORMED_RECORD;
    }

    let destination = unsafe {
        (state.add(DESTINATION_OFFSET) as *const u32).read() as usize as *mut u8
    };
    let mut field_len = SHORT_FIELD_LEN;
    if unsafe { state.add(LATCH_OFFSET).read() } == 0 {
        for offset in 0..SHORT_FIELD_LEN {
            unsafe { destination.add(offset).write(source.add(offset).read()) };
        }
    }

    if include_extra != 0 {
        if unsafe { source.add(LONG_FIELD_LEN) } > end {
            return MALFORMED_RECORD;
        }
        field_len = LONG_FIELD_LEN;
        if unsafe { state.add(LATCH_OFFSET).read() } == 0 {
            for offset in SHORT_FIELD_LEN..LONG_FIELD_LEN {
                unsafe { destination.add(offset).write(source.add(offset).read()) };
            }
        }
    }

    unsafe {
        state.add(LATCH_OFFSET).write(1);
        cursor.write(source.add(field_len) as usize as u32);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn validates_lengths_copies_once_and_advances_cursor() {
        let Some(slab) = try_map_u32_slab(hints::PLST_OPTIONAL_FIELDS_READ, 0x1000) else {
            assert!(note_missing_u32_fixture("ui/plst_optional_fields_read"));
            return;
        };
        unsafe {
            let state = slab;
            let source = slab.add(0x100);
            let destination = slab.add(0x300);
            core::ptr::copy_nonoverlapping([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17].as_ptr(), source, 8);
            destination.write_bytes(0xa5, 8);
            (state.add(DESTINATION_OFFSET) as *mut u32).write(destination as usize as u32);

            let mut cursor = source as usize as u32;
            assert_eq!(read_plst_optional_fields(state, &mut cursor, source.add(4), 0), MALFORMED_RECORD);
            assert_eq!(cursor, source as usize as u32);
            assert_eq!(*state.add(LATCH_OFFSET), 0);
            assert_eq!(&*core::ptr::slice_from_raw_parts(destination, 8), &[0xa5; 8]);

            assert_eq!(read_plst_optional_fields(state, &mut cursor, source.add(5), 0), 0);
            assert_eq!(cursor, source.add(5) as usize as u32);
            assert_eq!(&*core::ptr::slice_from_raw_parts(destination, 8), &[0x10, 0x11, 0x12, 0x13, 0x14, 0xa5, 0xa5, 0xa5]);

            state.add(LATCH_OFFSET).write(0);
            cursor = source as usize as u32;
            destination.write_bytes(0xa5, 8);
            assert_eq!(read_plst_optional_fields(state, &mut cursor, source.add(7), 1), MALFORMED_RECORD);
            assert_eq!(cursor, source as usize as u32);
            assert_eq!(&*core::ptr::slice_from_raw_parts(destination, 8), &[0x10, 0x11, 0x12, 0x13, 0x14, 0xa5, 0xa5, 0xa5]);

            state.add(LATCH_OFFSET).write(0);
            cursor = source as usize as u32;
            destination.write_bytes(0xa5, 8);
            assert_eq!(read_plst_optional_fields(state, &mut cursor, source.add(8), 1), 0);
            assert_eq!(cursor, source.add(8) as usize as u32);
            assert_eq!(&*core::ptr::slice_from_raw_parts(destination, 8), &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);

            destination.write_bytes(0xa5, 8);
            cursor = source as usize as u32;
            assert_eq!(read_plst_optional_fields(state, &mut cursor, source.add(8), 1), 0);
            assert_eq!(&*core::ptr::slice_from_raw_parts(destination, 8), &[0xa5; 8]);
        }
    }
}
