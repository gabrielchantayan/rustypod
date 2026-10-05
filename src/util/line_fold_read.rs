//! Read a character following a folded line break.
//!
//! Original: FUN_081ba8a4 @ 0x081ba8a4, 140 bytes through 0x081ba930.
//! Raw aligned ARM decoding verifies two inbound plain BLs (0x081ba89c,
//! 0x081ba978), zero predicated BLs. Body: zero direct BLs, three plain
//! indirect BLX sites, zero predicated calls.
//!
//! Query virtual slot +0x20 into a temporary halfword. On failure return zero.
//! For space/tab, preserve it when byte +0x0c is nonzero; otherwise query the
//! same slot directly into the caller's output and normalize its status.
//! For every other character invoke slot +0x08 and return zero. The callers
//! handle LF and CR before entering this helper. Virtual identities remain
//! unresolved; slot names describe only their ABI, not invented callees.
//! Deliberate deviations: native host pointers widen the vtable and object
//! layout; target repr(C) offsets remain +0x20, +0x08, and +0x0c. Rust uses
//! a halfword temporary instead of the stock four-byte stack reservation.

#[repr(C)]
pub struct LineFoldVtable {
    pub unresolved_00_04: [usize; 2],
    pub slot_08: unsafe extern "C" fn(*mut LineFoldReader) -> u32,
    pub unresolved_0c_1c: [usize; 5],
    pub slot_20: unsafe extern "C" fn(*mut LineFoldReader, *mut u16) -> u32,
}

#[repr(C)]
pub struct LineFoldReader {
    pub vtable: *const LineFoldVtable,
    pub unresolved_04_08: [u32; 2],
    pub preserve_whitespace: u8,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(LineFoldReader, preserve_whitespace) == 0x0c);
    assert!(core::mem::offset_of!(LineFoldVtable, slot_08) == 0x08);
    assert!(core::mem::offset_of!(LineFoldVtable, slot_20) == 0x20);
};

/// # Safety
/// `reader` must expose the fields and callable virtual slots above. A
/// successful first query must initialize its halfword. `output` must be
/// writable when whitespace is found; virtual methods retain their own
/// unchecked contracts and may mutate the reader or output even on failure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn line_fold_read(reader: *mut LineFoldReader, output: *mut u16) -> u32 {
    let mut character = core::mem::MaybeUninit::<u16>::uninit();
    let vtable = unsafe { (*reader).vtable };
    if unsafe { ((*vtable).slot_20)(reader, character.as_mut_ptr()) } == 0 {
        return 0;
    }
    let character = unsafe { character.assume_init() };
    if character != 0x20 && character != 9 {
        let vtable = unsafe { (*reader).vtable };
        unsafe { ((*vtable).slot_08)(reader) };
        return 0;
    }
    if unsafe { (*reader).preserve_whitespace } != 0 {
        unsafe { output.write(character) };
        return 1;
    }
    let vtable = unsafe { (*reader).vtable };
    (unsafe { ((*vtable).slot_20)(reader, output) } != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        reader: LineFoldReader,
        characters: [u16; 2],
        statuses: [u32; 2],
        reads: usize,
        rewinds: usize,
        write_on_failure: bool,
        replacement: *const LineFoldVtable,
    }

    unsafe extern "C" fn read(reader: *mut LineFoldReader, output: *mut u16) -> u32 {
        let fixture = unsafe { &mut *reader.cast::<Fixture>() };
        let index = fixture.reads;
        fixture.reads += 1;
        if fixture.statuses[index] != 0 || fixture.write_on_failure {
            unsafe { output.write(fixture.characters[index]) };
        }
        if index == 0 && !fixture.replacement.is_null() {
            fixture.reader.vtable = fixture.replacement;
        }
        fixture.statuses[index]
    }

    unsafe extern "C" fn rewind(reader: *mut LineFoldReader) -> u32 {
        unsafe { (*reader.cast::<Fixture>()).rewinds += 1 };
        0xdeadbeef
    }

    static VTABLE: LineFoldVtable = LineFoldVtable {
        unresolved_00_04: [0; 2], slot_08: rewind,
        unresolved_0c_1c: [0; 5], slot_20: read,
    };

    fn fixture(character: u16, flag: u8, statuses: [u32; 2]) -> Fixture {
        Fixture {
            reader: LineFoldReader { vtable: &VTABLE, unresolved_04_08: [0; 2], preserve_whitespace: flag },
            characters: [character, 0x1234], statuses, reads: 0, rewinds: 0,
            write_on_failure: false, replacement: core::ptr::null(),
        }
    }

    #[test]
    fn initial_failure_does_not_touch_output_or_rewind() {
        let mut f = fixture(0x20, 1, [0, 1]);
        let mut output = 0xbeef;
        assert_eq!(unsafe { line_fold_read(&mut f.reader, &mut output) }, 0);
        assert_eq!((output, f.reads, f.rewinds), (0xbeef, 1, 0));
    }

    #[test]
    fn only_space_and_tab_are_accepted_and_all_nonzero_flags_preserve() {
        for character in [0, 9, 10, 13, 0x20, 0x21, 0x109, 0x120, 0xffff] {
            for flag in [1, 0x80, 0xff] {
                let mut f = fixture(character, flag, [0x80000000, 1]);
                let mut output = 0xbeef;
                let accepted = character == 9 || character == 0x20;
                assert_eq!(unsafe { line_fold_read(&mut f.reader, &mut output) }, accepted as u32);
                assert_eq!(output, if accepted { character } else { 0xbeef });
                assert_eq!((f.reads, f.rewinds), (1, if accepted { 0 } else { 1 }));
            }
        }
    }

    #[test]
    fn stripped_whitespace_returns_second_status_and_preserves_failure_writes() {
        for character in [9, 0x20] {
            for status in [0, 1, 0xffffffff] {
                for write_on_failure in [false, true] {
                    let mut f = fixture(character, 0, [1, status]);
                    f.write_on_failure = write_on_failure;
                    let mut output = 0xbeef;
                    assert_eq!(unsafe { line_fold_read(&mut f.reader, &mut output) }, (status != 0) as u32);
                    assert_eq!(output, if status != 0 || write_on_failure { 0x1234 } else { 0xbeef });
                    assert_eq!((f.reads, f.rewinds), (2, 0));
                }
            }
        }
    }

    unsafe extern "C" fn replacement_read(reader: *mut LineFoldReader, output: *mut u16) -> u32 {
        unsafe { (*reader.cast::<Fixture>()).reads += 1; output.write(0xabcd); }
        7
    }

    #[test]
    fn reloads_virtual_table_after_first_query() {
        let replacement = LineFoldVtable { slot_20: replacement_read, ..VTABLE };
        let mut f = fixture(9, 0, [1, 0]);
        f.replacement = &replacement;
        let mut output = 0;
        assert_eq!(unsafe { line_fold_read(&mut f.reader, &mut output) }, 1);
        assert_eq!((output, f.reads, f.rewinds), (0xabcd, 2, 0));
    }
}
