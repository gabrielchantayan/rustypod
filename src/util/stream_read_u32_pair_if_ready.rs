//! `stream_read_u32_pair_if_ready` — retailOS `FUN_081a3724` at
//! **0x081a3724** (72 bytes, `0x081a3724..0x081a376b`). The next separately
//! entered function begins at `0x081a376c` with `push {r4,r5,r6,lr}`.
//!
//! Raw ARM decoding verifies two unconditional direct `bl` instructions, both
//! to the ported [`crate::util::stream_read_u32::stream_read_u32`], plus one
//! unconditional indirect `blx` through vtable slot `+0x18`; no calls are
//! predicated. A full-image decode finds three inbound unconditional plain
//! `bl` sites (0x081a300c, 0x081a376c, and 0x081a4440), with no predicated
//! direct callers.
//!
//! # Algorithm
//!
//! Probe the reader through its vtable slot `+0x18`. On a zero result, read
//! two native-endian words and store them consecutively; otherwise leave the
//! output unchanged and return zero.
//!
//! # Deliberate deviations
//!
//! The probe's concrete semantic identity remains unrecovered, so its name
//! records only its observed readiness role. Host vtables use pointer-width
//! slots; the target dispatch reads the verified four-byte slot offset.

use crate::util::stream_read_u32::{stream_read_u32, EndianWordReader};
#[cfg(test)]
use crate::util::stream_read_u32::EndianWordReaderVtable;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn reader_is_ready(reader: *mut EndianWordReader) -> i32 {
    type ReaderIsReady = unsafe extern "C" fn(*mut EndianWordReader) -> i32;

    let vtable = reader.cast::<u32>().read_volatile() as usize as *const u32;
    let probe = vtable.add(0x18 / 4).read_volatile() as usize;
    core::mem::transmute::<usize, ReaderIsReady>(probe)(reader)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn reader_is_ready(reader: *mut EndianWordReader) -> i32 {
    ((*(*reader).vtable).ready_18)(reader)
}

/// Reads two stream words when the reader's vtable slot `+0x18` returns zero.
///
/// # Safety
///
/// `reader` must have a callable vtable slot `+0x18` and satisfy
/// [`stream_read_u32`]'s reader contract. `output` must point to two writable
/// `u32` values when the readiness probe succeeds.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_u32_pair_if_ready")]
#[inline(never)]
pub unsafe extern "C" fn stream_read_u32_pair_if_ready(
    _context: *mut u8,
    reader: *mut EndianWordReader,
    output: *mut u32,
) -> u32 {
    if unsafe { reader_is_ready(reader) } != 0 {
        return 0;
    }

    unsafe {
        output.write(stream_read_u32(reader));
        output.add(1).write(stream_read_u32(reader));
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut READY_RESULT: i32 = 0;
    static mut READ_VALUES: [u32; 2] = [0; 2];
    static mut READ_CALLS: usize = 0;

    unsafe extern "C" fn ready(_reader: *mut EndianWordReader) -> i32 {
        unsafe { READY_RESULT }
    }

    unsafe extern "C" fn read_word(_reader: *mut EndianWordReader, output: *mut u8, length: u32) -> i32 {
        unsafe {
            assert_eq!(length, 4);
            output.cast::<u32>().write(READ_VALUES[READ_CALLS]);
            READ_CALLS += 1;
        }
        4
    }

    static VTABLE: EndianWordReaderVtable = EndianWordReaderVtable {
        slots_00_14: [0; 6],
        ready_18: ready,
        slots_1c_28: [0; 4],
        read_2c: read_word,
    };

    fn reader() -> EndianWordReader {
        EndianWordReader { vtable: &VTABLE, opaque_04: 0, swap_word_bytes: 0 }
    }

    #[test]
    fn reads_and_stores_two_words_when_ready() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            READY_RESULT = 0;
            READ_VALUES = [0x1234_5678, 0x9abc_def0];
            READ_CALLS = 0;
            let mut output = [0; 2];
            assert_eq!(stream_read_u32_pair_if_ready(core::ptr::null_mut(), &mut reader(), output.as_mut_ptr()), 1);
            assert_eq!(output, READ_VALUES);
            assert_eq!(READ_CALLS, 2);
        }
    }

    #[test]
    fn leaves_output_unchanged_when_not_ready() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            READY_RESULT = -1;
            READ_CALLS = 0;
            let mut output = [0xa5a5_a5a5, 0x5a5a_5a5a];
            assert_eq!(stream_read_u32_pair_if_ready(core::ptr::null_mut(), &mut reader(), output.as_mut_ptr()), 0);
            assert_eq!(output, [0xa5a5_a5a5, 0x5a5a_5a5a]);
            assert_eq!(READ_CALLS, 0);
        }
    }
}
