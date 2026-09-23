//! Native-endian stream word reader — `stream_read_u32` @ 0x08275c88.
//!
//! Original: `FUN_08275c88` @ 0x08275c88 (76 bytes; extent verified from raw
//! osos.dec words: `push {r4,r5,lr}` at 0x08275c88 through `pop {r3,r4,r5,pc}`
//! at 0x08275cd0; the next function begins with `push {r4,lr}` at 0x08275cd4).
//! Decoding the body finds one plain direct `bl`, no predicated direct `bl`,
//! and one indirect `blx` through vtable slot +0x2c. The five inbound direct
//! call sites are outside this function.
//!
//! Algorithm: invoke the reader's three-argument vtable slot +0x2c to fill a
//! four-byte stack word. Return -1 unless it reports exactly four bytes. For a
//! reader whose byte +0x08 is nonzero, byte-swap the successful word before
//! returning it.
//!
//! Deliberate deviations: Rust initializes the local word to zero; retailOS
//! leaves its stack slot uninitialized, but both discard it unless the vtable
//! reports a complete four-byte read.

/// Reader object layout used by `stream_read_u32`.
///
/// On ARM the fields occupy offsets +0x00, +0x04, and +0x08 respectively.
/// Pointer-sized vtable slots preserve their word indices on host fixtures.
#[repr(C)]
pub struct EndianWordReader {
    pub vtable: *const EndianWordReaderVtable,
    pub opaque_04: u32,
    pub swap_word_bytes: u8,
}

/// Vtable prefix used by [`EndianWordReader`].
#[repr(C)]
pub struct EndianWordReaderVtable {
    pub slots_00_14: [usize; 6],
    pub ready_18: unsafe extern "C" fn(this: *mut EndianWordReader) -> i32,
    pub slots_1c_28: [usize; 4],
    pub read_2c: unsafe extern "C" fn(this: *mut EndianWordReader, buf: *mut u8, len: u32) -> i32,
}

/// stream_read_u32 — original: `FUN_08275c88` @ 0x08275c88 (76 bytes; one
/// plain direct `bl`, zero predicated direct `bl`, and one vtable `blx`).
///
/// Reads exactly four bytes through vtable slot +0x2c. A short or failed read
/// returns -1; otherwise the reader's +0x08 byte controls whether the word is
/// byte-swapped before return. The original has no NULL guard.
///
/// # Safety
///
/// `reader` must reference a valid reader object and vtable; its `read_2c`
/// slot must accept a writable four-byte buffer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_u32")]
pub unsafe extern "C" fn stream_read_u32(reader: *mut EndianWordReader) -> u32 {
    let mut value = 0u32;
    let read = unsafe { (*(*reader).vtable).read_2c };
    if unsafe { read(reader, core::ptr::addr_of_mut!(value).cast(), 4) } != 4 {
        return u32::MAX;
    }
    if unsafe { (*reader).swap_word_bytes } != 0 {
        value.swap_bytes()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut VALUE: u32 = 0;
    static mut RESULT: i32 = 0;
    static mut CALL_LEN: u32 = 0;

    unsafe extern "C" fn recording_read(
        _reader: *mut EndianWordReader,
        buf: *mut u8,
        len: u32,
    ) -> i32 {
        unsafe {
            CALL_LEN = len;
            buf.cast::<u32>().write(VALUE);
            RESULT
        }
    }

    unsafe extern "C" fn unused_ready(_reader: *mut EndianWordReader) -> i32 {
        unreachable!()
    }
    static VTABLE: EndianWordReaderVtable = EndianWordReaderVtable {
        slots_00_14: [0; 6],
        ready_18: unused_ready,
        slots_1c_28: [0; 4],
        read_2c: recording_read,
    };

    fn fixture(value: u32, result: i32, swap: bool) -> (parking_lot::MutexGuard<'static, ()>, EndianWordReader) {
        let lock = TEST_LOCK.lock();
        unsafe {
            VALUE = value;
            RESULT = result;
            CALL_LEN = 0;
        }
        (lock, EndianWordReader { vtable: &VTABLE, opaque_04: 0, swap_word_bytes: swap as u8 })
    }

    #[test]
    fn returns_word_after_an_exact_native_endian_read() {
        let (_lock, mut reader) = fixture(0x1234_5678, 4, false);
        assert_eq!(unsafe { stream_read_u32(&mut reader) }, 0x1234_5678);
        assert_eq!(unsafe { CALL_LEN }, 4);
    }

    #[test]
    fn swaps_word_when_reader_marks_opposite_endianness() {
        let (_lock, mut reader) = fixture(0x1234_5678, 4, true);
        assert_eq!(unsafe { stream_read_u32(&mut reader) }, 0x7856_3412);
    }

    #[test]
    fn rejects_short_and_overlong_read_results() {
        for result in [-1, 0, 3, 5] {
            let (_lock, mut reader) = fixture(0x1234_5678, result, false);
            assert_eq!(unsafe { stream_read_u32(&mut reader) }, u32::MAX, "result {result}");
        }
    }
}
