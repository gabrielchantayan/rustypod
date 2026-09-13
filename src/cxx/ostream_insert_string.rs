//! `ostream_insert_cxx_string` — original: `FUN_083ead34` @ 0x083ead34.
//!
//! **68 bytes**, exactly 17 ARM instructions from 0x083ead34 through
//! 0x083ead74; the next separately linked function starts at 0x083ead78.
//! Decoding every ARM B/BL word in osos.dec finds six direct call sites, all
//! unconditional `bl` (0x0825c524, 0x0825c540, 0x0825c550, 0x0825c5cc,
//! 0x0825c5e0, and 0x0825c5f4), with no predicated or tail branches.
//!
//! Implements the C++ `operator<<` wrapper for a COW string: load the
//! string's character pointer and its `_Rep` length at `data - 4`, call the
//! shared ostream insertion core, then clear the ostream width word at
//! `this + *(vptr - 12) + 12`. The core's return value is used only to find
//! that adjusted width word; this wrapper returns its original ostream.
//!
//! # Deliberate deviation
//!
//! The shared insertion core is retailOS `FUN_083b5348` @ 0x083b5348 and is
//! not ported. A volatile seam reaches its verified device address on target;
//! host tests replace that one boundary rather than inventing formatting behavior.

/// The unported shared ostream insertion helper's ABI.
pub type OstreamInsertCore = unsafe extern "C" fn(
    stream: *mut u8,
    data: *const u8,
    length: u32,
    width: u32,
) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ostream_insert_core(
    stream: *mut u8,
    data: *const u8,
    length: u32,
    width: u32,
) -> *mut u8 {
    let core: OstreamInsertCore = core::mem::transmute(0x083b_5348usize);
    core(stream, data, length, width)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ostream_insert_core(
    stream: *mut u8,
    _data: *const u8,
    _length: u32,
    _width: u32,
) -> *mut u8 {
    stream
}

/// The device bridge for the unported shared insertion core; host tests
/// temporarily replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut OSTREAM_INSERT_CORE: OstreamInsertCore = firmware_ostream_insert_core;
#[cfg(not(target_os = "none"))]
pub static mut OSTREAM_INSERT_CORE: OstreamInsertCore = missing_ostream_insert_core;

#[inline(always)]
fn ostream_insert_core() -> OstreamInsertCore {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OSTREAM_INSERT_CORE)) }
}

/// Inserts a COW string into an ostream and consumes the stream's width.
///
/// The string object holds its data pointer in its first target word; a
/// libstdc++ `_Rep` stores its character count in the word immediately before
/// the data pointer. `stream` must be a valid ostream object whose vtable has
/// a signed base adjustment word at `vptr - 12`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_insert_cxx_string(
    stream: *mut u8,
    string: *const *const u8,
) -> *mut u8 {
    let data = string.read();
    let length = data.sub(4).cast::<u32>().read();
    let vptr = stream.cast::<*mut u8>().read();
    let adjustment = vptr.sub(12).cast::<i32>().read();
    let width = stream.offset(adjustment as isize).add(12).cast::<u32>();
    let result = (ostream_insert_core())(stream, data, length, width.read());
    let result_vptr = result.cast::<*mut u8>().read();
    let result_adjustment = result_vptr.sub(12).cast::<i32>().read();
    result.offset(result_adjustment as isize).add(12).cast::<u32>().write(0);
    stream
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;
    static mut CALLED_STREAM: usize = 0;
    static mut CALLED_DATA: usize = 0;
    static mut CALLED_LENGTH: u32 = 0;
    static mut CALLED_WIDTH: u32 = 0;
    static mut CORE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_core(
        stream: *mut u8,
        data: *const u8,
        length: u32,
        width: u32,
    ) -> *mut u8 {
        CALLS += 1;
        CALLED_STREAM = stream as usize;
        CALLED_DATA = data as usize;
        CALLED_LENGTH = length;
        CALLED_WIDTH = width;
        CORE_RESULT
    }

    struct CoreRestore {
        _lock: MutexGuard<'static, ()>,
        previous: OstreamInsertCore,
    }

    impl Drop for CoreRestore {
        fn drop(&mut self) {
            unsafe { OSTREAM_INSERT_CORE = self.previous; }
        }
    }

    fn install_core(result: *mut u8) -> CoreRestore {
        let lock = TEST_LOCK.lock();
        unsafe {
            let previous = OSTREAM_INSERT_CORE;
            OSTREAM_INSERT_CORE = recording_core;
            CALLS = 0;
            CALLED_STREAM = 0;
            CALLED_DATA = 0;
            CALLED_LENGTH = 0;
            CALLED_WIDTH = 0;
            CORE_RESULT = result;
            CoreRestore { _lock: lock, previous }
        }
    }

    #[repr(C)]
    struct StringStorage {
        refcount: i32,
        capacity: u32,
        length: u32,
        data: [u8; 8],
    }

    #[repr(align(4))]
    struct AlignedBytes([u8; 64]);

    #[repr(align(4))]
    struct AlignedVtable([u8; 16]);

    impl AlignedBytes {
        fn new(byte: u8) -> Self {
            Self([byte; 64])
        }
    }

    impl AlignedVtable {
        fn new() -> Self {
            Self([0; 16])
        }
    }


    fn store_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn load_word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    /// Installs a vptr with its RTTI base-adjustment word 12 bytes before it.
    fn make_stream(
        stream_bytes: &mut AlignedBytes,
        vtable_bytes: &mut AlignedVtable,
        adjustment: i32,
        width: u32,
    ) -> *mut u8 {
        let stream = unsafe { stream_bytes.0.as_mut_ptr().add(16) };
        let vptr = unsafe { vtable_bytes.0.as_mut_ptr().add(12) };
        store_word(&mut vtable_bytes.0, 0, adjustment as u32);
        unsafe { stream.cast::<*mut u8>().write(vptr); }
        let width_offset = 16isize + adjustment as isize + 12;
        store_word(&mut stream_bytes.0, width_offset as usize, width);
        stream
    }

    #[test]
    fn forwards_rep_data_length_and_current_width_then_clears_width() {
        let mut stream_bytes = AlignedBytes::new(0xa5);
        let mut vtable_bytes = AlignedVtable::new();
        let stream = make_stream(&mut stream_bytes, &mut vtable_bytes, 8, 19);
        let _core = install_core(stream);
        let mut string = StringStorage {
            refcount: 3,
            capacity: 8,
            length: 5,
            data: *b"hello\0zz",
        };
        let string_data = string.data.as_ptr();
        let mut string_object = string.data.as_mut_ptr() as *const u8;

        let returned = unsafe { ostream_insert_cxx_string(stream, &mut string_object) };

        assert_eq!(returned, stream);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(CALLED_STREAM, stream as usize);
            assert_eq!(CALLED_DATA, string_data as usize);
            assert_eq!(CALLED_LENGTH, 5, "length is the _Rep word at data - 4");
            assert_eq!(CALLED_WIDTH, 19, "width is read through vptr - 12");
        }
        assert_eq!(load_word(&stream_bytes.0, 36), 0, "the adjusted width is consumed");
        assert_eq!(stream_bytes.0[35], 0xa5);
        assert_eq!(stream_bytes.0[40], 0xa5);
    }

    #[test]
    fn clears_width_on_the_core_returned_subobject_with_negative_adjustment() {
        let mut input_bytes = AlignedBytes::new(0xa5);
        let mut input_vtable = AlignedVtable::new();
        let input = make_stream(&mut input_bytes, &mut input_vtable, 8, 7);
        let mut result_bytes = AlignedBytes::new(0xa5);
        let mut result_vtable = AlignedVtable::new();
        let result = make_stream(&mut result_bytes, &mut result_vtable, -16, 0xdead_beef);
        let _core = install_core(result);
        let mut string = StringStorage {
            refcount: 0,
            capacity: 8,
            length: 0,
            data: *b"\0unused!",
        };
        let mut string_object = string.data.as_mut_ptr() as *const u8;

        assert_eq!(unsafe { ostream_insert_cxx_string(input, &mut string_object) }, input);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(CALLED_WIDTH, 7);
            assert_eq!(CALLED_LENGTH, 0, "empty strings still enter the shared core");
        }
        assert_eq!(load_word(&input_bytes.0, 36), 7, "only the core-returned object's width clears");
        assert_eq!(load_word(&result_bytes.0, 12), 0, "negative vptr adjustment is honored");
        assert_eq!(result_bytes.0[11], 0xa5);
        assert_eq!(result_bytes.0[28], 0xa5);
    }
}
