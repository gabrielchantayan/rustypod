//! `stream_read_cxx_string` — original: `FUN_080745b8` @ `0x080745b8`.
//!
//! **84 bytes**, from 0x080745b8 through the `pop {r4, r5, pc}` at
//! 0x08074608; the separately linked next function begins at 0x0807460c.
//! A complete aligned ARM B/BL-immediate scan of `osos.dec` finds **six**
//! inbound calls, all unconditional `bl` (no predicated or tail-branch forms):
//! 0x082aae3c, 0x082aaeb0, 0x082aaedc, 0x082aaf44, 0x082ab000, and 0x082ab0e8.
//!
//! Algorithm: read a little-endian u32 byte count through the stream owner,
//! reject counts above 255 through the non-returning heap panic path, then read
//! exactly that many bytes into a 256-byte stack buffer. It terminates the
//! buffer at the count and assigns it as a C string to the destination COW
//! string. No length, stream, or destination guards exist in the raw ARM body.
//!
//! Deliberate deviations: none. This directly composes the existing
//! `stream_read`, `heap_panic`, and `cxx_string_assign_cstr` ports.

use core::mem::MaybeUninit;
use crate::cxx::stream_read::{stream_read, StreamReadOwner};
use crate::cxx::string::cxx_string_assign_cstr;
use crate::heap::veneers::heap_panic;

/// Deserializes a length-prefixed byte string into a COW C++ string.
///
/// Original: `FUN_080745b8` @ 0x080745b8 (84 bytes, six unconditional `bl`
/// call sites verified by decoding every aligned ARM B/BL immediate in
/// `osos.dec`). The firmware stores the count in a four-byte stack word,
/// compares it unsigned against 255, then indexes its 256-byte stack array to
/// add the C-string terminator. Therefore a count of 255 is accepted, while
/// 256 and every larger u32 take the fatal path before the payload read.
///
/// # Safety
///
/// `owner` must satisfy [`stream_read`]'s owner ABI and provide a four-byte
/// little-endian count followed by that many readable bytes. `string` must
/// designate a valid COW string object. The original validates none of these
/// conditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_cxx_string")]
#[inline(never)]
pub unsafe extern "C" fn stream_read_cxx_string(
    owner: *mut StreamReadOwner,
    string: *mut *mut u8,
) {
    let mut bytes = MaybeUninit::<[u8; 256]>::uninit();
    let buffer = bytes.as_mut_ptr().cast::<u8>();
    let mut length = 0u32;

    unsafe { stream_read(owner, (&mut length as *mut u32).cast::<u8>(), 4) };
    if length > 255 {
        unsafe { heap_panic() };
    }
    unsafe { stream_read(owner, buffer, length) };
    unsafe { buffer.add(length as usize).write(0) };
    unsafe { cxx_string_assign_cstr(string, buffer) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::stream_read::{StreamReadOps, STREAM_READ_OPS, STREAM_READ_TEST_LOCK};
    use crate::cxx::string::StringRep;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::vec::Vec;
    use std::vec;

    const SLAB_LEN: usize = 0x1000;
    const DESCRIPTOR_AT: usize = 0x20;
    const OWNER_AT: usize = 0x100;
    const STATE_AT: usize = 0x200;
    const READER_AT: usize = 0x300;

    #[repr(C)]
    struct DescriptorPrefix {
        state_offset: i32,
        _rest: [u32; 2],
    }

    #[repr(C)]
    struct OwnerStateFixture {
        _prefix: [u32; 13],
        reader: u32,
    }

    const _: [u8; 0x34] = [0; core::mem::offset_of!(OwnerStateFixture, reader)];

    #[repr(C)]
    struct OwnerFixture {
        owner_descriptor: u32,
        completed: i32,
    }

    #[repr(C)]
    struct StringStorage {
        rep: StringRep,
        data: [u8; 256],
    }

    const _: [u8; 12] = [0; core::mem::offset_of!(StringStorage, data)];

    #[derive(Default)]
    struct Recorder {
        payload: Vec<u8>,
        prepare_calls: usize,
        read_lengths: Vec<u32>,
        signals: Vec<u32>,
    }

    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        payload: Vec::new(),
        prepare_calls: 0,
        read_lengths: Vec::new(),
        signals: Vec::new(),
    });

    unsafe extern "C" fn prepare(_owner: *mut StreamReadOwner) -> bool {
        RECORDER.lock().prepare_calls += 1;
        true
    }

    unsafe extern "C" fn read(_reader: *mut u8, buffer: *mut u8, requested: u32) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.read_lengths.push(requested);
        if recorder.read_lengths.len() == 1 {
            assert_eq!(requested, 4);
            buffer.cast::<u32>().write(recorder.payload.len() as u32);
        } else {
            assert_eq!(requested as usize, recorder.payload.len());
            core::ptr::copy_nonoverlapping(recorder.payload.as_ptr(), buffer, requested as usize);
        }
        requested as i32
    }

    unsafe extern "C" fn signal(_state: *mut u8, error: u32) -> u32 {
        RECORDER.lock().signals.push(error);
        0
    }

    struct StreamReadOpsRestore(StreamReadOps);

    impl Drop for StreamReadOpsRestore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(STREAM_READ_OPS).write(self.0) };
        }
    }

    unsafe fn fixture() -> Option<*mut OwnerFixture> {
        let base = try_map_u32_slab(hints::CXX_STREAM_READ_CXX_STRING, SLAB_LEN)?;
        core::ptr::write_bytes(base, 0, SLAB_LEN);

        let descriptor_prefix = base.add(DESCRIPTOR_AT).cast::<DescriptorPrefix>();
        let descriptor = descriptor_prefix.cast::<u8>().add(core::mem::size_of::<DescriptorPrefix>());
        let owner = base.add(OWNER_AT).cast::<OwnerFixture>();
        let state = base.add(STATE_AT).cast::<OwnerStateFixture>();

        descriptor_prefix.write(DescriptorPrefix {
            state_offset: (STATE_AT - OWNER_AT) as i32,
            _rest: [0; 2],
        });
        state.write(OwnerStateFixture {
            _prefix: [0; 13],
            reader: base.add(READER_AT) as usize as u32,
        });
        owner.write(OwnerFixture {
            owner_descriptor: descriptor as usize as u32,
            completed: -1,
        });
        Some(owner)
    }

    #[test]
    fn reads_empty_single_and_maximum_length_c_strings() {
        let _stream_guard = STREAM_READ_TEST_LOCK.lock();
        let Some(owner) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/stream_read_cxx_string"));
            return;
        };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_READ_OPS)) };
        let _restore = StreamReadOpsRestore(previous);
        unsafe {
            core::ptr::addr_of_mut!(STREAM_READ_OPS).write(StreamReadOps {
                prepare,
                read,
                signal,
            });
        }

        for payload in [Vec::new(), vec![b'Q'], vec![b'Z'; 255]] {
            {
                let mut recorder = RECORDER.lock();
                recorder.payload = payload.clone();
                recorder.prepare_calls = 0;
                recorder.read_lengths.clear();
                recorder.signals.clear();
            }
            let mut string = StringStorage {
                rep: StringRep {
                    refcount: 0,
                    capacity: 255,
                    length: 0,
                },
                data: [0; 256],
            };
            let mut string_data = string.data.as_mut_ptr();

            unsafe { stream_read_cxx_string(owner.cast(), &mut string_data) };

            let recorder = RECORDER.lock();
            assert_eq!(recorder.prepare_calls, 2);
            assert_eq!(recorder.read_lengths, vec![4, payload.len() as u32]);
            assert!(recorder.signals.is_empty());
            assert_eq!(unsafe { owner.read().completed }, payload.len() as i32);
            assert_eq!(string.rep.length, payload.len() as u32);
            assert_eq!(&string.data[..payload.len()], payload.as_slice());
            assert_eq!(string.data[payload.len()], 0);
        }
    }
}
