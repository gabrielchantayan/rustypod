//! ft_stream_read_capped — original: `FUN_080764e4` @ 0x080764e4 (44 bytes; 13 `bl` call sites).
//!
//! Size-gated wrapper over the buffered-stream reader at 0x08042fd4. The
//! owner object carries the stream handle in its word at +0x00 and a size
//! limit in its word at +0x08. A request longer than the limit (unsigned
//! compare) is rejected with `!0xcf` (-208) without touching the stream;
//! otherwise the wrapper loads the stream handle from +0x00, seeds a
//! one-word count slot with the requested length, and forwards the stream
//! handle, count slot, destination buffer, and the limit word itself as the
//! live r3 fourth argument.
//!
//! Verified: the next separately linked function (`resource_fork_probe`)
//! starts at 0x08076510, confirming the exact 44-byte extent. Decoding
//! every ARM B/BL word in osos.dec found exactly 13 inbound branches, all
//! unconditional `bl` at 0x08063f74, 0x0806405c, 0x0807f900, 0x0807f958,
//! 0x0807fa24, 0x0807fb2c, 0x0807fc0c, 0x0807fcd0, 0x080963e0, 0x0809ed08,
//! 0x0809edf4, 0x080be5f0, and 0x080be618; no predicated BL, no plain B
//! callers, and no data-word references (not virtually dispatched).
//!
//! Deviation: the lower-level 0x08042fd4 reader stays behind a small
//! host-mockable seam. Target builds transmute the original retailOS entry;
//! host tests replace the seam with a recorder. Same seam pattern as the
//! sibling wrapper `ft_stream_read_bounded` @ 0x08073e10.

const STREAM_WORD: usize = 0;
const LIMIT_WORD: usize = 2;
const TOO_LARGE: i32 = !0xcf_i32;

type BufferedStreamReadFn = unsafe extern "C" fn(u32, *mut u32, *mut u8, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_read(
    stream: u32,
    count: *mut u32,
    buffer: *mut u8,
    extra: u32,
) -> i32 {
    let f: BufferedStreamReadFn = core::mem::transmute(0x08042fd4usize);
    f(stream, count, buffer, extra)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_read(
    _stream: u32,
    _count: *mut u32,
    _buffer: *mut u8,
    _extra: u32,
) -> i32 {
    panic!("ft_stream_read_capped requires buffered reader 0x08042fd4")
}

static mut BUFFERED_STREAM_READ: BufferedStreamReadFn = firmware_buffered_stream_read;

#[inline(always)]
fn buffered_stream_read() -> BufferedStreamReadFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_READ)) }
}

/// `FUN_080764e4` — wrapper around the buffered-stream reader.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_stream_read_capped(
    owner: *mut u8,
    buffer: *mut u8,
    len: u32,
) -> i32 {
    let words = owner.cast::<u32>();
    let limit = words.add(LIMIT_WORD).read();
    if limit < len {
        return TOO_LARGE;
    }
    let mut request = len;
    let stream = words.add(STREAM_WORD).read();
    buffered_stream_read()(stream, &mut request, buffer, limit)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_stream_read_capped, BufferedStreamReadFn, BUFFERED_STREAM_READ, LIMIT_WORD,
        STREAM_WORD, TOO_LARGE};
    use parking_lot::Mutex;
    use std::vec;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut CALLS: u32 = 0;
    static mut SEEN_STREAM: u32 = 0;
    static mut SEEN_COUNT: u32 = 0;
    static mut SEEN_EXTRA: u32 = 0;
    static mut RETURN_VALUE: i32 = 0;

    unsafe extern "C" fn record_reader(
        stream: u32,
        count: *mut u32,
        _buffer: *mut u8,
        extra: u32,
    ) -> i32 {
        CALLS = CALLS.wrapping_add(1);
        SEEN_STREAM = stream;
        SEEN_COUNT = count.read();
        SEEN_EXTRA = extra;
        count.write(count.read().wrapping_sub(1));
        RETURN_VALUE
    }

    fn owner_with(stream: u32, limit: u32) -> Vec<u32> {
        let mut owner = vec![0u32; LIMIT_WORD + 1];
        owner[STREAM_WORD] = stream;
        owner[LIMIT_WORD] = limit;
        owner
    }

    #[test]
    fn forwards_stream_count_buffer_and_limit_word() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with(0x1234_5678, 0x0001_0000);
        let mut buffer = [0u8; 4];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            SEEN_STREAM = 0;
            SEEN_COUNT = 0;
            SEEN_EXTRA = 0;
            RETURN_VALUE = 0x55;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_capped(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0x1234,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, 0x55);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_STREAM, 0x1234_5678);
            assert_eq!(SEEN_COUNT, 0x1234);
            assert_eq!(SEEN_EXTRA, 0x0001_0000);
        }
    }

    #[test]
    fn rejects_len_above_the_owner_limit_without_calling_the_reader() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with(0x1234_5678, 0x100);
        let mut buffer = [0u8; 4];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_capped(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0x101,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, TOO_LARGE);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn len_equal_to_the_limit_is_accepted() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with(0x8765_4321, 0x400);
        let mut buffer = [0u8; 1];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            SEEN_COUNT = 0xdead_beef;
            RETURN_VALUE = 0x33;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_capped(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0x400,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, 0x33);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_STREAM, 0x8765_4321);
            assert_eq!(SEEN_COUNT, 0x400);
            assert_eq!(SEEN_EXTRA, 0x400);
        }
    }

    #[test]
    fn zero_length_still_forwards_the_request_slot() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with(0xdead_beef, 0);
        let mut buffer = [0u8; 1];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            SEEN_COUNT = 0xdead_beef;
            RETURN_VALUE = 0;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_capped(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, 0);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_STREAM, 0xdead_beef);
            assert_eq!(SEEN_COUNT, 0);
            assert_eq!(SEEN_EXTRA, 0);
        }
    }
}
