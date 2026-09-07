//! ft_stream_read_bounded — original: `FUN_08073e10` @ 0x08073e10 (44 bytes; 22 `bl` call sites).
//!
//! Length-gated wrapper over the buffered-stream reader at 0x08042fd4. It
//! rejects requests above 0x40000 with `!0xcf`, otherwise loads the stream
//! handle from the owner object's word at +0x40000, seeds a one-word count
//! slot, and forwards the stream handle, count slot, destination buffer, and
//! the live r3 word unchanged.
//!
//! Deviation: the lower-level 0x08042fd4 reader stays behind a small
//! host-mockable seam. Target builds transmute the original retailOS entry;
//! host tests replace the seam with a recorder.

const MAX_READ: u32 = 0x40000;
const STREAM_SLOT_WORD: usize = 0x10000;
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
    panic!("ft_stream_read_bounded requires buffered reader 0x08042fd4")
}

static mut BUFFERED_STREAM_READ: BufferedStreamReadFn = firmware_buffered_stream_read;

#[inline(always)]
fn buffered_stream_read() -> BufferedStreamReadFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_READ)) }
}

/// `FUN_08073e10` — wrapper around the buffered-stream reader.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_stream_read_bounded(
    owner: *mut u8,
    buffer: *mut u8,
    len: u32,
    extra: u32,
) -> i32 {
    if len > MAX_READ {
        return TOO_LARGE;
    }
    let mut request = len;
    let stream = owner.cast::<u32>().add(STREAM_SLOT_WORD).read();
    buffered_stream_read()(stream, &mut request, buffer, extra)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_stream_read_bounded, BufferedStreamReadFn, BUFFERED_STREAM_READ, MAX_READ,
        STREAM_SLOT_WORD, TOO_LARGE};
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

    fn owner_with_stream(stream: u32) -> Vec<u32> {
        let mut owner = vec![0u32; STREAM_SLOT_WORD + 1];
        owner[STREAM_SLOT_WORD] = stream;
        owner
    }

    #[test]
    fn forwards_the_stream_slot_and_live_extra_word() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with_stream(0x1234_5678);
        let mut buffer = [0u8; 4];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            SEEN_STREAM = 0;
            SEEN_COUNT = 0;
            SEEN_EXTRA = 0;
            RETURN_VALUE = 0x55;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_bounded(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0x1234,
                0x9abc_def0,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, 0x55);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_STREAM, 0x1234_5678);
            assert_eq!(SEEN_COUNT, 0x1234);
            assert_eq!(SEEN_EXTRA, 0x9abc_def0);
        }
    }

    #[test]
    fn rejects_counts_above_the_hard_cap_without_calling_the_reader() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with_stream(0x1234_5678);
        let mut buffer = [0u8; 4];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_bounded(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                MAX_READ + 1,
                0,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, TOO_LARGE);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn zero_length_still_forwards_the_request_slot() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with_stream(0x8765_4321);
        let mut buffer = [0u8; 1];
        unsafe {
            let saved = BUFFERED_STREAM_READ;
            CALLS = 0;
            SEEN_COUNT = 0xdead_beef;
            RETURN_VALUE = 0x33;
            BUFFERED_STREAM_READ = record_reader as BufferedStreamReadFn;
            let result = ft_stream_read_bounded(
                owner.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                0,
                0x1111_2222,
            );
            BUFFERED_STREAM_READ = saved;
            assert_eq!(result, 0x33);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_STREAM, 0x8765_4321);
            assert_eq!(SEEN_COUNT, 0);
            assert_eq!(SEEN_EXTRA, 0x1111_2222);
        }
    }
}
