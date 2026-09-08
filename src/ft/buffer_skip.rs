//! Buffered stream skip helper — original: `FUN_080bbb00` @ `0x080bbb00`
//! (124 bytes; 18 verified direct `bl` call sites, all unconditional).
//!
//! # Algorithm
//!
//! The owner stores a `buff`-tagged buffered-stream pointer at `+0x00` and a
//! 32 KiB discard area at `+0x14`. Negative distances first ask the stream for
//! its 64-bit position, add the sign-extended distance with ARM wrapping, and
//! seek to that result. Nonnegative distances are consumed as 32 KiB reads
//! into the discard area; the requested chunk is subtracted before each read,
//! so a callee's count-slot update does not affect later chunks. Every callee
//! error returns unchanged. Zero does not call the stream.
//!
//! # Deliberate deviations
//!
//! The tell (`0x08042e70`), seek (`0x08043124`), and read (`0x08042fd4`)
//! helpers are not ported (checked against `names.yaml`). Target builds call
//! their retailOS entries directly; host tests replace their volatile seams.

const DISCARD_OFFSET: usize = 0x14;
const MAX_DISCARD_CHUNK: u32 = 0x8000;

/// ABI of the buffered-stream position helper at `0x08042e70`.
pub type BufferedStreamTellFn = unsafe extern "C" fn(stream: u32, position: *mut u64) -> i32;
/// ABI of the buffered-stream absolute-seek helper at `0x08043124`.
pub type BufferedStreamSeekFn = unsafe extern "C" fn(stream: u32, position: u64) -> i32;
/// ABI of the buffered-stream reader at `0x08042fd4`.
pub type BufferedStreamReadFn = unsafe extern "C" fn(stream: u32, count: *mut u32, buffer: *mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_tell(stream: u32, position: *mut u64) -> i32 {
    let tell: BufferedStreamTellFn = core::mem::transmute(0x08042e70usize);
    tell(stream, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_tell(_stream: u32, _position: *mut u64) -> i32 {
    panic!("buffered_stream_skip requires buffered tell 0x08042e70")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_seek(stream: u32, position: u64) -> i32 {
    let seek: BufferedStreamSeekFn = core::mem::transmute(0x08043124usize);
    seek(stream, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_seek(_stream: u32, _position: u64) -> i32 {
    panic!("buffered_stream_skip requires buffered seek 0x08043124")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_read(
    stream: u32,
    count: *mut u32,
    buffer: *mut u8,
) -> i32 {
    let read: BufferedStreamReadFn = core::mem::transmute(0x08042fd4usize);
    read(stream, count, buffer)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_read(
    _stream: u32,
    _count: *mut u32,
    _buffer: *mut u8,
) -> i32 {
    panic!("buffered_stream_skip requires buffered read 0x08042fd4")
}

pub static mut BUFFERED_STREAM_TELL: BufferedStreamTellFn = firmware_buffered_stream_tell;
pub static mut BUFFERED_STREAM_SEEK: BufferedStreamSeekFn = firmware_buffered_stream_seek;
pub static mut BUFFERED_STREAM_READ: BufferedStreamReadFn = firmware_buffered_stream_read;

#[inline(always)]
unsafe fn buffered_stream_tell() -> BufferedStreamTellFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_TELL))
}

#[inline(always)]
unsafe fn buffered_stream_seek() -> BufferedStreamSeekFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_SEEK))
}

#[inline(always)]
unsafe fn buffered_stream_read() -> BufferedStreamReadFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_READ))
}

/// `FUN_080bbb00` — skips bytes through a buffered stream.
///
/// # Safety
///
/// `owner` must point to an object holding a valid 32-bit buffered-stream
/// handle at `+0x00` and at least 32 KiB of writable discard storage at `+0x14`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.buffered_stream_skip")]
#[inline(never)]
pub unsafe extern "C" fn buffered_stream_skip(owner: *mut u8, distance: i32) -> i32 {
    let stream = owner.cast::<u32>().read();

    if distance < 0 {
        let mut position = 0u64;
        let result = buffered_stream_tell()(stream, &mut position);
        if result != 0 {
            return result;
        }
        return buffered_stream_seek()(stream, position.wrapping_add_signed(distance as i64));
    }

    let mut remaining = distance as u32;
    while remaining != 0 {
        let mut chunk = remaining.min(MAX_DISCARD_CHUNK);
        remaining -= chunk;
        let result = buffered_stream_read()(stream, &mut chunk, owner.add(DISCARD_OFFSET));
        if result != 0 {
            return result;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{buffered_stream_skip, BufferedStreamReadFn, BufferedStreamSeekFn, BufferedStreamTellFn,
        BUFFERED_STREAM_READ, BUFFERED_STREAM_SEEK, BUFFERED_STREAM_TELL, DISCARD_OFFSET};
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TELL_RESULT: i32 = 0;
    static mut TELL_POSITION: u64 = 0;
    static mut TELL_CALLS: usize = 0;
    static mut SEEK_RESULT: i32 = 0;
    static mut SEEK_POSITION: u64 = 0;
    static mut SEEK_CALLS: usize = 0;
    static mut READ_RESULT: i32 = 0;
    static mut READ_CALLS: usize = 0;
    static mut READ_REQUESTS: [u32; 3] = [0; 3];
    static mut READ_BUFFERS: [usize; 3] = [0; 3];
    static mut READ_STREAMS: [u32; 3] = [0; 3];

    #[repr(C, align(4))]
    struct Owner {
        stream: u32,
        reserved: [u8; 16],
        discard: [u8; 0x8000],
    }

    struct Seams {
        _lock: MutexGuard<'static, ()>,
        tell: BufferedStreamTellFn,
        seek: BufferedStreamSeekFn,
        read: BufferedStreamReadFn,
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                BUFFERED_STREAM_TELL = self.tell;
                BUFFERED_STREAM_SEEK = self.seek;
                BUFFERED_STREAM_READ = self.read;
            }
        }
    }

    unsafe extern "C" fn record_tell(_stream: u32, position: *mut u64) -> i32 {
        TELL_CALLS += 1;
        position.write(TELL_POSITION);
        TELL_RESULT
    }

    unsafe extern "C" fn record_seek(_stream: u32, position: u64) -> i32 {
        SEEK_CALLS += 1;
        SEEK_POSITION = position;
        SEEK_RESULT
    }

    unsafe extern "C" fn record_read(stream: u32, count: *mut u32, buffer: *mut u8) -> i32 {
        let call = READ_CALLS;
        READ_CALLS += 1;
        READ_REQUESTS[call] = count.read();
        READ_BUFFERS[call] = buffer as usize;
        READ_STREAMS[call] = stream;
        count.write(0);
        READ_RESULT
    }

    fn install() -> Seams {
        let lock = TEST_LOCK.lock();
        unsafe {
            let seams = Seams {
                _lock: lock,
                tell: BUFFERED_STREAM_TELL,
                seek: BUFFERED_STREAM_SEEK,
                read: BUFFERED_STREAM_READ,
            };
            BUFFERED_STREAM_TELL = record_tell;
            BUFFERED_STREAM_SEEK = record_seek;
            BUFFERED_STREAM_READ = record_read;
            TELL_RESULT = 0;
            TELL_POSITION = 0;
            TELL_CALLS = 0;
            SEEK_RESULT = 0;
            SEEK_POSITION = 0;
            SEEK_CALLS = 0;
            READ_RESULT = 0;
            READ_CALLS = 0;
            READ_REQUESTS = [0; 3];
            READ_BUFFERS = [0; 3];
            READ_STREAMS = [0; 3];
            seams
        }
    }

    fn owner() -> Owner {
        Owner { stream: 0x1234_5678, reserved: [0; 16], discard: [0; 0x8000] }
    }

    #[test]
    fn zero_distance_does_not_touch_the_stream() {
        let _seams = install();
        let mut owner = owner();
        assert_eq!(unsafe { buffered_stream_skip((&mut owner as *mut Owner).cast(), 0) }, 0);
        unsafe {
            assert_eq!(TELL_CALLS, 0);
            assert_eq!(SEEK_CALLS, 0);
            assert_eq!(READ_CALLS, 0);
        }
    }

    #[test]
    fn positive_distance_reads_full_chunks_before_the_tail() {
        let _seams = install();
        let mut owner = owner();
        assert_eq!(unsafe { buffered_stream_skip((&mut owner as *mut Owner).cast(), 0x8001) }, 0);
        unsafe {
            assert_eq!(READ_CALLS, 2);
            assert_eq!(READ_REQUESTS[..2], [0x8000, 1]);
            assert_eq!(READ_STREAMS[..2], [0x1234_5678, 0x1234_5678]);
            assert_eq!(READ_BUFFERS[..2], [owner.discard.as_mut_ptr() as usize; 2]);
            assert_eq!(TELL_CALLS, 0);
            assert_eq!(SEEK_CALLS, 0);
        }
    }

    #[test]
    fn positive_distance_returns_the_first_read_error() {
        let _seams = install();
        unsafe { READ_RESULT = -39; }
        let mut owner = owner();
        assert_eq!(unsafe { buffered_stream_skip((&mut owner as *mut Owner).cast(), 0x10000) }, -39);
        unsafe {
            assert_eq!(READ_CALLS, 1);
            assert_eq!(READ_REQUESTS[0], 0x8000);
        }
    }

    #[test]
    fn negative_distance_wraps_the_told_position_then_seeks() {
        let _seams = install();
        unsafe { TELL_POSITION = 1; }
        let mut owner = owner();
        assert_eq!(unsafe { buffered_stream_skip((&mut owner as *mut Owner).cast(), -2) }, 0);
        unsafe {
            assert_eq!(TELL_CALLS, 1);
            assert_eq!(SEEK_CALLS, 1);
            assert_eq!(SEEK_POSITION, u64::MAX);
            assert_eq!(READ_CALLS, 0);
        }
    }

    #[test]
    fn tell_error_returns_without_seeking_or_reading() {
        let _seams = install();
        unsafe { TELL_RESULT = -17; }
        let mut owner = owner();
        assert_eq!(unsafe { buffered_stream_skip((&mut owner as *mut Owner).cast(), i32::MIN) }, -17);
        unsafe {
            assert_eq!(TELL_CALLS, 1);
            assert_eq!(SEEK_CALLS, 0);
            assert_eq!(READ_CALLS, 0);
        }
    }

    const _: () = assert!(core::mem::offset_of!(Owner, discard) == DISCARD_OFFSET);
}
