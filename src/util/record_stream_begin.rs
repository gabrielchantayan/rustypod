//! `record_stream_begin` — original: `FUN_0839b864` @ **0x0839b864**.
//!
//! Raw ARM is exactly **156 bytes**, `0x0839b864..0x0839b900`: the next
//! separately linked function starts at `0x0839b900`. Decoding every ARM
//! `B`/`BL` word in `osos.dec` finds **8 direct `bl` call sites**: seven
//! unconditional (`0x082b5c28`, `0x082b641c`, `0x082b68b4`, `0x082b6ac0`,
//! `0x082bdb80`, `0x082bde90`, and `0x082dae70`) and one `bleq`
//! (`0x082c3688`). The sole predicated caller has already gated the reset on
//! its equality condition; this body has no NULL guards.
//!
//! # Algorithm
//!
//! Starts the record at `stream->buffer + stream->buffer_position`: clears the
//! remainder of the buffer, writes the eight-byte record header, and derives
//! the next record offset. Flag bit 3 selects the compact eight-byte header;
//! otherwise the offset includes a four-byte extension. It stores the wrapped
//! remaining capacity, invokes the stock flag-derived stream configuration,
//! then publishes the reset state fields in the original store order.
//!
//! # Deliberate deviations
//!
//! On firmware the configuration call reaches still-stock `FUN_082c5d1c` at
//! `0x082c5d1c` with its recovered `(stream, flags)` ABI. Host builds use an
//! inert default because that callee is not ported; tests replace it to prove
//! the call arguments and ordering. This is the only deviation.

use crate::libc::iram_veneers::iram_memzero_veneer;

/// Metadata whose halfword at +0x1e gives the record buffer capacity.
#[repr(C)]
pub struct RecordStreamInfo {
    _prefix: [u8; 0x1e],
    pub buffer_size: u16,
}

/// Fixed portion of the opaque record stream touched by [`record_stream_begin`].
///
/// The two pointer fields remain named `repr(C)` fields rather than byte
/// offsets: they are four bytes apart on firmware and naturally widen on the
/// host without overlapping. All scalar fields before them retain their target
/// byte offsets.
#[repr(C)]
pub struct RecordStream {
    pub state: u8,
    pub flag_1: u8,
    pub flag_2: u8,
    _configure_bytes_03_07: [u8; 5],
    pub buffer_position: u8,
    _reserved_09_0d: [u8; 5],
    pub record_offset: u16,
    _reserved_10_11: [u8; 2],
    pub remaining: u16,
    pub record_count: u16,
    _reserved_16_3f: [u8; 42],
    pub info: *mut RecordStreamInfo,
    pub buffer: *mut u8,
}

type RecordStreamConfigure = unsafe extern "C" fn(*mut RecordStream, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn configure_record_stream(stream: *mut RecordStream, flags: u32) {
    let configure: RecordStreamConfigure = core::mem::transmute(0x082c_5d1cusize);
    configure(stream, flags);
}

#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn configure_record_stream(_stream: *mut RecordStream, _flags: u32) {}

#[cfg(test)]
unsafe extern "C" fn inert_record_stream_configure(_stream: *mut RecordStream, _flags: u32) {}

#[cfg(test)]
static mut RECORD_STREAM_CONFIGURE: RecordStreamConfigure = inert_record_stream_configure;

#[cfg(test)]
unsafe fn configure_record_stream(stream: *mut RecordStream, flags: u32) {
    RECORD_STREAM_CONFIGURE(stream, flags);
}

/// Starts a record stream at its current buffer position.
///
/// # Safety
///
/// `stream`, `stream->info`, and `stream->buffer` must be non-NULL. The
/// buffer must be writable through `info->buffer_size` bytes, plus the
/// eight-byte header beginning at `buffer_position`; retailOS performs no
/// bounds checks before those writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_stream_begin")]
#[inline(never)]
pub unsafe extern "C" fn record_stream_begin(stream: *mut RecordStream, flags: u32) {
    let position = (*stream).buffer_position;
    let buffer_size = (*(*stream).info).buffer_size;
    let record = (*stream).buffer.add(position as usize);

    iram_memzero_veneer(record, buffer_size.wrapping_sub(position as u16) as usize);
    record.write_volatile(flags as u8);

    let record_offset = (position as u32)
        .wrapping_add((1 & !(flags >> 3)).wrapping_mul(4))
        .wrapping_add(8);
    iram_memzero_veneer(record.add(1), 4);
    record.add(7).write_volatile(0);
    record.add(5).write_volatile((buffer_size >> 8) as u8);
    record.add(6).write_volatile(buffer_size as u8);

    core::ptr::addr_of_mut!((*stream).remaining)
        .write_volatile(buffer_size.wrapping_sub(record_offset as u16));
    configure_record_stream(stream, flags);
    core::ptr::addr_of_mut!((*stream).buffer_position).write_volatile(position);
    core::ptr::addr_of_mut!((*stream).record_offset).write_volatile(record_offset as u16);
    core::ptr::addr_of_mut!((*stream).flag_2).write_volatile(0);
    core::ptr::addr_of_mut!((*stream).flag_1).write_volatile(0);
    core::ptr::addr_of_mut!((*stream).record_count).write_volatile(0);
    core::ptr::addr_of_mut!((*stream).state).write_volatile(1);
}

#[cfg(test)]
mod tests {
    use super::{record_stream_begin, RecordStream, RecordStreamConfigure, RecordStreamInfo, RECORD_STREAM_CONFIGURE};
    use parking_lot::Mutex;

    static CONFIGURE_LOCK: Mutex<()> = Mutex::new(());
    static mut CONFIGURE_CALLS: u32 = 0;
    static mut CONFIGURE_STREAM: *mut RecordStream = core::ptr::null_mut();
    static mut CONFIGURE_FLAGS: u32 = 0;
    static mut CONFIGURE_REMAINING: u16 = 0;
    static mut CONFIGURE_STATE: u8 = 0;

    unsafe extern "C" fn recording_configure(stream: *mut RecordStream, flags: u32) {
        CONFIGURE_CALLS += 1;
        CONFIGURE_STREAM = stream;
        CONFIGURE_FLAGS = flags;
        CONFIGURE_REMAINING = (*stream).remaining;
        CONFIGURE_STATE = (*stream).state;
    }

    struct ConfigureRestore(RecordStreamConfigure);

    impl Drop for ConfigureRestore {
        fn drop(&mut self) {
            unsafe { RECORD_STREAM_CONFIGURE = self.0; }
        }
    }

    unsafe fn install_recording_configure() -> ConfigureRestore {
        let old = RECORD_STREAM_CONFIGURE;
        RECORD_STREAM_CONFIGURE = recording_configure;
        CONFIGURE_CALLS = 0;
        CONFIGURE_STREAM = core::ptr::null_mut();
        ConfigureRestore(old)
    }

    fn stream(info: &mut RecordStreamInfo, buffer: &mut [u8]) -> RecordStream {
        RecordStream {
            state: 0xa1,
            flag_1: 0xa2,
            flag_2: 0xa3,
            _configure_bytes_03_07: [0xa4; 5],
            buffer_position: 0,
            _reserved_09_0d: [0xa5; 5],
            record_offset: 0xa6a6,
            _reserved_10_11: [0xa7; 2],
            remaining: 0xa8a8,
            record_count: 0xa9a9,
            _reserved_16_3f: [0xaa; 42],
            info,
            buffer: buffer.as_mut_ptr(),
        }
    }

    #[test]
    fn starts_extended_record_clears_tail_and_configures_before_publish() {
        let _lock = CONFIGURE_LOCK.lock();
        let _restore = unsafe { install_recording_configure() };
        let mut info = RecordStreamInfo { _prefix: [0; 0x1e], buffer_size: 0x20 };
        let mut buffer = [0xcc; 0x28];
        let mut state = stream(&mut info, &mut buffer);
        state.buffer_position = 3;

        unsafe { record_stream_begin(&mut state, 0); }
        assert_eq!(&buffer[..3], &[0xcc; 3]);
        assert_eq!(&buffer[3..11], &[0, 0, 0, 0, 0, 0, 0x20, 0]);
        assert_eq!(&buffer[11..0x20], &[0; 0x15]);
        assert_eq!(&buffer[0x20..], &[0xcc; 8]);
        assert_eq!(state.buffer_position, 3);
        assert_eq!(state.record_offset, 15);
        assert_eq!(state.remaining, 17);
        assert_eq!((state.state, state.flag_1, state.flag_2, state.record_count), (1, 0, 0, 0));
        unsafe {
            assert_eq!(CONFIGURE_CALLS, 1);
            assert_eq!(CONFIGURE_STREAM as usize, &mut state as *mut RecordStream as usize);
            assert_eq!(CONFIGURE_FLAGS, 0);
            assert_eq!(CONFIGURE_REMAINING, 17);
            assert_eq!(CONFIGURE_STATE, 0xa1);
        }
    }

    #[test]
    fn compact_flag_and_underflowing_remaining_match_arm_halfword_stores() {
        let _lock = CONFIGURE_LOCK.lock();
        let _restore = unsafe { install_recording_configure() };
        let mut info = RecordStreamInfo { _prefix: [0; 0x1e], buffer_size: 0x100 };
        let mut buffer = [0xcc; 0x108];
        let mut state = stream(&mut info, &mut buffer);
        state.buffer_position = 250;

        unsafe { record_stream_begin(&mut state, 8); }

        assert_eq!(&buffer[250..258], &[8, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(&buffer[258..], &[0xcc; 6]);
        assert_eq!(state.record_offset, 258);
        assert_eq!(state.remaining, 0xfffe);
        unsafe {
            assert_eq!(CONFIGURE_CALLS, 1);
            assert_eq!(CONFIGURE_FLAGS, 8);
            assert_eq!(CONFIGURE_REMAINING, 0xfffe);
        }
    }
}
