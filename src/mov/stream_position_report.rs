//! Parser stream-position reporting.
use core::mem::MaybeUninit;

use crate::ft::buffer::{buffered_stream_tell, FtBufferedStream};

/// ABI of the unported range-tracker getter at `0x081fa3b0`.
pub type RangeTrackerGetFn = unsafe extern "C" fn() -> *mut u8;
/// ABI of the unported range-tracker updater at `0x081fa378`.
pub type RangeTrackerUpdateFn = unsafe extern "C" fn(tracker: *mut u8, range: u32, position: u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_range_tracker_get() -> *mut u8 {
    let get: RangeTrackerGetFn = unsafe { core::mem::transmute(0x081f_a3b0usize) };
    unsafe { get() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_range_tracker_get() -> *mut u8 {
    panic!("stream_position_report requires range tracker getter 0x081fa3b0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_range_tracker_update(tracker: *mut u8, range: u32, position: u32) {
    let update: RangeTrackerUpdateFn = unsafe { core::mem::transmute(0x081f_a378usize) };
    unsafe { update(tracker, range, position) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_range_tracker_update(_tracker: *mut u8, _range: u32, _position: u32) {
    panic!("stream_position_report requires range tracker updater 0x081fa378")
}

/// Host-replaceable direct calls. The tracker routines are absent from
/// `names.yaml`; target builds dispatch to their verified retailOS addresses.
pub static mut RANGE_TRACKER_GET: RangeTrackerGetFn = firmware_range_tracker_get;
pub static mut RANGE_TRACKER_UPDATE: RangeTrackerUpdateFn = firmware_range_tracker_update;

#[inline(always)]
unsafe fn range_tracker_get() -> RangeTrackerGetFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RANGE_TRACKER_GET)) }
}

#[inline(always)]
unsafe fn range_tracker_update() -> RangeTrackerUpdateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RANGE_TRACKER_UPDATE)) }
}

/// stream_position_report — original: `FUN_080877f4` @ `0x080877f4` (60
/// bytes; 3 verified direct `bl` call sites, all unconditional).
///
/// Obtains the parser's logical position from its `+0x40000` buffered stream.
/// On success, converts the low 32 bits from bytes to 1 KiB units and reports
/// it to range 3 of the lazily obtained range tracker. The original discards
/// tell errors and does not report the upper 32 bits. Deliberate deviations:
/// the two unported tracker calls are volatile host seams; target builds call
/// their verified retailOS entries directly.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_position_report")]
#[inline(never)]
pub unsafe extern "C" fn stream_position_report(parser: *mut u8) {
    const BUFFERED_STREAM_OFFSET: usize = 0x40000;
    const RANGE: u32 = 3;

    let mut position = MaybeUninit::<u64>::uninit();
    let stream = unsafe { parser.add(BUFFERED_STREAM_OFFSET).cast::<FtBufferedStream>() };
    if unsafe { buffered_stream_tell(stream, position.as_mut_ptr()) } == 0 {
        let position_kib = unsafe { position.assume_init() as u32 } >> 10;
        let tracker = unsafe { range_tracker_get()() };
        unsafe { range_tracker_update()(tracker, RANGE, position_kib) };
    }
}

#[cfg(test)]
mod tests {
    use super::{stream_position_report, RangeTrackerGetFn, RangeTrackerUpdateFn, RANGE_TRACKER_GET, RANGE_TRACKER_UPDATE};
    use crate::ft::buffer::{BackingStreamTellFn, FtBufferedStream, BACKING_STREAM_TELL};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut TELL_RESULT: i32 = 0;
    static mut TELL_POSITION: u64 = 0;
    static mut UPDATE_CALLS: u32 = 0;
    static mut UPDATE_ARGUMENTS: (*mut u8, u32, u32) = (core::ptr::null_mut(), 0, 0);
    static mut TRACKER: u8 = 0;

    unsafe extern "C" fn tell(_context: u32, position: *mut u64) -> i32 {
        unsafe { position.write(TELL_POSITION); TELL_RESULT }
    }
    unsafe extern "C" fn get_tracker() -> *mut u8 { core::ptr::addr_of_mut!(TRACKER) }
    unsafe extern "C" fn update(tracker: *mut u8, range: u32, position: u32) {
        unsafe { UPDATE_CALLS += 1; UPDATE_ARGUMENTS = (tracker, range, position); }
    }

    unsafe fn install_seams() {
        unsafe {
            BACKING_STREAM_TELL = tell as BackingStreamTellFn;
            RANGE_TRACKER_GET = get_tracker as RangeTrackerGetFn;
            RANGE_TRACKER_UPDATE = update as RangeTrackerUpdateFn;
            UPDATE_CALLS = 0;
        }
    }

    #[test]
    fn reports_low_word_position_in_kibibytes() {
        let _lock = LOCK.lock();
        let mut parser = [0u8; 0x40000 + core::mem::size_of::<FtBufferedStream>()];
        let stream = unsafe { parser.as_mut_ptr().add(0x40000).cast::<FtBufferedStream>() };
        unsafe { stream.write(core::mem::zeroed()); TELL_RESULT = 0; TELL_POSITION = 0xbeef_ffff_0000_17ff; install_seams(); stream_position_report(parser.as_mut_ptr()); }
        unsafe {
            assert_eq!(UPDATE_CALLS, 1);
            assert_eq!(UPDATE_ARGUMENTS, (core::ptr::addr_of_mut!(TRACKER), 3, 5));
        }
    }

    #[test]
    fn suppresses_tracker_update_after_tell_error() {
        let _lock = LOCK.lock();
        let mut parser = [0u8; 0x40000 + core::mem::size_of::<FtBufferedStream>()];
        let stream = unsafe { parser.as_mut_ptr().add(0x40000).cast::<FtBufferedStream>() };
        unsafe { stream.write(core::mem::zeroed()); TELL_RESULT = -17; TELL_POSITION = 0xffff_ffff_ffff_ffff; install_seams(); stream_position_report(parser.as_mut_ptr()); assert_eq!(UPDATE_CALLS, 0); }
    }
}
