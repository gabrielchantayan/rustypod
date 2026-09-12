//! Volume cursor seeking wrapper.
//!
//! `volume_seek` — retailOS `FUN_082e628c` at load address **0x082e628c**,
//! 128 bytes (32 ARM words; the next entry starts at 0x082e630c). A complete
//! decode of every ARM B/BL word in `osos.dec` finds 10 direct branch callers:
//! nine unconditional `bl` at 0x081bca9c, 0x081bcb40, 0x081bd24c,
//! 0x081bd2b8, 0x081be02c, 0x081be168, 0x082e5c44, 0x082e5c74, and
//! 0x082e5dc8, plus one predicated `bllt` at 0x082e5cf4. There are no tail
//! branches or aligned data words that reference this entry.
//!
//! It looks up a mounted-volume descriptor, locks the descriptor's ATA
//! semaphore, synchronizes its cursor through ported `fat_cursor_synchronize`,
//! then forwards the requested 64-bit offset and origin to resident
//! `FUN_082b1784`. It always releases the semaphore after a successful lookup,
//! records ATA status 0 on that path and status 9 on a missing descriptor, and
//! preserves the seek result across status reporting.
//!
//! Deliberate deviations: only the unrecovered cursor seek routine remains a
//! typed resident boundary. Target builds call the ported cursor synchronizer,
//! volume-table, ATA-semaphore, and ATA-error entries directly; host builds
//! substitute a volatile operation table for the remaining external behavior.

use crate::drivers::{ata_cmd, ata_semaphore};
use crate::fs::{fat_cursor::{fat_cursor_synchronize, FatCursor}, volume_table};

/// Resident descriptor cursor seek routine, `FUN_082b1784`.
pub const CURSOR_SEEK_ADDRESS: usize = 0x082b_1784;

type ResidentCursorSeek = unsafe extern "C" fn(*mut u8, u32, u32, i32, u32) -> u64;
type VolumeLookup = unsafe extern "C" fn(i32, u32) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_cursor_seek(
    descriptor: *mut u8, unused: u32, offset_low: u32, offset_high: i32, origin: u32,
) -> u64 {
    let seek: ResidentCursorSeek = core::mem::transmute(CURSOR_SEEK_ADDRESS);
    seek(descriptor, unused, offset_low, offset_high, origin)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_index: i32, _flags: u32) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore(_index: usize) -> usize { 0 }


#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_seek(
    _descriptor: *mut u8, _unused: u32, _offset_low: u32, _offset_high: i32, _origin: u32,
) -> u64 {
    u64::MAX
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error_report(_error: u32) -> u32 { u32::MAX }

/// Host-only call boundaries. Device builds reach the ported helpers directly
/// and use direct typed calls only for the two unrecovered cursor entries.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct VolumeSeekHostOps {
    lookup: VolumeLookup,
    semaphore_wait: unsafe extern "C" fn(usize) -> usize,
    cursor_seek: ResidentCursorSeek,
    semaphore_signal: unsafe extern "C" fn(usize) -> usize,
    error_report: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: VolumeSeekHostOps = VolumeSeekHostOps {
    lookup: missing_lookup,
    semaphore_wait: missing_semaphore,
    cursor_seek: missing_cursor_seek,
    semaphore_signal: missing_semaphore,
    error_report: missing_error_report,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: VolumeSeekHostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> VolumeSeekHostOps {
    core::ptr::addr_of!(HOST_OPS).read_volatile()
}

#[inline(always)]
unsafe fn lookup_volume(index: i32) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        volume_table::volume_table_lookup(index, 0)
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().lookup)(index, 0)
    }
}

#[inline(always)]
unsafe fn wait_for_ata(index: usize) {
    #[cfg(target_os = "none")]
    {
        ata_semaphore::ata_semaphore_wait(index);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().semaphore_wait)(index);
    }
}

#[inline(always)]
unsafe fn signal_ata(index: usize) {
    #[cfg(target_os = "none")]
    {
        ata_semaphore::ata_semaphore_signal(index);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().semaphore_signal)(index);
    }
}


#[inline(always)]
unsafe fn seek_cursor(
    descriptor: *mut u8, unused: u32, offset_low: u32, offset_high: i32, origin: u32,
) -> u64 {
    #[cfg(target_os = "none")]
    {
        retail_cursor_seek(descriptor, unused, offset_low, offset_high, origin)
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().cursor_seek)(descriptor, unused, offset_low, offset_high, origin)
    }
}

#[inline(always)]
unsafe fn report_ata_error(error: u32) {
    #[cfg(target_os = "none")]
    {
        ata_cmd::ata_report_error(error);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().error_report)(error);
    }
}

/// Reads the ATA semaphore index through the descriptor's two target-width
/// pointer words. The retail layout stores a u32 pointer at descriptor +0,
/// another at its +0, then the index as a u16 at +0x78.
#[inline(always)]
unsafe fn descriptor_ata_semaphore_index(descriptor: *const u8) -> usize {
    let owner = (descriptor as *const u32).read() as usize as *const u8;
    let ata = (owner as *const u32).read() as usize as *const u8;
    (ata.add(0x78) as *const u16).read() as usize
}

/// Seeks a mounted volume descriptor — retailOS `FUN_082e628c` @ `0x082e628c`
/// (128 bytes; 10 direct branches: nine unconditional `bl`, one `bllt`).
///
/// The caller-provided second register word is ABI-preserved but unused by the
/// retail body. `offset_low` and `offset_high` are forwarded unchanged as a
/// signed 64-bit cursor position; `origin` selects the resident seek mode.
/// The return is the resident seek's r0/r1 pair, or `u64::MAX` when lookup
/// fails. Like retailOS, this does not NULL-check a descriptor returned by a
/// successful lookup before following its pointer chain.
///
/// # Safety
///
/// On device, `index` must select a live descriptor whose two pointer words
/// and ATA-index field are readable. The resident cursor routines retain their
/// original unchecked object and offset contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_seek(
    index: i32, unused: u32, offset_low: u32, offset_high: i32, origin: u32,
) -> u64 {
    let descriptor = lookup_volume(index);
    if descriptor.is_null() {
        report_ata_error(9);
        return u64::MAX;
    }

    let ata_index = descriptor_ata_semaphore_index(descriptor);
    wait_for_ata(ata_index);
    fat_cursor_synchronize(descriptor.cast::<FatCursor>());
    let result = seek_cursor(descriptor, unused, offset_low, offset_high, origin);
    signal_ata(ata_index);
    report_ata_error(0);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static HOST_OPS_LOCK: Mutex<()> = Mutex::new(());
    static LOOKUP_RESULT: AtomicUsize = AtomicUsize::new(0);
    static EVENT_LOG: AtomicU32 = AtomicU32::new(0);
    static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);
    static LOOKUP_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
    static LOOKUP_FLAGS: AtomicU32 = AtomicU32::new(u32::MAX);
    static SEMAPHORE_INDEX: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SEEK_DESCRIPTOR: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SEEK_UNUSED: AtomicU32 = AtomicU32::new(u32::MAX);
    static SEEK_LOW: AtomicU32 = AtomicU32::new(u32::MAX);
    static SEEK_HIGH: AtomicU32 = AtomicU32::new(u32::MAX);
    static SEEK_ORIGIN: AtomicU32 = AtomicU32::new(u32::MAX);
    static ERROR: AtomicU32 = AtomicU32::new(u32::MAX);

    fn note(event: u32) {
        let shift = EVENT_COUNT.fetch_add(1, Ordering::SeqCst) * 4;
        EVENT_LOG.fetch_or(event << shift, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_lookup(index: i32, flags: u32) -> *mut u8 {
        note(1);
        LOOKUP_INDEX.store(index as u32, Ordering::SeqCst);
        LOOKUP_FLAGS.store(flags, Ordering::SeqCst);
        LOOKUP_RESULT.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn record_wait(index: usize) -> usize {
        note(2);
        SEMAPHORE_INDEX.store(index, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn record_seek(
        descriptor: *mut u8, unused: u32, offset_low: u32, offset_high: i32, origin: u32,
    ) -> u64 {
        note(4);
        SEEK_DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
        SEEK_UNUSED.store(unused, Ordering::SeqCst);
        SEEK_LOW.store(offset_low, Ordering::SeqCst);
        SEEK_HIGH.store(offset_high as u32, Ordering::SeqCst);
        SEEK_ORIGIN.store(origin, Ordering::SeqCst);
        0x1234_5678_9abc_def0
    }

    unsafe extern "C" fn record_signal(index: usize) -> usize {
        note(5);
        SEMAPHORE_INDEX.store(index, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn record_error(error: u32) -> u32 {
        note(6);
        ERROR.store(error, Ordering::SeqCst);
        u32::MAX
    }

    fn install(lookup_result: *mut u8) -> (MutexGuard<'static, ()>, VolumeSeekHostOps) {
        let guard = HOST_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let saved = unsafe { addr_of!(HOST_OPS).read_volatile() };
        unsafe {
            addr_of_mut!(HOST_OPS).write_volatile(VolumeSeekHostOps {
                lookup: record_lookup,
                semaphore_wait: record_wait,
                cursor_seek: record_seek,
                semaphore_signal: record_signal,
                error_report: record_error,
            });
            LOOKUP_RESULT.store(lookup_result as usize, Ordering::SeqCst);
        }
        EVENT_LOG.store(0, Ordering::SeqCst);
        EVENT_COUNT.store(0, Ordering::SeqCst);
        LOOKUP_INDEX.store(u32::MAX, Ordering::SeqCst);
        LOOKUP_FLAGS.store(u32::MAX, Ordering::SeqCst);
        SEMAPHORE_INDEX.store(usize::MAX, Ordering::SeqCst);
        SEEK_DESCRIPTOR.store(usize::MAX, Ordering::SeqCst);
        SEEK_UNUSED.store(u32::MAX, Ordering::SeqCst);
        SEEK_LOW.store(u32::MAX, Ordering::SeqCst);
        SEEK_HIGH.store(u32::MAX, Ordering::SeqCst);
        SEEK_ORIGIN.store(u32::MAX, Ordering::SeqCst);
        ERROR.store(u32::MAX, Ordering::SeqCst);
        (guard, saved)
    }

    fn restore(state: (MutexGuard<'static, ()>, VolumeSeekHostOps)) {
        unsafe { addr_of_mut!(HOST_OPS).write_volatile(state.1); }
        drop(state);
    }

    #[test]
    fn missing_descriptor_reports_nine_without_locking_or_seeking() {
        let state = install(core::ptr::null_mut());
        assert_eq!(unsafe { volume_seek(-4, 0xfeed_beef, 3, -2, 2) }, u64::MAX);
        assert_eq!(LOOKUP_INDEX.load(Ordering::SeqCst), (-4i32) as u32);
        assert_eq!(LOOKUP_FLAGS.load(Ordering::SeqCst), 0);
        assert_eq!(ERROR.load(Ordering::SeqCst), 9);
        assert_eq!(EVENT_LOG.load(Ordering::SeqCst), 0x61);
        assert_eq!(SEMAPHORE_INDEX.load(Ordering::SeqCst), usize::MAX);
        assert_eq!(SEEK_DESCRIPTOR.load(Ordering::SeqCst), usize::MAX);
        restore(state);
    }

    #[test]
    fn forwards_full_seek_and_brackets_it_with_the_descriptor_ata_lock() {
        let slab = match try_map_u32_slab(hints::VOLUME_SEEK, 0x1000) {
            Some(slab) => slab,
            None => {
                assert!(note_missing_u32_fixture("fs/volume_seek"));
                return;
            }
        };
        let descriptor = slab;
        let cursor_state = unsafe { slab.add(0x100) };
        let volume = unsafe { slab.add(0x200) };
        let entry = unsafe { slab.add(0x500) };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            (descriptor as *mut u32).write_volatile(cursor_state as usize as u32);
            (cursor_state as *mut u32).write_volatile(volume as usize as u32);
            (cursor_state.add(4) as *mut u32).write_volatile(entry as usize as u32);
            (volume.add(0x78) as *mut u16).write_volatile(6);
            (volume.add(0x74) as *mut u32).write_volatile(10);
            (volume.add(0x1ce) as *mut u16).write_volatile(2);
            (volume.add(0x1d8) as *mut u32).write_volatile(100);
            (entry.add(0x1a) as *mut u16).write_volatile(3);
        }

        let state = install(descriptor);
        assert_eq!(unsafe { volume_seek(2, 0x7a, 0x89ab_cdef, -2, 1) }, 0x1234_5678_9abc_def0);
        assert_eq!(LOOKUP_INDEX.load(Ordering::SeqCst), 2);
        assert_eq!(LOOKUP_FLAGS.load(Ordering::SeqCst), 0);
        assert_eq!(SEMAPHORE_INDEX.load(Ordering::SeqCst), 6);
        assert_eq!(SEEK_DESCRIPTOR.load(Ordering::SeqCst), descriptor as usize);
        assert_eq!(SEEK_UNUSED.load(Ordering::SeqCst), 0x7a);
        assert_eq!(SEEK_LOW.load(Ordering::SeqCst), 0x89ab_cdef);
        assert_eq!(SEEK_HIGH.load(Ordering::SeqCst), (-2i32) as u32);
        assert_eq!(SEEK_ORIGIN.load(Ordering::SeqCst), 1);
        assert_eq!(ERROR.load(Ordering::SeqCst), 0);
        assert_eq!(EVENT_LOG.load(Ordering::SeqCst), 0x65421);
        restore(state);
    }
}
