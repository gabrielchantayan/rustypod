//! Path-prefix drive-index resolution.
//!
//! The retail filesystem accepts either a path beginning with a drive prefix or
//! a path whose drive is selected elsewhere. This wrapper obtains that index,
//! makes the storage-layer drive-ready check while holding the corresponding
//! ATA semaphore, and rejects a missing drive-slot record.

use crate::drivers::{ata_cmd, ata_semaphore};
use crate::fs::drive_slot;

/// Resident retailOS drive-prefix parser at `0x082e377c`.
pub const DRIVE_PREFIX_PARSE_ADDRESS: usize = 0x082e_377c;
/// Resident retailOS drive-ready wrapper at `0x082c3168`.
pub const DRIVE_READY_CHECK_ADDRESS: usize = 0x082c_3168;

/// ABI of the unrecovered resident drive-prefix parser.
pub type DrivePrefixParse = unsafe extern "C" fn(*mut u32, *const u8) -> *const u8;
/// ABI of the unrecovered resident drive-ready wrapper.
pub type DriveReadyCheck = unsafe extern "C" fn(u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_drive_prefix_parse(index_out: *mut u32, path: *const u8) -> *const u8 {
    let parse: DrivePrefixParse = core::mem::transmute(DRIVE_PREFIX_PARSE_ADDRESS);
    parse(index_out, path)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_drive_ready_check(index: u32) -> u32 {
    let ready: DriveReadyCheck = core::mem::transmute(DRIVE_READY_CHECK_ADDRESS);
    ready(index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error_report(_error: u32) -> u32 {
    u32::MAX
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prefix_parse(_index_out: *mut u32, _path: *const u8) -> *const u8 {
    core::ptr::null()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ready_check(_index: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore(_index: usize) -> usize {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot_lookup(_index: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Host-test boundaries for each externally observable call in the wrapper.
/// Device builds call the retail parser/checker and the already ported ATA and
/// drive-slot entry points directly.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PathDriveIndexHostOps {
    error_report: unsafe extern "C" fn(u32) -> u32,
    prefix_parse: DrivePrefixParse,
    ready_check: DriveReadyCheck,
    semaphore_wait: unsafe extern "C" fn(usize) -> usize,
    semaphore_signal: unsafe extern "C" fn(usize) -> usize,
    slot_lookup: unsafe extern "C" fn(u32) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: PathDriveIndexHostOps = PathDriveIndexHostOps {
    error_report: missing_error_report,
    prefix_parse: missing_prefix_parse,
    ready_check: missing_ready_check,
    semaphore_wait: missing_semaphore,
    semaphore_signal: missing_semaphore,
    slot_lookup: missing_slot_lookup,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: PathDriveIndexHostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PathDriveIndexHostOps {
    core::ptr::addr_of!(HOST_OPS).read_volatile()
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

#[inline(always)]
unsafe fn parse_drive_prefix(index_out: *mut u32, path: *const u8) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        retail_drive_prefix_parse(index_out, path)
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().prefix_parse)(index_out, path)
    }
}

#[inline(always)]
unsafe fn drive_ready_check(index: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        retail_drive_ready_check(index)
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().ready_check)(index)
    }
}

#[inline(always)]
unsafe fn wait_for_drive(index: u32) {
    #[cfg(target_os = "none")]
    {
        ata_semaphore::ata_semaphore_wait(index as usize);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().semaphore_wait)(index as usize);
    }
}

#[inline(always)]
unsafe fn signal_drive(index: u32) {
    #[cfg(target_os = "none")]
    {
        ata_semaphore::ata_semaphore_signal(index as usize);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().semaphore_signal)(index as usize);
    }
}

#[inline(always)]
unsafe fn live_drive_slot(index: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        drive_slot::drive_slot_lookup(index)
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().slot_lookup)(index)
    }
}

/// resolve_path_drive_index — original: `FUN_082c3000` @ `0x082c3000` (116
/// bytes; 12 verified direct `bl` call sites, all unconditional).
///
/// ```text
/// 082c3000:  ata_report_error(0)
/// 082c300c:  prefix_parse(&index, path)
/// 082c3024:  ata_semaphore_wait(index)
/// 082c3030:  drive_ready_check(index)
/// 082c3040:  drive_slot_lookup(index)
/// 082c3050:  ata_semaphore_signal(index)
/// 082c3054:  ata_report_error(31); return -1
/// ```
///
/// Clears the ATA error code, parses a drive index from `path`, then holds the
/// index's ATA semaphore across the resident drive-ready check and ported
/// drive-slot lookup. It returns that index only when both gates succeed. A
/// parse failure skips the semaphore entirely; either post-lock failure still
/// releases it before recording error `31` and returning `-1`. The parser and
/// ready checker deliberately receive no added NULL guard.
///
/// The 12 decoded callers are `bl` at 0x082e0600, 0x082e173c, 0x082e1d40,
/// 0x082e22a4, 0x082e30f8, 0x082e3458, 0x082e4094, 0x082e458c, 0x082e462c,
/// 0x082e46d4, 0x082e47b4, and 0x082e6338; there are zero predicated calls or
/// tail branches. No data word dispatch was introduced: `ata_report_error`,
/// both ATA semaphore thunks, and `drive_slot_lookup` are already ported;
/// target builds call the two unrecovered resident entries at their verified
/// addresses. Host builds use volatile test boundaries for those calls.
///
/// # Safety
///
/// `path` is forwarded to the retail parser unchanged. It must satisfy that
/// parser's unchecked path-string ABI; this function does not dereference it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resolve_path_drive_index(path: *const u8) -> i32 {
    let mut index = 0u32;
    report_ata_error(0);

    if parse_drive_prefix(&mut index, path).is_null() {
        report_ata_error(31);
        return -1;
    }

    wait_for_drive(index);
    let live = drive_ready_check(index) != 0 && !live_drive_slot(index).is_null();
    signal_drive(index);

    if live {
        index as i32
    } else {
        report_ata_error(31);
        -1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<Event>> = Mutex::new(std::vec::Vec::new());
    static RESULTS: Mutex<Results> = Mutex::new(Results {
        parsed_index: 0,
        parse_result: 0,
        ready_result: 0,
        slot_result: 0,
    });

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Error(u32),
        Parse(usize),
        Wait(u32),
        Ready(u32),
        Lookup(u32),
        Signal(u32),
    }

    #[derive(Clone, Copy)]
    struct Results {
        parsed_index: u32,
        parse_result: usize,
        ready_result: u32,
        slot_result: usize,
    }

    fn events() -> std::sync::MutexGuard<'static, std::vec::Vec<Event>> {
        EVENTS.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn results() -> std::sync::MutexGuard<'static, Results> {
        RESULTS.lock().unwrap_or_else(|error| error.into_inner())
    }

    unsafe extern "C" fn record_error(error: u32) -> u32 {
        events().push(Event::Error(error));
        u32::MAX
    }

    unsafe extern "C" fn record_parse(index_out: *mut u32, path: *const u8) -> *const u8 {
        let result = *results();
        index_out.write(result.parsed_index);
        events().push(Event::Parse(path as usize));
        result.parse_result as *const u8
    }

    unsafe extern "C" fn record_ready(index: u32) -> u32 {
        events().push(Event::Ready(index));
        results().ready_result
    }

    unsafe extern "C" fn record_wait(index: usize) -> usize {
        events().push(Event::Wait(index as u32));
        0
    }

    unsafe extern "C" fn record_signal(index: usize) -> usize {
        events().push(Event::Signal(index as u32));
        0
    }

    unsafe extern "C" fn record_slot(index: u32) -> *mut u8 {
        events().push(Event::Lookup(index));
        results().slot_result as *mut u8
    }

    fn install() -> (MutexGuard<'static, ()>, PathDriveIndexHostOps) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved = addr_of!(HOST_OPS).read_volatile();
            addr_of_mut!(HOST_OPS).write_volatile(PathDriveIndexHostOps {
                error_report: record_error,
                prefix_parse: record_parse,
                ready_check: record_ready,
                semaphore_wait: record_wait,
                semaphore_signal: record_signal,
                slot_lookup: record_slot,
            });
            (guard, saved)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, PathDriveIndexHostOps)) {
        unsafe {
            addr_of_mut!(HOST_OPS).write_volatile(state.1);
        }
        drop(state);
    }

    fn configure(parsed_index: u32, parse_result: usize, ready_result: u32, slot_result: usize) {
        *results() = Results {
            parsed_index,
            parse_result,
            ready_result,
            slot_result,
        };
        events().clear();
    }

    fn observed_events() -> std::vec::Vec<Event> {
        events().clone()
    }

    #[test]
    fn returns_parsed_index_after_ready_live_slot() {
        let state = install();
        configure(2, 1, 1, 0x1000);
        let path = b"C:\\music\0";

        assert_eq!(unsafe { resolve_path_drive_index(path.as_ptr()) }, 2);
        assert_eq!(
            observed_events(),
            [
                Event::Error(0),
                Event::Parse(path.as_ptr() as usize),
                Event::Wait(2),
                Event::Ready(2),
                Event::Lookup(2),
                Event::Signal(2),
            ]
        );
        restore(state);
    }

    #[test]
    fn parser_failure_skips_lock_and_reports_error_31() {
        let state = install();
        configure(3, 0, 1, 0x1000);
        let path = b"Z:\\missing\0";

        assert_eq!(unsafe { resolve_path_drive_index(path.as_ptr()) }, -1);
        assert_eq!(
            observed_events(),
            [Event::Error(0), Event::Parse(path.as_ptr() as usize), Event::Error(31)]
        );
        restore(state);
    }

    #[test]
    fn failed_ready_check_releases_lock_before_error() {
        let state = install();
        configure(1, 1, 0, 0x1000);

        assert_eq!(unsafe { resolve_path_drive_index(core::ptr::null()) }, -1);
        assert_eq!(
            observed_events(),
            [
                Event::Error(0),
                Event::Parse(0),
                Event::Wait(1),
                Event::Ready(1),
                Event::Signal(1),
                Event::Error(31),
            ]
        );
        restore(state);
    }

    #[test]
    fn missing_slot_releases_lock_before_error() {
        let state = install();
        configure(0, 1, 1, 0);
        let path = b"A:\\empty\0";

        assert_eq!(unsafe { resolve_path_drive_index(path.as_ptr()) }, -1);
        assert_eq!(
            observed_events(),
            [
                Event::Error(0),
                Event::Parse(path.as_ptr() as usize),
                Event::Wait(0),
                Event::Ready(0),
                Event::Lookup(0),
                Event::Signal(0),
                Event::Error(31),
            ]
        );
        restore(state);
    }
}
