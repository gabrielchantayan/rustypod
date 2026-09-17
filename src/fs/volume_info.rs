//! Mounted-volume information query.
//!
//! `volume_info_query` — retailOS `FUN_082e19ec` at load address
//! **0x082e19ec**, 72 bytes (18 ARM words; the next separately entered
//! function begins with `push {r4,r5,r6,lr}` at 0x082e1a34). Decoding every
//! ARM B/BL word in `osos.dec` finds four direct callers — all plain `bl` at
//! 0x081bcac4, 0x081bcb14, 0x081bd214, and 0x081bdcbc — and no predicated
//! calls or tail branches.
//!
//! Looks up a mounted-volume descriptor, supplies the descriptor's +4 target
//! pointer to resident `FUN_082e1390` to populate `output`, then records ATA
//! error 0. A missing descriptor records error 9 and returns -1. Deliberate
//! deviation: `FUN_082e1390` is not yet ported, so target builds retain a
//! typed resident boundary and host builds use a volatile operation table.

use crate::drivers::ata_cmd;
use crate::fs::volume_table;

/// Resident volume-information writer, `FUN_082e1390`.
const VOLUME_INFO_WRITE_ADDRESS: usize = 0x082e_1390;

type ResidentVolumeInfoWrite = unsafe extern "C" fn(*mut u8, *mut u8);
type VolumeLookup = unsafe extern "C" fn(i32, u32) -> *mut u8;
type ErrorReport = unsafe extern "C" fn(u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn write_volume_info(descriptor: *mut u8, output: *mut u8) {
    let writer: ResidentVolumeInfoWrite = core::mem::transmute(VOLUME_INFO_WRITE_ADDRESS);
    writer(descriptor, output);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_index: i32, _flags: u32) -> *mut u8 {
    core::ptr::null_mut()
}


#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn write_volume_info(descriptor: *mut u8, output: *mut u8) {
    (host_ops().write)(descriptor, output);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_writer(_descriptor: *mut u8, _output: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error_report(_error: u32) -> u32 { u32::MAX }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct VolumeInfoHostOps {
    lookup: VolumeLookup,
    write: ResidentVolumeInfoWrite,
    report_error: ErrorReport,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: VolumeInfoHostOps = VolumeInfoHostOps {
    lookup: missing_lookup,
    write: missing_writer,
    report_error: missing_error_report,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: VolumeInfoHostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> VolumeInfoHostOps {
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
unsafe fn report_ata_error(error: u32) {
    #[cfg(target_os = "none")]
    {
        ata_cmd::ata_report_error(error);
    }
    #[cfg(not(target_os = "none"))]
    {
        (host_ops().report_error)(error);
    }
}

/// Queries a mounted volume's resident information — retailOS `FUN_082e19ec`
/// @ `0x082e19ec` (72 bytes; four plain `bl` callers).
///
/// `output` is passed unchanged to the resident writer. The descriptor's first
/// target-width word names an object whose +4 word is that writer's input.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_info_query(index: i32, output: *mut u8) -> u32 {
    let entry = lookup_volume(index);
    if entry.is_null() {
        report_ata_error(9);
        return u32::MAX;
    }

    let descriptor = (entry as *const u32).read() as usize as *mut u8;
    write_volume_info(descriptor.add(4), output);
    report_ata_error(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ENTRY: [u32; 1] = [0];
    static mut EVENTS: [u32; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn lookup(index: i32, flags: u32) -> *mut u8 {
        EVENTS[EVENT_COUNT] = 0x1000_0000 | (index as u32 & 0xffff) | (flags << 16);
        EVENT_COUNT += 1;
        core::ptr::addr_of_mut!(ENTRY) as *mut u32 as *mut u8
    }

    unsafe extern "C" fn no_entry(index: i32, flags: u32) -> *mut u8 {
        EVENTS[EVENT_COUNT] = 0x1000_0000 | (index as u32 & 0xffff) | (flags << 16);
        EVENT_COUNT += 1;
        core::ptr::null_mut()
    }

    unsafe extern "C" fn write(descriptor: *mut u8, output: *mut u8) {
        EVENTS[EVENT_COUNT] = descriptor as usize as u32;
        EVENT_COUNT += 1;
        output.write(0xa5);
    }

    unsafe extern "C" fn report(error: u32) -> u32 {
        EVENTS[EVENT_COUNT] = 0x2000_0000 | error;
        EVENT_COUNT += 1;
        u32::MAX
    }

    unsafe fn install(lookup: VolumeLookup) -> VolumeInfoHostOps {
        let previous = addr_of!(HOST_OPS).read_volatile();
        addr_of_mut!(HOST_OPS).write_volatile(VolumeInfoHostOps {
            lookup,
            write,
            report_error: report,
        });
        EVENT_COUNT = 0;
        previous
    }

    #[test]
    fn writes_info_from_descriptor_plus_four_then_reports_success() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            ENTRY[0] = 0x1234_5000;
            let previous = install(lookup);
            let mut output = 0;
            assert_eq!(volume_info_query(7, &mut output), 0);
            assert_eq!(output, 0xa5);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0x1000_0007, 0x1234_5004, 0x2000_0000]);
            addr_of_mut!(HOST_OPS).write_volatile(previous);
        }
    }

    #[test]
    fn missing_entry_reports_nine_without_writing_output() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let previous = install(no_entry);
            let mut output = 0x5a;
            assert_eq!(volume_info_query(-1, &mut output), u32::MAX);
            assert_eq!(output, 0x5a);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0x1000_ffff, 0x2000_0009]);
            addr_of_mut!(HOST_OPS).write_volatile(previous);
        }
    }
}
