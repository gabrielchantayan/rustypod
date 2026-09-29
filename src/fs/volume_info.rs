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
//! pointer to the ported FAT directory-entry volume-information writer, then
//! records ATA error 0. A missing descriptor records error 9 and returns -1.
//! No deliberate deviations.
#[cfg(target_os = "none")]
use crate::{drivers::ata_cmd, fs::volume_table};
use crate::fs::fat_dirent_volume_info::fat_dirent_write_volume_info;

type VolumeLookup = unsafe extern "C" fn(i32, u32) -> *mut u8;
type ErrorReport = unsafe extern "C" fn(u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_index: i32, _flags: u32) -> *mut u8 {
    core::ptr::null_mut()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error_report(_error: u32) -> u32 { u32::MAX }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct VolumeInfoHostOps {
    lookup: VolumeLookup,
    report_error: ErrorReport,
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: VolumeInfoHostOps = VolumeInfoHostOps {
    lookup: missing_lookup,
    report_error: missing_error_report,
};
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
/// `output` is passed unchanged to [`fat_dirent_write_volume_info`]. The
/// descriptor's first target-width word names a source whose +4 address is the
/// writer's directory-entry input.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_info_query(index: i32, output: *mut u8) -> u32 {
    let entry = lookup_volume(index);
    if entry.is_null() {
        report_ata_error(9);
        return u32::MAX;
    }

    let descriptor = (entry as *const u32).read() as usize as *mut u8;
    fat_dirent_write_volume_info(descriptor.add(4), output);
    report_ata_error(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;
    static mut SLAB: Option<usize> = None;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    unsafe fn slab() -> Option<usize> {
        if SLAB.is_none() {
            SLAB = try_map_u32_slab(hints::VOLUME_INFO_QUERY, 0x1000).map(|base| base as usize);
        }
        SLAB
    }
    static mut EVENTS: [u32; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn lookup(index: i32, flags: u32) -> *mut u8 {
        EVENTS[EVENT_COUNT] = 0x1000_0000 | (index as u32 & 0xffff) | (flags << 16);
        EVENT_COUNT += 1;
        slab().unwrap() as *mut u8
    }

    unsafe extern "C" fn no_entry(index: i32, flags: u32) -> *mut u8 {
        EVENTS[EVENT_COUNT] = 0x1000_0000 | (index as u32 & 0xffff) | (flags << 16);
        EVENT_COUNT += 1;
        core::ptr::null_mut()
    }

    unsafe extern "C" fn report(error: u32) -> u32 {
        EVENTS[EVENT_COUNT] = 0x2000_0000 | error;
        EVENT_COUNT += 1;
        u32::MAX
    }

    unsafe fn install(lookup: VolumeLookup) -> VolumeInfoHostOps {
        let previous = addr_of!(HOST_OPS).read_volatile();
        addr_of_mut!(HOST_OPS).write_volatile(VolumeInfoHostOps { lookup, report_error: report });
        EVENT_COUNT = 0;
        previous
    }

    #[test]
    fn writes_info_from_descriptor_plus_four_then_reports_success() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = (unsafe { slab() }) else { return };
        unsafe {
            let slab = slab as *mut u8;
            slab.write_bytes(0, 0x1000);
            let descriptor = slab.add(0x100);
            let entry = descriptor.add(4);
            let volume = slab.add(0x300);
            slab.cast::<u32>().write(descriptor as usize as u32);
            entry.add(0x1c).cast::<u32>().write(513);
            entry.add(0x2c).cast::<u32>().write(volume as usize as u32);
            volume.add(0x64).cast::<u16>().write(9);
            let previous = install(lookup);
            let output = slab.add(0x500);
            assert_eq!(volume_info_query(7, output), 0);
            assert_eq!(output.cast::<u32>().read(), 513);
            assert_eq!(output.add(0x24).cast::<u32>().read(), 9);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0x1000_0007, 0x2000_0000]);
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
