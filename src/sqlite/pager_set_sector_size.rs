//! SQLite Pager sector-size initialization — `FUN_08369040` @ **0x08369040**.
//!
//! The raw ARM body is 52 bytes (`0x08369040..0x08369074`); the next separately
//! linked function begins at `0x08369074`. It has one direct, unconditional
//! `bl` to `0x0837dbc0`. Binary-scanning every ARM `B`/`BL` immediate finds
//! three inbound calls: two plain `bl` and one predicated `bleq`.
//!
//! The Pager's `sectorSize` is refreshed from its file only while the flag at
//! `+0x0f` is clear, then clamped to SQLite's 512-byte minimum. The direct
//! callee is still retailOS-owned: on target it is called at `0x0837dbc0`;
//! host tests supply its result through a private callback because target
//! `sqlite3_file` method-table offsets use 32-bit pointers.
//!
//! # Deliberate deviations
//! The host callback substitutes only the unported direct callee. The Pager is
//! otherwise accessed by target byte offsets, preserving the 32-bit layout on
//! a host with native-width pointers.

/// Target-layout byte offset of `Pager.sectorSize`.
const SECTOR_SIZE: usize = 0xc0;
/// Target-layout byte offset of the flag that suppresses file sector probing.
const SKIP_SECTOR_PROBE: usize = 0x0f;
/// Target-layout byte offset of `Pager.fd`.
const FILE: usize = 0x6c;
const MINIMUM_SECTOR_SIZE: u32 = 512;

type FileSectorSize = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn file_sector_size(file: *mut u8) -> u32 {
    let sector_size: FileSectorSize = core::mem::transmute(0x0837_dbc0usize);
    sector_size(file)
}

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn unavailable_file_sector_size(_file: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut FILE_SECTOR_SIZE: FileSectorSize = unavailable_file_sector_size;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn file_sector_size(file: *mut u8) -> u32 {
    let sector_size = core::ptr::read_volatile(core::ptr::addr_of!(FILE_SECTOR_SIZE));
    sector_size(file)
}

#[cfg(test)]
pub(crate) unsafe fn set_file_sector_size_for_test(callback: FileSectorSize) {
    core::ptr::write_volatile(core::ptr::addr_of_mut!(FILE_SECTOR_SIZE), callback);
}

/// `pager_set_sector_size` — original: `FUN_08369040` @ `0x08369040` (52
/// bytes; one direct unconditional `bl`; three inbound calls: two `bl`, one
/// `bleq`).
///
/// If Pager's `+0x0f` flag is clear, stores the result of the file sector-size
/// helper for `Pager.fd` (`+0x6c`) into `Pager.sectorSize` (`+0xc0`). It then
/// clamps `sectorSize` to at least 512, including values already present when
/// probing is skipped.
///
/// # Safety
/// `pager` must name a readable and writable target-layout Pager through
/// `+0xc3`. If its `+0x0f` flag is clear, its `Pager.fd` field must name an
/// object accepted by the retailOS file-sector-size helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_set_sector_size")]
#[inline(never)]
pub unsafe extern "C" fn pager_set_sector_size(pager: *mut u8) {
    if pager.add(SKIP_SECTOR_PROBE).read() == 0 {
        let sector_size = file_sector_size(pager.add(FILE));
        pager.add(SECTOR_SIZE).cast::<u32>().write(sector_size);
    }

    let sector_size = pager.add(SECTOR_SIZE).cast::<u32>();
    if sector_size.read() < MINIMUM_SECTOR_SIZE {
        sector_size.write(MINIMUM_SECTOR_SIZE);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RESULT: u32 = 0;
    static mut FILE_POINTER: usize = 0;

    unsafe extern "C" fn recording_file_sector_size(file: *mut u8) -> u32 {
        CALLS += 1;
        FILE_POINTER = file as usize;
        RESULT
    }

    #[test]
    fn pager_set_sector_size_probes_only_when_enabled_and_clamps() {
        let _guard = LOCK.lock();
        let mut storage = [0u32; 49];
        let pager = storage.as_mut_ptr().cast::<u8>();

        unsafe {
            CALLS = 0;
            RESULT = 256;
            FILE_POINTER = 0;
            set_file_sector_size_for_test(recording_file_sector_size);

            pager_set_sector_size(pager);
            assert_eq!(CALLS, 1);
            assert_eq!(FILE_POINTER, pager.add(FILE) as usize);
            assert_eq!(pager.add(SECTOR_SIZE).cast::<u32>().read(), MINIMUM_SECTOR_SIZE);

            RESULT = 4096;
            pager.add(SKIP_SECTOR_PROBE).write(1);
            pager.add(SECTOR_SIZE).cast::<u32>().write(256);
            pager_set_sector_size(pager);
            assert_eq!(CALLS, 1, "the flag suppresses the file probe");
            assert_eq!(pager.add(SECTOR_SIZE).cast::<u32>().read(), MINIMUM_SECTOR_SIZE);

            pager.add(SECTOR_SIZE).cast::<u32>().write(8192);
            pager_set_sector_size(pager);
            assert_eq!(pager.add(SECTOR_SIZE).cast::<u32>().read(), 8192);
            set_file_sector_size_for_test(unavailable_file_sector_size);
        }
    }
}
