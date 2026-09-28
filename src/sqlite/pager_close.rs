//! SQLite pager destruction — `pager_close`.
//!
//! `pager_close` is retailOS `FUN_0837dd9c` at `0x0837dd9c` (188 bytes,
//! `0x0837dd9c..0x0837de58`). Raw ARM decoding verifies seven plain `bl` and
//! two predicated `blne` instructions. It unlinks a non-memory pager from the
//! global pager list, brackets teardown with SQLite's benign-fault scope,
//! resets its cache, closes open journal files, destroys the journal bitvec,
//! closes the primary file, then frees its owned allocations and itself.
//!
//! Deliberate deviation: `0x082dd800` remains retailOS-owned. Target builds
//! call that fixed address; host builds use private recording seams for it and
//! embedded target-layout file fields.

use crate::heap::tracked::tracked_free;
use crate::sqlite::{bitvec::{sqlite3_bitvec_destroy, Bitvec}, mem::{fault_begin_benign, fault_end_benign}, os_close::sqlite_os_close, os_write::SqliteFile, pager_reset::pager_reset};

const MEMORY_PAGER: usize = 0x14;
const ERROR_CODE: usize = 0x20;
const JOURNAL_OPEN: usize = 4;
const SYNC_OPEN: usize = 8;
const JOURNAL_BITVEC: usize = 0x54;
const PRIMARY_FILE: usize = 0x6c;
const JOURNAL_FILE: usize = 0x70;
const SYNC_FILE: usize = 0x74;
const PREVIOUS: usize = 0xd4;
const NEXT: usize = 0xd8;
const EXTRA: usize = 0xd0;
const BACKUP: usize = 0xe4;
const PAGER_LIST: usize = 0x08a0_9918;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_pager_context(pager: *mut u8) {
    let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x082d_d800usize);
    release(pager);
}
#[cfg(not(target_os = "none"))]
static mut PAGER_LIST_HEAD: [*mut u8; 2] = [core::ptr::null_mut(); 2];
#[cfg(not(target_os = "none"))]
static mut RELEASE_PAGER_CONTEXT: unsafe extern "C" fn(*mut u8) = host_release_pager_context;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_release_pager_context(_pager: *mut u8) {}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_pager_context(pager: *mut u8) {
    (core::ptr::read_volatile(core::ptr::addr_of!(RELEASE_PAGER_CONTEXT)))(pager);
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn close_file(file: *mut u8) { sqlite_os_close(file.cast::<SqliteFile>()); }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn close_file(_file: *mut u8) {}

#[inline(always)]
unsafe fn pager_list_head() -> *mut *mut u8 {
    #[cfg(target_os = "none")]
    { PAGER_LIST as *mut *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(PAGER_LIST_HEAD).cast::<*mut u8>() }
}

/// `pager_close` — original `FUN_0837dd9c` @ `0x0837dd9c` (188 bytes;
/// seven plain `bl`, two `blne`, verified from `osos.dec`).
///
/// # Safety
/// `pager` must be a writable target-layout Pager. Every non-NULL target
/// pointer word it owns must designate the object expected by its callee.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_close")]
#[inline(never)]
pub unsafe extern "C" fn pager_close(pager: *mut u8) -> i32 {
    if pager.add(MEMORY_PAGER).read() == 0 {
        let next = pager.add(NEXT).cast::<u32>().read() as usize as *mut u8;
        let previous = pager.add(PREVIOUS).cast::<u32>().read() as usize as *mut u8;
        if next.is_null() { pager_list_head().add(1).write(previous); }
        else { next.add(PREVIOUS).cast::<u32>().write(previous as usize as u32); }
        if !previous.is_null() { previous.add(NEXT).cast::<u32>().write(next as usize as u32); }
    }
    fault_begin_benign(-1);
    pager.add(ERROR_CODE).cast::<u32>().write(0);
    pager.add(0x17).write(0);
    pager_reset(pager);
    release_pager_context(pager);
    fault_end_benign(-1);
    if pager.add(JOURNAL_OPEN).read() != 0 { close_file(pager.add(JOURNAL_FILE).cast::<u32>().read() as usize as *mut u8); }
    sqlite3_bitvec_destroy(pager.add(JOURNAL_BITVEC).cast::<u32>().read() as usize as *mut Bitvec);
    if pager.add(SYNC_OPEN).read() != 0 { close_file(pager.add(SYNC_FILE).cast::<u32>().read() as usize as *mut u8); }
    close_file(pager.add(PRIMARY_FILE).cast::<u32>().read() as usize as *mut u8);
    tracked_free(pager.add(EXTRA).cast::<u32>().read() as usize as *mut u8);
    tracked_free(pager.add(BACKUP).cast::<u32>().read() as usize as *mut u8);
    tracked_free(pager);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{heap::veneers::tests::mock_heap, testing::{hints, note_missing_u32_fixture, try_map_u32_slab}};
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut RELEASED: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn record_release(pager: *mut u8) { RELEASED = pager; }

    #[test]
    fn unlinks_listed_pager_and_runs_teardown() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PAGER_CLOSE, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_guard = mock_heap();
        unsafe {
            let pager = slab.add(0x100);
            let previous = slab.add(0x300);
            let next = slab.add(0x500);
            PAGER_LIST_HEAD = [core::ptr::null_mut(), pager];
            RELEASE_PAGER_CONTEXT = record_release;
            RELEASED = core::ptr::null_mut();
            pager.sub(0x20).cast::<i32>().write(0);
            pager.sub(4).cast::<u32>().write(0x1c);
            pager.add(MEMORY_PAGER).write(0);
            pager.add(NEXT).cast::<u32>().write(next as usize as u32);
            pager.add(PREVIOUS).cast::<u32>().write(previous as usize as u32);
            pager_close(pager);
            assert_eq!(next.add(PREVIOUS).cast::<u32>().read(), previous as usize as u32);
            assert_eq!(previous.add(NEXT).cast::<u32>().read(), next as usize as u32);
            assert_eq!(RELEASED, pager);
            assert_eq!(pager.add(0x17).read(), 0);
            RELEASE_PAGER_CONTEXT = host_release_pager_context;
        }
    }
}
