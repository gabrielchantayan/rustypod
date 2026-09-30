//! SQLite VDBE FIFO page allocation.
//!
//! Original: FUN_082b39b8 @ 0x082b39b8; true extent 64 bytes through
//! 0x082b39f8 (60 instruction bytes plus the 0x7ffe literal at 0x082b39f4).
//! Raw osos.dec scan: 2 incoming plain BL calls, 0 predicated BL calls;
//! body: 1 plain BL to sqlite3_malloc @ 0x08390b14, 0 predicated BL calls.
//! Clamp the unsigned capacity to 32766, allocate capacity * 8 + 16 bytes,
//! and initialize the four-word header only on success. Return the allocation
//! in r0, including NULL; the trailing 64-bit FIFO entries stay uninitialized.
//! Callers @ 0x0838a398/0x0838a3c4 append at +16 + write_index * 8 and
//! link a full page through +12.
//!
//! Deviations: allocation uses the existing DB_MEM_OPS malloc seam, whose
//! default is the ported sqlite3_malloc. The next pointer remains a u32 word
//! on hosts to preserve the target header layout. No behavioral deviations.

use super::mem::db_malloc_op;

#[repr(C)]
pub struct FifoPage {
    pub capacity: u32,
    pub write_index: u32,
    pub read_index: u32,
    pub next: u32,
}

/// Allocate an empty FIFO page; payload entries are not initialized.
///
/// # Safety
/// The allocator must return at least `16 + min(capacity, 32766) * 8`
/// writable bytes, aligned for u32, or NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fifo_page_allocate(capacity: u32) -> *mut FifoPage {
    let capacity = capacity.min(0x7ffe);
    let page = (db_malloc_op())((capacity * 8 + 16) as i32).cast::<FifoPage>();
    if !page.is_null() {
        (*page).write_index = 0;
        (*page).capacity = capacity;
        (*page).read_index = 0;
        (*page).next = 0;
    }
    page
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::mem::{DbMemOps, DB_MEM_OPS};
    use super::super::mem::tests::{OPS_LOCK, REALLOC_LOG, REALLOC_RESULT, recording_malloc, recording_realloc, realloc_log};

    struct AllocatorFixture {
        saved: DbMemOps,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl AllocatorFixture {
        fn new(result: *mut u8) -> Self {
            let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                let saved = core::ptr::read_volatile(core::ptr::addr_of!(DB_MEM_OPS));
                (*core::ptr::addr_of_mut!(REALLOC_LOG)).clear();
                core::ptr::write(core::ptr::addr_of_mut!(REALLOC_RESULT), result);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS),
                    DbMemOps { malloc: recording_malloc, realloc: recording_realloc });
                Self { saved, _guard: guard }
            }
        }
    }

    impl Drop for AllocatorFixture {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), self.saved); }
        }
    }

    #[test]
    fn initializes_only_header_at_unsigned_capacity_boundaries() {
        for requested in [0, 1, 14, 0x7ffd, 0x7ffe, 0x7fff, 0x8000_0000, u32::MAX] {
            let capacity = requested.min(0x7ffe);
            let bytes = 16 + capacity as usize * 8;
            let mut arena = std::vec![0xa5a5_a5a5u32; bytes / 4 + 2];
            let base = arena.as_mut_ptr().cast::<u8>();
            let _guard = AllocatorFixture::new(base);
            let page = unsafe { fifo_page_allocate(requested) };
            assert_eq!(page.cast::<u8>(), base);
            assert_eq!(realloc_log(), std::vec![(0, bytes as i32)]);
            assert_eq!(&arena[..4], &[capacity, 0, 0, 0]);
            assert!(arena[4..].iter().all(|&word| word == 0xa5a5_a5a5));
        }
    }

    #[test]
    fn allocation_failure_returns_null_even_for_zero_capacity() {
        for requested in [0, 14, u32::MAX] {
            let _guard = AllocatorFixture::new(core::ptr::null_mut());
            assert!(unsafe { fifo_page_allocate(requested) }.is_null());
            assert_eq!(realloc_log(), std::vec![(0, (requested.min(0x7ffe) * 8 + 16) as i32)]);
        }
    }
}
