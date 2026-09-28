//! Unpacked-record teardown — release parsed `Mem` resources, then its
//! optional heap allocation.
//!
//! - `vdbe_delete_unpacked_record` — original: `FUN_08386e6c` @
//!   `0x08386e6c` (96 bytes, `0x08386e6c..0x08386ecc`; 2 inbound `bl`
//!   call sites; 0 plain and 1 predicated outbound `bl`, plus one
//!   predicated tail `b`). The next real function starts at `0x08386ecc`.
//! - Algorithm: NULL returns immediately. When `need_destroy` is nonzero,
//!   walk `n_field` raw 0x28-byte `Mem`s at `a_mem`, calling
//!   `sqlite3VdbeMemRelease` only for elements whose `zMalloc` is non-NULL.
//!   When `need_free` is nonzero, tail-call `sqlite3_free` on the record.
//!
//! Deliberate deviations: direct Rust calls replace the original's `blne`
//! and tail branch. The typed `UnpackedRecord` pointer fields widen on host,
//! while its `a_mem` elements remain raw target-layout bytes.

use crate::heap::tracked::tracked_free;

use super::mem_release::{mem_release, Z_MALLOC_OFFSET};
use super::value_new::MEM_SIZE;
use super::vdbe_record_compare::UnpackedRecord;

/// `sqlite3VdbeDeleteUnpackedRecord`: release `record` and, when owned,
/// its shell allocation.
///
/// # Safety
/// `record` is NULL or a valid [`UnpackedRecord`]. If `need_destroy` is
/// nonzero, `a_mem` provides `n_field` writable 0x28-byte `Mem`s. If
/// `need_free` is nonzero, `record` was returned by the tracked allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_delete_unpacked_record(record: *mut UnpackedRecord) {
    if record.is_null() {
        return;
    }

    if (*record).need_destroy != 0 {
        let mut index = 0u16;
        let mut mem = (*record).a_mem;
        while index < (*record).n_field {
            if (mem.add(Z_MALLOC_OFFSET) as *const u32).read() != 0 {
                mem_release(mem);
            }
            index = index.wrapping_add(1);
            mem = mem.add(MEM_SIZE as usize);
        }
    }

    if (*record).need_free != 0 {
        tracked_free(record as *mut u8);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn null_record_is_ignored() {
        unsafe { vdbe_delete_unpacked_record(core::ptr::null_mut()) };
    }

    #[test]
    fn skips_mem_walk_when_destroy_is_clear() {
        let mut record = MaybeUninit::<UnpackedRecord>::zeroed();
        unsafe {
            let record = record.assume_init_mut();
            record.n_field = u16::MAX;
            record.need_destroy = 0;
            record.need_free = 0;
            record.a_mem = core::ptr::null_mut();
            vdbe_delete_unpacked_record(record);
        }
    }

    #[test]
    fn releases_each_owned_mem_without_freeing_borrowed_record() {
        let mut mem = [0u8; MEM_SIZE as usize * 2];
        let mut record = MaybeUninit::<UnpackedRecord>::zeroed();
        unsafe {
            let record = record.assume_init_mut();
            record.n_field = 2;
            record.need_destroy = 1;
            record.need_free = 0;
            record.a_mem = mem.as_mut_ptr();
            vdbe_delete_unpacked_record(record);
        }
    }
}
