//! Lazy storage-transfer scratch buffer at retailOS 0x0814da74.
//!
//! Raw A32 extent: [0x0814da74, 0x0814dab8), 68 bytes, seventeen
//! instructions, no literals; the next function starts with a separate push.
//! Two outgoing plain BLs, zero predicated BLs, one virtual BLX through
//! vtable slot +0x2c. Whole-image decoding finds two incoming plain BLs
//! (0x0814e0fc and 0x0814e1bc), zero predicated BLs.
//! If the scratch owner at +8 is already installed, do nothing. Otherwise
//! query the block size through slot 11; zero leaves the slot empty. For
//! any nonzero size, allocate an eight-byte owner with operator_new and
//! construct it with aligned_buffer_init before publishing its pointer.
//! Callers use its aligned data for unaligned storage reads and writes.
//!
//! Deviations: native pointer fields and vtable entries widen on hosts only;
//! ARM retains the original word layout. Both direct callees use existing
//! Rust ports. No allocation-failure check is added: the original constructor
//! dereferences a NULL owner allocation. The incidental r0 on early returns
//! is not exposed; callers treat this operation as void.
//!
//! ARM match.py reports 19 Rust instructions versus 17 original: LLVM
//! adds a frame-pointer setup and branches to the shared epilogue for zero
//! size instead of a predicated pop. Both direct calls, virtual slot +0x2c,
//! allocation size 8, guards and final pointer store at +8 are retained.

use crate::heap::aligned_buffer::aligned_buffer_init;
use crate::heap::veneers::operator_new;

/// Prefix of the storage-transfer object; trailing fields remain opaque.
#[repr(C)]
pub struct StorageScratchBuffer {
    pub vtable: *const usize,
    pub backend: *mut u8,
    pub scratch: *mut u8,
}

/// Ensure one block of aligned scratch storage exists.
///
/// # Safety
/// `storage` must be a writable constructed object. If scratch is absent,
/// its vtable must contain a callable slot 11 with signature
/// `unsafe extern "C" fn(*mut StorageScratchBuffer) -> u32`. The heap must
/// return valid storage for the eight-byte owner; ownership stays with the
/// object and is not released here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_scratch_buffer_ensure(storage: *mut StorageScratchBuffer) {
    if !(*storage).scratch.is_null() { return; }
    let block_size: unsafe extern "C" fn(*mut StorageScratchBuffer) -> u32 =
        core::mem::transmute((*storage).vtable.add(11).read());
    let size = block_size(storage);
    if size == 0 { return; }
    let owner = operator_new(8);
    (*storage).scratch = aligned_buffer_init(owner, size as usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    unsafe extern "C" fn block_size(storage: *mut StorageScratchBuffer) -> u32 {
        (*storage).backend as usize as u32
    }

    #[test]
    fn installed_owner_skips_even_an_unavailable_vtable() {
        let _heap = mock_heap();
        let mut owner = [0x1234_5678u32, 0x8765_4321];
        let mut storage = StorageScratchBuffer {
            vtable: core::ptr::null(), backend: core::ptr::null_mut(),
            scratch: owner.as_mut_ptr().cast(),
        };
        unsafe { storage_scratch_buffer_ensure(&mut storage) };
        assert_eq!(storage.scratch, owner.as_mut_ptr().cast());
        assert_eq!(owner, [0x1234_5678, 0x8765_4321]);
        assert_eq!(alloc_log().0, 0);
    }

    #[test]
    fn zero_size_remains_retryable_then_nonzero_size_installs_once() {
        let _heap = mock_heap();
        let mut vtable = [0usize; 12];
        vtable[11] = block_size as *const () as usize;
        let mut owner = [0xaaaa_aaaau32; 2];
        let owner_ptr = owner.as_mut_ptr().cast::<u8>();
        set_alloc_ret(owner_ptr);
        let mut storage = StorageScratchBuffer {
            vtable: vtable.as_ptr(), backend: core::ptr::null_mut(),
            scratch: core::ptr::null_mut(),
        };
        unsafe { storage_scratch_buffer_ensure(&mut storage) };
        assert!(storage.scratch.is_null());
        assert_eq!(owner, [0xaaaa_aaaa; 2]);
        assert_eq!(alloc_log().0, 0);

        storage.backend = 513usize as *mut u8;
        unsafe { storage_scratch_buffer_ensure(&mut storage) };
        assert_eq!(storage.scratch, owner_ptr);
        let raw = owner_ptr as usize as u32;
        assert_eq!(owner, [raw.wrapping_add(31) & !31, raw]);
        assert_eq!(alloc_log(), (2, 545, 3));

        storage.vtable = core::ptr::null();
        unsafe { storage_scratch_buffer_ensure(&mut storage) };
        assert_eq!(alloc_log().0, 2);
        assert_eq!(storage.scratch, owner_ptr);
    }
}
