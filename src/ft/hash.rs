//! FreeType hash-table initialization and teardown.
//! True extent [0x080f4a5c, 0x080f4aa8): 76 bytes, no literal pool.
//! Raw A32 decoding verifies one outbound plain BL (ft_mem_realloc at
//! 0x082cfc3c), zero predicated BLs, and two inbound plain BLs, both from
//! the BDF parser at 0x0809878c. Initialize the growth limit to 80, bucket
//! capacity to 241, and used count to zero; allocate 241 zeroed ARM words,
//! store the allocation result even on failure, and return the error.
//! The insert consumer at 0x0807807c checks limit against used, doubles
//! capacity, and rehashes the bucket array. Deliberate deviations: represent
//! the bucket pointer natively on hosts using repr(C); bucket elements remain
//! four-byte target words. Return only the meaningful r0 error, not Ghidra's
//! spurious undefined8 (the epilogue restores the caller's r1).
//! LLVM inlines ft_mem_realloc and emits alignment-aware zero-fill helpers;
//! it also combines/reorders the two nonvolatile limit/capacity stores.

use crate::ft::memory::{ft_mem_free, ft_mem_realloc, FtMemory};

/// Sixteen bytes on ARM; native pointer width on hosts.
#[repr(C)]
pub struct FtHash {
    pub limit: u32,
    pub capacity: u32,
    pub used: u32,
    pub buckets: *mut u32,
}

/// Initializes a fresh hash table; does not release any previous storage.
///
/// # Safety
/// `hash` must be writable and `memory` must provide a valid allocator whose
/// successful allocation is writable for 964 bytes. Existing buckets, if any,
/// are overwritten without being freed, just as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_hash_init(hash: *mut FtHash, memory: *mut FtMemory) -> i32 {
    (*hash).capacity = 241;
    (*hash).limit = 80;
    (*hash).used = 0;
    let mut error = 0;
    (*hash).buckets = ft_mem_realloc(
        memory, 4, 0, 241, core::ptr::null_mut(), &mut error,
    ) as *mut u32;
    error
}

/// FreeType hash teardown — `FUN_080f4a08` @ 0x080f4a08.
/// True extent [0x080f4a08, 0x080f4a5c): 84 bytes, no literal pool.
/// Raw ARM words verify two outbound plain BLs to ft_mem_free at
/// 0x080f4a34 and 0x080f4a50, zero predicated BLs; two inbound plain
/// BLs at 0x08081d80 and 0x08081ef4, zero predicated BLs.
///
/// A null hash returns immediately. Snapshot the buckets and capacity,
/// free each bucket in order and clear its word, then reload and free the
/// bucket array and clear its pointer. Limit, capacity, and used survive.
/// The ARM BLT treats capacity as signed: zero or negative skips the loop.
/// Deliberate deviation: repr(C) keeps the header pointer native on hosts,
/// but bucket entries remain four-byte ARM addresses. Existing ft_mem_free
/// is called directly; no new allocator seam is introduced.
///
/// # Safety
/// A non-null hash must be writable. A positive signed capacity requires
/// that many writable bucket words; each nonzero word and the bucket array
/// must satisfy ft_mem_free's allocator contract. Callbacks must not
/// invalidate the hash or bucket storage before its final release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_hash_done(hash: *mut FtHash, memory: *mut FtMemory) {
    if hash.is_null() {
        return;
    }
    let buckets = (*hash).buckets;
    let capacity = (*hash).capacity as i32;
    let mut index = 0i32;
    while index < capacity {
        let slot = buckets.add(index as usize);
        ft_mem_free(memory, (*slot as usize) as *mut u8);
        *slot = 0;
        index += 1;
    }
    ft_mem_free(memory, (*hash).buckets.cast());
    (*hash).buckets = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ft::error::FT_ERR_OUT_OF_MEMORY;

    struct Fixture {
        storage: [u32; 243],
        fail: bool,
    }

    unsafe extern "C" fn alloc(memory: *mut FtMemory, size: i32) -> *mut u8 {
        assert_eq!(size, 964);
        let fixture = &mut *((*memory).user as *mut Fixture);
        if fixture.fail { core::ptr::null_mut() }
        else { fixture.storage.as_mut_ptr().add(1) as *mut u8 }
    }

    unsafe extern "C" fn free(_: *mut FtMemory, _: *mut u8) {
        panic!("initialization must not free previous storage");
    }

    unsafe extern "C" fn realloc(
        _: *mut FtMemory, _: i32, _: i32, _: *mut u8,
    ) -> *mut u8 {
        panic!("initialization must allocate, not resize previous storage");
    }

    #[test]
    fn success_zeroes_every_bucket_without_touching_guards() {
        let mut fixture = Fixture { storage: [0xa5a5a5a5; 243], fail: false };
        let mut memory = FtMemory {
            user: &mut fixture as *mut Fixture as *mut core::ffi::c_void,
            alloc, free, realloc,
        };
        let mut previous = 0x12345678u32;
        let mut hash = FtHash {
            limit: u32::MAX, capacity: 7, used: 6, buckets: &mut previous,
        };
        assert_eq!(unsafe { ft_hash_init(&mut hash, &mut memory) }, 0);
        assert_eq!((hash.limit, hash.capacity, hash.used), (80, 241, 0));
        assert_eq!(hash.buckets, unsafe { fixture.storage.as_mut_ptr().add(1) });
        assert_eq!(fixture.storage[1..242], [0u32; 241]);
        assert_eq!(fixture.storage[0], 0xa5a5a5a5);
        assert_eq!(fixture.storage[242], 0xa5a5a5a5);
        assert_eq!(previous, 0x12345678);
    }

    #[test]
    fn allocation_failure_still_initializes_header_and_replaces_pointer() {
        let mut fixture = Fixture { storage: [0xa5a5a5a5; 243], fail: true };
        let mut memory = FtMemory {
            user: &mut fixture as *mut Fixture as *mut core::ffi::c_void,
            alloc, free, realloc,
        };
        let mut previous = 0x12345678u32;
        let mut hash = FtHash {
            limit: 1, capacity: 2, used: 3, buckets: &mut previous,
        };
        assert_eq!(unsafe { ft_hash_init(&mut hash, &mut memory) }, FT_ERR_OUT_OF_MEMORY);
        assert_eq!((hash.limit, hash.capacity, hash.used), (80, 241, 0));
        assert!(hash.buckets.is_null());
        assert_eq!(fixture.storage, [0xa5a5a5a5; 243]);
        assert_eq!(previous, 0x12345678);
    }

    struct Teardown {
        buckets: *mut u32,
        calls: std::vec::Vec<usize>,
    }

    unsafe extern "C" fn release(memory: *mut FtMemory, block: *mut u8) {
        let state = &mut *((*memory).user as *mut Teardown);
        if block == state.buckets.cast() {
            // Every element is cleared before the array is released.
            assert_eq!(core::slice::from_raw_parts(state.buckets, 4), &[0; 4]);
        } else {
            let index = if block as usize == 0x1234 { 0 } else { 2 };
            assert_eq!(*state.buckets.add(index), block as usize as u32);
            if index == 2 { assert_eq!(*state.buckets, 0); }
        }
        state.calls.push(block as usize);
    }

    #[test]
    fn teardown_frees_sparse_buckets_in_order_then_array_and_preserves_header() {
        let mut storage = [0xfeedface, 0x1234, 0, 0x5678, 0, 0xdeadbeef];
        let buckets = unsafe { storage.as_mut_ptr().add(1) };
        let mut state = Teardown { buckets, calls: std::vec::Vec::new() };
        let mut memory = FtMemory {
            user: (&mut state as *mut Teardown).cast(), alloc, free: release, realloc,
        };
        let mut hash = FtHash { limit: 80, capacity: 4, used: 2, buckets };
        unsafe { ft_hash_done(&mut hash, &mut memory); }
        assert_eq!(state.calls, [0x1234, 0x5678, buckets as usize]);
        assert_eq!(storage, [0xfeedface, 0, 0, 0, 0, 0xdeadbeef]);
        assert!(hash.buckets.is_null());
        assert_eq!((hash.limit, hash.capacity, hash.used), (80, 4, 2));
    }

    unsafe extern "C" fn release_array_only(memory: *mut FtMemory, block: *mut u8) {
        let state = &mut *((*memory).user as *mut Teardown);
        assert_eq!(block, state.buckets.cast());
        assert_eq!(*state.buckets, 0xfeedface);
        state.calls.push(block as usize);
    }

    #[test]
    fn nonpositive_signed_capacity_skips_elements_but_releases_array() {
        for capacity in [0, 0x80000000, u32::MAX] {
            let mut word = 0xfeedface;
            let mut state = Teardown { buckets: &mut word, calls: std::vec::Vec::new() };
            let mut memory = FtMemory {
                user: (&mut state as *mut Teardown).cast(),
                alloc, free: release_array_only, realloc,
            };
            let mut hash = FtHash { limit: 80, capacity, used: 2, buckets: &mut word };
            unsafe { ft_hash_done(&mut hash, &mut memory); }
            assert_eq!(state.calls, [&mut word as *mut u32 as usize]);
            assert!(hash.buckets.is_null());
            assert_eq!((hash.limit, hash.capacity, hash.used), (80, capacity, 2));
        }
    }

    #[test]
    fn null_hash_and_empty_null_array_do_not_dereference_allocator() {
        unsafe { ft_hash_done(core::ptr::null_mut(), core::ptr::null_mut()); }
        let mut hash = FtHash {
            limit: 80, capacity: 0, used: 0, buckets: core::ptr::null_mut(),
        };
        unsafe { ft_hash_done(&mut hash, core::ptr::null_mut()); }
        assert_eq!((hash.limit, hash.capacity, hash.used), (80, 0, 0));
        assert!(hash.buckets.is_null());
    }
}
