//! FreeType hash-table initialization — `FUN_080f4a5c` @ 0x080f4a5c.
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

use crate::ft::memory::{ft_mem_realloc, FtMemory};

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

#[cfg(test)]
mod tests {
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
}
