//! BDF token-list capacity growth — FUN_08098704 @ 0x08098704.
//! True extent [0x08098704, 0x0809878c): 136 bytes, no literal pool.
//! Raw A32 words verify one outbound plain BL to ft_mem_realloc at
//! 0x08098770 and two inbound plain BLs at 0x0808fd8c and 0x0808fe44;
//! there are no predicated BLs. The caller splits a BDF line into tokens,
//! appending four-byte pointers and a terminating null entry.
//!
//! If signed capacity is below the requested minimum, grow once by
//! capacity + (capacity >> 1) + 4, saturating to 0x1fffffff on signed
//! wrap or excess. A full list returns error 0x40. Store the allocation
//! result even on error; update capacity only on success. Count is untouched.
//! Deliberate deviations: repr(C) uses native header pointers on hosts,
//! while token storage remains four-byte words. Return only the r0 error;
//! the original restores r1, not a meaningful second return value. LLVM
//! may inline the existing ft_mem_realloc wrapper; no new allocator seam.

use crate::ft::memory::{ft_mem_free, ft_mem_realloc, FtMemory};

#[repr(C)]
pub struct BdfList {
    pub tokens: *mut u32,
    pub capacity: i32,
    pub count: i32,
    pub memory: *mut FtMemory,
}

/// Grow once, rather than guaranteeing an arbitrarily large minimum.
///
/// # Safety
/// `list` must be writable. When growth is needed, its memory and token
/// storage must satisfy ft_mem_realloc's contract for four-byte elements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bdf_list_ensure_capacity(list: *mut BdfList, minimum: i32) -> i32 {
    let capacity = (*list).capacity;
    if capacity >= minimum {
        return 0;
    }
    if capacity == 0x1fffffff {
        return 0x40;
    }
    let mut grown = capacity.wrapping_add(capacity >> 1).wrapping_add(4);
    if grown < capacity || grown > 0x1fffffff {
        grown = 0x1fffffff;
    }
    let mut error = 0;
    (*list).tokens = ft_mem_realloc(
        (*list).memory, 4, capacity, grown, (*list).tokens.cast(), &mut error,
    ).cast();
    if error == 0 {
        (*list).capacity = grown;
    }
    error
}

/// BDF token-list destruction — FUN_0808799c @ 0x0808799c.
/// True extent [0x0808799c, 0x080879d0): 52 bytes, ending in POP PC;
/// the next function begins with PUSH. Raw words verify one outgoing
/// plain BL to ft_mem_free (0x082cfae8), two incoming plain BLs
/// (0x08082284, 0x080d37f8), and no predicated BLs.
///
/// A null allocator leaves the entire list untouched. Otherwise release
/// tokens through the saved allocator, then clear tokens, capacity, count,
/// and memory, including any changes made by the release callback.
/// Deliberate deviations: native host pointers use the existing repr(C)
/// BdfList; target fields remain at +0, +4, +8, +12. Omit the original's
/// redundant second zero store to tokens; no behavioral deviation.
///
/// # Safety
/// `list` must be writable. For non-null tokens and memory, the allocator
/// must satisfy ft_mem_free's contract. Callbacks must leave `list` valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bdf_list_done(list: *mut BdfList) {
    let memory = (*list).memory;
    if memory.is_null() {
        return;
    }
    ft_mem_free(memory, (*list).tokens.cast());
    (*list).tokens = core::ptr::null_mut();
    (*list).capacity = 0;
    (*list).count = 0;
    (*list).memory = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ft::error::{FT_ERR_INVALID_ARGUMENT, FT_ERR_OUT_OF_MEMORY};

    #[test]
    fn done_without_allocator_preserves_all_fields() {
        let mut token = 0xdeadbeef;
        let mut list = BdfList {
            tokens: &mut token, capacity: -7, count: 19, memory: core::ptr::null_mut(),
        };
        unsafe { bdf_list_done(&mut list); }
        assert_eq!(list.tokens, &mut token as *mut u32);
        assert_eq!((list.capacity, list.count, token), (-7, 19, 0xdeadbeef));
        assert!(list.memory.is_null());
    }

    #[test]
    fn done_with_null_tokens_clears_header_without_accessing_allocator() {
        let mut list = BdfList {
            tokens: core::ptr::null_mut(), capacity: 8, count: 3,
            memory: core::ptr::without_provenance_mut(1),
        };
        unsafe { bdf_list_done(&mut list); }
        assert!(list.tokens.is_null() && list.memory.is_null());
        assert_eq!((list.capacity, list.count), (0, 0));
        unsafe { bdf_list_done(&mut list); }
        assert_eq!((list.capacity, list.count), (0, 0));
    }

    #[test]
    fn done_releases_live_storage_before_clearing_callback_changes() {
        struct ReleaseState {
            list: *mut BdfList,
            storage: Option<std::boxed::Box<[u32; 4]>>,
            observed: Option<(i32, i32)>,
        }
        unsafe extern "C" fn free_list(memory: *mut FtMemory, block: *mut u8) {
            let state = &mut *((*memory).user as *mut ReleaseState);
            let storage = state.storage.take().unwrap();
            assert_eq!(block, storage.as_ptr() as *mut u8);
            assert_eq!((*state.list).memory, memory);
            state.observed = Some(((*state.list).capacity, (*state.list).count));
            drop(storage);
            (*state.list).tokens = core::ptr::without_provenance_mut(4);
            (*state.list).capacity = -1;
            (*state.list).count = -2;
            (*state.list).memory = core::ptr::null_mut();
        }
        let mut state = ReleaseState {
            list: core::ptr::null_mut(),
            storage: Some(std::boxed::Box::new([11, 22, 33, 44])),
            observed: None,
        };
        let mut memory = FtMemory {
            user: (&mut state as *mut ReleaseState).cast(),
            alloc: allocate, free: free_list, realloc: resize,
        };
        let mut list = BdfList {
            tokens: state.storage.as_mut().unwrap().as_mut_ptr(),
            capacity: 4, count: 3, memory: &mut memory,
        };
        state.list = &mut list;
        unsafe { bdf_list_done(&mut list); }
        assert_eq!(state.observed, Some((4, 3)));
        assert!(state.storage.is_none());
        assert!(list.tokens.is_null() && list.memory.is_null());
        assert_eq!((list.capacity, list.count), (0, 0));
        unsafe { bdf_list_done(&mut list); }
        assert_eq!(state.observed, Some((4, 3)));
    }

    struct Fixture {
        words: [u32; 32],
        fail: bool,
    }

    unsafe extern "C" fn allocate(memory: *mut FtMemory, size: i32) -> *mut u8 {
        resize(memory, 0, size, core::ptr::null_mut())
    }

    unsafe extern "C" fn release(_: *mut FtMemory, _: *mut u8) {
        panic!("growth must not free storage");
    }

    unsafe extern "C" fn resize(
        memory: *mut FtMemory, _: i32, size: i32, _: *mut u8,
    ) -> *mut u8 {
        let fixture = &mut *((*memory).user as *mut Fixture);
        if fixture.fail { return core::ptr::null_mut(); }
        assert!(size > 0 && size <= 120);
        fixture.words.as_mut_ptr().add(1).cast()
    }

    #[test]
    fn growth_preserves_prefix_zeroes_tail_and_leaves_count() {
        for (old, minimum, expected) in [(0, 1, 4), (1, 2, 5), (3, 4, 8), (4, 100, 10)] {
            let mut fixture = Fixture { words: [0xa5a5a5a5; 32], fail: false };
            let mut memory = FtMemory {
                user: (&mut fixture as *mut Fixture).cast(),
                alloc: allocate, free: release, realloc: resize,
            };
            let storage = unsafe { fixture.words.as_mut_ptr().add(1) };
            let mut list = BdfList {
                tokens: if old == 0 { core::ptr::null_mut() } else { storage },
                capacity: old, count: 17, memory: &mut memory,
            };
            assert_eq!(unsafe { bdf_list_ensure_capacity(&mut list, minimum) }, 0);
            assert_eq!((list.capacity, list.count), (expected, 17));
            assert_eq!(list.tokens, storage);
            for index in 0..32 {
                let want = if index > old as usize && index <= expected as usize {
                    0
                } else { 0xa5a5a5a5 };
                assert_eq!(fixture.words[index], want, "old={old}, index={index}");
            }
        }
    }

    #[test]
    fn no_growth_and_full_limit_do_not_access_allocator() {
        for (capacity, minimum, error) in [(4, 4, 0), (4, -1, 0), (0x1fffffff, 0x20000000, 0x40)] {
            let mut token = 123;
            let mut list = BdfList {
                tokens: &mut token, capacity, count: 3, memory: core::ptr::null_mut(),
            };
            assert_eq!(unsafe { bdf_list_ensure_capacity(&mut list, minimum) }, error);
            assert_eq!((list.capacity, list.count, token), (capacity, 3, 123));
            assert_eq!(list.tokens, &mut token as *mut u32);
        }
    }

    #[test]
    fn failures_preserve_capacity_and_follow_allocator_pointer_result() {
        for (capacity, expected_error) in [
            (4, FT_ERR_OUT_OF_MEMORY),
            (0x1ffffffe, FT_ERR_OUT_OF_MEMORY),
            (i32::MAX - 1, FT_ERR_OUT_OF_MEMORY),
            (-1, FT_ERR_INVALID_ARGUMENT),
        ] {
            let mut fixture = Fixture { words: [0xabcdef01; 32], fail: true };
            let mut memory = FtMemory {
                user: (&mut fixture as *mut Fixture).cast(),
                alloc: allocate, free: release, realloc: resize,
            };
            let original = fixture.words.as_mut_ptr();
            let mut list = BdfList { tokens: original, capacity, count: 9, memory: &mut memory };
            assert_eq!(unsafe { bdf_list_ensure_capacity(&mut list, capacity + 1) }, expected_error);
            assert_eq!((list.capacity, list.count), (capacity, 9));
            if capacity < 0 { assert_eq!(list.tokens, original); }
            else { assert!(list.tokens.is_null()); }
            assert_eq!(fixture.words, [0xabcdef01; 32]);
        }
    }
}
