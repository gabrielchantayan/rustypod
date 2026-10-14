//! Word-pair list pool release — `FUN_083dcf40` @ load address `0x083dcf40`.
//! True extent: 84 bytes, ending before the next function at `0x083dcf94`.
//! Raw A32 verifies two outgoing plain BLs (both `cxx_array_dealloc` at
//! `0x08266f2c`), one incoming plain BL at `0x083dd19c`, and no predicated BLs.
//! Unlink each pool chunk before freeing its node arena (capacity, 0), then
//! its 12-byte record (1, 0). Finally clear free, next, and end; leave the
//! sentinel and remaining list state untouched. Deliberate deviations: none;
//! aligned u32 word accesses preserve target layout on 64-bit hosts.

#[inline(always)]
unsafe fn release_with(list: *mut u8, mut dealloc: impl FnMut(*mut u8, usize, usize)) {
    let pool = list.cast::<u32>();
    loop {
        let chunk_word = pool.read();
        if chunk_word == 0 { break; }
        let chunk = (chunk_word as usize as *mut u8).cast::<u32>();
        pool.write(chunk.read());
        dealloc(chunk.add(2).read() as usize as *mut u8, chunk.add(1).read() as usize, 0);
        dealloc(chunk.cast(), 1, 0);
    }
    pool.add(1).write(0);
    pool.add(2).write(0);
    pool.add(3).write(0);
}

/// # Safety
/// `list` must contain writable pool words and valid live chunk/arena allocations
/// belonging to the allocator used by `cxx_array_dealloc`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_pair_list_pool_release(list: *mut u8) {
    release_with(list, |ptr, count, elem| crate::heap::veneers::cxx_array_dealloc(ptr, count, elem));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pool_clears_cursors_but_preserves_sentinel_and_tail() {
        let mut words = [0, u32::MAX, 17, 23, 0x1234, 0x5678];
        unsafe { word_pair_list_pool_release(words.as_mut_ptr().cast()); }
        assert_eq!(words, [0, 0, 0, 0, 0x1234, 0x5678]);
    }

    #[test]
    fn chunks_unlink_before_arena_release_and_survive_freed_record_poisoning() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::WORD_PAIR_LIST_POOL_RELEASE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("word_pair_list_pool_release"));
            return;
        };
        unsafe {
            let first = slab.add(0x40).cast::<u32>();
            let second = slab.add(0x80).cast::<u32>();
            let arena_a = slab.add(0x100);
            let arena_b = slab.add(0x200);
            first.write(second as usize as u32);
            first.add(1).write(32);
            first.add(2).write(arena_a as usize as u32);
            second.write(0);
            second.add(1).write(1);
            second.add(2).write(arena_b as usize as u32);
            let mut words = [first as usize as u32, 9, 11, 13, 0xabcdef];
            let pool = words.as_mut_ptr();
            let mut calls = 0;
            release_with(pool.cast(), |ptr, count, elem| {
                let expected = [(arena_a, 32), (first.cast(), 1), (arena_b, 1), (second.cast(), 1)];
                assert_eq!((ptr, count), expected[calls]);
                assert_eq!(elem, 0);
                assert_eq!(pool.read(), if calls < 2 { second as usize as u32 } else { 0 });
                assert_eq!([pool.add(1).read(), pool.add(2).read(), pool.add(3).read()], [9, 11, 13]);
                if calls % 2 == 1 { ptr.cast::<u32>().write(u32::MAX); }
                calls += 1;
            });
            assert_eq!(calls, 4);
            assert_eq!(words, [0, 0, 0, 0, 0xabcdef]);
        }
    }
}
