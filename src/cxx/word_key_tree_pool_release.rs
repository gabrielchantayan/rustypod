//! Word-key tree pool release, `FUN_083bf5a0` @ `0x083bf5a0`.
//!
//! Raw A32 extent: 68 bytes, 0x083bf5a0..0x083bf5e4 (next PUSH).
//! Two outgoing plain BLs at 0x083bf5c0/0x083bf5d0 to cxx_array_dealloc;
//! one incoming plain BL at 0x082a8464; zero predicated BLs in either set.
//! Pop chunks from owner word 0, then release chunk word 2 with the count
//! in word 1, followed by the chunk itself with count 1; both use elem 0.
//! Reload the owner's head after both releases. Empty pools do nothing.
//! Deliberate deviations: target pointers remain u32 on hosts; private
//! injected deallocation supports host ownership/order tests. No other
//! algorithm or ABI deviations.

type Dealloc = unsafe extern "C" fn(*mut u8, usize, usize);

/// Releases every chunk and its payload, leaving the pool head null.
///
/// # Safety
/// `pool` is an aligned writable target word. Each linked chunk contains
/// three aligned words (next, count, payload); chunks and payloads must be
/// owned allocations accepted by cxx_array_dealloc, with an acyclic chain.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_tree_pool_release(pool: *mut u32) {
    unsafe { release_with(pool, crate::heap::veneers::cxx_array_dealloc) }
}

unsafe fn release_with(pool: *mut u32, dealloc: Dealloc) {
    loop {
        let chunk = unsafe { pool.read() } as usize as *mut u32;
        if chunk.is_null() { break; }
        unsafe {
            pool.write(chunk.read());
            dealloc(chunk.add(2).read() as usize as *mut u8, chunk.add(1).read() as usize, 0);
            dealloc(chunk.cast(), 1, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::WORD_KEY_TREE_POOL_RELEASE, 4096).map(|p| p as usize)
    });

    unsafe extern "C" fn forbidden(_: *mut u8, _: usize, _: usize) {
        panic!("empty pool must not deallocate")
    }

    #[test]
    fn empty_pool_preserves_adjacent_words() {
        let mut owner = [0, 0x12345678, 0x87654321];
        unsafe { release_with(owner.as_mut_ptr(), forbidden) };
        unsafe { word_key_tree_pool_release(owner.as_mut_ptr()) };
        assert_eq!(owner, [0, 0x12345678, 0x87654321]);
    }

    unsafe extern "C" fn retire(ptr: *mut u8, count: usize, elem: usize) {
        let base = SLAB.as_ref().copied().unwrap() as *mut u32;
        unsafe {
            let step = base.add(2).read();
            let first = base.add(8);
            let second = base.add(16);
            assert_eq!(elem, 0);
            match step {
                0 => {
                    assert_eq!((ptr, count), (base.add(32).cast(), 7));
                    assert_eq!(base.read(), second as usize as u32);
                    // A freed payload may clobber metadata; no later reads allowed.
                    first.add(1).write(0xdead);
                    first.add(2).write(0xbeef);
                }
                1 => {
                    assert_eq!((ptr, count), (first.cast(), 1));
                    assert_eq!(base.read(), second as usize as u32);
                    core::ptr::write_bytes(first, 0xff, 3);
                }
                2 => {
                    assert_eq!((ptr, count), (core::ptr::null_mut(), 0));
                    assert_eq!(base.read(), 0);
                }
                3 => {
                    assert_eq!((ptr, count), (second.cast(), 1));
                    assert_eq!(base.read(), 0);
                    core::ptr::write_bytes(second, 0xff, 3);
                }
                _ => panic!("unexpected additional deallocation"),
            }
            base.add(2).write(step + 1);
        }
    }

    #[test]
    fn unlinks_before_free_and_releases_payload_before_chunk() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::word_key_tree_pool_release"));
            return;
        };
        unsafe {
            let pool = slab as *mut u32;
            core::ptr::write_bytes(pool, 0, 64);
            let first = pool.add(8);
            let second = pool.add(16);
            pool.write(first as usize as u32);
            pool.add(1).write(0x12345678);
            first.write(second as usize as u32);
            first.add(1).write(7);
            first.add(2).write(pool.add(32) as usize as u32);
            release_with(pool, retire);
            assert_eq!(pool.read(), 0);
            assert_eq!(pool.add(1).read(), 0x12345678);
            assert_eq!(pool.add(2).read(), 4);
            release_with(pool, forbidden);
        }
    }
}
