//! Shared path-data reference release.
//!
//! `shared_data_release` is retailOS `FUN_082e1960` at `0x082e1960` (104
//! bytes: 100 bytes of code plus the list-head literal at `0x082e19c8`; the
//! next independently entered function starts at `0x082e19cc`, so Ghidra's
//! reported 208-byte extent includes a sibling). Raw ARM decoding finds 9
//! call sites, all unconditional `bl` (`0x082e126c`, `0x082e1288`,
//! `0x082e1840`, `0x082e19dc`, `0x082e1fc8`, `0x082e21ac`, `0x082e220c`,
//! `0x082e2368`, and `0x082e241c`); there are no predicated calls, tail
//! branches, or data-word references, so it is neither caller-gated nor
//! virtually dispatched.
//!
//! A non-NULL 0x54-byte shared-data block is protected by the cache lock. A
//! nonzero refcount at +0x24 is decremented; a remaining reference leaves the
//! block linked. A zero count (including an already-zero count) unlinks the
//! block from the doubly linked list headed at `0x08a0a720`, whose links are
//! at +0x38 and +0x3c, then returns it to the 0x54-byte data pool through
//! `FUN_082e2f74`. NULL returns immediately without acquiring the lock.
//!
//! Deliberate deviation: the lock thunks are already ported, so this calls
//! `cache_lock_wait` and `cache_lock_signal` instead of their retailOS load
//! addresses. The still-unported, separately entered pool recycle function
//! @ `0x082e2f74` remains a fixed-address call on firmware; host tests install
//! a recording boundary only for that unported dependency.

use super::cache_lock::{cache_lock_signal, cache_lock_wait};

const REFCOUNT_WORD: usize = 0x24 / 4;
const NEXT_WORD: usize = 0x38 / 4;
const PREVIOUS_WORD: usize = 0x3c / 4;
const SHARED_DATA_LIST_HEAD: *mut *mut u8 = 0x08a0_a720 as *mut *mut u8;
const SHARED_DATA_POOL_RECYCLE_ADDRESS: usize = 0x082e_2f74;

type SharedDataPoolRecycle = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[inline(always)]
unsafe fn read_word(data: *mut u8, word: usize) -> u32 {
    data.cast::<u32>().add(word).read()
}

#[inline(always)]
unsafe fn write_word(data: *mut u8, word: usize, value: u32) {
    data.cast::<u32>().add(word).write(value);
}

#[inline(always)]
unsafe fn read_link(data: *mut u8, word: usize) -> *mut u8 {
    read_word(data, word) as usize as *mut u8
}

#[inline(always)]
unsafe fn write_link(data: *mut u8, word: usize, link: *mut u8) {
    write_word(data, word, link as usize as u32);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_data_list_head() -> *mut u8 {
    SHARED_DATA_LIST_HEAD.read_volatile()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_shared_data_list_head(data: *mut u8) {
    SHARED_DATA_LIST_HEAD.write_volatile(data);
}

#[cfg(not(target_os = "none"))]
static mut HOST_SHARED_DATA_LIST_HEAD: *mut u8 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_data_list_head() -> *mut u8 {
    core::ptr::addr_of!(HOST_SHARED_DATA_LIST_HEAD).read_volatile()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn set_shared_data_list_head(data: *mut u8) {
    core::ptr::addr_of_mut!(HOST_SHARED_DATA_LIST_HEAD).write_volatile(data);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_data_pool_recycle(data: *mut u8) -> *mut u8 {
    let recycle: SharedDataPoolRecycle = core::mem::transmute(SHARED_DATA_POOL_RECYCLE_ADDRESS);
    recycle(data)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_data_pool_recycle(_data: *mut u8) -> *mut u8 {
    panic!("shared_data_release requires pool recycle 0x082e2f74")
}

#[cfg(not(target_os = "none"))]
static mut SHARED_DATA_POOL_RECYCLE: SharedDataPoolRecycle = missing_shared_data_pool_recycle;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_data_pool_recycle(data: *mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(SHARED_DATA_POOL_RECYCLE))(data)
}

/// shared_data_release — original: `FUN_082e1960` @ `0x082e1960` (104 bytes:
/// 100 code bytes plus its 4-byte list-head literal; the next function starts
/// @ `0x082e19cc`).
///
/// Releases one reference to a path-resolution shared-data block. NULL is a
/// no-op. A nonzero count at +0x24 is decremented under the cache lock; if it
/// reaches zero, or was already zero, the +0x38/+0x3c list links are unlinked
/// and the block is recycled through the separate data-pool entry @
/// `0x082e2f74`. The returned pointer word is the cache-lock signal result on
/// a retained reference and the data-pool recycle result after unlinking.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_data_release(data: *mut u8) -> *mut u8 {
    if data.is_null() {
        return core::ptr::null_mut();
    }

    cache_lock_wait();
    let references = read_word(data, REFCOUNT_WORD);
    if references != 0 {
        let remaining = references - 1;
        write_word(data, REFCOUNT_WORD, remaining);
        if remaining != 0 {
            return cache_lock_signal() as *mut u8;
        }
    }

    let previous = read_link(data, PREVIOUS_WORD);
    let next = read_link(data, NEXT_WORD);
    if previous.is_null() {
        set_shared_data_list_head(next);
    } else {
        write_link(previous, NEXT_WORD, next);
    }
    if !next.is_null() {
        write_link(next, PREVIOUS_WORD, previous);
    }

    cache_lock_signal();
    shared_data_pool_recycle(data)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{RomThunkOps, ROM_KERNEL};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut SEMAPHORE_EVENTS: Vec<u8> = Vec::new();
    static mut RECYCLED: Vec<usize> = Vec::new();

    unsafe extern "C" fn record_wait(_semaphore: usize) -> usize {
        (*addr_of_mut!(SEMAPHORE_EVENTS)).push(0);
        0
    }

    unsafe extern "C" fn record_signal(_semaphore: usize) -> usize {
        (*addr_of_mut!(SEMAPHORE_EVENTS)).push(1);
        0
    }

    unsafe extern "C" fn record_recycle(data: *mut u8) -> *mut u8 {
        (*addr_of_mut!(RECYCLED)).push(data as usize);
        data
    }

    struct Bench {
        saved_kernel: RomThunkOps,
        _guard: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let guard = crate::kernel::task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            (*addr_of_mut!(SEMAPHORE_EVENTS)).clear();
            (*addr_of_mut!(RECYCLED)).clear();
            set_shared_data_list_head(core::ptr::null_mut());
            addr_of_mut!(SHARED_DATA_POOL_RECYCLE).write(record_recycle);
            let saved_kernel = addr_of!(ROM_KERNEL).read_volatile();
            let mut patched_kernel = saved_kernel;
            patched_kernel.rom_sem_wait = record_wait;
            patched_kernel.rom_sem_signal = record_signal;
            addr_of_mut!(ROM_KERNEL).write(patched_kernel);
            Bench { saved_kernel, _guard: guard }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(ROM_KERNEL).write(self.saved_kernel);
                addr_of_mut!(SHARED_DATA_POOL_RECYCLE).write(missing_shared_data_pool_recycle);
                set_shared_data_list_head(core::ptr::null_mut());
            }
        }
    }

    unsafe fn slab() -> Option<*mut u8> {
        crate::testing::try_map_u32_slab(crate::testing::hints::SHARED_DATA_RELEASE, 0x1000)
    }

    #[test]
    fn null_returns_without_lock_or_recycle() {
        let _bench = bench();
        assert!(unsafe { shared_data_release(core::ptr::null_mut()) }.is_null());
        unsafe {
            assert!((*addr_of!(SEMAPHORE_EVENTS)).is_empty());
            assert!((*addr_of!(RECYCLED)).is_empty());
        }
    }

    #[test]
    fn reference_transitions_preserve_or_unlink_the_list() {
        let _bench = bench();
        let Some(slab) = (unsafe { slab() }) else {
            assert!(crate::testing::note_missing_u32_fixture("fs/shared_data"));
            return;
        };
        let first = slab;
        let middle = unsafe { slab.add(0x80) };
        let last = unsafe { slab.add(0x100) };

        unsafe {
            write_word(first, REFCOUNT_WORD, 2);
            set_shared_data_list_head(first);
            assert!(shared_data_release(first).is_null(), "signal result passes through");
            assert_eq!(read_word(first, REFCOUNT_WORD), 1);
            assert_eq!(shared_data_list_head(), first);
            assert_eq!((*addr_of!(SEMAPHORE_EVENTS)).clone(), std::vec![0, 1]);
            assert!((*addr_of!(RECYCLED)).is_empty());

            (*addr_of_mut!(SEMAPHORE_EVENTS)).clear();
            write_link(first, PREVIOUS_WORD, core::ptr::null_mut());
            write_link(first, NEXT_WORD, middle);
            write_word(middle, REFCOUNT_WORD, 1);
            write_link(middle, PREVIOUS_WORD, first);
            write_link(middle, NEXT_WORD, last);
            write_link(last, PREVIOUS_WORD, middle);
            write_link(last, NEXT_WORD, core::ptr::null_mut());
            set_shared_data_list_head(first);

            assert_eq!(shared_data_release(middle), middle);
            assert_eq!(read_word(middle, REFCOUNT_WORD), 0);
            assert_eq!(read_link(first, NEXT_WORD), last);
            assert_eq!(read_link(last, PREVIOUS_WORD), first);
            assert_eq!(shared_data_list_head(), first);
            assert_eq!((*addr_of!(SEMAPHORE_EVENTS)).clone(), std::vec![0, 1]);
            assert_eq!((*addr_of!(RECYCLED)).clone(), std::vec![middle as usize]);

            (*addr_of_mut!(SEMAPHORE_EVENTS)).clear();
            (*addr_of_mut!(RECYCLED)).clear();
            write_word(middle, REFCOUNT_WORD, 0);
            write_link(middle, PREVIOUS_WORD, core::ptr::null_mut());
            write_link(middle, NEXT_WORD, core::ptr::null_mut());
            set_shared_data_list_head(middle);

            assert_eq!(shared_data_release(middle), middle, "an already-zero reference is recycled");
            assert!(shared_data_list_head().is_null());
            assert_eq!((*addr_of!(SEMAPHORE_EVENTS)).clone(), std::vec![0, 1]);
            assert_eq!((*addr_of!(RECYCLED)).clone(), std::vec![middle as usize]);
        }
    }
}
