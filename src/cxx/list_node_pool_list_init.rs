//! `list_node_pool_list_init` — original: `FUN_083dd6c8` @ `0x083dd6c8`
//! (72 bytes; 18 A32 words through `pop {r4,pc}` at `0x083dd70c`; the next
//! function begins at `0x083dd710`). Raw decoding finds one plain outgoing
//! `bl` to `FUN_083dd4cc`, no predicated `bl`, and two inbound plain `bl`
//! calls at `0x082acbb0` and `0x082acbc8`.
//!
//! Clears the 24-byte list owner, acquires one 12-byte node from its embedded
//! pool with `single = 1`, and makes that node the empty intrusive-ring
//! sentinel. Deliberate deviation: `FUN_083dd4cc` is unported, so target
//! builds call its verified address and host tests replace the volatile seam.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

/// Target-width intrusive list node. Its value word remains uninitialized by
/// the constructor, exactly as the retail pool acquire call leaves it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNode {
    pub next: u32,
    pub previous: u32,
    pub value: u32,
}

/// The complete 24-byte owner: 16-byte node pool followed by its sentinel and
/// an untouched trailing state word.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNodePoolList {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
    pub sentinel: u32,
    pub state: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(ListNodePoolList, sentinel)];
const _: [u8; 0x18] = [0; core::mem::size_of::<ListNodePoolList>()];

/// ABI of the unported one-node pool acquisition helper `FUN_083dd4cc`.
pub type ListNodePoolAcquire = unsafe extern "C" fn(
    list: *mut ListNodePoolList,
    single: u32,
) -> *mut ListNode;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_list_node_pool_acquire(
    list: *mut ListNodePoolList,
    single: u32,
) -> *mut ListNode {
    unsafe {
        core::mem::transmute::<usize, ListNodePoolAcquire>(0x083d_d4cc)(list, single)
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_node_pool_acquire(
    _list: *mut ListNodePoolList,
    _single: u32,
) -> *mut ListNode {
    panic!("list_node_pool_list_init requires pool acquire 0x083dd4cc")
}

#[cfg(target_os = "none")]
const DEFAULT_LIST_NODE_POOL_ACQUIRE: ListNodePoolAcquire = firmware_list_node_pool_acquire;
#[cfg(not(target_os = "none"))]
const DEFAULT_LIST_NODE_POOL_ACQUIRE: ListNodePoolAcquire = missing_list_node_pool_acquire;

/// Active pool-acquisition boundary. Host tests replace it to observe the
/// constructor's exact argument and sentinel stores.
pub static mut LIST_NODE_POOL_ACQUIRE: ListNodePoolAcquire = DEFAULT_LIST_NODE_POOL_ACQUIRE;

#[inline(always)]
unsafe fn list_node_pool_acquire() -> ListNodePoolAcquire {
    unsafe { read_volatile(addr_of!(LIST_NODE_POOL_ACQUIRE)) }
}

/// Initializes and returns `list` as an empty node-pool-backed intrusive list.
///
/// # Safety
///
/// `list` must identify 24 writable bytes. The installed pool-acquisition
/// helper must return a writable 12-byte node.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_init(
    list: *mut ListNodePoolList,
) -> *mut ListNodePoolList {
    unsafe {
        addr_of_mut!((*list).chunks).write(0);
        addr_of_mut!((*list).free).write(0);
        addr_of_mut!((*list).next).write(0);
        addr_of_mut!((*list).end).write(0);
        addr_of_mut!((*list).sentinel).write(0);
        addr_of_mut!((*list).state).write(0);

        let sentinel = list_node_pool_acquire()(list, 1);
        let sentinel_word = sentinel as usize as u32;
        addr_of_mut!((*list).sentinel).write(sentinel_word);
        addr_of_mut!((*sentinel).next).write(sentinel_word);
        addr_of_mut!((*sentinel).previous).write(sentinel_word);
        list
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SENTINEL: AtomicUsize = AtomicUsize::new(0);
    static ARGUMENTS: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn acquire(
        _list: *mut ListNodePoolList,
        single: u32,
    ) -> *mut ListNode {
        ARGUMENTS.store(single as usize, Ordering::Relaxed);
        SENTINEL.load(Ordering::Relaxed) as *mut ListNode
    }

    struct RestoreAcquire(ListNodePoolAcquire);

    impl Drop for RestoreAcquire {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(LIST_NODE_POOL_ACQUIRE).write_volatile(self.0) };
        }
    }

    #[test]
    fn clears_owner_and_links_the_acquired_sentinel_to_itself() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_INIT, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_init");
            return;
        };

        unsafe {
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            core::ptr::write_bytes(list.cast::<u8>(), 0xa5, core::mem::size_of::<ListNodePoolList>());
            (*sentinel).value = 0xfeed_beef;
            SENTINEL.store(sentinel as usize, Ordering::Relaxed);
            ARGUMENTS.store(usize::MAX, Ordering::Relaxed);
            let old = addr_of!(LIST_NODE_POOL_ACQUIRE).read_volatile();
            let _restore = RestoreAcquire(old);
            addr_of_mut!(LIST_NODE_POOL_ACQUIRE).write_volatile(acquire);

            assert_eq!(list_node_pool_list_init(list), list);
            assert_eq!(ARGUMENTS.load(Ordering::Relaxed), 1);
            assert_eq!((*list).chunks, 0);
            assert_eq!((*list).free, 0);
            assert_eq!((*list).next, 0);
            assert_eq!((*list).end, 0);
            assert_eq!((*list).state, 0);
            assert_eq!((*list).sentinel, sentinel as usize as u32);
            assert_eq!((*sentinel).next, sentinel as usize as u32);
            assert_eq!((*sentinel).previous, sentinel as usize as u32);
            assert_eq!((*sentinel).value, 0xfeed_beef);
        }
    }
}
