//! Global word-list prepend — original: `FUN_08292994` @ `0x08292994`.
//!
//! Raw `osos.dec` establishes the exact 100-byte extent: 24 ARM words from
//! `push {r2,r3,r4,r5,r6,lr}` through `pop {r2,r3,r4,r5,r6,pc}`, followed by
//! the one-word literal pool at `0x082929f8`; the next independently linked
//! function begins at `0x082929fc`. There are three inbound direct calls, all
//! unconditional plain `bl`; there are no predicated direct calls. The body
//! calls the unported 12-byte node-pool acquire routine at `0x083dd78c` once.
//!
//! It acquires an uninitialized `{next, previous, value}` node from the global
//! list at `0x08ad2c98`, stores the supplied opaque word, prepends the node to
//! the circular list, and increments its count. Deliberate deviation: host
//! builds use an installable node-pool seam; target builds call the fixed
//! retail address with the verified ABI.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

const GLOBAL_WORD_LIST_ADDRESS: usize = 0x08ad_2c98;

#[repr(C)]
pub struct GlobalWordList {
    _chunks: u32,
    _free: u32,
    _next: u32,
    _end: u32,
    sentinel: u32,
    count: u32,
}

const _: () = assert!(core::mem::size_of::<GlobalWordList>() == 0x18);
const _: [u8; 0x10] = [0; core::mem::offset_of!(GlobalWordList, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(GlobalWordList, count)];

#[repr(C)]
struct GlobalWordListNode {
    next: u32,
    previous: u32,
    value: u32,
}

const _: () = assert!(core::mem::size_of::<GlobalWordListNode>() == 0x0c);

type GlobalWordListNodeAcquire = unsafe extern "C" fn(*mut GlobalWordList, u32) -> *mut GlobalWordListNode;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_global_word_list_node_acquire(
    list: *mut GlobalWordList,
    single: u32,
) -> *mut GlobalWordListNode {
    let acquire: GlobalWordListNodeAcquire = core::mem::transmute(0x083d_d78cusize);
    acquire(list, single)
}

#[cfg(target_os = "none")]
const GLOBAL_WORD_LIST_NODE_ACQUIRE: GlobalWordListNodeAcquire = retail_global_word_list_node_acquire;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_global_word_list_node_acquire(
    _list: *mut GlobalWordList,
    _single: u32,
) -> *mut GlobalWordListNode {
    panic!("install global word-list node acquire host operation before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_WORD_LIST_NODE_ACQUIRE: GlobalWordListNodeAcquire = missing_global_word_list_node_acquire;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_word_list() -> *mut GlobalWordList {
    GLOBAL_WORD_LIST_ADDRESS as *mut GlobalWordList
}

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_WORD_LIST: *mut GlobalWordList = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_word_list() -> *mut GlobalWordList {
    read_volatile(addr_of!(HOST_GLOBAL_WORD_LIST))
}

/// Prepends `value` to the global target-width circular word list.
///
/// Original: `FUN_08292994` at `0x08292994` (100 bytes; **3 direct plain
/// `bl` callers, no predicated forms**).
///
/// # Safety
///
/// The global list and its sentinel must be valid writable target-width
/// objects. The retail allocator or installed host seam must return a valid
/// writable 12-byte node.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_word_list_prepend(value: u32) {
    let list = global_word_list();
    let node = GLOBAL_WORD_LIST_NODE_ACQUIRE(list, 0);
    (*node).value = value;

    let sentinel = (*list).sentinel as usize as *mut GlobalWordListNode;
    (*node).next = (*sentinel).next;
    (*node).previous = (*list).sentinel;
    let first = (*node).next as usize as *mut GlobalWordListNode;
    (*first).previous = node as usize as u32;
    (*sentinel).next = node as usize as u32;
    (*list).count = (*list).count.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut NODES: *mut u8 = core::ptr::null_mut();
    static mut NODE_INDEX: usize = 0;
    static mut ACQUIRE_ARGUMENTS: [u32; 2] = [0; 2];

    unsafe extern "C" fn acquire(list: *mut GlobalWordList, single: u32) -> *mut GlobalWordListNode {
        ACQUIRE_ARGUMENTS[NODE_INDEX] = single;
        assert!(!list.is_null());
        let node = NODES.add(0x0c * (NODE_INDEX + 1)).cast::<GlobalWordListNode>();
        NODE_INDEX += 1;
        node
    }

    #[test]
    fn prepends_opaque_words_and_updates_circular_links() {
        let Some(slab) = try_map_u32_slab(hints::GLOBAL_WORD_LIST_PREPEND, 0x1000) else {
            note_missing_u32_fixture("app/global_word_list_prepend");
            return;
        };

        unsafe {
            let sentinel = slab.cast::<GlobalWordListNode>();
            (*sentinel).next = sentinel as usize as u32;
            (*sentinel).previous = sentinel as usize as u32;
            let mut list = GlobalWordList {
                _chunks: 0,
                _free: 0,
                _next: 0,
                _end: 0,
                sentinel: sentinel as usize as u32,
                count: 0,
            };
            HOST_GLOBAL_WORD_LIST = &mut list;
            NODES = slab;
            NODE_INDEX = 0;
            ACQUIRE_ARGUMENTS = [u32::MAX; 2];
            GLOBAL_WORD_LIST_NODE_ACQUIRE = acquire;

            global_word_list_prepend(0);
            global_word_list_prepend(0xfeed_beef);

            let first = slab.add(0x18).cast::<GlobalWordListNode>();
            let second = slab.add(0x0c).cast::<GlobalWordListNode>();
            assert_eq!(NODE_INDEX, 2);
            assert_eq!(ACQUIRE_ARGUMENTS, [0, 0]);
            assert_eq!(list.count, 2);
            assert_eq!((*first).value, 0xfeed_beef);
            assert_eq!((*first).next, second as usize as u32);
            assert_eq!((*first).previous, sentinel as usize as u32);
            assert_eq!((*second).value, 0);
            assert_eq!((*second).next, sentinel as usize as u32);
            assert_eq!((*second).previous, first as usize as u32);
            assert_eq!((*sentinel).next, first as usize as u32);
            assert_eq!((*sentinel).previous, second as usize as u32);
        }
    }
}
