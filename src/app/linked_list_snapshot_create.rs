//! `linked_list_snapshot_create` — original: `FUN_0805e310` @ **0x0805e310**.
//!
//! The raw A32 words establish a 92-byte body (`0x0805e310..0x0805e36c`);
//! `push {r4-r10,lr}` at `0x0805e36c` starts the next separately linked
//! function. Decoding every aligned ARM branch-immediate word in `osos.dec`
//! finds exactly three inbound plain `bl` calls (0x0805045c, 0x080505a0, and
//! 0x08052644) and no predicated inbound `bl` calls. The body has three plain
//! outgoing `bl` calls and no predicated calls.
//!
//! # Algorithm
//!
//! Read the optional collection's count at +0x08, allocate a zeroed
//! `count + 1` word buffer through `calloc_tag4`, store the count in word zero,
//! then snapshot the collection's +0x0c singly linked list into the remaining
//! words. The list head and next accessors remain direct calls to their
//! verified retail addresses because neither is ported yet; host tests install
//! equivalent seams. Deliberate deviation: the already ported allocator uses
//! its documented Rust heap dispatch instead of the retail direct `bl`.

#[cfg(target_os = "none")]
use crate::heap::veneers::calloc_tag4;

type CollectionAccess = unsafe extern "C" fn(*mut u8) -> *mut u8;
type SnapshotAllocate = unsafe extern "C" fn(usize) -> *mut u32;

const COLLECTION_HEAD_ADDRESS: usize = 0x0805_22a4;
const NODE_NEXT_ADDRESS: usize = 0x0805_3ba0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn collection_head(collection: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, CollectionAccess>(COLLECTION_HEAD_ADDRESS)(collection) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn node_next(node: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, CollectionAccess>(NODE_NEXT_ADDRESS)(node) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn snapshot_allocate(size: usize) -> *mut u32 {
    unsafe { calloc_tag4(size).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_access(_value: *mut u8) -> *mut u8 {
    panic!("linked_list_snapshot_create requires collection-access fixtures")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_snapshot_allocate(_size: usize) -> *mut u32 {
    panic!("linked_list_snapshot_create requires an allocation fixture")
}

#[cfg(not(target_os = "none"))]
pub struct LinkedListSnapshotOps {
    pub head: CollectionAccess,
    pub next: CollectionAccess,
    pub allocate: SnapshotAllocate,
}

#[cfg(not(target_os = "none"))]
pub static mut LINKED_LIST_SNAPSHOT_OPS: LinkedListSnapshotOps = LinkedListSnapshotOps {
    head: missing_collection_access,
    next: missing_collection_access,
    allocate: missing_snapshot_allocate,
};

/// Allocates and populates `{ count, node[0], ..., node[count - 1] }`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_list_snapshot_create(collection: *mut u8) -> *mut u32 {
    let count = if collection.is_null() {
        0
    } else {
        unsafe { (collection.add(8) as *const u32).read() }
    };
    let size = count.wrapping_mul(4).wrapping_add(8) as usize;

    #[cfg(target_os = "none")]
    let snapshot = unsafe { snapshot_allocate(size) };
    #[cfg(not(target_os = "none"))]
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LINKED_LIST_SNAPSHOT_OPS)) };
    #[cfg(not(target_os = "none"))]
    let snapshot = unsafe { (ops.allocate)(size) };

    if snapshot.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { snapshot.write(count) };

    #[cfg(target_os = "none")]
    let mut node = unsafe { collection_head(collection) };
    #[cfg(not(target_os = "none"))]
    let mut node = unsafe { (ops.head)(collection) };

    for index in 0..count as usize {
        unsafe { snapshot.add(index + 1).write(node as usize as u32) };
        #[cfg(target_os = "none")]
        { node = unsafe { node_next(node) }; }
        #[cfg(not(target_os = "none"))]
        { node = unsafe { (ops.next)(node) }; }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OUTPUT: [u32; 4] = [0; 4];
    static mut LAST_SIZE: usize = 0;
    static mut ALLOCATE: bool = true;
    static mut FIRST: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn head(_collection: *mut u8) -> *mut u8 { unsafe { FIRST } }
    unsafe extern "C" fn next(node: *mut u8) -> *mut u8 { unsafe { *(node as *mut *mut u8) } }
    unsafe extern "C" fn allocate(size: usize) -> *mut u32 {
        unsafe { LAST_SIZE = size; if ALLOCATE { core::ptr::addr_of_mut!(OUTPUT).cast() } else { core::ptr::null_mut() } }
    }

    unsafe fn install() {
        unsafe { LINKED_LIST_SNAPSHOT_OPS = LinkedListSnapshotOps { head, next, allocate }; }
    }

    #[test]
    fn snapshots_count_and_each_linked_node_in_order() {
        let _lock = LOCK.lock();
        let mut collection = [0u8; 12];
        let mut terminal: *mut u8 = core::ptr::null_mut();
        let mut third = (&mut terminal as *mut *mut u8).cast::<u8>();
        let mut second = (&mut third as *mut *mut u8).cast::<u8>();
        let first = (&mut second as *mut *mut u8).cast::<u8>();
        unsafe {
            install(); ALLOCATE = true; FIRST = first; OUTPUT = [0; 4];
            (collection.as_mut_ptr().add(8) as *mut u32).write(3);
            let snapshot = linked_list_snapshot_create(collection.as_mut_ptr());
            assert_eq!(LAST_SIZE, 20);
            assert_eq!(*snapshot, 3);
            assert_eq!(*snapshot.add(1), first as usize as u32);
            assert_eq!(*snapshot.add(2), second as usize as u32);
            assert_eq!(*snapshot.add(3), third as usize as u32);
        }
    }

    #[test]
    fn null_collection_still_allocates_a_zero_count_snapshot() {
        let _lock = LOCK.lock();
        unsafe {
            install(); ALLOCATE = true; FIRST = core::ptr::null_mut(); OUTPUT = [0; 4];
            let snapshot = linked_list_snapshot_create(core::ptr::null_mut());
            assert_eq!(LAST_SIZE, 8);
            assert_eq!(*snapshot, 0);
        }
    }

    #[test]
    fn allocation_failure_returns_null_before_accessing_the_list() {
        let _lock = LOCK.lock();
        let mut collection = [0u8; 12];
        unsafe {
            install(); ALLOCATE = false;
            (collection.as_mut_ptr().add(8) as *mut u32).write(1);
            assert!(linked_list_snapshot_create(collection.as_mut_ptr()).is_null());
            assert_eq!(LAST_SIZE, 12);
        }
    }
}
