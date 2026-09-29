//! Path-resolution node release.
//!
//! `path_node_release` is retailOS `FUN_082e19cc` at `0x082e19cc` (32
//! bytes — byte-verified: the next function's `push {r4,r5,r6,lr}` sits
//! at `0x082e19ec`, so Ghidra's size is exact for once). Call sites: 32,
//! verified by decoding every B/BL word in osos.dec — 23 plain `bl` plus
//! 9 `blne` (`0x082e1950`, `0x082e1d10`, `0x082e1d1c`, `0x082e20c4`,
//! `0x082e3690`, `0x082e369c`, `0x082e36a8`, `0x082e41d4`, `0x082e6530`).
//! The `blne` sites are callers that already gate the call on a non-NULL
//! node of their own; the callee keeps its own NULL guard regardless, so
//! a predicated skip is a pure optimization with identical semantics.
//!
//! The node belongs to the path-resolution cluster at `0x082exxxx`
//! (separator-splitting lookup `FUN_082e15d8`, mount-table query
//! `FUN_082e0e1c` over the 0x24-stride table at `DAT_082e0e88`, node
//! factory `FUN_082e0100`). A node is a 0x1c-byte cursor (the pool pop
//! path zeroes exactly 0x1c bytes) whose word at +0x04 points at a
//! shared, refcounted 0x54-byte data block (refcount at its +0x24,
//! bumped under lock by the cloning lookup `FUN_082e1f74`).
//!
//! Raw body:
//!
//! ```text
//! 082e19cc:  push {r4, lr}
//! 082e19d0:  movs r4, r0          ; node == NULL?
//! 082e19d4:  popeq {r4, pc}       ;   -> return NULL
//! 082e19d8:  ldr  r0, [r4, #4]    ; data = node->data
//! 082e19dc:  bl   0x082e1960      ; shared_data_release(data)
//! 082e19e0:  mov  r0, r4
//! 082e19e4:  pop  {r4, lr}
//! 082e19e8:  b    0x082e2f04      ; tail: pool_recycle(node)
//! ```
//!
//! `0x082e1960` decrements the data block's refcount under the cluster
//! lock and, on the transition to zero, unlinks it from the doubly
//! linked list headed at `0x08a0a720` and pushes it onto the data pool
//! at `0x08a0a738`. `0x082e2f04` is the node pool's combined
//! recycle-or-pop: a non-NULL argument is pushed onto the freelist
//! headed at `0x08a0a73c` (pointer literal @ `0x082e2f70`) and the push
//! path returns NULL, which is this function's return value on every
//! non-NULL input; a NULL node short-circuits before either call.
//!
//! Deviation: the shared-data release and node-pool recycle-or-pop are now
//! ported, including on host builds. The pool's still-unidentified error
//! helper @ `0x082e406c` remains a fixed-address target call and a recording
//! host seam.
//!
//! `path_node_create` is retailOS `FUN_082e0100` at `0x082e0100` (56
//! bytes). Raw ARM extends from its `push {r4,lr}` through the `pop {r4,pc}`
//! at `0x082e0134`, with the next separate function beginning at
//! `0x082e0138`. Decoding every ARM B/BL word in osos.dec finds exactly five
//! direct callers, all plain unconditional `bl` at `0x082e1fb8`,
//! `0x082e2104`, `0x082e21e4`, `0x082e3094`, and `0x082e3280`; there are no
//! predicated calls or tail branches. It pops a zeroed 0x1c-byte node, obtains
//! a 0x54-byte shared-data block, stores that block in the node's +0x04 word,
//! and recycles the node when the data allocation fails. Both node-pool paths
//! now use the ported recycle-or-pop helper. Shared-data allocation calls the
//! ported `shared_data_allocate` veneer, which retains its own pool boundary.

use super::shared_data::shared_data_release;
use super::cache_lock::{cache_lock_signal, cache_lock_wait};
#[cfg(target_os = "none")]
use super::shared_data::shared_data_allocate as shared_data_pool_allocate;


/// Width of a target pointer field: 4 on ARMv5TE and pointer-sized in the
/// host fixtures, so widened host pointers never overlap adjacent fields.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Target offset of the node's shared data block pointer.
const NODE_DATA: usize = 0x04;

/// Converts a target pointer slot offset into a host fixture offset.
#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[inline(always)]
unsafe fn read_pointer(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read()
}

#[inline(always)]
unsafe fn write_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
    (base.add(pointer_offset(target_offset)) as *mut *mut u8).write(value);
}


const PATH_NODE_POOL_HEAD: *mut *mut u8 = 0x08a0_a73c as *mut *mut u8;
const PATH_NODE_POOL_ERROR_ADDRESS: usize = 0x082e_406c;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn path_node_pool_head() -> *mut u8 {
    PATH_NODE_POOL_HEAD.read_volatile()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_path_node_pool_head(node: *mut u8) {
    PATH_NODE_POOL_HEAD.write_volatile(node);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn path_node_pool_error(code: u32) {
    let report: unsafe extern "C" fn(u32) = core::mem::transmute(PATH_NODE_POOL_ERROR_ADDRESS);
    report(code);
}

#[cfg(not(target_os = "none"))]
static mut HOST_PATH_NODE_POOL_HEAD: *mut u8 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_path_node_pool_error(_code: u32) {
    panic!("path_node_pool_pop_or_recycle requires error reporter 0x082e406c")
}

#[cfg(not(target_os = "none"))]
static mut PATH_NODE_POOL_ERROR: unsafe extern "C" fn(u32) = missing_path_node_pool_error;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn path_node_pool_head() -> *mut u8 {
    core::ptr::addr_of!(HOST_PATH_NODE_POOL_HEAD).read_volatile()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn set_path_node_pool_head(node: *mut u8) {
    core::ptr::addr_of_mut!(HOST_PATH_NODE_POOL_HEAD).write_volatile(node);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn path_node_pool_error(code: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_NODE_POOL_ERROR))(code);
}
#[cfg(target_os = "none")]
unsafe fn shared_data_allocate() -> *mut u8 {
    shared_data_pool_allocate()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_shared_data_allocate() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe fn shared_data_allocate() -> *mut u8 {
    host_shared_data_allocate()
}


/// path_node_pool_pop_or_recycle — original: `FUN_082e2f04` @ `0x082e2f04`.
///
/// Load address: `0x082e2f04`; true size: 108 bytes (`0x6c`), from `push
/// {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x082e2f6c`; the literal
/// pool-head address at `0x082e2f70` is followed by the next separately
/// entered function at `0x082e2f74`. Two direct caller `bl` sites were
/// binary-verified, both plain and unconditional (`0x082e0104`,
/// `0x082e0128`); there are no predicated caller forms.
///
/// With a node, pushes it onto the singly linked free list rooted at
/// `0x08a0a73c` and returns NULL. With NULL, pops one node, clears all seven
/// words of its 0x1c-byte body, and returns it. Every list mutation is
/// bracketed by the cache lock. An empty pool releases the lock, reports
/// error code 10 through the still-unidentified helper at `0x082e406c`, and
/// returns NULL.
///
/// Deliberate deviation: uses the already ported cache-lock thunks instead
/// of their retailOS BL targets. The error helper's identity is not inferred:
/// target builds call its verified load address; host builds install a
/// recording seam only for that unported dependency.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_pool_pop_or_recycle(node: *mut u8) -> *mut u8 {
    cache_lock_wait();
    if !node.is_null() {
        write_pointer(node, 0, path_node_pool_head());
        set_path_node_pool_head(node);
        cache_lock_signal();
        return core::ptr::null_mut();
    }

    let result = path_node_pool_head();
    if result.is_null() {
        cache_lock_signal();
        path_node_pool_error(10);
        return core::ptr::null_mut();
    }

    set_path_node_pool_head(read_pointer(result, 0));
    for offset in 0..0x1c {
        result.add(offset).write_volatile(0);
    }
    cache_lock_signal();
    result
}

/// path_node_release — original: `FUN_082e19cc` @ `0x082e19cc` (32
/// bytes; 32 `bl` call sites, binary-verified: 23 plain + 9 `blne`).
///
/// NULL-guarded release of a path-resolution node: hands the shared data
/// block at node +0x04 to the refcounted release @ `0x082e1960`, then
/// recycles the 0x1c-byte node through the pool push @ `0x082e2f04`.
/// Returns NULL on every path (the pool's push path returns NULL; a NULL
/// node returns NULL before either call).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_release(node: *mut u8) -> *mut u8 {
    if node.is_null() {
        return core::ptr::null_mut();
    }
    shared_data_release(read_pointer(node, NODE_DATA));
    path_node_pool_pop_or_recycle(node)
}

/// path_node_create — original: `FUN_082e0100` @ `0x082e0100` (56 bytes;
/// five binary-verified plain `bl` call sites).
///
/// Pops a zeroed 0x1c-byte path node, allocates its 0x54-byte shared-data
/// block, and writes that block to node +0x04. If allocation fails, writes
/// NULL first, recycles the node, and returns NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_create() -> *mut u8 {
    let node = path_node_pool_pop_or_recycle(core::ptr::null_mut());
    if node.is_null() {
        return core::ptr::null_mut();
    }

    let data = shared_data_allocate();
    write_pointer(node, NODE_DATA, data);
    if data.is_null() {
        path_node_pool_pop_or_recycle(node);
        return core::ptr::null_mut();
    }

    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{tests::OPS_LOCK as ROM_OPS_LOCK, RomThunkOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut EVENTS: Vec<&'static str> = Vec::new();
    static LAST_ERROR: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_wait(_sem: usize) -> usize {
        EVENTS.push("wait");
        0
    }

    unsafe extern "C" fn record_signal(_sem: usize) -> usize {
        EVENTS.push("signal");
        0
    }

    unsafe extern "C" fn record_error(code: u32) {
        LAST_ERROR.store(code as usize, Ordering::SeqCst);
        EVENTS.push("error");
    }

    struct Bench {
        _local_lock: TestLock,
        _rom_lock: MutexGuard<'static, ()>,
        rom: RomThunkOps,
        head: *mut u8,
        error: unsafe extern "C" fn(u32),
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    fn bench() -> Bench {
        let local_lock = lock_ops();
        let rom_lock = ROM_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let rom = core::ptr::addr_of!(ROM_KERNEL).read_volatile();
            let mut installed = rom;
            installed.rom_sem_wait = record_wait;
            installed.rom_sem_signal = record_signal;
            core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(installed);
            let head = core::ptr::addr_of!(HOST_PATH_NODE_POOL_HEAD).read_volatile();
            let error = core::ptr::addr_of!(PATH_NODE_POOL_ERROR).read_volatile();
            core::ptr::addr_of_mut!(HOST_PATH_NODE_POOL_HEAD).write_volatile(core::ptr::null_mut());
            core::ptr::addr_of_mut!(PATH_NODE_POOL_ERROR).write_volatile(record_error);
            EVENTS.clear();
            LAST_ERROR.store(usize::MAX, Ordering::SeqCst);
            Bench { _local_lock: local_lock, _rom_lock: rom_lock, rom, head, error }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(self.rom);
                core::ptr::addr_of_mut!(HOST_PATH_NODE_POOL_HEAD).write_volatile(self.head);
                core::ptr::addr_of_mut!(PATH_NODE_POOL_ERROR).write_volatile(self.error);
            }
        }
    }

    #[repr(align(8))]
    struct NodeFixture {
        bytes: [u8; 0x20],
    }

    impl NodeFixture {
        fn new(fill: u8) -> Self {
            NodeFixture { bytes: [fill; 0x20] }
        }

        fn pointer(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
    }

    #[test]
    fn recycle_pushes_a_node_ahead_of_the_existing_free_list() {
        let _bench = bench();
        let mut old = NodeFixture::new(0);
        let mut node = NodeFixture::new(0);
        unsafe {
            set_path_node_pool_head(old.pointer());
            assert!(path_node_pool_pop_or_recycle(node.pointer()).is_null());
            assert_eq!(path_node_pool_head(), node.pointer());
            assert_eq!(read_pointer(node.pointer(), 0), old.pointer());
            assert_eq!(EVENTS, std::vec!["wait", "signal"]);
        }
    }

    #[test]
    fn pop_unlinks_and_zeroes_all_target_node_words() {
        let _bench = bench();
        let mut next = NodeFixture::new(0);
        let mut node = NodeFixture::new(0xa5);
        unsafe {
            write_pointer(node.pointer(), 0, next.pointer());
            set_path_node_pool_head(node.pointer());
            assert_eq!(path_node_pool_pop_or_recycle(core::ptr::null_mut()), node.pointer());
            assert_eq!(path_node_pool_head(), next.pointer());
            assert!(node.bytes[..0x1c].iter().all(|byte| *byte == 0));
            assert_eq!(EVENTS, std::vec!["wait", "signal"]);
        }
    }

    #[test]
    fn an_empty_pool_releases_the_lock_before_reporting_error_ten() {
        let _bench = bench();
        unsafe {
            assert!(path_node_pool_pop_or_recycle(core::ptr::null_mut()).is_null());
            assert_eq!(LAST_ERROR.load(Ordering::SeqCst), 10);
            assert_eq!(EVENTS, std::vec!["wait", "signal", "error"]);
        }
    }
}
