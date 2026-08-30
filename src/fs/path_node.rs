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
//! Deviation: both callees are still unported, so on the firmware target
//! they are direct calls to their retailOS load addresses (`0x082e1960`,
//! `0x082e2f04`). Host builds route them through recording boundaries so
//! argument pass-through, call order, the NULL guard and the return
//! value can be exercised; this does not replace or bypass
//! `path_node_release` itself.

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

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_data_release(data: *mut u8) -> *mut u8 {
    let release: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(0x082e_1960usize);
    release(data)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pool_recycle(node: *mut u8) -> *mut u8 {
    let recycle: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(0x082e_2f04usize);
    recycle(node)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PathNodeHostOps {
    shared_data_release: unsafe extern "C" fn(*mut u8) -> *mut u8,
    pool_recycle: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_shared_data_release(_data: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_pool_recycle(_node: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PATH_NODE_HOST_OPS: PathNodeHostOps = PathNodeHostOps {
    shared_data_release: host_shared_data_release,
    pool_recycle: host_pool_recycle,
};

#[cfg(not(target_os = "none"))]
static mut PATH_NODE_HOST_OPS: PathNodeHostOps = DEFAULT_PATH_NODE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PathNodeHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_NODE_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_data_release(data: *mut u8) -> *mut u8 {
    (host_ops().shared_data_release)(data)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pool_recycle(node: *mut u8) -> *mut u8 {
    (host_ops().pool_recycle)(node)
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
    pool_recycle(node)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut EVENTS: Vec<Event> = Vec::new();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        SharedDataRelease(usize),
        PoolRecycle(usize),
    }

    unsafe extern "C" fn recording_shared_data_release(data: *mut u8) -> *mut u8 {
        EVENTS.push(Event::SharedDataRelease(data as usize));
        data
    }

    unsafe extern "C" fn recording_pool_recycle(node: *mut u8) -> *mut u8 {
        EVENTS.push(Event::PoolRecycle(node as usize));
        core::ptr::null_mut()
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
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

    struct Bench {
        _lock: TestLock,
    }

    fn bench() -> Bench {
        let lock = lock_ops();
        unsafe {
            EVENTS.clear();
            core::ptr::addr_of_mut!(PATH_NODE_HOST_OPS).write_volatile(PathNodeHostOps {
                shared_data_release: recording_shared_data_release,
                pool_recycle: recording_pool_recycle,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_NODE_HOST_OPS)
                    .write_volatile(DEFAULT_PATH_NODE_HOST_OPS);
            }
        }
    }

    fn events() -> Vec<Event> {
        unsafe { EVENTS.clone() }
    }

    /// A node fixture: 0x1c target bytes, widened on host so the +0x04
    /// pointer slot lands at host offset `pointer_offset(NODE_DATA)`.
    #[repr(align(8))]
    struct NodeFixture {
        node: [u8; 0x20],
    }

    impl NodeFixture {
        fn new(data: *mut u8) -> Self {
            let mut fixture = NodeFixture { node: [0; 0x20] };
            unsafe {
                (fixture.node_ptr().add(pointer_offset(NODE_DATA)) as *mut *mut u8).write(data);
            }
            fixture
        }

        fn node_ptr(&mut self) -> *mut u8 {
            self.node.as_mut_ptr()
        }
    }

    #[test]
    fn a_null_node_returns_null_and_never_touches_either_callee() {
        let _bench = bench();
        assert!(unsafe { path_node_release(core::ptr::null_mut()) }.is_null());
        assert!(events().is_empty());
    }

    #[test]
    fn a_node_releases_its_data_then_recycles_itself_in_order() {
        let _bench = bench();
        let mut data_block = [0u8; 0x54];
        let data = data_block.as_mut_ptr();
        let mut fixture = NodeFixture::new(data);
        let node = fixture.node_ptr();

        assert!(unsafe { path_node_release(node) }.is_null());
        assert_eq!(
            events(),
            std::vec![
                Event::SharedDataRelease(data as usize),
                Event::PoolRecycle(node as usize),
            ]
        );
    }

    #[test]
    fn a_null_data_pointer_is_passed_through_without_a_guard() {
        let _bench = bench();
        let mut fixture = NodeFixture::new(core::ptr::null_mut());
        let node = fixture.node_ptr();

        assert!(unsafe { path_node_release(node) }.is_null());
        assert_eq!(
            events(),
            std::vec![
                Event::SharedDataRelease(0),
                Event::PoolRecycle(node as usize),
            ],
            "the NULL behavior of the data block belongs to 0x082e1960"
        );
    }

    #[test]
    fn the_recycle_result_is_the_return_value() {
        let _bench = bench();
        unsafe extern "C" fn echo_pool_recycle(node: *mut u8) -> *mut u8 {
            node
        }
        unsafe {
            core::ptr::addr_of_mut!(PATH_NODE_HOST_OPS).write_volatile(PathNodeHostOps {
                shared_data_release: recording_shared_data_release,
                pool_recycle: echo_pool_recycle,
            });
        }
        let mut data_block = [0u8; 0x54];
        let mut fixture = NodeFixture::new(data_block.as_mut_ptr());
        let node = fixture.node_ptr();

        assert_eq!(unsafe { path_node_release(node) }, node);
    }
}
