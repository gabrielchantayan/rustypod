//! Path-resolution child lookup.
//!
//! `path_node_lookup_component` is retailOS `FUN_082e2004` at `0x082e2004`.
//! `path_node_lookup_component_with_continuation` is `FUN_082e202c` at
//! `0x082e202c`: 164 bytes (`0x082e202c..0x082e20cf`), ending at its
//! `pop {r4-r9,sl,pc}`; the next `push {r4-r9,sl,lr}` at `0x082e20d0` starts
//! a separate function. Raw complete-image ARM decoding finds two direct
//! callers, both plain `bl` (`0x082e2024` and `0x082e640c`), and no predicated
//! caller forms. The body makes three plain BL calls (`0x082e3080`,
//! `0x082e36c8`, and `0x082e10ec`) and one predicated `blne` release call
//! (`0x082e19cc`).
//!
//! The helper creates a node from `parent` when none is supplied, optionally
//! stores its caller-provided continuation state at +0x0c, advances an
//! exhausted 16-entry directory cursor, then scans `component`. A scan failure
//! releases only a node created by this invocation. Deliberate deviation: the
//! unported create-from-parent and component-scan dependencies remain verified
//! fixed-address target calls and recording host seams; cursor advancement and
//! node release use their existing Rust ports.

use super::fat_cursor_advance_block::fat_cursor_advance_block;
use super::path_node::path_node_release;

const WORD: usize = core::mem::size_of::<*mut u8>();
const NODE_CONTINUATION_STATE: usize = 0x0c;
const NODE_CURSOR_INDEX: usize = 0x10;
const PATH_NODE_CREATE_FROM_PARENT_ADDRESS: usize = 0x082e_3080;
const PATH_NODE_SCAN_COMPONENT_ADDRESS: usize = 0x082e_10ec;

#[inline(always)]
const fn word_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn path_node_create_from_parent(parent: *mut u8) -> *mut u8 {
    let create: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(PATH_NODE_CREATE_FROM_PARENT_ADDRESS);
    create(parent)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn path_node_scan_component(
    node: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> u32 {
    let scan: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, u32) -> u32 =
        core::mem::transmute(PATH_NODE_SCAN_COMPONENT_ADDRESS);
    scan(node, component, component_state, flags)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PathNodeLookupHostOps {
    create: unsafe extern "C" fn(*mut u8) -> *mut u8,
    scan: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_path_node_create_from_parent(_parent: *mut u8) -> *mut u8 {
    panic!("path_node_lookup_component requires create seam 0x082e3080")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_path_node_scan_component(
    _node: *mut u8,
    _component: *mut u8,
    _component_state: *mut u8,
    _flags: u32,
) -> u32 {
    panic!("path_node_lookup_component requires scan seam 0x082e10ec")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PATH_NODE_LOOKUP_HOST_OPS: PathNodeLookupHostOps = PathNodeLookupHostOps {
    create: unavailable_path_node_create_from_parent,
    scan: unavailable_path_node_scan_component,
};

#[cfg(not(target_os = "none"))]
static mut PATH_NODE_LOOKUP_HOST_OPS: PathNodeLookupHostOps = DEFAULT_PATH_NODE_LOOKUP_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn path_node_create_from_parent(parent: *mut u8) -> *mut u8 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(PATH_NODE_LOOKUP_HOST_OPS));
    (ops.create)(parent)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn path_node_scan_component(
    node: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(PATH_NODE_LOOKUP_HOST_OPS));
    (ops.scan)(node, component, component_state, flags)
}

/// path_node_lookup_component_with_continuation — original: `FUN_082e202c`
/// @ `0x082e202c`.
///
/// Load address: `0x082e202c`; true size: 164 bytes; verified call count:
/// two plain inbound `bl` calls and zero predicated inbound calls. Creates or
/// reuses a path node, resets its cursor index after successful block advance,
/// and scans one component. A failed scan recycles only a newly created node.
///
/// Deliberate deviation: fixed-address seams retain the two unported
/// dependencies at `0x082e3080` and `0x082e10ec`; existing Rust ports replace
/// the advance and release BL targets.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_lookup_component_with_continuation(
    mut node: *mut u8,
    parent: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
    continuation_state: i32,
) -> *mut u8 {
    let created = node.is_null();
    if created {
        node = path_node_create_from_parent(parent);
        if node.is_null() {
            return core::ptr::null_mut();
        }
        if continuation_state != -1 {
            (node.add(word_offset(NODE_CONTINUATION_STATE)) as *mut i32).write(continuation_state);
        }
    } else {
        let cursor_index = (node.add(word_offset(NODE_CURSOR_INDEX)) as *mut u32).read().wrapping_add(1);
        (node.add(word_offset(NODE_CURSOR_INDEX)) as *mut u32).write(cursor_index);
        if cursor_index >= 16 {
            if fat_cursor_advance_block(node as *mut u32) == 0 {
                return core::ptr::null_mut();
            }
            (node.add(word_offset(NODE_CURSOR_INDEX)) as *mut u32).write(0);
        }
    }

    if path_node_scan_component(node, component, component_state, flags) != 0 {
        node
    } else {
        if created {
            path_node_release(node);
        }
        core::ptr::null_mut()
    }
}

/// path_node_lookup_component — original: `FUN_082e2004` @ `0x082e2004`.
///
/// Supplies retailOS's default continuation state, `-1`, to the ported
/// `path_node_lookup_component_with_continuation` helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_lookup_component(
    node: *mut u8,
    parent: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> *mut u8 {
    path_node_lookup_component_with_continuation(node, parent, component, component_state, flags, -1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut CREATED: *mut u8 = core::ptr::null_mut();
    static mut SCAN_RESULT: u32 = 0;
    static LAST_CREATE_PARENT: AtomicUsize = AtomicUsize::new(0);
    static mut LAST_SCAN: Option<(usize, usize, usize, u32)> = None;

    unsafe extern "C" fn recording_create(parent: *mut u8) -> *mut u8 {
        LAST_CREATE_PARENT.store(parent as usize, Ordering::Relaxed);
        CREATED
    }

    unsafe extern "C" fn recording_scan(
        node: *mut u8,
        component: *mut u8,
        component_state: *mut u8,
        flags: u32,
    ) -> u32 {
        LAST_SCAN = Some((node as usize, component as usize, component_state as usize, flags));
        SCAN_RESULT
    }

    struct TestLock;
    fn lock_ops() -> TestLock {
        while OPS_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            while OPS_LOCK.load(Ordering::Relaxed) { core::hint::spin_loop(); }
        }
        TestLock
    }
    impl Drop for TestLock {
        fn drop(&mut self) { OPS_LOCK.store(false, Ordering::Release); }
    }

    struct Bench { _lock: TestLock }
    fn bench(created: *mut u8, scan_result: u32) -> Bench {
        let lock = lock_ops();
        unsafe {
            CREATED = created;
            SCAN_RESULT = scan_result;
            LAST_CREATE_PARENT.store(0, Ordering::Relaxed);
            LAST_SCAN = None;
            core::ptr::addr_of_mut!(PATH_NODE_LOOKUP_HOST_OPS).write_volatile(PathNodeLookupHostOps {
                create: recording_create, scan: recording_scan,
            });
        }
        Bench { _lock: lock }
    }
    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(PATH_NODE_LOOKUP_HOST_OPS).write_volatile(DEFAULT_PATH_NODE_LOOKUP_HOST_OPS); }
        }
    }

    #[test]
    fn creation_failure_does_not_scan() {
        let _bench = bench(core::ptr::null_mut(), 1);
        let mut parent = [0u8; 32];
        assert!(unsafe {
            path_node_lookup_component_with_continuation(
                core::ptr::null_mut(), parent.as_mut_ptr(), core::ptr::null_mut(),
                core::ptr::null_mut(), 0, 7,
            )
        }.is_null());
        assert_eq!(LAST_CREATE_PARENT.load(Ordering::Relaxed), parent.as_mut_ptr() as usize);
        assert_eq!(unsafe { LAST_SCAN }, None);
    }

    #[test]
    fn new_node_receives_continuation_and_scans() {
        let mut node = [0u8; 64];
        let _bench = bench(node.as_mut_ptr(), 1);
        let mut parent = [0u8; 32];
        let mut component = *b"Music";
        let mut state = [0u8; 4];
        assert_eq!(unsafe {
            path_node_lookup_component_with_continuation(
                core::ptr::null_mut(), parent.as_mut_ptr(), component.as_mut_ptr(),
                state.as_mut_ptr(), 0x55, 9,
            )
        }, node.as_mut_ptr());
        assert_eq!(unsafe { (node.as_ptr().add(word_offset(NODE_CONTINUATION_STATE)) as *const i32).read() }, 9);
        assert_eq!(unsafe { LAST_SCAN }, Some((node.as_mut_ptr() as usize, component.as_mut_ptr() as usize, state.as_mut_ptr() as usize, 0x55)));
    }

    #[test]
    fn reused_node_increments_cursor_without_creating() {
        let mut node = [0u8; 64];
        let _bench = bench(core::ptr::null_mut(), 1);
        let mut component = *b"Pod";
        let mut state = [0u8; 4];
        unsafe { (node.as_mut_ptr().add(word_offset(NODE_CURSOR_INDEX)) as *mut u32).write(3); }
        assert_eq!(unsafe {
            path_node_lookup_component(node.as_mut_ptr(), core::ptr::null_mut(), component.as_mut_ptr(), state.as_mut_ptr(), 0)
        }, node.as_mut_ptr());
        assert_eq!(unsafe { (node.as_ptr().add(word_offset(NODE_CURSOR_INDEX)) as *const u32).read() }, 4);
        assert_eq!(LAST_CREATE_PARENT.load(Ordering::Relaxed), 0);
    }
}
