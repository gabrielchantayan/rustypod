//! Path-resolution child lookup with the default continuation state.
//!
//! `path_node_lookup_component` is retailOS `FUN_082e2004` at `0x082e2004`.
//! Its raw extent is 40 bytes (`0x082e2004..0x082e202b`): the following
//! `push {r4-r10,lr}` at `0x082e202c` starts the separately linked helper.
//! Every ARM `B`/`BL` word in `osos.dec` was decoded: 10 direct call sites,
//! all plain `bl` (at `0x082e16a8`, `0x082e2344`, `0x082e23fc`, `0x082e2e70`,
//! `0x082e3190`, `0x082e3520`, `0x082e4110`, `0x082e415c`, `0x082e41b0`, and
//! `0x082e4840`); there are no predicated calls or tail branches.
//!
//! The wrapper preserves its five ABI arguments, places `-1` in the sixth
//! stack argument slot, and calls the unported `FUN_082e202c`.  Its result is
//! returned unchanged.  The helper allocates or advances a path node and
//! scans a component, but its exact identity and the sixth argument's field
//! meaning remain unported.  Deliberate deviation: Ghidra declares this
//! function `void`; raw ARM and every caller show that it propagates `r0`, so
//! the Rust ABI returns the helper's node pointer.

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_lookup_component(
    node: *mut u8,
    parent: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> *mut u8 {
    let lookup: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8, u32, i32) -> *mut u8 =
        core::mem::transmute(0x082e_202cusize);
    lookup(node, parent, component, component_state, flags, -1)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PathNodeLookupHostOps {
    lookup: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8, u32, i32) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_lookup_component(
    _node: *mut u8,
    _parent: *mut u8,
    _component: *mut u8,
    _component_state: *mut u8,
    _flags: u32,
    _continuation_state: i32,
) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PATH_NODE_LOOKUP_HOST_OPS: PathNodeLookupHostOps = PathNodeLookupHostOps {
    lookup: host_lookup_component,
};

#[cfg(not(target_os = "none"))]
static mut PATH_NODE_LOOKUP_HOST_OPS: PathNodeLookupHostOps = DEFAULT_PATH_NODE_LOOKUP_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_lookup_component(
    node: *mut u8,
    parent: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> *mut u8 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(PATH_NODE_LOOKUP_HOST_OPS));
    (ops.lookup)(node, parent, component, component_state, flags, -1)
}

/// path_node_lookup_component — original: `FUN_082e2004` @ `0x082e2004`
/// (40 bytes; 10 binary-verified plain `bl` call sites).
///
/// Looks up one parsed path component below `parent`, optionally reusing
/// `node`.  The retail helper at `0x082e202c` receives the caller's raw
/// component state and flags plus its wrapper-supplied continuation state
/// `-1`; this wrapper returns that helper's node pointer unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_lookup_component(
    node: *mut u8,
    parent: *mut u8,
    component: *mut u8,
    component_state: *mut u8,
    flags: u32,
) -> *mut u8 {
    retail_lookup_component(node, parent, component, component_state, flags)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut CALL: Option<Call> = None;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Call {
        node: usize,
        parent: usize,
        component: usize,
        component_state: usize,
        flags: u32,
        continuation_state: i32,
    }

    unsafe extern "C" fn recording_lookup_component(
        node: *mut u8,
        parent: *mut u8,
        component: *mut u8,
        component_state: *mut u8,
        flags: u32,
        continuation_state: i32,
    ) -> *mut u8 {
        CALL = Some(Call {
            node: node as usize,
            parent: parent as usize,
            component: component as usize,
            component_state: component_state as usize,
            flags,
            continuation_state,
        });
        component_state
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
            CALL = None;
            core::ptr::addr_of_mut!(PATH_NODE_LOOKUP_HOST_OPS).write_volatile(PathNodeLookupHostOps {
                lookup: recording_lookup_component,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_NODE_LOOKUP_HOST_OPS)
                    .write_volatile(DEFAULT_PATH_NODE_LOOKUP_HOST_OPS);
            }
        }
    }

    #[test]
    fn every_argument_and_default_continuation_state_reach_the_helper() {
        let _bench = bench();
        let mut node = [0u8; 0x1c];
        let mut parent = [0u8; 0x1c];
        let mut component = *b"Music";
        let mut component_state = [0u8; 4];

        assert_eq!(
            unsafe {
                path_node_lookup_component(
                    node.as_mut_ptr(),
                    parent.as_mut_ptr(),
                    component.as_mut_ptr(),
                    component_state.as_mut_ptr(),
                    1,
                )
            },
            component_state.as_mut_ptr()
        );
        assert_eq!(
            unsafe { CALL },
            Some(Call {
                node: node.as_mut_ptr() as usize,
                parent: parent.as_mut_ptr() as usize,
                component: component.as_mut_ptr() as usize,
                component_state: component_state.as_mut_ptr() as usize,
                flags: 1,
                continuation_state: -1,
            })
        );
    }

    #[test]
    fn null_reused_node_is_forwarded_without_a_wrapper_guard() {
        let _bench = bench();
        let mut parent = [0u8; 0x1c];
        let mut component = *b"Pod";
        let mut component_state = [0u8; 4];

        assert_eq!(
            unsafe {
                path_node_lookup_component(
                    core::ptr::null_mut(),
                    parent.as_mut_ptr(),
                    component.as_mut_ptr(),
                    component_state.as_mut_ptr(),
                    0,
                )
            },
            component_state.as_mut_ptr()
        );
        assert_eq!(
            unsafe { CALL }.unwrap().node,
            0,
            "the allocation decision belongs to 0x082e202c"
        );
    }
}
