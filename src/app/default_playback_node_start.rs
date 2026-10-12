//! Initializes and starts the fixed default playback node.
//!
//! `FUN_0803c264` @ `0x0803c264`: true extent 196 bytes through
//! `0x0803c328` (180 code + 16 literal bytes). Raw A32 verifies eight
//! plain outbound BLs, zero predicated outbound BLs, and a tail B to
//! playback_node_start. Both inbound BLs are predicated BLEQ, at
//! 0x0811a97c and 0x0811aba4; there are no plain inbound BLs.
//! Acquire the static guard, construct/register the node if acquired,
//! apply record 1 once, set limit 0x7fff and chain status 1, clear each
//! chain node's +0x3c byte, publish readiness, then overwrite +0x3e with
//! 1 and start playback without a callback. No semantic deviations;
//! target-width links and existing semantic ports replace retail calls.

#[derive(Clone, Copy)]
enum Operation { Register(*mut u32), Defaults(*mut u32), Start(*mut u8) }

unsafe fn retail(operation: Operation) {
    match operation {
        Operation::Register(node) => {
            crate::runtime::shutdown_chain::cxa_atexit(
                node.cast(), core::mem::transmute(0x081e_a268usize), 0x089c_a09c);
        }
        Operation::Defaults(node) => {
            let name = crate::util::extended_basic_layout_name::extended_basic_layout_name();
            crate::util::indexed_record_defaults::indexed_record_defaults(name as usize as u32, 1, node);
        }
        Operation::Start(node) => {
            let name = crate::app::no_content_layout_default::viewer_no_content_layout_default_resource_name();
            crate::app::playback_node_start::playback_node_start(name as usize as u32, node, 0, 0);
        }
    }
}

unsafe fn initialize(state: *mut u8, node: *mut u32, mut call: impl FnMut(Operation)) {
    let guard = state.add(0x10).cast::<u32>();
    if guard.read() & 1 == 0 && crate::runtime::cxa_guard::cxa_guard_acquire(guard) != 0 {
        let constructed = crate::app::linked_node_construct::linked_node_construct(node);
        call(Operation::Register(constructed));
        crate::runtime::cxa_guard::cxa_guard_release(guard);
    }
    if state.add(1).read() == 0 {
        call(Operation::Defaults(node));
        node.add(7).write(0x7fff);
        crate::app::linked_node_status_set::linked_node_status_set(node as usize as u32, 1);
        let root = node.cast::<u8>();
        let mut current = root;
        loop {
            current.add(0x3c).write(0);
            current = current.add(0x40).cast::<u32>().read() as usize as *mut u8;
            if current.is_null() || current == root { break; }
        }
        state.add(1).write(1);
    }
    node.cast::<u8>().add(0x3e).write(1);
    call(Operation::Start(node.cast()));
}

/// # Safety
/// Fixed firmware globals and all downstream firmware services must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn default_playback_node_start() {
    initialize(0x089c_a5e0usize as *mut u8, 0x08a1_25ecusize as *mut u32, |op| retail(op));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_clears_linear_and_circular_chains_only_once() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::DEFAULT_PLAYBACK_NODE_START, 4096) else {
            assert!(crate::testing::note_missing_u32_fixture("default_playback_node_start")); return;
        };
        unsafe {
            let node = slab.cast::<u32>();
            let tail = slab.add(0x100);
            for circular in [false, true] {
                core::ptr::write_bytes(slab, 0xa5, 512);
                let mut state = [0u32; 5];
                state[4] = 1;
                node.add(16).write(tail as usize as u32);
                tail.add(0x40).cast::<u32>().write(if circular { slab as usize as u32 } else { 0 });
                initialize(state.as_mut_ptr().cast(), node, |op| {
                    if let Operation::Defaults(dst) = op { dst.add(7).write(123); }
                    if let Operation::Start(_) = op {
                        assert_eq!(state.as_ptr().cast::<u8>().add(1).read(), 1);
                        assert_eq!(node.add(7).read(), 0x7fff);
                        assert_eq!(slab.add(0x3c).read(), 0);
                        assert_eq!(tail.add(0x3c).read(), 0);
                        assert_eq!(slab.add(0x3d).read(), 1);
                        assert_eq!(tail.add(0x3d).read(), 1);
                        assert_eq!(slab.add(0x3e).read(), 1);
                    }
                });
                node.add(7).write(99);
                slab.add(0x3c).write(7);
                tail.add(0x3c).write(8);
                slab.add(0x3e).write(0xff);
                initialize(state.as_mut_ptr().cast(), node, |op| {
                    assert!(matches!(op, Operation::Start(_)));
                });
                assert_eq!(node.add(7).read(), 99);
                assert_eq!(slab.add(0x3c).read(), 7);
                assert_eq!(tail.add(0x3c).read(), 8);
                assert_eq!(slab.add(0x3e).read(), 1);
            }
            for guard in [0, 2] {
                let mut state = [0u32; 5];
                state[4] = guard;
                state.as_mut_ptr().cast::<u8>().add(1).write(1);
                node.write(0xdead_beef);
                initialize(state.as_mut_ptr().cast(), node, |_| {});
                assert_eq!(state[4], if guard == 0 { 1 } else { 2 });
                assert_eq!(node.read(), if guard == 0 { 0x089901fc } else { 0xdead_beef });
                assert_eq!(slab.add(0x3e).read(), 1);
            }
        }
    }
}
