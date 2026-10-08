//! Starts a playback node on a child of the shared event-handler source.
//!
//! `FUN_081b111c` @ `0x081b111c`, true size 156 bytes, next real function
//! `0x081b11b8`. Raw A32: seven plain and two predicated outbound BLs;
//! two plain inbound BLs (0x082070ac, 0x082c9ebc), no predicated inbound BLs,
//! and two inbound tail branches (0x0803c314, 0x0805bc00).
//! Capture the node's +0x48 delay before acquiring a child. On success bind
//! the node, optionally install its callback AND fourth-argument context,
//! enable the child, optionally post a click, apply the captured delay and
//! source override, then mark the intrusive node chain with status 1.
//! No semantic deviations. Existing ports replace their retail targets;
//! unported helpers remain exact-address seams, including IRAM mirror calls.

#[derive(Clone, Copy, Debug, PartialEq)]
enum Operation {
    Source,
    Acquire(usize),
    Bind(usize, usize),
    Callback(usize, u32, u32),
    Enable(usize),
    Click,
    Delay(usize, u32),
    Override(usize, u32, u32),
}

unsafe fn retail(operation: Operation) -> usize {
    use core::mem::transmute;
    match operation {
        Operation::Source => crate::kernel::event_handler_source::event_handler_source() as usize,
        Operation::Acquire(source) => transmute::<usize, unsafe extern "C" fn(usize) -> usize>(0x2200_78b0)(source),
        Operation::Bind(child, node) => {
            transmute::<usize, unsafe extern "C" fn(usize, usize)>(0x0812_1e5c)(child, node); 0
        }
        Operation::Callback(child, callback, context) => {
            transmute::<usize, unsafe extern "C" fn(usize, u32, u32)>(0x0812_25f8)(child, callback, context); 0
        }
        Operation::Enable(child) => {
            crate::kernel::event_handler_source_child_enable::event_handler_source_child_enable(child as *mut u8); 0
        }
        Operation::Click => { crate::drivers::piezo::piezo_note_post(500, 2); 0 }
        Operation::Delay(child, delay) => {
            transmute::<usize, unsafe extern "C" fn(usize, u32)>(0x0812_25f0)(child, delay); 0
        }
        Operation::Override(source, delay, value) => {
            transmute::<usize, unsafe extern "C" fn(usize, u32, u32, u32)>(0x2200_7c04)(source, 1, delay, value); 0
        }
    }
}

unsafe fn start(node: *mut u8, callback: u32, context: u32, mut call: impl FnMut(Operation) -> usize) {
    let delay = node.add(0x48).cast::<u32>().read();
    let source = call(Operation::Source);
    let child = call(Operation::Acquire(source));
    if child == 0 { return; }
    call(Operation::Bind(child, node as usize));
    if callback != 0 { call(Operation::Callback(child, callback, context)); }
    call(Operation::Enable(child));
    if node.add(0x3e).read() & 2 != 0 { call(Operation::Click); }
    if delay != 0 {
        call(Operation::Delay(child, delay));
        let value = node.add(0x44).cast::<u32>().read();
        let source = call(Operation::Source);
        call(Operation::Override(source, delay, value));
    }
    crate::app::linked_node_status_set::linked_node_status_set(node as usize as u32, 1);
}

/// # Safety
/// `node` is an aligned retail-layout node with valid +0x40 links; all firmware
/// services must be initialized. `callback` and `context` obey the child ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn playback_node_start(_context: u32, node: *mut u8, callback: u32, callback_context: u32) {
    start(node, callback, callback_context, |operation| retail(operation));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PLAYBACK_NODE_START, 4096).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn failed_acquisition_preserves_node_and_skips_callback() {
        let mut node = [0x5555_5555u32; 20];
        let original = node;
        let mut calls = std::vec::Vec::new();
        unsafe { start(node.as_mut_ptr().cast(), 7, 9, |op| {
            calls.push(op);
            if op == Operation::Source { 42 } else { 0 }
        }); }
        assert_eq!(node, original);
        assert_eq!(calls, [Operation::Source, Operation::Acquire(42)]);
    }

    #[test]
    fn optional_actions_and_delay_snapshot_survive_binding_mutation() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/playback_node_start")); return;
        };
        unsafe {
            let node = base as *mut u8;
            let tail = node.add(0x100);
            for callback in [0, 0x1234] {
                for delay in [0, 77] {
                    for click in [false, true] {
                        core::ptr::write_bytes(node, 0, 0x200);
                        node.add(0x48).cast::<u32>().write(delay);
                        node.add(0x40).cast::<u32>().write(tail as usize as u32);
                        tail.add(0x40).cast::<u32>().write(base as u32);
                        let mut calls = std::vec::Vec::new();
                        start(node, callback, 0xabcd, |op| {
                            calls.push(op);
                            match op {
                                Operation::Source => 42,
                                Operation::Acquire(42) => 99,
                                Operation::Bind(99, _) => {
                                    node.add(0x48).cast::<u32>().write(88);
                                    node.add(0x44).cast::<u32>().write(66);
                                    node.add(0x3e).write(if click { 2 } else { 1 });
                                    0
                                }
                                _ => 0,
                            }
                        });
                        let mut expected = std::vec![Operation::Source, Operation::Acquire(42), Operation::Bind(99, base)];
                        if callback != 0 { expected.push(Operation::Callback(99, callback, 0xabcd)); }
                        expected.push(Operation::Enable(99));
                        if click { expected.push(Operation::Click); }
                        if delay != 0 {
                            expected.extend([Operation::Delay(99, delay), Operation::Source, Operation::Override(42, delay, 66)]);
                        }
                        assert_eq!(calls, expected);
                        assert_eq!(node.add(0x3d).read(), 1);
                        assert_eq!(tail.add(0x3d).read(), 1);
                    }
                }
            }
        }
    }
}
