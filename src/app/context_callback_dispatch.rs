//! Context callback dispatch depth management.
//!
//! `context_dispatch_callbacks_and_advance` — original: `FUN_080d6b14` @
//! `0x080d6b14` (**144 bytes**, `0x080d6b14..0x080d6ba4`; the next separately
//! linked function begins at `0x080d6ba4`).
//!
//! A complete ARM B/BL decode of `osos.dec` finds **8 direct `bl` call sites**,
//! all unconditional, at `0x080747d0`, `0x080771c0`, `0x080f288c`,
//! `0x080f2ab4`, `0x0820f304`, `0x08212fd4`, `0x08262ea8`, and `0x08263ed8`.
//! There are no predicated direct calls. A ninth reference is the unconditional
//! tail branch at `0x08277520`, which is not a call site.
//!
//! `context_dispatch_callbacks_and_finish` — original: `FUN_080d2118` @
//! `0x080d2118` (**184 bytes**, `0x080d2118..0x080d21d0`; the next separately
//! linked function begins at `0x080d21d0`).
//!
//! A complete ARM B/BL decode of `osos.dec` finds **8 direct `bl` call sites**,
//! all unconditional, at `0x0807488c`, `0x08077240`, `0x080f2a50`,
//! `0x080f2b3c`, `0x0820fa44`, `0x08213534`, `0x082630c8`, and `0x08264048`.
//! There are no predicated direct calls. The separate unconditional tail branch
//! at `0x08277720` is not a call site.
//!
//! # Algorithm
//!
//! `context_dispatch_callbacks_and_advance` conditionally locks the state mutex,
//! dispatches its circular mode-1 callback list and clears queued-entry flags at
//! depth zero, then increments the depth with wrapping arithmetic.
//! `context_dispatch_callbacks_and_finish` decrements the same depth with
//! wrapping arithmetic; only when it reaches zero does it drain all queued
//! entries through their two observed callback passes, invoke every nonzero
//! completion callback with mode 0, and finally conditionally unlock the mutex.
//! Neither function NULL-checks `context` or its state pointer.
//!
//! # Deliberate deviations
//!
//! The raw callback words and the unported queued-entry helpers
//! (`FUN_0829cfc8`, `FUN_080aa3a8`, and `FUN_080b28bc`) are called at their
//! verified device addresses. Host builds expose replaceable seams because
//! target-width callback words cannot contain 64-bit host function pointers.
//! The surrounding context remains a target-width layout on both platforms;
//! host tests use a low-4-GiB slab.

use core::ptr::{addr_of, addr_of_mut};

use crate::kernel::sync_mutex::{kernel_running, mutex_lock_counted, mutex_unlock_counted, CountedMutex};

const RETAIL_CLEAR_CONTEXT_ENTRY_FLAGS: usize = 0x0818_5b60;

/// Caller-owned record as read by the original. Every pointer field remains a
/// target-width word even on the host.
#[repr(C)]
pub struct CallbackDispatchContext {
    _before_state: [u8; 0x24],
    pub state: u32,
    _before_callback_argument: [u8; 0x68],
    pub callback_argument: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackDispatchContext>() == 0x94);
const _: [u8; 0x24] = [0; core::mem::offset_of!(CallbackDispatchContext, state)];
const _: [u8; 0x90] = [0; core::mem::offset_of!(CallbackDispatchContext, callback_argument)];

/// Recovered state fields reached by this routine.
#[repr(C)]
pub struct CallbackDispatchState {
    pub list_anchor: u32,
    pub queued_entries: u32,
    _before_dispatch_depth: [u8; 0x4c],
    pub dispatch_depth: u32,
    pub counted_mutex: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackDispatchState>() == 0x5c);
const _: [u8; 0x54] = [0; core::mem::offset_of!(CallbackDispatchState, dispatch_depth)];
const _: [u8; 0x58] = [0; core::mem::offset_of!(CallbackDispatchState, counted_mutex)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(CallbackDispatchState, queued_entries)];

/// The linked-list anchor's only reached word is its first node at `+0x10`.
#[repr(C)]
pub struct CallbackListAnchor {
    _before_first_node: [u8; 0x10],
    pub first_node: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(CallbackListAnchor, first_node)];

/// The circular list node fields reached by the original.
#[repr(C)]
pub struct CallbackListNode {
    _before_callback: [u8; 8],
    pub callback: u32,
    _before_next: [u8; 4],
    pub next: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackListNode>() == 0x14);
const _: [u8; 0x08] = [0; core::mem::offset_of!(CallbackListNode, callback)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(CallbackListNode, next)];

/// The final-mode callback list traversed while completing a dispatch. It is
/// distinct from the circular mode-1 list above.
#[repr(C)]
pub struct CompletionCallbackListNode {
    _before_callback: [u8; 0x0c],
    pub callback: u32,
    _before_next: [u8; 4],
    pub next: u32,
}

const _: () = assert!(core::mem::size_of::<CompletionCallbackListNode>() == 0x18);
const _: [u8; 0x0c] = [0; core::mem::offset_of!(CompletionCallbackListNode, callback)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(CompletionCallbackListNode, next)];

/// Host representation of the two edges whose target ABI carries raw code
/// words. `callback_word` is exactly the node's word at `+0x08`.
#[cfg(not(target_os = "none"))]
pub type ContextCallbackInvocation = unsafe extern "C" fn(callback_word: u32, argument: u32, mode: u32);
#[cfg(not(target_os = "none"))]
pub type QueuedEntryPop = unsafe extern "C" fn(queue: *mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type QueuedEntryCallbacks = unsafe extern "C" fn(context: *mut CallbackDispatchContext, entry: *mut u8);
#[cfg(not(target_os = "none"))]
pub type ContextEntryFlagsClear = unsafe extern "C" fn(state_plus_4: *mut u8);

/// Host-only equivalents of the raw callback and unported clear edge.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ContextCallbackDispatchOps {
    pub invoke_callback: ContextCallbackInvocation,
    pub pop_queued_entry: QueuedEntryPop,
    pub invoke_queued_entry_primary_callbacks: QueuedEntryCallbacks,
    pub invoke_queued_entry_secondary_callbacks: QueuedEntryCallbacks,
    pub clear_entry_flags: ContextEntryFlagsClear,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_callback(_callback_word: u32, _argument: u32, _mode: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_entry_flag_clear(_state_plus_4: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queued_entry_pop(_queue: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queued_entry_callbacks(
    _context: *mut CallbackDispatchContext,
    _entry: *mut u8,
) {}

/// Inert defaults retain the raw control flow when host callers have no model
/// for the still-unported edges.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTEXT_CALLBACK_DISPATCH_OPS: ContextCallbackDispatchOps = ContextCallbackDispatchOps {
    invoke_callback: missing_context_callback,
    pop_queued_entry: missing_queued_entry_pop,
    invoke_queued_entry_primary_callbacks: missing_queued_entry_callbacks,
    invoke_queued_entry_secondary_callbacks: missing_queued_entry_callbacks,
    clear_entry_flags: missing_entry_flag_clear,
};

/// Host-only replacement for target-width callback words and `FUN_08185b60`.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_CALLBACK_DISPATCH_OPS: ContextCallbackDispatchOps =
    DEFAULT_CONTEXT_CALLBACK_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_callback_dispatch_ops() -> ContextCallbackDispatchOps {
    core::ptr::read_volatile(addr_of!(CONTEXT_CALLBACK_DISPATCH_OPS))
}

#[cfg(target_os = "none")]
unsafe fn invoke_retail_callback(callback_word: u32, argument: u32, mode: u32) {
    let callback: unsafe extern "C" fn(u32, u32) = core::mem::transmute(callback_word as usize);
    callback(argument, mode);
}

#[cfg(target_os = "none")]
unsafe fn clear_retail_context_entry_flags(state_plus_4: *mut u8) {
    let clear: unsafe extern "C" fn(*mut u8) = core::mem::transmute(RETAIL_CLEAR_CONTEXT_ENTRY_FLAGS);
    clear(state_plus_4);
}

#[cfg(target_os = "none")]
unsafe fn pop_retail_queued_entry(queue: *mut u8) -> *mut u8 {
    let pop: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(0x0829_cfc8usize);
    pop(queue)
}

#[cfg(target_os = "none")]
unsafe fn invoke_retail_queued_entry_primary_callbacks(
    context: *mut CallbackDispatchContext,
    entry: *mut u8,
) {
    let invoke: unsafe extern "C" fn(*mut CallbackDispatchContext, *mut u8) =
        core::mem::transmute(0x080a_a3a8usize);
    invoke(context, entry);
}

#[cfg(target_os = "none")]
unsafe fn invoke_retail_queued_entry_secondary_callbacks(
    context: *mut CallbackDispatchContext,
    entry: *mut u8,
) {
    let invoke: unsafe extern "C" fn(*mut CallbackDispatchContext, *mut u8) =
        core::mem::transmute(0x080b_28bcusize);
    invoke(context, entry);
}

/// Dispatches a context's callbacks once and advances its dispatch depth —
/// original: `FUN_080d6b14` @ `0x080d6b14` (144 bytes; 8 direct,
/// unconditional `bl` call sites and no predicated forms, binary-verified).
///
/// # Safety
///
/// `context` must point to a writable [`CallbackDispatchContext`] whose state,
/// list links, callback words, and optional counted mutex meet the firmware's
/// requirements. The list must be circular when nonempty; ARM has no malformed
/// link or callback target guards beyond the callback word's zero test.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_dispatch_callbacks_and_advance")]
#[inline(never)]
pub unsafe extern "C" fn context_dispatch_callbacks_and_advance(context: *mut CallbackDispatchContext) {
    let state = addr_of!((*context).state).read_volatile() as usize as *mut CallbackDispatchState;
    let counted_mutex = addr_of!((*state).counted_mutex).read_volatile() as usize as *mut CountedMutex;
    if !counted_mutex.is_null() && kernel_running() != 0 {
        mutex_lock_counted(counted_mutex);
    }

    let dispatch_depth = addr_of_mut!((*state).dispatch_depth);
    if dispatch_depth.read_volatile() == 0 {
        #[cfg(not(target_os = "none"))]
        let ops = context_callback_dispatch_ops();

        let list_anchor = addr_of!((*state).list_anchor).read_volatile() as usize as *mut CallbackListAnchor;
        if !list_anchor.is_null() {
            let first_node = addr_of!((*list_anchor).first_node).read_volatile() as usize as *mut CallbackListNode;
            let mut node = first_node;
            loop {
                let callback_word = addr_of!((*node).callback).read_volatile();
                if callback_word != 0 {
                    #[cfg(target_os = "none")]
                    invoke_retail_callback(
                        callback_word,
                        addr_of!((*context).callback_argument).read_volatile(),
                        1,
                    );
                    #[cfg(not(target_os = "none"))]
                    (ops.invoke_callback)(
                        callback_word,
                        addr_of!((*context).callback_argument).read_volatile(),
                        1,
                    );
                }
                node = addr_of!((*node).next).read_volatile() as usize as *mut CallbackListNode;
                if node == first_node {
                    break;
                }
            }
        }

        let state_plus_4 = addr_of_mut!((*state).queued_entries).cast::<u8>();
        #[cfg(target_os = "none")]
        clear_retail_context_entry_flags(state_plus_4);
        #[cfg(not(target_os = "none"))]
        (ops.clear_entry_flags)(state_plus_4);
    }
    dispatch_depth.write_volatile(dispatch_depth.read_volatile().wrapping_add(1));
}

/// Completes a context callback dispatch — original: `FUN_080d2118` @
/// `0x080d2118` (184 bytes; 8 direct, unconditional `bl` call sites and no
/// predicated forms, binary-verified).
///
/// # Safety
///
/// `context` must point to a writable [`CallbackDispatchContext`] whose state,
/// queued-entry storage, completion-list links, callback words, and optional
/// counted mutex meet the firmware's requirements. ARM wraps the decrement and
/// traverses completion links until NULL; it provides no malformed-link guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_dispatch_callbacks_and_finish")]
#[inline(never)]
pub unsafe extern "C" fn context_dispatch_callbacks_and_finish(context: *mut CallbackDispatchContext) {
    let state = addr_of!((*context).state).read_volatile() as usize as *mut CallbackDispatchState;
    let dispatch_depth = addr_of_mut!((*state).dispatch_depth);
    dispatch_depth.write_volatile(dispatch_depth.read_volatile().wrapping_sub(1));

    if dispatch_depth.read_volatile() == 0 {
        #[cfg(not(target_os = "none"))]
        let ops = context_callback_dispatch_ops();

        let queued_entries = addr_of_mut!((*state).queued_entries).cast::<u8>();
        loop {
            #[cfg(target_os = "none")]
            let entry = pop_retail_queued_entry(queued_entries);
            #[cfg(not(target_os = "none"))]
            let entry = (ops.pop_queued_entry)(queued_entries);
            if entry.is_null() {
                break;
            }

            #[cfg(target_os = "none")]
            invoke_retail_queued_entry_primary_callbacks(context, entry);
            #[cfg(not(target_os = "none"))]
            (ops.invoke_queued_entry_primary_callbacks)(context, entry);

            #[cfg(target_os = "none")]
            invoke_retail_queued_entry_secondary_callbacks(context, entry);
            #[cfg(not(target_os = "none"))]
            (ops.invoke_queued_entry_secondary_callbacks)(context, entry);
        }

        let mut node = addr_of!((*state).list_anchor).read_volatile() as usize as *mut CompletionCallbackListNode;
        while !node.is_null() {
            let callback_word = addr_of!((*node).callback).read_volatile();
            if callback_word != 0 {
                let argument = addr_of!((*context).callback_argument).read_volatile();
                #[cfg(target_os = "none")]
                invoke_retail_callback(callback_word, argument, 0);
                #[cfg(not(target_os = "none"))]
                (ops.invoke_callback)(callback_word, argument, 0);
            }
            node = addr_of!((*node).next).read_volatile() as usize as *mut CompletionCallbackListNode;
        }
    }

    let counted_mutex = addr_of!((*state).counted_mutex).read_volatile() as usize as *mut CountedMutex;
    if !counted_mutex.is_null() && kernel_running() != 0 {
        mutex_unlock_counted(counted_mutex);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const STATE_AT: usize = 0x100;
    const ANCHOR_AT: usize = 0x200;
    const FIRST_NODE_AT: usize = 0x240;
    const SECOND_NODE_AT: usize = 0x280;
    const THIRD_NODE_AT: usize = 0x2c0;
    const COMPLETION_FIRST_AT: usize = 0x300;
    const COMPLETION_SECOND_AT: usize = 0x340;
    const QUEUED_FIRST_AT: usize = 0x380;
    const QUEUED_SECOND_AT: usize = 0x3c0;
    const CLEAR_EVENT: u32 = 0xc1ea_0001;
    const POP_EVENT_BASE: u32 = 0x9000_0000;
    const PRIMARY_EVENT_BASE: u32 = 0xa100_0000;
    const SECONDARY_EVENT_BASE: u32 = 0xb200_0000;


    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTEXT_CALLBACK_DISPATCH, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut ORDER: [u32; 12] = [0; 12];
    static mut ORDER_LEN: usize = 0;
    static mut CALLBACK_ARGUMENTS: [(u32, u32); 3] = [(0, 0); 3];
    static mut CALLBACK_LEN: usize = 0;
    static mut POP_RESULTS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut POP_LEN: usize = 0;
    static mut PRIMARY_LEN: usize = 0;
    static mut SECONDARY_LEN: usize = 0;
    static mut STATE_DURING_CLEAR: *mut CallbackDispatchState = core::ptr::null_mut();
    static mut DEPTH_SEEN_BY_CLEAR: u32 = u32::MAX;

    unsafe extern "C" fn record_callback(callback_word: u32, argument: u32, mode: u32) {
        ORDER[ORDER_LEN] = callback_word;
        ORDER_LEN += 1;
        CALLBACK_ARGUMENTS[CALLBACK_LEN] = (argument, mode);
        CALLBACK_LEN += 1;
    }

    unsafe extern "C" fn record_clear(_state_plus_4: *mut u8) {
        ORDER[ORDER_LEN] = CLEAR_EVENT;
        ORDER_LEN += 1;
        DEPTH_SEEN_BY_CLEAR = addr_of!((*STATE_DURING_CLEAR).dispatch_depth).read_volatile();
    }

    unsafe extern "C" fn pop_queued_entry(_queue: *mut u8) -> *mut u8 {
        ORDER[ORDER_LEN] = POP_EVENT_BASE + POP_LEN as u32;
        ORDER_LEN += 1;
        let entry = POP_RESULTS[POP_LEN];
        POP_LEN += 1;
        entry
    }

    unsafe extern "C" fn record_primary_queued_entry(
        _context: *mut CallbackDispatchContext,
        _entry: *mut u8,
    ) {
        ORDER[ORDER_LEN] = PRIMARY_EVENT_BASE + PRIMARY_LEN as u32;
        ORDER_LEN += 1;
        PRIMARY_LEN += 1;
    }

    unsafe extern "C" fn record_secondary_queued_entry(
        _context: *mut CallbackDispatchContext,
        _entry: *mut u8,
    ) {
        ORDER[ORDER_LEN] = SECONDARY_EVENT_BASE + SECONDARY_LEN as u32;
        ORDER_LEN += 1;
        SECONDARY_LEN += 1;
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        base: *mut u8,
        previous_ops: ContextCallbackDispatchOps,
    }

    impl Fixture {
        fn map() -> Option<*mut u8> {
            (*BASE).map(|pointer| pointer as *mut u8)
        }

        fn new() -> Option<Self> {
            let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let base = Self::map()?;
            unsafe {
                core::ptr::write_bytes(base, 0, FIXTURE_LEN);
                let previous_ops = addr_of!(CONTEXT_CALLBACK_DISPATCH_OPS).read_volatile();
                addr_of_mut!(CONTEXT_CALLBACK_DISPATCH_OPS).write(ContextCallbackDispatchOps {
                    invoke_callback: record_callback,
                    pop_queued_entry,
                    invoke_queued_entry_primary_callbacks: record_primary_queued_entry,
                    invoke_queued_entry_secondary_callbacks: record_secondary_queued_entry,
                    clear_entry_flags: record_clear,
                });
                addr_of_mut!(ORDER).write([0; 12]);
                addr_of_mut!(ORDER_LEN).write(0);
                addr_of_mut!(CALLBACK_ARGUMENTS).write([(0, 0); 3]);
                addr_of_mut!(CALLBACK_LEN).write(0);
                addr_of_mut!(POP_RESULTS).write([core::ptr::null_mut(); 3]);
                addr_of_mut!(POP_LEN).write(0);
                addr_of_mut!(PRIMARY_LEN).write(0);
                addr_of_mut!(SECONDARY_LEN).write(0);
                addr_of_mut!(STATE_DURING_CLEAR).write(base.add(STATE_AT).cast());
                addr_of_mut!(DEPTH_SEEN_BY_CLEAR).write(u32::MAX);
                Some(Self { _guard: guard, base, previous_ops })
            }
        }

        fn at(&self, offset: usize) -> *mut u8 {
            unsafe { self.base.add(offset) }
        }

        fn word(pointer: *mut u8) -> u32 {
            u32::try_from(pointer as usize).expect("fixture mapping is target-width")
        }

        unsafe fn context(&self) -> *mut CallbackDispatchContext {
            self.at(0).cast()
        }

        unsafe fn state(&self) -> *mut CallbackDispatchState {
            self.at(STATE_AT).cast()
        }

        unsafe fn initialize(&self, depth: u32, with_list: bool) {
            addr_of_mut!((*self.context()).state).write(Self::word(self.at(STATE_AT)));
            addr_of_mut!((*self.context()).callback_argument).write(0x0bad_f00d);
            addr_of_mut!((*self.state()).dispatch_depth).write(depth);
            addr_of_mut!((*self.state()).counted_mutex).write(0);
            if with_list {
                addr_of_mut!((*self.state()).list_anchor).write(Self::word(self.at(ANCHOR_AT)));
                addr_of_mut!((*self.at(ANCHOR_AT).cast::<CallbackListAnchor>()).first_node)
                    .write(Self::word(self.at(FIRST_NODE_AT)));
            }
        }

        unsafe fn node(&self, offset: usize, callback: u32, next_offset: usize) {
            let node = self.at(offset).cast::<CallbackListNode>();
            addr_of_mut!((*node).callback).write(callback);
            addr_of_mut!((*node).next).write(Self::word(self.at(next_offset)));
        }

        unsafe fn completion_node(&self, offset: usize, callback: u32, next_offset: Option<usize>) {
            let node = self.at(offset).cast::<CompletionCallbackListNode>();
            addr_of_mut!((*node).callback).write(callback);
            addr_of_mut!((*node).next).write(
                next_offset.map_or(0, |next| Self::word(self.at(next))),
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(CONTEXT_CALLBACK_DISPATCH_OPS).write(self.previous_ops);
                addr_of_mut!(STATE_DURING_CLEAR).write(core::ptr::null_mut());
            }
        }
    }

    #[test]
    fn traverses_circular_callbacks_skips_zero_and_clears_before_advancing() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/context_callback_dispatch"));
            return;
        };
        unsafe {
            fixture.initialize(0, true);
            fixture.node(FIRST_NODE_AT, 0x1111_1111, SECOND_NODE_AT);
            fixture.node(SECOND_NODE_AT, 0, THIRD_NODE_AT);
            fixture.node(THIRD_NODE_AT, 0x3333_3333, FIRST_NODE_AT);
            context_dispatch_callbacks_and_advance(fixture.context());
            assert_eq!(ORDER_LEN, 3);
            assert_eq!(&ORDER[..ORDER_LEN], &[0x1111_1111, 0x3333_3333, CLEAR_EVENT]);
            assert_eq!(CALLBACK_LEN, 2);
            assert_eq!(&CALLBACK_ARGUMENTS[..CALLBACK_LEN], &[(0x0bad_f00d, 1), (0x0bad_f00d, 1)]);
            assert_eq!(DEPTH_SEEN_BY_CLEAR, 0, "clear follows callbacks before the increment");
            assert_eq!(addr_of!((*fixture.state()).dispatch_depth).read(), 1);
        }
    }

    #[test]
    fn empty_list_still_clears_and_advances() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/context_callback_dispatch"));
            return;
        };
        unsafe {
            fixture.initialize(0, false);
            context_dispatch_callbacks_and_advance(fixture.context());
            assert_eq!(ORDER_LEN, 1);
            assert_eq!(ORDER[0], CLEAR_EVENT);
            assert_eq!(CALLBACK_LEN, 0);
            assert_eq!(addr_of!((*fixture.state()).dispatch_depth).read(), 1);
        }
    }

    #[test]
    fn nonzero_depth_suppresses_dispatch_and_clear_but_wraps_increment() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/context_callback_dispatch"));
            return;
        };
        unsafe {
            fixture.initialize(u32::MAX, true);
            fixture.node(FIRST_NODE_AT, 0x1111_1111, FIRST_NODE_AT);
            context_dispatch_callbacks_and_advance(fixture.context());
            assert_eq!(ORDER_LEN, 0);
            assert_eq!(CALLBACK_LEN, 0);
            assert_eq!(addr_of!((*fixture.state()).dispatch_depth).read(), 0);
        }
    }
    #[test]
    fn finish_drains_queued_entries_then_final_callbacks_at_depth_zero() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/context_callback_dispatch"));
            return;
        };
        unsafe {
            fixture.initialize(1, false);
            addr_of_mut!((*fixture.state()).list_anchor)
                .write(Fixture::word(fixture.at(COMPLETION_FIRST_AT)));
            fixture.completion_node(COMPLETION_FIRST_AT, 0xc001_0001, Some(COMPLETION_SECOND_AT));
            fixture.completion_node(COMPLETION_SECOND_AT, 0, None);
            addr_of_mut!(POP_RESULTS).write([
                fixture.at(QUEUED_FIRST_AT),
                fixture.at(QUEUED_SECOND_AT),
                core::ptr::null_mut(),
            ]);

            context_dispatch_callbacks_and_finish(fixture.context());

            assert_eq!(ORDER_LEN, 8);
            assert_eq!(
                &ORDER[..ORDER_LEN],
                &[
                    POP_EVENT_BASE,
                    PRIMARY_EVENT_BASE,
                    SECONDARY_EVENT_BASE,
                    POP_EVENT_BASE + 1,
                    PRIMARY_EVENT_BASE + 1,
                    SECONDARY_EVENT_BASE + 1,
                    POP_EVENT_BASE + 2,
                    0xc001_0001,
                ],
            );
            assert_eq!(CALLBACK_LEN, 1);
            assert_eq!(CALLBACK_ARGUMENTS[0], (0x0bad_f00d, 0));
            assert_eq!(addr_of!((*fixture.state()).dispatch_depth).read(), 0);
        }
    }

    #[test]
    fn finish_wraps_zero_depth_without_draining_or_invoking_callbacks() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/context_callback_dispatch"));
            return;
        };
        unsafe {
            fixture.initialize(0, false);
            addr_of_mut!((*fixture.state()).list_anchor)
                .write(Fixture::word(fixture.at(COMPLETION_FIRST_AT)));
            fixture.completion_node(COMPLETION_FIRST_AT, 0xc001_0001, None);
            addr_of_mut!(POP_RESULTS).write([
                fixture.at(QUEUED_FIRST_AT),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ]);

            context_dispatch_callbacks_and_finish(fixture.context());

            assert_eq!(ORDER_LEN, 0);
            assert_eq!(CALLBACK_LEN, 0);
            assert_eq!(addr_of!((*fixture.state()).dispatch_depth).read(), u32::MAX);
        }
    }
}
