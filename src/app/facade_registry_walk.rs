//! The facade registry walk: resolves an interface object's published
//! facade against a selector, retrying through the registry's default
//! interface root until a facade is accepted.
//!
//! Port:
//! - [`facade_registry_walk`] — original: `FUN_08296ec0` @ `0x08296ec0`
//!   (60 bytes; **9 `bl` call sites plus one tail branch** from
//!   `facade_for_selector` @ `0x0818a0c0`).
//!
//! ## Stock algorithm
//!
//! ```text
//! node = interface;
//! loop {
//!     facade = node->field_0x08;
//!     if (facade != NULL) {
//!         if (selector == 0 ||
//!             (node->state_0x19 | (facade->kind_0x08 - 1)) == 0)
//!             return facade;
//!     }
//!     FUN_0814a08c(dead_argument); // trace-static accessor
//!     node = FUN_0814a030();        // default interface root
//!     selector = 0;                 // accept any facade after a miss
//! }
//! ```
//!
//! The raw ARM at `0x08296ec0..0x08296ef8` loads the facade from +0x08,
//! checks a nonzero selector with a byte state at +0x19 and facade kind at
//! +0x08, then calls the two ADS local-static accessors on a miss. Kind zero
//! intentionally wraps its subtraction to `0xffff_ffff`, so only kind one
//! and state zero satisfy a nonzero selector. The trace accessor never reads
//! the value supplied in r0 and its result is discarded, but the target port
//! still calls it because it may initialize its own static state.
//!
//! `FUN_0814a030` returns the fixed default root at `0x08a778f4`; its
//! constructor publishes a facade into field +0x08 before releasing its
//! local-static guard. Therefore retailOS normally completes after at most
//! one fallback. The host model preserves that born-published default, while
//! tests replace the two accessor seams with house-static chains to exercise
//! the polling loop.
//!
//! Direct callers are at `0x080a28cc`, `0x0813a34c`, `0x0813a3ec`,
//! `0x0813a6d4`, `0x0813a9d8`, `0x08296f50`, `0x082971a8`, `0x08297200`,
//! and `0x08297288`; three pass selector 1 and six pass selector 0. The
//! `b 0x08296ec0` at `0x0818a0c0` is the tail branch in
//! [`crate::app::facade_for_selector::facade_for_selector`], whose 34
//! callers forward selector 1 thirty-three times and selector 0 once.
//!
//! ## Deliberate host deviation
//!
//! The two ADS local-static accessors remain retailOS functions. On the
//! target their fixed load addresses are called directly. Host builds use a
//! no-op trace accessor and a born-published house-static default root; test
//! seams may replace both. Pointer fields are native-width for the host
//! parked-pointer convention; all relevant offsets are literal on the
//! 32-bit target.

/// Firmware load address of the trace-static accessor called after every
/// miss (`FUN_0814a08c`).
pub const TRACE_STATIC_ACCESSOR_ADDRESS: usize = 0x0814_a08c;

/// Firmware load address of the ADS local-static accessor returning the
/// registry's default interface root (`FUN_0814a030`).
pub const DEFAULT_ROOT_ACCESSOR_ADDRESS: usize = 0x0814_a030;

/// Fixed object returned by `FUN_0814a030`: the registry's default interface
/// root, whose constructor publishes its facade before releasing the guard.
pub const REGISTRY_DEFAULT_ROOT_ADDRESS: usize = 0x08a7_78f4;

/// Byte offset of the facade kind the walk loads at `0x08296ed0`.
pub const FACADE_KIND_OFFSET: usize = 0x08;

/// Selector zero accepts any published facade without reading state or kind.
pub const SELECTOR_ANY: u32 = 0;

/// The selector value used by the matching path: state must be zero and kind
/// must be one. The walk treats every nonzero selector equivalently.
pub const SELECTOR_MATCHING: u32 = 1;

/// The facade object as the registry walk reads it. The path probe's
/// `FacadeObject` view covers +0x00; this view additionally exposes the kind
/// byte at +0x08.
#[repr(C)]
pub struct RegistryFacade {
    /// +0x00 — class vtable word; opaque to this walk.
    pub vtable: usize,
    /// +0x04 — opaque to this walk.
    pub opaque_04: u32,
    /// +0x08 — facade kind. A nonzero selector accepts only kind one.
    pub kind_08: u8,
    /// +0x09..+0x0c — pad to the next word.
    pub pad_09: [u8; 3],
}

/// The interface object as the registry walk reads it. It consumes only the
/// published facade at +0x08 and state byte at +0x19.
#[repr(C)]
pub struct RegistryNode {
    /// +0x00..+0x08 — opaque object data.
    pub opaque_00: [u32; 2],
    /// +0x08 — published facade (`ldr r2, [r0, #0x8]`).
    pub facade: *mut RegistryFacade,
    /// +0x0c..+0x17 — opaque object data.
    pub opaque_0c: [u32; 3],
    /// +0x18 — opaque byte immediately preceding the state byte.
    pub opaque_18: u8,
    /// +0x19 — interface state; nonzero selectors require zero.
    pub state_19: u8,
    /// +0x1a..+0x1c — pad to the next word.
    pub pad_1a: [u8; 2],
}

/// ABI of `FUN_08296ec0`: an interface node in r0 and selector in r1 return
/// the accepted facade in r0.
pub type RegistryWalk =
    unsafe extern "C" fn(interface: *mut RegistryNode, selector: u32) -> *mut RegistryFacade;

/// ABI boundary for `FUN_0814a08c`. The real function's r0 result is ignored
/// by this walk, so the boundary intentionally models only its argument.
type TraceStaticAccessor = unsafe extern "C" fn(dead_argument: u32);

/// ABI boundary for `FUN_0814a030`, which returns the registry default root.
type DefaultRootAccessor = unsafe extern "C" fn() -> *mut RegistryNode;

/// Target boundary for the trace-static accessor; the host equivalent is a
/// no-op because the walk cannot observe the accessor's result.
unsafe extern "C" fn trace_static_accessor_default(dead_argument: u32) {
    #[cfg(target_os = "none")]
    {
        let accessor: TraceStaticAccessor = core::mem::transmute(TRACE_STATIC_ACCESSOR_ADDRESS);
        accessor(dead_argument);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = dead_argument;
    }
}

/// Target boundary for the default-root ADS accessor. The host equivalent
/// models the stock root as born published.
unsafe extern "C" fn default_root_accessor_default() -> *mut RegistryNode {
    #[cfg(target_os = "none")]
    {
        let accessor: DefaultRootAccessor = core::mem::transmute(DEFAULT_ROOT_ACCESSOR_ADDRESS);
        accessor()
    }

    #[cfg(not(target_os = "none"))]
    {
        host_default_root()
    }
}

/// The modeled default root. In retailOS this is the fixed object at
/// `0x08a778f4`; zero is its pre-construction state on host.
#[cfg(not(target_os = "none"))]
static mut REGISTRY_DEFAULT_NODE: RegistryNode = RegistryNode {
    opaque_00: [0; 2],
    facade: core::ptr::null_mut(),
    opaque_0c: [0; 3],
    opaque_18: 0,
    state_19: 0,
    pad_1a: [0; 2],
};

/// The modeled facade published by the default root's constructor. Its kind
/// is irrelevant because the walk resets the selector to zero before retry.
#[cfg(not(target_os = "none"))]
static mut REGISTRY_DEFAULT_FACADE: RegistryFacade = RegistryFacade {
    vtable: 0,
    opaque_04: 0,
    kind_08: 1,
    pad_09: [0; 3],
};

/// Host model of `FUN_0814a030`: publish the default facade before returning
/// the node, matching the stock constructor's publish-before-guard-release
/// order.
#[cfg(not(target_os = "none"))]
unsafe fn host_default_root() -> *mut RegistryNode {
    let node = core::ptr::addr_of_mut!(REGISTRY_DEFAULT_NODE);
    (*node).facade = core::ptr::addr_of_mut!(REGISTRY_DEFAULT_FACADE);
    node
}

/// Test-only access to the host model's published default facade for the
/// veneer integration tests.
#[cfg(test)]
pub(crate) unsafe fn host_default_facade() -> *mut RegistryFacade {
    core::ptr::addr_of_mut!(REGISTRY_DEFAULT_FACADE)
}

/// Active trace-static accessor boundary. Tests replace it to observe missed
/// iterations and late publication.
static mut TRACE_STATIC_ACCESSOR: TraceStaticAccessor = trace_static_accessor_default;

/// Active default-root accessor boundary. Tests replace it with chains of
/// house-static nodes; target builds call `FUN_0814a030` through the default.
static mut DEFAULT_ROOT_ACCESSOR: DefaultRootAccessor = default_root_accessor_default;

#[inline(always)]
unsafe fn trace_static_accessor_fn() -> TraceStaticAccessor {
    core::ptr::read_volatile(core::ptr::addr_of!(TRACE_STATIC_ACCESSOR))
}

#[inline(always)]
unsafe fn default_root_accessor_fn() -> DefaultRootAccessor {
    core::ptr::read_volatile(core::ptr::addr_of!(DEFAULT_ROOT_ACCESSOR))
}

/// facade_registry_walk — original: `FUN_08296ec0` @ `0x08296ec0` (60
/// bytes).
///
/// Returns `interface`'s published facade when selector zero accepts it, or
/// when a nonzero selector sees state zero and kind one. Otherwise invokes
/// the trace-static accessor, switches to the default interface root, resets
/// the selector to zero, and retries. A NULL facade is retried in the same
/// way; the stock default root's born-published facade makes that polling
/// loop terminate.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn facade_registry_walk(
    interface: *mut RegistryNode,
    selector: u32,
) -> *mut RegistryFacade {
    let mut node = interface;
    let mut selector = selector;

    loop {
        // 08296ec4: ldr r2,[r0,#0x8]
        let facade = (*node).facade;
        // On the NULL path r0 still holds the node pointer; on a selector
        // mismatch it holds the state|kind-minus-one residue. FUN_0814a08c
        // never reads this argument, but preserve the ARM data flow.
        let mut dead_argument = node as usize as u32;

        if !facade.is_null() {
            // 08296ed4..08296ee8: selector zero accepts immediately.
            if selector == SELECTOR_ANY {
                return facade;
            }

            // ldrbne/subne/orrnes: arithmetic is exactly 32-bit, so kind
            // zero wraps and cannot accidentally match.
            let match_residue = ((*node).state_19 as u32)
                | ((*facade).kind_08 as u32).wrapping_sub(1);
            if match_residue == 0 {
                return facade;
            }
            dead_argument = match_residue;
        }

        // 08296eec..08296ef8: trace accessor, default root accessor,
        // selector reset, then branch back to the facade load.
        trace_static_accessor_fn()(dead_argument);
        node = default_root_accessor_fn()();
        selector = SELECTOR_ANY;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use crate::app::facade_for_selector::tests::FACADE_TEST_LOCK;

    const EMPTY_NODE: RegistryNode = RegistryNode {
        opaque_00: [0; 2],
        facade: core::ptr::null_mut(),
        opaque_0c: [0; 3],
        opaque_18: 0,
        state_19: 0,
        pad_1a: [0; 2],
    };

    const EMPTY_FACADE: RegistryFacade = RegistryFacade {
        vtable: 0,
        opaque_04: 0,
        kind_08: 0,
        pad_09: [0; 3],
    };

    static mut HEAD_NODE: RegistryNode = EMPTY_NODE;
    static mut HEAD_FACADE: RegistryFacade = EMPTY_FACADE;
    static mut CHAIN_NODES: [RegistryNode; 3] = [EMPTY_NODE; 3];
    static mut CHAIN_FACADES: [RegistryFacade; 3] = [EMPTY_FACADE; 3];
    static mut SPIN_NODE: RegistryNode = EMPTY_NODE;
    static mut SPIN_FACADE: RegistryFacade = EMPTY_FACADE;
    static mut CHAIN_LEN: usize = 0;
    static mut CHAIN_INDEX: usize = 0;
    static mut TRACE_CALLS: u32 = 0;
    static mut ROOT_CALLS: u32 = 0;
    static mut PUBLISH_ON_TRACE_CALL: u32 = 0;

    /// Restores the two boundaries even if a test panics.
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRACE_STATIC_ACCESSOR)
                    .write_volatile(trace_static_accessor_default);
                core::ptr::addr_of_mut!(DEFAULT_ROOT_ACCESSOR)
                    .write_volatile(default_root_accessor_default);
            }
        }
    }

    unsafe extern "C" fn recording_trace(_dead_argument: u32) {
        TRACE_CALLS += 1;
        if PUBLISH_ON_TRACE_CALL != 0 && TRACE_CALLS == PUBLISH_ON_TRACE_CALL {
            SPIN_NODE.facade = core::ptr::addr_of_mut!(SPIN_FACADE);
        }
    }

    /// Returns the next test node on each retry, then the born-published
    /// house default root. This models the walk's loop while exposing head,
    /// middle, and tail positions deterministically.
    unsafe extern "C" fn chain_root() -> *mut RegistryNode {
        ROOT_CALLS += 1;
        let index = CHAIN_INDEX;
        CHAIN_INDEX += 1;
        if index < CHAIN_LEN {
            core::ptr::addr_of_mut!(CHAIN_NODES[index])
        } else {
            host_default_root()
        }
    }

    /// Repeatedly returns one initially-unpublished node, matching the stock
    /// wait-out-a-NULL behavior until the trace mock publishes its facade.
    unsafe extern "C" fn spin_root() -> *mut RegistryNode {
        ROOT_CALLS += 1;
        core::ptr::addr_of_mut!(SPIN_NODE)
    }

    unsafe fn install(trace: TraceStaticAccessor, root: DefaultRootAccessor) {
        CHAIN_LEN = 0;
        CHAIN_INDEX = 0;
        TRACE_CALLS = 0;
        ROOT_CALLS = 0;
        PUBLISH_ON_TRACE_CALL = 0;
        HEAD_NODE = EMPTY_NODE;
        HEAD_FACADE = EMPTY_FACADE;
        CHAIN_NODES = [EMPTY_NODE; 3];
        CHAIN_FACADES = [EMPTY_FACADE; 3];
        SPIN_NODE = EMPTY_NODE;
        SPIN_FACADE = EMPTY_FACADE;
        core::ptr::addr_of_mut!(TRACE_STATIC_ACCESSOR).write_volatile(trace);
        core::ptr::addr_of_mut!(DEFAULT_ROOT_ACCESSOR).write_volatile(root);
    }

    fn take_lock() -> std::sync::MutexGuard<'static, ()> {
        FACADE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn selector_one_hits_a_state_zero_kind_one_facade_at_the_head() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install(recording_trace, chain_root);
            HEAD_FACADE.kind_08 = 1;
            HEAD_NODE.facade = core::ptr::addr_of_mut!(HEAD_FACADE);
            HEAD_NODE.state_19 = 0;

            assert_eq!(
                facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_MATCHING),
                core::ptr::addr_of_mut!(HEAD_FACADE),
                "state zero plus kind one accepts the interface's own facade"
            );
            assert_eq!(TRACE_CALLS, 0, "a head hit does not trace a miss");
            assert_eq!(ROOT_CALLS, 0, "a head hit does not fetch the fallback root");
        }
    }

    #[test]
    fn selector_zero_accepts_any_published_facade_at_the_head() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install(recording_trace, chain_root);
            HEAD_FACADE.kind_08 = 0x5a;
            HEAD_NODE.facade = core::ptr::addr_of_mut!(HEAD_FACADE);
            HEAD_NODE.state_19 = 0x7f;

            assert_eq!(
                facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_ANY),
                core::ptr::addr_of_mut!(HEAD_FACADE),
                "selector zero bypasses both state and kind"
            );
            assert_eq!(TRACE_CALLS, 0);
            assert_eq!(ROOT_CALLS, 0);
        }
    }

    #[test]
    fn selector_mismatches_trace_once_then_fall_back_to_the_default_root() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            for (kind, state, why) in [
                (0u8, 0u8, "kind zero wraps to 0xffff_ffff"),
                (2u8, 0u8, "kind two leaves residue one"),
                (0xffu8, 0u8, "kind 0xff leaves residue 0xfe"),
                (1u8, 1u8, "a busy interface contributes nonzero state"),
            ] {
                install(recording_trace, chain_root);
                HEAD_FACADE.kind_08 = kind;
                HEAD_NODE.facade = core::ptr::addr_of_mut!(HEAD_FACADE);
                HEAD_NODE.state_19 = state;

                assert_eq!(
                    facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_MATCHING),
                    host_default_facade(),
                    "{why}: retry resets selector and accepts the born-published default"
                );
                assert_eq!(TRACE_CALLS, 1, "the rejected head is one miss");
                assert_eq!(ROOT_CALLS, 1, "one miss fetches the default root");
            }
        }
    }

    #[test]
    fn null_head_reaches_a_published_middle_node_with_selector_relaxed() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install(recording_trace, chain_root);
            CHAIN_LEN = 2;
            // First fallback node remains unpublished. The second has a kind
            // that would fail selector one, proving the first miss reset it.
            CHAIN_FACADES[1].kind_08 = 0x5a;
            CHAIN_NODES[1].facade = core::ptr::addr_of_mut!(CHAIN_FACADES[1]);
            CHAIN_NODES[1].state_19 = 0x7f;

            assert_eq!(
                facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_MATCHING),
                core::ptr::addr_of_mut!(CHAIN_FACADES[1]),
                "the walk skips NULL nodes and accepts the middle facade after relaxing selector"
            );
            assert_eq!(TRACE_CALLS, 2, "the null head and null first fallback both miss");
            assert_eq!(ROOT_CALLS, 2);
        }
    }

    #[test]
    fn null_chain_reaches_the_born_published_tail_default_root() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install(recording_trace, chain_root);
            CHAIN_LEN = 3;

            assert_eq!(
                facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_MATCHING),
                host_default_facade(),
                "after every test node is NULL, the real default root terminates the loop"
            );
            assert_eq!(TRACE_CALLS, 4, "head plus three NULL chain nodes miss");
            assert_eq!(ROOT_CALLS, 4);
        }
    }

    #[test]
    fn empty_default_root_is_polled_until_its_facade_is_published() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install(recording_trace, spin_root);
            SPIN_FACADE.kind_08 = 0x5a;
            PUBLISH_ON_TRACE_CALL = 3;

            assert_eq!(
                facade_registry_walk(core::ptr::addr_of_mut!(HEAD_NODE), SELECTOR_MATCHING),
                core::ptr::addr_of_mut!(SPIN_FACADE),
                "NULL field_8 is retried until publication; selector is already accept-any"
            );
            assert_eq!(TRACE_CALLS, 3, "three empty iterations precede publication");
            assert_eq!(ROOT_CALLS, 3, "each empty iteration reacquires the default root");
        }
    }
}
