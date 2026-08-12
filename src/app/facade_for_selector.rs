//! The interface-guard facade accessor: a two-instruction veneer that
//! reloads the guard's interface word and tail-branches into the
//! facade registry walk.
//!
//! Port:
//! - [`facade_for_selector`] — original: `FUN_0818a0bc` @ 0x0818a0bc
//!   (8 bytes; **34 `bl` call sites**, grep on `decomp/osos.asm`).
//!
//! ## What it is
//!
//! Decoded from the raw ARM at 0x0818a0bc:
//!
//! ```text
//! 0818a0bc  ldr r0, [r0, #0x4]   @ r0 = guard->interface
//! 0818a0c0  b   0x08296ec0       @ tail: registry_walk(interface, selector)
//! ```
//!
//! r0 arrives holding the 16-byte scoped interface guard (the object
//! path_probe.rs models as `InterfaceGuard`); the guard constructor @
//! 0x08206e40 planted the resolved interface pointer at its +0x04 (via
//! 0x0818a06c, a registry lookup through 0x0814a130 over the trace
//! buffer from 0x0814a08c). The veneer reloads that word and tail-
//! branches; r1 (the selector) flows through untouched.
//!
//! Ghidra's `decomp/c/016/0818a0bc_FUN_0818a0bc.c` shows a LOOP — it
//! inlined the tail callee. The 8-byte function itself is only the
//! veneer above; the loop belongs to the walk @ 0x08296ec0.
//!
//! ## The facade registry the walk reads
//!
//! The tail callee @ 0x08296ec0 (unported, rides the
//! [`FACADE_REGISTRY_WALK`] seam) is the registry walk:
//!
//! ```text
//! node = interface;  sel = selector;
//! loop {
//!     child = node->field_0x08;                 // the published facade
//!     if (child != NULL) {
//!         if (sel == 0) return child;                       // accept any
//!         if ((node->state_0x19 | (child->kind_0x08 - 1)) == 0)
//!             return child;    // state == 0 AND kind == 1: accept match
//!     }
//!     FUN_0814a08c(residue);   // trace static accessor; argument dead
//!     node = FUN_0814a030();   // the registry's DEFAULT interface root
//!     sel  = 0;                // selector relaxes to accept-any
//! }
//! ```
//!
//! `FUN_0814a030` is an ADS function-local static accessor (guard page
//! 0x089cb1ec, its word at +0x08; ctor 0x082973bc, dtor 0x0828c580):
//! the **default interface root** is the fixed object @ 0x08a778f4.
//! Its constructor zeroes +0x04..+0x19, sets +0x1c = 0x200 and
//! +0x20 = 1, and publishes a freshly-built facade into field +0x08
//! (`str r0, [r4, #0x8]` @ 0x08297430) BEFORE the guard release — the
//! default root is born published, which is what makes the stock spin
//! terminate. `FUN_0814a08c` (the sibling static accessor over object
//! 0x08a778e8 plus a lazy 0x40-byte buffer) never reads its argument:
//! the mismatch residue the walk leaves in r0 is dead.
//!
//! So the accessor answers: "the interface's own facade, if published
//! and matching the selector; otherwise whatever facade the registry's
//! default root has published."
//!
//! ## Call-site census
//!
//! 34 `bl` sites: 0x08084d70, 0x0808911c, 0x080891ac, 0x08089234,
//! 0x08089284, 0x080892e0, 0x08090c18, 0x0809b6c0, 0x080a8ef8,
//! 0x080b6b70, 0x080f4af0 (path_probe_via_facade), 0x080f4b8c,
//! 0x081ef64c, 0x081ef688, 0x081ef804, 0x081efa00, 0x08277a60,
//! 0x08277b1c, 0x08277c48, 0x08277d9c, 0x08277df4, 0x0827843c,
//! 0x08278488, 0x08278588, 0x082786bc, 0x082788dc, 0x08278908,
//! 0x08278974, 0x08278a58, 0x08278ad8, 0x08278c20, 0x08278d98,
//! 0x08278e50 and 0x08278f10. **33 sites pass selector 1** (`mov r1,
//! #0x1` immediately ahead of the `bl`); the lone selector-0 site is
//! 0x082788dc (vtable slot +0x18 dispatch, immediately followed by a
//! selector-1 fetch at 0x08278908 for slot +0x30 on the same facade).
//! Every site indirect-calls a facade vtable slot with the result —
//! slots +0x18, +0x1c, +0x30, +0x34, +0x38, +0x3c, +0x40, +0x44,
//! +0x50 (path_probe_via_facade), +0x54, +0x5c, +0x60, +0x64, +0x68,
//! +0x6c, +0x70, +0x78, +0x7c, +0x80, +0x9c observed.
//!
//! ## The seam
//!
//! The walk @ 0x08296ec0 remains in retailOS, so — the
//! ui/object_state.rs `firmware_clock_sample` precedent — the seam's
//! wired default calls the fixed firmware load address on
//! `target_os = "none"` and this symbol IS hook-ready. Host builds
//! cannot call retailOS: the default is a faithful MODEL of the walk
//! over house statics (the media_command_facade.rs statics pattern),
//! with the default root born published like the stock 0x08a778f4
//! object, so the modeled chain is total on host.
//!
//! ## Faithful details
//!
//! - The selector is never inspected by the veneer — it flows to the
//!   walk in r1 exactly as received (any u32, not just 0/1; the walk
//!   tests it against 0).
//! - The match arithmetic is 32-bit: `kind_0x08 - 1` wraps, so a kind
//!   byte of 0 yields 0xffff_ffff and can never match; only kind == 1
//!   with state == 0 matches a nonzero selector.
//! - The veneer does not save lr: it is a true tail branch, so the
//!   walk returns directly to the accessor's caller.
//!
//! ## Deviations
//!
//! - The walk rides the [`FACADE_REGISTRY_WALK`] seam (read_volatile
//!   dispatch; host tests install a recording mock). On
//!   `target_os = "none"` the default calls the fixed retailOS
//!   address; on host the default is the documented model.
//! - Model struct pointer fields are native-width (the
//!   drivers/display_layer.rs parked-pointer rule): on the 32-bit
//!   target every offset is literal; on 64-bit hosts the guard view's
//!   interface word parks at +0x08.

use crate::app::path_probe::{FacadeObject, InterfaceGuard};

/// Firmware load address of the facade registry walk (the `b` @
/// 0x0818a0c0): the loop documented in the module header.
pub const REGISTRY_WALK_ADDRESS: usize = 0x0829_6ec0;

/// Firmware load address of the registry's default interface root —
/// the fixed object `FUN_0814a030` hands the walk's retry path (pool
/// word @ 0x0814a080; ADS static, ctor 0x082973bc, guard word
/// 0x089cb1f4).
pub const REGISTRY_DEFAULT_ROOT_ADDRESS: usize = 0x08a7_78f4;

/// Byte offset of the facade kind byte the walk tests (`ldrb r3,
/// [r2, #0x8]` @ 0x08296ed0): a selector-1 match requires kind == 1.
pub const FACADE_KIND_OFFSET: usize = 0x08;

/// The selector value 33 of 34 call sites pass (`mov r1, #0x1`):
/// accept the interface's own facade only when it matches (state 0,
/// kind 1).
pub const SELECTOR_MATCHING: u32 = 1;

/// The selector value the lone 0x082788dc site passes (`mov r1, #0x0`):
/// accept any published facade.
pub const SELECTOR_ANY: u32 = 0;

/// The guard frame as the accessor reads it: only the interface word
/// (+0x04 on the target, `ldr r0, [r0, #0x4]`) is decoded;
/// path_probe.rs's [`InterfaceGuard`] is the full 16-byte frame used
/// for pass-through. Native words — byte-exact on the 32-bit target,
/// the interface word parks at +0x08 on 64-bit hosts (the
/// parked-pointer rule).
#[repr(C)]
pub struct GuardInterface {
    /// +0x00 — the guard-class vtable word (never read by the
    /// accessor).
    pub guard_vtable: usize,
    /// +0x04 on the target — the interface pointer the guard
    /// constructor resolved via 0x0818a06c.
    pub interface: *mut RegistryNode,
}

/// The facade object as the registry walk reads it: path_probe.rs's
/// [`FacadeObject`] models +0x00 (the vtable word the probe
/// dereferences); the walk additionally reads the kind byte at
/// +0x08.
#[repr(C)]
pub struct RegistryFacade {
    /// +0x00 — the class vtable word (the [`FacadeObject`] model; the
    /// walk never reads it).
    pub vtable: usize,
    /// +0x04 — opaque to the walk.
    pub opaque_04: u32,
    /// +0x08 — the facade kind byte; a nonzero-selector match requires
    /// 1 (`ldrb r3, [r2, #0x8]` @ 0x08296ed0).
    pub kind_08: u8,
    /// +0x09..+0x0c — pad back to the word.
    pub pad_09: [u8; 3],
}

/// The interface object as the registry walk reads it: +0x08 the
/// published facade (field_8), +0x19 the interface state byte. Every
/// other byte is opaque to the walk. The facade field is native-width
/// (byte-exact +0x08 on the 32-bit target — it is eight-aligned, so
/// the host layout coincides through +0x0c).
#[repr(C)]
pub struct RegistryNode {
    /// +0x00..+0x08 — opaque to the walk (the stock object's own
    /// data; the default root's ctor plants the class vtable at +0x00).
    pub opaque_00: [u32; 2],
    /// +0x08 — field_8: the published facade, NULL until publication
    /// (`ldr r2, [r0, #0x8]` @ 0x08296ec4).
    pub facade: *mut RegistryFacade,
    /// +0x0c..+0x18 — opaque to the walk.
    pub opaque_0c: [u32; 3],
    /// +0x19 — the interface state byte; a nonzero-selector match
    /// requires 0 (`ldrbne r0, [r0, #0x19]` @ 0x08296ed8).
    pub state_19: u8,
    /// +0x1a..+0x1c — pad back to the word.
    pub pad_1a: [u8; 2],
}

/// The facade registry walk @ 0x08296ec0: takes the interface object
/// in r0 and the selector in r1, returns the accepted facade.
pub type RegistryWalk =
    unsafe extern "C" fn(interface: *mut RegistryNode, selector: u32) -> *mut RegistryFacade;

/// Boundary default for the registry walk: calls the stock 0x08296ec0,
/// which remains in retailOS (the ui/object_state.rs
/// `firmware_clock_sample` precedent). The host default is the modeled
/// walk over house statics below.
unsafe extern "C" fn registry_walk_default(
    interface: *mut RegistryNode,
    selector: u32,
) -> *mut RegistryFacade {
    #[cfg(target_os = "none")]
    {
        let walk: RegistryWalk = core::mem::transmute(REGISTRY_WALK_ADDRESS);
        walk(interface, selector)
    }

    #[cfg(not(target_os = "none"))]
    {
        modeled_registry_walk(interface, selector)
    }
}

/// The modeled registry default root (original: the fixed object @
/// 0x08a778f4). Same crate-static deviation as the
/// media_command_facade.rs object statics: the 0x08axxxxx pages are
/// runtime-initialized, and zero is the exact pre-construction state.
/// `registry_default_root` publishes the facade before handing the
/// node out, matching the stock ctor's publish-before-release.
#[cfg(not(target_os = "none"))]
static mut REGISTRY_DEFAULT_NODE: RegistryNode = RegistryNode {
    opaque_00: [0; 2],
    facade: core::ptr::null_mut(),
    opaque_0c: [0; 3],
    state_19: 0,
    pad_1a: [0; 2],
};

/// The modeled default root's facade (original: the 0x081bc95c-built
/// object the default root's ctor publishes into field +0x08). Its
/// kind byte is never read — the walk's retry relaxes the selector to
/// 0 before reaching this node.
#[cfg(not(target_os = "none"))]
static mut REGISTRY_DEFAULT_FACADE: RegistryFacade = RegistryFacade {
    vtable: 0,
    opaque_04: 0,
    kind_08: 1,
    pad_09: [0; 3],
};

/// The modeled `FUN_0814a030`: returns the registry's default
/// interface root with its facade published (the stock static is born
/// published — the ctor's `str r0, [r4, #0x8]` runs before the guard
/// release — so publication here is instantaneous, not lazy).
#[cfg(not(target_os = "none"))]
unsafe fn registry_default_root() -> *mut RegistryNode {
    let node = core::ptr::addr_of_mut!(REGISTRY_DEFAULT_NODE);
    (*node).facade = core::ptr::addr_of_mut!(REGISTRY_DEFAULT_FACADE);
    node
}

/// Host model of the registry walk @ 0x08296ec0, over house statics:
/// the exact stock loop, with `FUN_0814a08c` (the trace static
/// accessor) elided — it never reads its argument and its return is
/// discarded, so it has no observable effect on the walk — and
/// `FUN_0814a030` answered by [`registry_default_root`]. Total on
/// host: the default root is always published, so a miss on the
/// interface's own facade resolves on the first retry.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn modeled_registry_walk(
    interface: *mut RegistryNode,
    selector: u32,
) -> *mut RegistryFacade {
    let mut node = interface;
    let mut selector = selector;
    loop {
        // ldr r2, [r0, #0x8]: the interface's published facade.
        let child = (*node).facade;
        if !child.is_null() {
            if selector == 0 {
                // moveq r0, r2: accept any published facade.
                return child;
            }
            // ldrb r3, [r2, #0x8]; ldrbne r0, [r0, #0x19]; subne/orrnes:
            // 32-bit match residue — kind 0 wraps to 0xffff_ffff.
            let residue =
                ((*node).state_19 as u32) | ((*child).kind_08 as u32).wrapping_sub(1);
            if residue == 0 {
                return child;
            }
        }
        // bl 0x0814a08c (trace accessor: no observable effect);
        // bl 0x0814a030 (the default root); mov r1, #0x0 (relax).
        node = registry_default_root();
        selector = SELECTOR_ANY;
    }
}

/// The active registry walk — the dispatch seam for 0x08296ec0 (the
/// `b` @ 0x0818a0c0). Host tests install a recording mock; the wired
/// default is the retailOS boundary (the model on host).
pub static mut FACADE_REGISTRY_WALK: RegistryWalk = registry_walk_default;

#[inline(always)]
unsafe fn registry_walk_fn() -> RegistryWalk {
    core::ptr::read_volatile(core::ptr::addr_of!(FACADE_REGISTRY_WALK))
}

/// facade_for_selector — original: `FUN_0818a0bc` @ 0x0818a0bc (8
/// bytes; **34 `bl` call sites**, grep on `decomp/osos.asm`; 33 sites
/// pass selector 1, the lone 0x082788dc site passes 0).
///
/// Reloads the guard's interface word (+0x04) and tail-branches to the
/// facade registry walk @ 0x08296ec0 with the selector untouched in
/// r1. See the module header for the stock instruction sequence, the
/// registry the walk reads, the call-site census, and the seam policy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn facade_for_selector(
    guard: *mut InterfaceGuard,
    selector: u32,
) -> *mut FacadeObject {
    // ldr r0, [r0, #0x4]: the guard's interface word.
    let interface = (*(guard as *const GuardInterface)).interface;
    // b 0x08296ec0: a true tail branch — the selector flows through in
    // r1 exactly as received, and the walk's r0 return reaches the
    // accessor's caller directly. RegistryFacade and FacadeObject share
    // the +0x00 vtable word; the callers dereference only vtable slots.
    registry_walk_fn()(interface, selector) as *mut FacadeObject
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that swap the walk seam (the
    /// path_probe.rs `PATH_PROBE_TEST_LOCK` precedent). `pub(crate)`
    /// so sibling app modules can serialize against these; facade
    /// tests never take any sibling lock, so no lock-order cycle is
    /// possible.
    pub(crate) static FACADE_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores the seam to its wired default on drop, even when a
    /// test panics (the path_probe.rs SeamGuard precedent).
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FACADE_REGISTRY_WALK)
                    .write_volatile(registry_walk_default);
            }
        }
    }

    static mut WALK_INTERFACE: *mut RegistryNode = core::ptr::null_mut();
    static mut WALK_SELECTOR: u32 = 0;
    static mut WALK_RESULT: *mut RegistryFacade = core::ptr::null_mut();
    static mut WALK_CALLS: u32 = 0;

    unsafe extern "C" fn recording_walk(
        interface: *mut RegistryNode,
        selector: u32,
    ) -> *mut RegistryFacade {
        WALK_INTERFACE = interface;
        WALK_SELECTOR = selector;
        WALK_CALLS += 1;
        WALK_RESULT
    }

    /// Resets the recording state and installs the recording walk.
    unsafe fn install_recording() {
        WALK_INTERFACE = core::ptr::null_mut();
        WALK_SELECTOR = 0xdead_beef;
        WALK_RESULT = core::ptr::null_mut();
        WALK_CALLS = 0;
        core::ptr::addr_of_mut!(FACADE_REGISTRY_WALK).write_volatile(recording_walk);
    }

    /// Takes the lock, tolerating poisoning from an earlier failed
    /// test (the path_probe.rs take_lock precedent) — the recording
    /// state is reset by `install_recording` anyway.
    fn take_lock() -> std::sync::MutexGuard<'static, ()> {
        FACADE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// A stand-in interface node for the veneer tests.
    static mut NODE: RegistryNode = RegistryNode {
        opaque_00: [0; 2],
        facade: core::ptr::null_mut(),
        opaque_0c: [0; 3],
        state_19: 0,
        pad_1a: [0; 2],
    };

    /// A stand-in facade for the recording walk to hand back.
    static mut FACADE: RegistryFacade = RegistryFacade {
        vtable: 0,
        opaque_04: 0,
        kind_08: 1,
        pad_09: [0; 3],
    };

    /// Builds a guard frame whose interface word points at `node` and
    /// returns it as the pass-through `InterfaceGuard` pointer.
    unsafe fn guard_with_interface(node: *mut RegistryNode) -> *mut InterfaceGuard {
        static mut GUARD: GuardInterface = GuardInterface {
            guard_vtable: 0,
            interface: core::ptr::null_mut(),
        };
        GUARD.interface = node;
        core::ptr::addr_of_mut!(GUARD) as *mut InterfaceGuard
    }

    #[test]
    fn reloads_the_interface_word_at_guard_plus_4_and_tail_calls_the_walk() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install_recording();
            let node = core::ptr::addr_of_mut!(NODE);
            let guard = guard_with_interface(node);
            facade_for_selector(guard, SELECTOR_MATCHING);
            assert_eq!(WALK_CALLS, 1, "exactly one walk call — the tail branch");
            assert_eq!(
                WALK_INTERFACE, node,
                "ldr r0, [r0, #0x4]: the guard's interface word reaches the walk in r0"
            );
        }
    }

    #[test]
    fn the_selector_flows_through_untouched_for_every_observed_value() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install_recording();
            let guard = guard_with_interface(core::ptr::addr_of_mut!(NODE));
            // SELECTOR_MATCHING (33 sites) and SELECTOR_ANY (the lone
            // 0x082788dc site), plus an unobserved nonzero value: the
            // veneer never inspects r1.
            for selector in [SELECTOR_MATCHING, SELECTOR_ANY, 0x5a5a_f00d] {
                WALK_SELECTOR = 0xdead_beef;
                facade_for_selector(guard, selector);
                assert_eq!(
                    WALK_SELECTOR, selector,
                    "the veneer never touches r1: the selector is verbatim"
                );
            }
        }
    }

    #[test]
    fn the_walk_result_returns_verbatim_as_the_facade() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            install_recording();
            let guard = guard_with_interface(core::ptr::addr_of_mut!(NODE));
            WALK_RESULT = core::ptr::addr_of_mut!(FACADE);
            let facade = facade_for_selector(guard, SELECTOR_MATCHING);
            assert_eq!(
                facade,
                core::ptr::addr_of_mut!(FACADE) as *mut FacadeObject,
                "a true tail branch: the walk's r0 is the caller's r0"
            );
            assert_eq!(
                WALK_CALLS, 1,
                "no second walk call on the return path"
            );
        }
    }

    /// The modeled-walk tests run the wired default (the host model)
    /// against caller-built interface nodes.

    /// Builds a node publishing `facade` with the given state byte.
    unsafe fn node_with(facade: *mut RegistryFacade, state_19: u8) -> *mut RegistryNode {
        static mut MODEL_NODE: RegistryNode = RegistryNode {
            opaque_00: [0; 2],
            facade: core::ptr::null_mut(),
            opaque_0c: [0; 3],
            state_19: 0,
            pad_1a: [0; 2],
        };
        MODEL_NODE.facade = facade;
        MODEL_NODE.state_19 = state_19;
        core::ptr::addr_of_mut!(MODEL_NODE)
    }

    /// A stand-in facade whose kind byte the model test sets per case.
    unsafe fn facade_with_kind(kind_08: u8) -> *mut RegistryFacade {
        static mut MODEL_FACADE: RegistryFacade = RegistryFacade {
            vtable: 0,
            opaque_04: 0,
            kind_08: 0,
            pad_09: [0; 3],
        };
        MODEL_FACADE.kind_08 = kind_08;
        core::ptr::addr_of_mut!(MODEL_FACADE)
    }

    unsafe fn default_facade() -> *mut RegistryFacade {
        core::ptr::addr_of_mut!(REGISTRY_DEFAULT_FACADE)
    }

    #[test]
    fn modeled_walk_selector_one_returns_the_matching_facade() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            let facade = facade_with_kind(1);
            let node = node_with(facade, 0);
            let guard = guard_with_interface(node);
            assert_eq!(
                facade_for_selector(guard, SELECTOR_MATCHING),
                facade as *mut FacadeObject,
                "state 0 and kind 1: the interface's own facade matches"
            );
        }
    }

    #[test]
    fn modeled_walk_selector_zero_accepts_any_published_facade() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            // Neither the state byte nor the kind byte is consulted on
            // the accept-any path (the 0x082788dc site's selector).
            let facade = facade_with_kind(0x5a);
            let node = node_with(facade, 0x7f);
            let guard = guard_with_interface(node);
            assert_eq!(
                facade_for_selector(guard, SELECTOR_ANY),
                facade as *mut FacadeObject,
                "moveq r0, r2: selector 0 accepts whatever is published"
            );
        }
    }

    #[test]
    fn modeled_walk_selector_one_rejects_mismatches_and_falls_back_to_the_default_root() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            for (kind, state, why) in [
                (2u8, 0u8, "kind 2: residue 1"),
                (0u8, 0u8, "kind 0: the 32-bit subtract wraps to 0xffff_ffff"),
                (0xffu8, 0u8, "kind 0xff: residue 0xfe"),
                (1u8, 1u8, "state 1: the interface is busy"),
            ] {
                let facade = facade_with_kind(kind);
                let node = node_with(facade, state);
                let guard = guard_with_interface(node);
                assert_eq!(
                    facade_for_selector(guard, SELECTOR_MATCHING),
                    default_facade() as *mut FacadeObject,
                    "{why}: the retry relaxes to selector 0 on the born-published default root"
                );
            }
        }
    }

    #[test]
    fn modeled_walk_unpublished_interface_falls_back_for_both_selectors() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        unsafe {
            let node = node_with(core::ptr::null_mut(), 0);
            let guard = guard_with_interface(node);
            for selector in [SELECTOR_ANY, SELECTOR_MATCHING] {
                assert_eq!(
                    facade_for_selector(guard, selector),
                    default_facade() as *mut FacadeObject,
                    "selector {selector}: a NULL field_8 waits out to the default root"
                );
            }
        }
    }
}
