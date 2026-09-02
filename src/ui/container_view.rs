//! The constructor of the container view — the retailOS screen element
//! that owns a registry of child views and forwards every framework
//! operation (draw, layout, event broadcast, teardown) to them. It sits
//! between the grand-base view (`ui/view_base.rs`, ctor @ 0x0826f26c)
//! and the concrete widgets: all 22 call sites are derived-class
//! constructors or their `new` wrappers chaining into this one.
//!
//! # What the class is
//!
//! The class identity rests on the +0xa8 registry, which every method
//! in its block of the image (0x081574c0..0x08158744) iterates before
//! dispatching a child virtual: 0x081574c0/0x081584f0 forward slot
//! +0xa4, 0x0815770c slot +0x94, 0x0815794c slot +0xa0, 0x08157a48
//! slot +0xb8, 0x08157cdc slot +0xf4, 0x08157fac unions the children's
//! bounding boxes (`rect_union` @ 0x0826c3d8) and re-fits the
//! scrollbars, and the destructor helper @ 0x08157b18 detaches every
//! child through slot +0x04 before clearing the registry through its
//! own slot +0x30. The accessor @ 0x081586e0 is a one-liner returning
//! `this + 0xa8`. No other class in the hierarchy owns this registry:
//! the grand-base ends at +0xa4 and the derived classes start their own
//! state at +0xe8 (the `operator_new(0xe8)` in the `new` wrapper @
//! 0x0815746c is this class's exact size).
//!
//! # Extent, from the raw bytes
//!
//! Decoded with `arm-none-eabi-objdump` over `work/firmware/osos.dec`
//! at load base 0x08000000, not taken from Ghidra:
//!
//! ```text
//! 08158778  push {r3, r4, r5, lr}
//! 0815877c  ldr  r4, [sp, #16]     @ spec (the stacked 5th argument)
//! 08158780  mov  r5, r2            @ controller
//! 08158784  str  r4, [sp]          @ re-store spec into the outgoing slot
//! 08158788  bl   0x0826f26c        @ view_base_construct
//! 0815878c  ldr  r1, [pc, #92]     @ -> 0x081587f0 = 0x08986f38
//! 08158790  str  r1, [r0]          @ plant this class's vtable
//! 08158794  ldr  r1, [r4, #88]     @ spec +0x58
//! 08158798  str  r1, [r0, #164]!   @ view +0xa4 = config; r0 = view+0xa4
//! 0815879c  add  r0, r0, #4        @ r0 = view +0xa8
//! 081587a0  bl   0x0813533c        @ registry_container_construct_default
//! 081587a4  sub  r4, r0, #168      @ r4 = view
//! 081587a8  mov  r1, #0
//! 081587ac  str  r1, [r4, #208]    @ clip_rect[0] (+0xd0)
//! 081587b0  str  r1, [r4, #212]    @ clip_rect[1] (+0xd4)
//! 081587b4  str  r1, [r4, #216]    @ clip_rect[2] (+0xd8)
//! 081587b8  str  r1, [r0, #52]     @ clip_rect[3] (+0xdc)
//! 081587bc  cmp  r5, #0
//! 081587c0  str  r1, [r0, #60]     @ word_e4 (+0xe4)
//! 081587c4  streq r4, [r4, #224]   @ content_provider = view when no ctl
//! 081587c8  beq  0x081587e0
//! 081587cc  ldr  r0, [r5]          @ controller vtable
//! 081587d0  ldr  r1, [r0, #92]     @ slot +0x5c
//! 081587d4  mov  r0, r5
//! 081587d8  blx  r1                @ content_provider = query(controller)
//! 081587dc  str  r0, [r4, #224]
//! 081587e0  mov  r0, r4
//! 081587e4  bl   0x08157f18        @ refresh_clip_rect
//! 081587e8  mov  r0, r4
//! 081587ec  pop  {r3, r4, r5, pc}
//! 081587f0  .word 0x08986f38       @ the class vtable literal
//! 081587f4  cmp  r0, #0            @ the deleting destructor starts here
//! ```
//!
//! So the extent is 0x08158778..0x081587f4 = **124 bytes**: 120 code
//! plus the 4-byte vtable literal @ 0x081587f0 that Ghidra's 120-byte
//! extent drops; the (separately listed) deleting destructor @
//! 0x081587f4 starts immediately after. Verified counts, from decoding
//! every B/BL word in the image: **22 `bl` call sites, 0 predicated, 0
//! tail `b`**, matching Ghidra's 22 — and **0 occurrences of
//! 0x08158778 as a data word**, so the constructor is never dispatched
//! virtually.
//!
//! # Layout (232 bytes, the `operator_new(0xe8)` @ 0x0815746c)
//!
//! ```text
//! +0x000  vtable                (ROM literal 0x08986f38)
//! +0x004  base subobject        grand-base view, ctor 0x0826f26c
//! +0x0a4  config: u32           spec +0x58, verbatim; read as a flag
//!                               word by 0x0815826c (`& 2` gates the
//!                               child walk)
//! +0x0a8  children              0x28-byte child-view registry, ctor
//!                               0x0813533c (capacity/growth 4, 4)
//! +0x0d0  clip_rect: [u32; 4]   the clip-rect cache `ui/invalidate.rs`
//!                               documents at parent+0xd0; refreshed from
//!                               the frame (+0x80..+0x8c) by 0x08157f18
//! +0x0e0  content_provider: u32 controller slot-+0x5c query result, or
//!                               `this` when there is no controller
//! +0x0e4  word_e4: u32          cleared here, purpose unrecovered
//! ```
//!
//! The deleting destructor @ 0x081587f4 (NULL-guarded) and the body @
//! 0x0815880c confirm the layout: the body replants the same vtable
//! from its own literal @ 0x08158838, runs the child-detach helper @
//! 0x08157b18, tears the registry down with 0x08135380 on view+0xa8
//! (`sub r0, r0, #168` afterwards recovers `view`), and tail-branches
//! to the grand-base destructor @ 0x0826f340.
//!
//! The +0xe0 fallback makes the view its own content provider when no
//! controller is attached; the query itself is the controller's vtable
//! slot +0x5c (role within the controller interface unrecovered — the
//! ctor only stores the result).
//!
//! # Deviations
//!
//! - Ghidra types the signature `int FUN_08158778(undefined4,
//!   undefined4, int *, undefined4, int)`; the assembly takes
//!   `(view, resources, controller, parent)` in r0-r3 plus the stacked
//!   spec and returns `view` (`mov r0, r4` before the pop).
//! - Both chained constructors and the registry ctor return their
//!   argument, so the port keeps `view` in hand instead of the
//!   original's `sub r4, r0, #168` byte arithmetic, which would be
//!   wrong on a 64-bit host (the `ui/styled_text_view.rs` precedent).
//! - The vtable is the `u32` ROM address
//!   [`CONTAINER_VIEW_VTABLE_ADDRESS`]; the words the image carries at
//!   0x08986f38 are stale RW init data (they decode as data-region
//!   pointers, not entry points — the same finding
//!   `ui/styled_text_view.rs` records), so there are no slots to model
//!   and nothing here dispatches through it.
//! - `view_base_construct` @ 0x0826f26c and
//!   `registry_container_construct_default` @ 0x0813533c are already
//!   ported and are called directly; only the clip-rect refresh @
//!   0x08157f18 (unported) rides the [`CONTAINER_VIEW_OPS`] seam.
//! - The spec is reused as `ui::view_base::ViewSpec`: this class adds
//!   no spec tail of its own — the word it keeps at view+0xa4 is the
//!   same spec +0x58 the grand-base reads for its own flag-gated
//!   +0x90 copy. Unlike the grand-base's gated copy, this one is
//!   unconditional.
//! - The controller query is modelled through a `usize`-slot vtable
//!   (the `app/path_probe.rs` idiom): two loads and an indirect call,
//!   byte-identical to the original's `ldr/ldr/blx` on the 32-bit
//!   target, and host-testable without mapping memory below 4 GiB.
//! - The original's `str r4, [sp]` re-stores the stacked spec into its
//!   own outgoing argument slot; the port simply forwards `spec`.

use crate::app::class_registry::registry_container_construct_default;
use crate::app::registry::Registry;
use crate::app::resource_chain::ResourceProvider;
use crate::ui::view_base::{view_base_construct, ViewBase, ViewSpec};

/// The ROM address of this class's vtable (the literal-pool word @
/// 0x081587f0, binary-verified; the destructor body @ 0x0815880c
/// replants the same value from its own literal @ 0x08158838).
///
/// Stored as the `u32` the original stores — see the module header for
/// why the image's data at that address is stale.
pub const CONTAINER_VIEW_VTABLE_ADDRESS: u32 = 0x0898_6f38;

/// Byte offset of the controller vtable slot this constructor queries
/// for the content provider.
pub const CONTENT_PROVIDER_SLOT: usize = 0x5c;
/// Word index of [`CONTENT_PROVIDER_SLOT`].
pub const CONTENT_PROVIDER_SLOT_INDEX: usize = CONTENT_PROVIDER_SLOT / 4;
/// Slots the vtable model carries: through the queried slot only.
pub const CONTAINER_CONTROLLER_VTABLE_SLOTS: usize = CONTENT_PROVIDER_SLOT_INDEX + 1;

/// The controller vtable, down to the one slot this constructor
/// dispatches (the `app/path_probe.rs` serialized-slots precedent).
/// `usize` slots keep the model byte-identical to the target's u32
/// table on the 32-bit build while staying host-callable in tests.
#[repr(C)]
pub struct ContainerControllerVtable {
    /// +0x00..+0x5c: not dispatched here.
    /// +0x5c (index [`CONTENT_PROVIDER_SLOT_INDEX`]):
    /// `query(controller) -> content_provider`, stored at view+0xe0.
    pub slots: [usize; CONTAINER_CONTROLLER_VTABLE_SLOTS],
}

/// The query behind [`CONTENT_PROVIDER_SLOT`]: takes the controller,
/// returns the content-provider object as a target word.
pub type ContentProviderQuery = unsafe extern "C" fn(controller: *mut u8) -> u32;

/// The constructed container view. Pointer-typed members are modelled
/// as `u32` target words or fixed byte arrays so the layout is exact on
/// both the 32-bit target and 64-bit hosts (the
/// `ui/styled_text_view.rs` convention): the constructor only ever
/// stores the view's own address or a query result in
/// `content_provider`, and the registry subobject is reached by byte
/// offset so its ported constructor sees the target address on any
/// host.
#[repr(C)]
pub struct ContainerView {
    /// +0x00 — vtable, see [`CONTAINER_VIEW_VTABLE_ADDRESS`].
    pub vtable: u32,
    /// +0x04..+0xa4 — the grand-base view subobject, owned by the
    /// 0x0826f26c ctor.
    pub base: [u8; 0xa0],
    /// +0xa4 — the class config word, copied verbatim from spec +0x58.
    pub config: u32,
    /// +0xa8..+0xd0 — the 0x28-byte child-view registry that
    /// [`registry_container_construct_default`] builds (capacity 4,
    /// growth 4).
    pub children: [u8; 0x28],
    /// +0xd0..+0xe0 — the clip-rect cache (the `parent+0xd0` clip rect
    /// of `ui/invalidate.rs`), zero until the first refresh.
    pub clip_rect: [u32; 4],
    /// +0xe0 — the content provider: the controller's slot-+0x5c query
    /// result, or the view itself when constructed without a
    /// controller (target word).
    pub content_provider: u32,
    /// +0xe4 — cleared here; untouched by the destructor, purpose
    /// unrecovered.
    pub word_e4: u32,
}

const _: [u8; 0xe8] = [0; core::mem::size_of::<ContainerView>()];
const _: [u8; 0xa4] = [0; core::mem::offset_of!(ContainerView, config)];
const _: [u8; 0xa8] = [0; core::mem::offset_of!(ContainerView, children)];
const _: [u8; 0xd0] = [0; core::mem::offset_of!(ContainerView, clip_rect)];
const _: [u8; 0xe0] = [0; core::mem::offset_of!(ContainerView, content_provider)];
const _: [u8; 0xe4] = [0; core::mem::offset_of!(ContainerView, word_e4)];

/// Indirect dispatch for this constructor's one unported callee (the
/// `StringViewOps` precedent in `ui/string_view.rs`).
#[derive(Clone, Copy)]
pub struct ContainerViewOps {
    /// Clip-rect cache refresh @ 0x08157f18 `(view)`: copies the
    /// view's frame (+0x80..+0x8c) into the clip-rect cache
    /// (+0xd0..+0xdc), intersects it with the parent's cache through
    /// `rect_intersect` @ 0x0826c1c8 (ported) when the view has a
    /// parent (+0x34), and when the cache actually changed
    /// (0x082a23fc) raises dirty flag 0x80 at +0x48 on the view and on
    /// every ancestor up the +0x34 chain that is not already flagged.
    /// The original returns the previous rect in r0:r1; this call site
    /// discards it (`mov r0, r4` follows the `bl` immediately), so the
    /// slot returns nothing. Not yet ported.
    pub refresh_clip_rect: unsafe extern "C" fn(view: *mut ContainerView),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_refresh_clip_rect(view: *mut ContainerView) {
    let refresh: unsafe extern "C" fn(*mut ContainerView) =
        unsafe { core::mem::transmute(0x0815_7f18usize) };
    unsafe { refresh(view) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh_clip_rect(_view: *mut ContainerView) {
    panic!("container_view_construct requires clip-rect refresh 0x08157f18")
}

/// Wired defaults (the `event_list.rs` split: firmware addresses on
/// target, panics on host).
pub const DEFAULT_CONTAINER_VIEW_OPS: ContainerViewOps = ContainerViewOps {
    #[cfg(target_os = "none")]
    refresh_clip_rect: firmware_refresh_clip_rect,
    #[cfg(not(target_os = "none"))]
    refresh_clip_rect: missing_refresh_clip_rect,
};

/// The active dispatch table. Written once at init on target; host
/// tests swap in recorders and restore the defaults.
pub static mut CONTAINER_VIEW_OPS: ContainerViewOps = DEFAULT_CONTAINER_VIEW_OPS;

/// container_view_construct — original: `FUN_08158778` @ 0x08158778
/// (124 bytes: 120 code ending in `ldmia sp!, {r3, r4, r5, pc}` @
/// 0x081587ec, plus the 4-byte vtable literal @ 0x081587f0; 22 `bl`
/// call sites, all unconditional, binary-scanned by decoding every
/// B/BL word in osos.dec — every one a derived-class constructor or
/// `new` wrapper chaining into this one, e.g. the `operator_new(0xe8)`
/// wrapper @ 0x0815746c that then dispatches slot +0x11c with its
/// sixth argument).
///
/// Chains the grand-base view ctor with the caller's five arguments
/// unchanged, plants the class vtable, copies the spec +0x58 config
/// word to view+0xa4, builds the capacity-4 child registry at +0xa8,
/// clears the clip-rect cache (+0xd0..+0xdc) and the word at +0xe4,
/// installs the content provider at +0xe0 — the view itself when
/// `controller` is NULL, otherwise the controller's vtable slot +0x5c
/// query result — and finishes with the clip-rect refresh before
/// returning `view`.
///
/// # Safety
/// `view` must point at a writable, 4-byte-aligned [`ContainerView`],
/// `spec` at a readable [`ViewSpec`], `controller` — when non-NULL —
/// at an object whose vtable carries a callable slot +0x5c, and the
/// installed [`CONTAINER_VIEW_OPS`] / `VIEW_BASE_OPS` /
/// `CLASS_REGISTRY_OPS` must accept them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_view_construct(
    view: *mut ContainerView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut ContainerView {
    // Read each slot directly rather than the whole table (the
    // timer_schedule_shim sibcall gotcha).
    let refresh_clip_rect =
        core::ptr::addr_of!(CONTAINER_VIEW_OPS.refresh_clip_rect).read_volatile();

    view_base_construct(view.cast::<ViewBase>(), resources, controller, parent, spec);
    core::ptr::addr_of_mut!((*view).vtable).write_volatile(CONTAINER_VIEW_VTABLE_ADDRESS);
    core::ptr::addr_of_mut!((*view).config).write_volatile((*spec).word_58);
    registry_container_construct_default(
        core::ptr::addr_of_mut!((*view).children).cast::<Registry>(),
    );
    // Four separate word stores, like the original's r1 = 0 replay —
    // an array write would spill each word through the stack.
    core::ptr::addr_of_mut!((*view).clip_rect[0]).write_volatile(0);
    core::ptr::addr_of_mut!((*view).clip_rect[1]).write_volatile(0);
    core::ptr::addr_of_mut!((*view).clip_rect[2]).write_volatile(0);
    core::ptr::addr_of_mut!((*view).clip_rect[3]).write_volatile(0);
    core::ptr::addr_of_mut!((*view).word_e4).write_volatile(0);
    let content_provider = if controller.is_null() {
        view as usize as u32
    } else {
        // ldr r0, [r5]; ldr r1, [r0, #0x5c]; mov r0, r5; blx r1.
        let vtable = core::ptr::read_volatile(
            controller as *const *const ContainerControllerVtable,
        );
        let slot = (*vtable).slots[CONTENT_PROVIDER_SLOT_INDEX];
        let query: ContentProviderQuery = core::mem::transmute(slot);
        query(controller)
    };
    core::ptr::addr_of_mut!((*view).content_provider).write_volatile(content_provider);
    refresh_clip_rect(view);
    view
}

/// container_view_children — original: `FUN_081586e0` @ 0x081586e0
/// (8 bytes exactly: `add r0, r0, #0xa8; bx lr`, no literal pool;
/// the previous method ends `pop {r2, r3, r4, pc}` immediately
/// before and the next method @ 0x081586e8 opens with
/// `push {r1, r2, r3, r4, r5, lr}` immediately after. **22 `bl`
/// call sites, 0 predicated, 0 tail `b`**, binary-scanned by
/// decoding every B/BL word in osos.dec — matching Ghidra's 22 —
/// and **0 occurrences of 0x081586e0 as a data word**, so the
/// accessor is never dispatched virtually).
///
/// The class's registry accessor: returns a pointer to the 0x28-byte
/// child-view registry subobject at view+0xa8 — pure pointer
/// arithmetic, nothing read or written. Every recovered caller feeds
/// the result straight into a ported collection iterator
/// (`cursor_init` @ 0x081ee17c / `cursor_advance` @ 0x081ee138, or
/// `iterator_state_construct` @ 0x08155e80 with mask -2) and walks
/// the children, or reads the registry's own fields through it
/// (0x081dd30c & siblings dereference +4).
///
/// No NULL guard, and the all-unconditional call split confirms the
/// callers never gate the call either: `add` is unconditional, so a
/// NULL `view` returns 0xa8 — the port reproduces that with wrapping
/// byte arithmetic instead of a field projection.
///
/// # Safety
/// None beyond pointer validity at the eventual use site: the
/// function itself dereferences nothing. `view` may be NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_view_children(view: *mut ContainerView) -> *mut Registry {
    view.cast::<u8>()
        .wrapping_add(core::mem::offset_of!(ContainerView, children))
        .cast::<Registry>()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::class_registry::{
        ClassRegistryOps, CLASS_REGISTRY_OPS, DEFAULT_CLASS_REGISTRY_OPS,
        REGISTRY_CONTAINER_VTABLE_ADDRESS,
    };
    use crate::ui::view_base::{ViewBaseOps, VIEW_BASE_OPS, DEFAULT_VIEW_BASE_OPS};
    use core::mem::{align_of, offset_of, size_of};
    use parking_lot::Mutex as ParkingMutex;
    use std::boxed::Box;
    use std::vec::Vec;

    /// Ops-table swaps are global; serialize the tests (the whole
    /// crate also runs single-threaded, but keep the local convention).
    static OPS_LOCK: ParkingMutex<()> = ParkingMutex::new(());

    /// Ordered trace of the mocked callees, so the construction
    /// sequence itself is under test.
    static mut TRACE: Vec<&'static str> = Vec::new();

    /// The arguments the recording stubs saw.
    static mut SEEN: [usize; 8] = [0; 8];

    struct OpsGuard;

    impl OpsGuard {
        fn install(
            view_base_ops: ViewBaseOps,
            class_registry_ops: ClassRegistryOps,
            container_view_ops: ContainerViewOps,
        ) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(TRACE).write_volatile(Vec::new());
                core::ptr::addr_of_mut!(SEEN).write_volatile([0; 8]);
                core::ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(view_base_ops);
                core::ptr::addr_of_mut!(CLASS_REGISTRY_OPS).write_volatile(class_registry_ops);
                core::ptr::addr_of_mut!(CONTAINER_VIEW_OPS).write_volatile(container_view_ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(DEFAULT_VIEW_BASE_OPS);
                core::ptr::addr_of_mut!(CLASS_REGISTRY_OPS)
                    .write_volatile(DEFAULT_CLASS_REGISTRY_OPS);
                core::ptr::addr_of_mut!(CONTAINER_VIEW_OPS)
                    .write_volatile(DEFAULT_CONTAINER_VIEW_OPS);
            }
        }
    }

    fn trace() -> &'static mut Vec<&'static str> {
        unsafe { &mut *core::ptr::addr_of_mut!(TRACE) }
    }

    fn seen() -> [usize; 8] {
        unsafe { core::ptr::addr_of!(SEEN).read_volatile() }
    }

    /// Faithful-lite linkage base stub: plants the linkage vtable the
    /// real 0x08103a4c plants (immediately overwritten twice more) and
    /// returns `view`, recording `(view, parent, create_link)`.
    unsafe extern "C" fn stub_construct_linkage_base(
        view: *mut ViewBase,
        parent: *mut u8,
        create_link: u32,
    ) -> *mut ViewBase {
        trace().push("linkage_base");
        let seen = core::ptr::addr_of_mut!(SEEN);
        (*seen)[0] = view as usize;
        (*seen)[1] = parent as usize;
        (*seen)[2] = create_link as usize;
        core::ptr::addr_of_mut!((*view).vtable).write_volatile(0x0898_0854);
        view
    }

    /// The 0x0826ee08 initialiser reduced to a recorder: the container
    /// ctor's observable behaviour does not depend on its effects.
    unsafe extern "C" fn stub_initialize(
        view: *mut ViewBase,
        controller: *mut u8,
        spec: *const ViewSpec,
    ) {
        trace().push("initialize");
        let seen = core::ptr::addr_of_mut!(SEEN);
        (*seen)[3] = view as usize;
        (*seen)[4] = controller as usize;
        (*seen)[5] = spec as usize;
    }

    /// Records the registry state initializer's arguments instead of
    /// running the real host-layout writes into the 0x28-byte target
    /// region (the class_registry.rs test precedent).
    unsafe extern "C" fn stub_container_initialize(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) {
        trace().push("container_initialize");
        let seen = core::ptr::addr_of_mut!(SEEN);
        (*seen)[6] = this as usize;
        (*seen)[7] = ((capacity as usize) << 32) | growth as usize;
    }

    unsafe extern "C" fn stub_refresh_clip_rect(view: *mut ContainerView) {
        trace().push("refresh_clip_rect");
        unsafe { REFRESH_VIEW = view as usize };
    }

    static mut REFRESH_VIEW: usize = 0;

    fn install_stubs() -> OpsGuard {
        OpsGuard::install(
            ViewBaseOps {
                construct_linkage_base: stub_construct_linkage_base,
                initialize: stub_initialize,
            },
            ClassRegistryOps {
                container_initialize: stub_container_initialize,
                ..DEFAULT_CLASS_REGISTRY_OPS
            },
            ContainerViewOps {
                refresh_clip_rect: stub_refresh_clip_rect,
            },
        )
    }

    fn blank_view() -> Box<ContainerView> {
        // 0xcd everywhere, so every field the constructor writes is
        // visibly written and every field it must not touch is visibly
        // untouched.
        Box::new(unsafe { core::mem::transmute([0xcdu8; size_of::<ContainerView>()]) })
    }

    fn spec(config: u32, flags: u32) -> ViewSpec {
        ViewSpec {
            word_00: 0,
            class_code: 0x436f_6e74, // 'Cont'
            word_08: 0x0808_0808,
            word_0c: 0,
            word_10: 0x1010_1010,
            word_14: 0,
            flags,
            geometry: [0x5a; 0x30],
            tail: [0; 0x0c],
            word_58: config,
        }
    }

    /// The struct must reproduce the target's byte offsets — the whole
    /// reason the members are `u32` words and byte arrays: the view is
    /// 232 bytes at the `operator_new(0xe8)` call sites and the fields
    /// land where the class's methods read them.
    #[test]
    fn layout_matches_the_target() {
        assert_eq!(size_of::<ContainerView>(), 0xe8);
        assert_eq!(align_of::<ContainerView>(), 4);
        assert_eq!(offset_of!(ContainerView, vtable), 0x00);
        assert_eq!(offset_of!(ContainerView, base), 0x04);
        assert_eq!(offset_of!(ContainerView, config), 0xa4);
        assert_eq!(offset_of!(ContainerView, children), 0xa8);
        assert_eq!(offset_of!(ContainerView, clip_rect), 0xd0);
        assert_eq!(offset_of!(ContainerView, content_provider), 0xe0);
        assert_eq!(offset_of!(ContainerView, word_e4), 0xe4);
        assert_eq!(CONTENT_PROVIDER_SLOT_INDEX, 23);
    }

    /// With no controller, +0xe0 falls back to the view itself (the
    /// original's `streq r4, [r4, #224]`), the config word copies
    /// unconditionally, and the whole chain runs in the original's
    /// order: base, registry, refresh.
    #[test]
    fn null_controller_installs_the_view_as_its_own_provider() {
        let _lock = OPS_LOCK.lock();
        let _guard = install_stubs();

        let mut view = blank_view();
        let spec = spec(0xc0de_0002, 0);
        let this = &mut *view as *mut ContainerView;
        let resources = 0x1234usize as *mut ResourceProvider;
        let parent = 0x9abcusize as *mut u8;
        let ret = unsafe {
            container_view_construct(this, resources, core::ptr::null_mut(), parent, &spec)
        };

        assert_eq!(ret, this);
        assert_eq!(view.vtable, CONTAINER_VIEW_VTABLE_ADDRESS);
        assert_eq!(view.config, 0xc0de_0002, "spec +0x58 copies verbatim");
        assert_eq!(view.clip_rect, [0; 4]);
        assert_eq!(view.word_e4, 0);
        assert_eq!(
            view.content_provider, this as usize as u32,
            "no controller: the view is its own content provider"
        );

        // The grand-base ctor really ran: its flag-gated +0x90 copy is
        // CLEAR for flags == 0 while this class's +0xa4 copy of the
        // same spec word is unconditional.
        let base = unsafe { &*(this as *const ViewBase) };
        assert_eq!(base.resources, resources as usize as u32);
        assert_eq!(base.class_code, 0x436f_6e74);
        assert_eq!(base.word_90, 0, "the base's spec+0x58 copy stays gated");
        assert_eq!(view.config, 0xc0de_0002);

        // The registry ctor saw view+0xa8 with capacity/growth 4, 4,
        // and planted the registry vtable at +0xa8.
        let seen = seen();
        assert_eq!(seen[6], this as usize + 0xa8);
        assert_eq!(seen[7], (4usize << 32) | 4);
        assert_eq!(
            u32::from_le_bytes(view.children[0..4].try_into().unwrap()),
            REGISTRY_CONTAINER_VTABLE_ADDRESS as u32
        );

        // Construction order: linkage base, initialiser, registry,
        // clip-rect refresh — the refresh runs last, on the finished
        // object.
        assert_eq!(
            *trace(),
            std::vec!["linkage_base", "initialize", "container_initialize", "refresh_clip_rect"]
        );
        assert_eq!(unsafe { REFRESH_VIEW }, this as usize);

        // The linkage stub saw (view, parent, spec flags bit 0).
        assert_eq!(seen[0], this as usize);
        assert_eq!(seen[1], parent as usize);
        assert_eq!(seen[2], 0, "flags bit 0 clear: no link node");
        // The initialiser saw (view, controller, spec) unchanged.
        assert_eq!(seen[3], this as usize);
        assert_eq!(seen[4], 0);
        assert_eq!(seen[5], &spec as *const _ as usize);
    }

    /// With a controller, +0xe0 is the slot-+0x5c query result — the
    /// original's `ldr r0,[r5]; ldr r1,[r0,#0x5c]; blx r1` — and the
    /// controller pointer reaches the query unchanged.
    #[test]
    fn controller_query_installs_the_returned_provider() {
        let _lock = OPS_LOCK.lock();
        let _guard = install_stubs();

        static mut CONTROLLER_VTABLE: ContainerControllerVtable =
            ContainerControllerVtable { slots: [0; CONTAINER_CONTROLLER_VTABLE_SLOTS] };
        static mut QUERY_ARG: usize = 0;

        unsafe extern "C" fn stub_query(controller: *mut u8) -> u32 {
            unsafe { QUERY_ARG = controller as usize };
            0x0bad_f00d
        }

        // A two-word fake controller: vtable pointer plus one word of
        // payload, addressed exactly like the original's ldr pair.
        #[repr(C)]
        struct FakeController {
            vtable: *const ContainerControllerVtable,
            payload: usize,
        }
        let mut controller = FakeController {
            vtable: unsafe {
                let table = core::ptr::addr_of_mut!(CONTROLLER_VTABLE);
                (*table).slots[CONTENT_PROVIDER_SLOT_INDEX] = stub_query as usize;
                table as *const _
            },
            payload: 0,
        };

        let mut view = blank_view();
        let spec = spec(7, 1);
        let this = &mut *view as *mut ContainerView;
        unsafe {
            container_view_construct(
                this,
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(controller).cast::<u8>(),
                core::ptr::null_mut(),
                &spec,
            )
        };

        assert_eq!(view.content_provider, 0x0bad_f00d);
        assert_eq!(
            unsafe { QUERY_ARG },
            core::ptr::addr_of_mut!(controller) as usize,
            "the query runs on the controller itself"
        );
        assert_eq!(view.config, 7);
        assert_eq!(view.clip_rect, [0; 4]);
        assert_eq!(view.word_e4, 0);

        // flags bit 0 set: the linkage stub saw create_link == 1.
        assert_eq!(seen()[2], 1);
    }

    /// A zero config word is still stored — the copy is not a flag
    /// test, and 0x0815826c's `& 2` gate depends on the verbatim word.
    #[test]
    fn zero_config_copies_as_zero() {
        let _lock = OPS_LOCK.lock();
        let _guard = install_stubs();

        let mut view = blank_view();
        let spec = spec(0, 0);
        let this = &mut *view as *mut ContainerView;
        unsafe {
            container_view_construct(
                this,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &spec,
            )
        };
        assert_eq!(view.config, 0);
        assert_eq!(view.content_provider, this as usize as u32);
    }

    /// The accessor lands exactly on the +0xa8 registry subobject:
    /// byte-identical to the original's `add r0, r0, #0xa8`, and the
    /// returned pointer aliases the `children` field the constructor
    /// hands to `registry_container_construct_default`.
    #[test]
    fn children_returns_the_registry_at_0xa8() {
        let mut view = blank_view();
        let this = &mut *view as *mut ContainerView;
        let registry = unsafe { container_view_children(this) };
        assert_eq!(registry as usize, this as usize + 0xa8);
        assert_eq!(
            registry as usize,
            core::ptr::addr_of!(view.children) as usize,
            "aliases the children field the ctor initializes"
        );
        // A second view at a different address tracks its own base.
        let mut other = blank_view();
        let other_this = &mut *other as *mut ContainerView;
        assert_eq!(
            unsafe { container_view_children(other_this) } as usize,
            other_this as usize + 0xa8
        );
    }

    /// The original is one unconditional `add` with no guard, and
    /// every one of the 22 call sites is an unconditional `bl`: a
    /// NULL view must come back as bare 0xa8, not trap.
    #[test]
    fn children_null_view_wraps_to_0xa8() {
        let registry = unsafe { container_view_children(core::ptr::null_mut()) };
        assert_eq!(registry as usize, 0xa8);
    }
}
