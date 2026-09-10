//! The grand-base view constructor — the root of the retailOS screen
//! element hierarchy that `ui/string_view.rs` and
//! `ui/styled_text_view.rs` derive from (29 `bl` call sites, all
//! unconditional, verified by decoding every B/BL word in osos.dec;
//! no predicated or tail form exists, matching the callers' own
//! NULL-free operator_new-then-construct wrappers).
//!
//! # What the class is
//!
//! Every screen element (`'Str '` string views, styled text views,
//! bitmap draws, ...) embeds this 0xa4-byte object at its start and
//! runs this constructor first, either directly (the `'Str '` view @
//! 0x08291c24) or through the intermediate base @ 0x0810b29c (the
//! styled text view). The constructor chains the framework linkage
//! base @ 0x08103a4c (which runs the ported
//! `app/class_6800::framework_base_construct` and plants its own
//! vtable 0x08980854), then overwrites the vtable with this class's
//! own, copies the caller's resource provider and the generic spec
//! fields into place, and hands the half-built object to the
//! initialiser @ 0x0826ee08, which wires the view into its parent's
//! child list and resource chain (it dispatches vtable slot +0x9c,
//! reads spec +0x0c/+0x4c/+0x50/+0x54 and fills view +0x98/+0x9c).
//!
//! # Layout (0xa4 bytes; every call site embeds it at offset 0 of the
//! derived view)
//!
//! ```text
//! +0x00  vtable            ROM literal 0x089a59e8 (this ctor)
//! +0x04  linkage state     framework linkage base, ctor 0x08103a4c
//!                          (-> framework_base_construct @ 0x081110d0)
//! +0x38  resources         the caller's ResourceProvider
//! +0x3c  word_3c           cleared here
//! +0x40  class_code        spec +0x04 (a fourcc: 'Str ', 'BMap', ...)
//! +0x44  word_44           spec +0x08
//! +0x48  flags             spec +0x18 — the view flag word every
//!                          derived class tests
//! +0x4c  word_4c           spec +0x10
//! +0x50  geometry          0x30-byte block copied from spec +0x1c
//! +0x80  word_80..+0x8c    four words cleared here
//! +0x90  word_90           spec +0x58 when flags covers 0x38000 or
//!                          0x1c0000, else 0
//! +0x94  byte_94           cleared here (0x0826ee08 may set it from
//!                          spec +0x4c bit 1)
//! +0x98  word_98/+0x9c     owned by the 0x0826ee08 initialiser
//! +0xa0  byte_a0           cleared here
//! ```
//!
//! The vtable is real RW init data, not the stale fragments
//! `ui/string_view.rs` records for its own literal: the words at
//! 0x089a59e8 in osos.dec are genuine code pointers (slot +0x00 ->
//! 0x081032e4, slot +0x9c -> 0x08122124, whose prologue
//! `mov r1, #1; strb r1, [r0, #0x8c]` is binary-verified) and the
//! 0x0826ee08 initialiser dispatches slot +0x9c through it while the
//! grand-base vtable is still planted (derived constructors overwrite
//! it only after this constructor returns).

use crate::app::resource_chain::ResourceProvider;
use crate::libc::iram_veneers::iram_memcpy_veneer;

/// The ROM address of this class's vtable — the constructor's
/// literal-pool word @ 0x0826f324, binary-verified.
///
/// Stored as the `u32` the original stores. Unlike the derived
/// classes' literals, the image data at this address is a live vtable
/// (see the module header): the 0x0826ee08 initialiser calls slot
/// +0x9c through it, on target through the firmware's own copy. The
/// port never dispatches through it, so the raw address suffices.
pub const VIEW_BASE_VTABLE_ADDRESS: u32 = 0x089a_59e8;

/// The generic 0x5c-byte view spec prefix this constructor reads.
/// Derived classes append their own tails after +0x58 (the `'Str '`
/// view keeps its resource ids at +0x58/+0x5c, the styled text view
/// its style fields at +0x5c..+0x68).
#[repr(C)]
pub struct ViewSpec {
    /// spec +0x00 — not read by this constructor.
    pub word_00: u32,
    /// spec +0x04 — the element class fourcc, kept at view +0x40.
    pub class_code: u32,
    /// spec +0x08 — copied verbatim to view +0x44.
    pub word_08: u32,
    /// spec +0x0c — read by the 0x0826ee08 initialiser, not here.
    pub word_0c: u32,
    /// spec +0x10 — copied verbatim to view +0x4c.
    pub word_10: u32,
    /// spec +0x14 — not read by this constructor.
    pub word_14: u32,
    /// spec +0x18 — the view flag word. Bit 0 selects link creation in
    /// the framework linkage base; the word itself is kept at view
    /// +0x48 and decides the +0x90 copy.
    pub flags: u32,
    /// spec +0x1c..+0x4c — the 0x30-byte block copied to view +0x50.
    pub geometry: [u8; 0x30],
    /// spec +0x4c..+0x58 — read by the 0x0826ee08 initialiser
    /// (+0x4c byte flags, +0x50/+0x54 words), opaque here.
    pub tail: [u8; 0x0c],
    /// spec +0x58 — copied to view +0x90 when `flags` covers 0x38000
    /// or 0x1c0000, otherwise view +0x90 is cleared.
    pub word_58: u32,
}

const _: [u8; 0x5c] = [0; core::mem::size_of::<ViewSpec>()];

/// The 0xa4-byte grand-base view. Pointer-typed members are modelled
/// as `u32` target words so the layout is exact on both the 32-bit
/// target and 64-bit hosts (the `ui/styled_text_view.rs` convention).
#[repr(C)]
pub struct ViewBase {
    /// +0x00 — planted twice per construction: 0x08980854 by the
    /// linkage base ctor, then [`VIEW_BASE_VTABLE_ADDRESS`] here.
    pub vtable: u32,
    /// +0x04..+0x38 — framework linkage state owned by the 0x08103a4c
    /// / `framework_base_construct` chain (+0x04/+0x08 cleared, the
    /// optional 16-byte link node at +0x0c, its word at +0x10).
    pub linkage: [u8; 0x34],
    /// +0x38 — the caller's resource provider (target word).
    pub resources: u32,
    /// +0x3c — cleared here.
    pub word_3c: u32,
    /// +0x40 — the class fourcc from spec +0x04.
    pub class_code: u32,
    /// +0x44 — spec +0x08, verbatim.
    pub word_44: u32,
    /// +0x48 — the view flag word from spec +0x18.
    pub flags: u32,
    /// +0x4c — spec +0x10, verbatim.
    pub word_4c: u32,
    /// +0x50..+0x80 — the 0x30-byte block from spec +0x1c.
    pub geometry: [u8; 0x30],
    /// +0x80 — cleared here.
    pub word_80: u32,
    /// +0x84 — cleared here.
    pub word_84: u32,
    /// +0x88 — cleared here.
    pub word_88: u32,
    /// +0x8c — cleared here.
    pub word_8c: u32,
    /// +0x90 — spec +0x58 when `flags` covers 0x38000 or 0x1c0000,
    /// else 0.
    pub word_90: u32,
    /// +0x94 — cleared here; the 0x0826ee08 initialiser sets it when
    /// spec +0x4c bit 1 is set.
    pub byte_94: u8,
    /// +0x95..+0x98 — alignment (never written by this constructor).
    pub padding_after_byte_94: [u8; 3],
    /// +0x98 — written by the 0x0826ee08 initialiser, not here.
    pub word_98: u32,
    /// +0x9c — written by the 0x0826ee08 initialiser, not here.
    pub word_9c: u32,
    /// +0xa0 — cleared here.
    pub byte_a0: u8,
    /// +0xa1..+0xa4 — tail alignment to the 0xa4-byte subobject.
    pub padding_after_byte_a0: [u8; 3],
}

const _: [u8; 0xa4] = [0; core::mem::size_of::<ViewBase>()];
const _: [u8; 0x38] = [0; core::mem::offset_of!(ViewBase, resources)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(ViewBase, class_code)];
const _: [u8; 0x48] = [0; core::mem::offset_of!(ViewBase, flags)];
const _: [u8; 0x50] = [0; core::mem::offset_of!(ViewBase, geometry)];
const _: [u8; 0x90] = [0; core::mem::offset_of!(ViewBase, word_90)];
const _: [u8; 0x94] = [0; core::mem::offset_of!(ViewBase, byte_94)];
const _: [u8; 0x98] = [0; core::mem::offset_of!(ViewBase, word_98)];
const _: [u8; 0xa0] = [0; core::mem::offset_of!(ViewBase, byte_a0)];

/// Calls that bind or unbind a view from its resource provider.
///
/// These are the two fixed retailOS targets reached by
/// [`view_base_set_resource_provider`]. They are not independently ported.
#[derive(Clone, Copy)]
pub struct ViewBaseResourceOps {
    /// `FUN_08124af4(provider, view)`.
    pub attach_view: unsafe extern "C" fn(*mut ResourceProvider, *mut ViewBase),
    /// `FUN_08124dbc(provider, view, 0)`.
    pub detach_view: unsafe extern "C" fn(*mut ResourceProvider, *mut ViewBase, u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_attach_view(provider: *mut ResourceProvider, view: *mut ViewBase) {
    let attach: unsafe extern "C" fn(*mut ResourceProvider, *mut ViewBase) =
        unsafe { core::mem::transmute(0x0812_4af4usize) };
    unsafe { attach(provider, view) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_detach_view(
    provider: *mut ResourceProvider,
    view: *mut ViewBase,
    flags: u32,
) {
    let detach: unsafe extern "C" fn(*mut ResourceProvider, *mut ViewBase, u32) =
        unsafe { core::mem::transmute(0x0812_4dbcusize) };
    unsafe { detach(provider, view, flags) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attach_view(_provider: *mut ResourceProvider, _view: *mut ViewBase) {
    panic!("view_base_set_resource_provider requires FUN_08124af4")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_detach_view(
    _provider: *mut ResourceProvider,
    _view: *mut ViewBase,
    _flags: u32,
) {
    panic!("view_base_set_resource_provider requires FUN_08124dbc")
}

/// Fixed retailOS calls used by [`view_base_set_resource_provider`].
pub const DEFAULT_VIEW_BASE_RESOURCE_OPS: ViewBaseResourceOps = ViewBaseResourceOps {
    #[cfg(target_os = "none")]
    attach_view: firmware_attach_view,
    #[cfg(not(target_os = "none"))]
    attach_view: missing_attach_view,
    #[cfg(target_os = "none")]
    detach_view: firmware_detach_view,
    #[cfg(not(target_os = "none"))]
    detach_view: missing_detach_view,
};

/// The active binding operations. Host tests replace this with recorders.
pub static mut VIEW_BASE_RESOURCE_OPS: ViewBaseResourceOps = DEFAULT_VIEW_BASE_RESOURCE_OPS;

#[inline(always)]
unsafe fn view_resource_provider(view: *mut ViewBase) -> *mut ResourceProvider {
    core::ptr::addr_of!((*view).resources).read_volatile() as usize as *mut ResourceProvider
}

#[inline(always)]
unsafe fn resource_provider_replacement_allowed(
    provider: *mut ResourceProvider,
    replacement: *mut ResourceProvider,
) -> u32 {
    let vtable = core::ptr::addr_of!((*provider).vtable).read_volatile();
    let allowed = core::ptr::addr_of!((*vtable).replacement_allowed).read_volatile();
    allowed(provider, replacement)
}

/// view_base_set_resource_provider — original: `FUN_0826ef88` @
/// **0x0826ef88** (100 bytes, `0x0826ef88..0x0826efec`; the separately
/// linked `FUN_0826efec` starts at the next word).
///
/// If an old provider exists, calls its vtable slot `+0x60` with the
/// replacement. A non-zero response detaches the currently installed
/// provider through `FUN_08124dbc(provider, view, 0)` and stores the
/// replacement. A zero response leaves the field unchanged. In both cases
/// (and when there was no old provider), it attaches the requested provider
/// through `FUN_08124af4(provider, view)`, then invalidates the complete view
/// bounds through [`crate::ui::invalidate::ui_element_invalidate`], returning
/// that function's restored view pointer.
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **10 direct call
/// sites: all 10 are unconditional `bl`; there are no predicated `bl` forms,
/// no direct tail `b` references, and no image-word references. The absent
/// predicate agrees with the unguarded `view + 0x38` and provider-vtable
/// accesses in this body.
///
/// Deliberate deviations: the two unported fixed helper entries remain behind
/// [`VIEW_BASE_RESOURCE_OPS`] (firmware addresses on target, recorders on
/// host). The dynamic `+0x60` slot is dispatched from the shared
/// [`ResourceProvider`](crate::app::resource_chain::ResourceProvider) vtable
/// model on both targets; no second host-only virtual seam is added. The raw
/// epilogue tail-branches directly to the region form at `0x0826ec14`; this
/// port calls its already-ported whole-bounds wrapper instead, preserving the
/// same rectangle and returned view.
///
/// # Safety
///
/// `view` must be writable and its non-NULL provider words must reference
/// valid provider objects with a valid `+0x60` vtable slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_base_set_resource_provider(
    view: *mut ViewBase,
    replacement: *mut ResourceProvider,
) -> *mut ViewBase {
    let current = unsafe { view_resource_provider(view) };
    if current.is_null() {
        unsafe {
            core::ptr::addr_of_mut!((*view).resources)
                .write_volatile(replacement as usize as u32);
        }
    } else if unsafe { resource_provider_replacement_allowed(current, replacement) } != 0 {
        let installed = unsafe { view_resource_provider(view) };
        if !installed.is_null() {
            let detach = unsafe {
                core::ptr::addr_of!(VIEW_BASE_RESOURCE_OPS.detach_view).read_volatile()
            };
            unsafe { detach(installed, view, 0) };
        }
        unsafe {
            core::ptr::addr_of_mut!((*view).resources)
                .write_volatile(replacement as usize as u32);
        }
    }

    let attach = unsafe { core::ptr::addr_of!(VIEW_BASE_RESOURCE_OPS.attach_view).read_volatile() };
    unsafe { attach(replacement, view) };
    unsafe { crate::ui::invalidate::ui_element_invalidate(view.cast()) }.cast()
}
/// The decoded portion of a view's runtime vtable used by
/// [`view_base_set_word_44`].
///
/// The dynamic target at slot `+0xd4` has no statically recoverable
/// identity; it is invoked only through the object-provided vtable.
#[repr(C)]
pub struct ViewBaseVtable {
    /// Slots `+0x00..+0xd0`, not decoded by this setter.
    pub unresolved_00_d0: [usize; 53],
    /// Slot `+0xd4`: called after `word_44` changes.
    pub word_44_changed: unsafe extern "C" fn(*mut ViewBase),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xd4] = [0; core::mem::offset_of!(ViewBaseVtable, word_44_changed)];

/// ABI of the runtime vtable slot `+0xd4`.
pub type ViewBaseWord44Changed = unsafe extern "C" fn(*mut ViewBase);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_view_base_word_44_changed(_view: *mut ViewBase) {
    panic!("view_base_set_word_44 requires a vtable slot +0xd4 handler")
}

/// Host replacement for the view's dynamic vtable slot `+0xd4`.
///
/// Target builds call the object's actual vtable directly. The `u32`
/// firmware vtable word cannot represent a host-width function pointer, so
/// host tests install the observed slot ABI here instead.
#[cfg(not(target_os = "none"))]
pub static mut VIEW_BASE_WORD_44_CHANGED: ViewBaseWord44Changed =
    missing_view_base_word_44_changed;

/// Dispatches the target's runtime vtable slot `+0xd4`.
#[cfg(target_os = "none")]
unsafe fn view_base_dispatch_word_44_changed(view: *mut ViewBase) {
    let vtable = (*view).vtable as usize as *const ViewBaseVtable;
    let changed = core::ptr::addr_of!((*vtable).word_44_changed).read_volatile();
    changed(view);
}

/// Dispatches the host model of the target's runtime vtable slot `+0xd4`.
#[cfg(not(target_os = "none"))]
unsafe fn view_base_dispatch_word_44_changed(view: *mut ViewBase) {
    let changed = core::ptr::addr_of!(VIEW_BASE_WORD_44_CHANGED).read_volatile();
    changed(view);
}

/// view_base_set_word_44 — original: `FUN_0826d834` @ `0x0826d834`
/// (24 bytes, `0x0826d834..0x0826d84c`; the distinct sibling
/// `FUN_0826d850` starts with `push {r4,r5,r6,lr}` at `0x0826d850`).
///
/// Raw ARM loads view `+0x44`, returns unchanged when it equals `word_44`,
/// otherwise stores the new word then tail-dispatches its vtable slot
/// `+0xd4` with `view` in r0. A full-image ARM B/BL-word decode finds
/// **15 direct `bl` call sites, all unconditional**; no predicated call or
/// direct tail `b` reaches this entry.
///
/// Deliberate host deviation: target builds dispatch the object's actual
/// runtime vtable. Host pointers are wider than the target's `u32` vtable
/// word, so host tests model the same slot ABI through
/// [`VIEW_BASE_WORD_44_CHANGED`].
///
/// # Safety
///
/// `view` must point to a writable [`ViewBase`] whose vtable's `+0xd4` slot
/// is a valid `void (*)(ViewBase *)` when `word_44` differs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_base_set_word_44(view: *mut ViewBase, word_44: u32) {
    if core::ptr::addr_of!((*view).word_44).read_volatile() != word_44 {
        core::ptr::addr_of_mut!((*view).word_44).write_volatile(word_44);
        view_base_dispatch_word_44_changed(view);
    }
}

/// Indirect dispatch for this constructor's two unported callees (the
/// `StringViewOps` precedent in `ui/string_view.rs`).
#[derive(Clone, Copy)]
pub struct ViewBaseOps {
    /// Framework linkage base constructor @ 0x08103a4c `(view, parent,
    /// create_link)`: runs the ported `framework_base_construct` @
    /// 0x081110d0 with the same three arguments and plants the vtable
    /// 0x08980854 at view+0x00 (immediately overwritten by this
    /// class's own). Returns `view`. Not yet ported as its own
    /// symbol. `create_link` is spec +0x18 bit 0 at this call site.
    pub construct_linkage_base: unsafe extern "C" fn(
        view: *mut ViewBase,
        parent: *mut u8,
        create_link: u32,
    ) -> *mut ViewBase,
    /// View initialiser @ 0x0826ee08 `(view, controller, spec)`:
    /// inherits the resource provider from `controller` when the
    /// view's own is NULL and spec +0x0c is -1, registers the view
    /// with the provider (0x08124af4), applies the flag-gated mode
    /// words (0x0826ddd4, 0x0826db24, 0x0826db10), dispatches vtable
    /// slot +0x9c, and fills view +0x98/+0x9c from spec +0x50/+0x54.
    /// Not yet ported.
    pub initialize: unsafe extern "C" fn(
        view: *mut ViewBase,
        controller: *mut u8,
        spec: *const ViewSpec,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_linkage_base(
    view: *mut ViewBase,
    parent: *mut u8,
    create_link: u32,
) -> *mut ViewBase {
    let construct: unsafe extern "C" fn(*mut ViewBase, *mut u8, u32) -> *mut ViewBase =
        unsafe { core::mem::transmute(0x0810_3a4cusize) };
    unsafe { construct(view, parent, create_link) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_linkage_base(
    _view: *mut ViewBase,
    _parent: *mut u8,
    _create_link: u32,
) -> *mut ViewBase {
    panic!("view_base_construct requires linkage base ctor 0x08103a4c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_initialize(
    view: *mut ViewBase,
    controller: *mut u8,
    spec: *const ViewSpec,
) {
    let initialize: unsafe extern "C" fn(*mut ViewBase, *mut u8, *const ViewSpec) =
        unsafe { core::mem::transmute(0x0826_ee08usize) };
    unsafe { initialize(view, controller, spec) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize(
    _view: *mut ViewBase,
    _controller: *mut u8,
    _spec: *const ViewSpec,
) {
    panic!("view_base_construct requires view initialiser 0x0826ee08")
}

/// Wired defaults (the `event_list.rs` split: firmware addresses on
/// target, panics on host).
pub const DEFAULT_VIEW_BASE_OPS: ViewBaseOps = ViewBaseOps {
    #[cfg(target_os = "none")]
    construct_linkage_base: firmware_construct_linkage_base,
    #[cfg(not(target_os = "none"))]
    construct_linkage_base: missing_construct_linkage_base,
    #[cfg(target_os = "none")]
    initialize: firmware_initialize,
    #[cfg(not(target_os = "none"))]
    initialize: missing_initialize,
};

/// The active dispatch table. Written once at init on target; host
/// tests swap in recorders and restore the defaults.
pub static mut VIEW_BASE_OPS: ViewBaseOps = DEFAULT_VIEW_BASE_OPS;

/// view_base_construct — original: `FUN_0826f26c` @ 0x0826f26c (188
/// bytes: 184 code ending in `ldmia sp!, {r4, r5, r6, r7, r8, pc}` @
/// 0x0826f320, plus the 4-byte vtable literal @ 0x0826f324 =
/// 0x089a59e8 that Ghidra's 184-byte extent drops; the next function —
/// the unlisted deleting destructor @ 0x0826f328 — starts immediately
/// after. 29 `bl` call sites, all unconditional, verified by decoding
/// every B/BL word in osos.dec).
///
/// Runs the framework linkage base ctor with `parent` and the spec's
/// flag bit 0, then plants this class's vtable and unpacks the generic
/// spec: `resources` to +0x38, +0x3c cleared, the class code to +0x40,
/// spec +0x08/+0x10/+0x18 to +0x44/+0x4c/+0x48, the 0x30-byte block
/// from spec +0x1c to +0x50 (through the ported
/// [`iram_memcpy_veneer`], the original's `bl 0x08037df8`), the four
/// words +0x80..+0x8c and the bytes +0x94/+0xa0 cleared, and +0x90 set
/// to spec +0x58 when the flag word covers 0x38000 or 0x1c0000, else
/// cleared. Finally the initialiser @ 0x0826ee08 runs with
/// `(view, controller, spec)` and the constructor returns `view`.
///
/// Deliberate deviations:
///
/// - Ghidra types this `int FUN_0826f26c(void)`; the assembly takes
///   four register arguments plus the stacked spec (`ldr r5,
///   [sp, #24]` past the six saved registers) and its closing
///   `mov r0, r4` returns the constructed object, so the port takes
///   the five arguments and returns `view` (the
///   `styled_text_view_construct` precedent).
/// - The original threads r0 out of the linkage ctor into every store
///   (`mov r4, r0`); the chain is verified to return its argument
///   (`framework_base_construct` returns `storage`, and 0x08103a4c
///   leaves that in r0), so the port keeps `view` in hand and
///   addresses members through `addr_of_mut!` — the same dataflow, but
///   correct on a 64-bit host (the `pool_parent_construct`
///   precedent).
/// - The vtable is the `u32` ROM address [`VIEW_BASE_VTABLE_ADDRESS`]
///   rather than a modeled static: the port never dispatches through
///   it, and the firmware's own initialiser uses the image's copy on
///   target (see the constant's docs — this one is live, not stale).
/// - `resources` is stored as its low 32 bits (`resources as usize as
///   u32`): view +0x38 is a target word, and on target the pointer
///   already fits. Host fixtures keep the pointer below 4 GiB so the
///   store round-trips exactly.
///
/// # Safety
/// `view` must point at a writable, 4-byte-aligned [`ViewBase`],
/// `spec` at a readable [`ViewSpec`], and the installed
/// [`VIEW_BASE_OPS`] must accept them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_base_construct(
    view: *mut ViewBase,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut ViewBase {
    // Read each slot directly rather than the whole table (the
    // timer_schedule_shim sibcall gotcha).
    let construct_linkage_base =
        core::ptr::addr_of!(VIEW_BASE_OPS.construct_linkage_base).read_volatile();
    let initialize = core::ptr::addr_of!(VIEW_BASE_OPS.initialize).read_volatile();


    construct_linkage_base(view, parent, (*spec).flags & 1);
    core::ptr::addr_of_mut!((*view).resources).write_volatile(resources as usize as u32);
    core::ptr::addr_of_mut!((*view).vtable).write_volatile(VIEW_BASE_VTABLE_ADDRESS);
    core::ptr::addr_of_mut!((*view).word_3c).write_volatile(0);
    core::ptr::addr_of_mut!((*view).class_code).write_volatile((*spec).class_code);
    core::ptr::addr_of_mut!((*view).word_44).write_volatile((*spec).word_08);
    core::ptr::addr_of_mut!((*view).flags).write_volatile((*spec).flags);
    core::ptr::addr_of_mut!((*view).word_4c).write_volatile((*spec).word_10);
    iram_memcpy_veneer(
        core::ptr::addr_of_mut!((*view).geometry).cast(),
        core::ptr::addr_of!((*spec).geometry).cast(),
        0x30,
    );
    core::ptr::addr_of_mut!((*view).word_80).write_volatile(0);
    core::ptr::addr_of_mut!((*view).word_84).write_volatile(0);
    core::ptr::addr_of_mut!((*view).word_88).write_volatile(0);
    core::ptr::addr_of_mut!((*view).word_8c).write_volatile(0);
    core::ptr::addr_of_mut!((*view).byte_94).write_volatile(0);
    core::ptr::addr_of_mut!((*view).byte_a0).write_volatile(0);
    let flags = core::ptr::addr_of!((*view).flags).read_volatile();
    let word_90 = if flags & 0x3_8000 == 0x3_8000 || flags & 0x1c_0000 == 0x1c_0000 {
        (*spec).word_58
    } else {
        0
    };
    core::ptr::addr_of_mut!((*view).word_90).write_volatile(word_90);
    initialize(view, controller, spec);
    view
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::resource_chain::ResourceProviderVTable;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const VIEW_OFFSET: usize = 0x000;
    const SPEC_OFFSET: usize = 0x400;
    const RESOURCES_OFFSET: usize = 0x600;
    const CONTROLLER_OFFSET: usize = 0x700;
    const PARENT_OFFSET: usize = 0x780;

    /// Ops-table swaps and the slab are global; serialize the tests.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        slab: *mut u8,
        previous: ViewBaseOps,
    }

    impl Fixture {
        fn map(ops: ViewBaseOps) -> Option<Self> {
            let guard = TEST_LOCK.lock();
            let slab = try_map_u32_slab(hints::VIEW_BASE, SLAB_LEN)?;
            unsafe {
                // Poison every byte the constructor is expected to
                // write, so a missed store is visible.
                ptr::write_bytes(slab, 0xa5, SLAB_LEN);
                let previous = ptr::addr_of!(VIEW_BASE_OPS).read_volatile();
                ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(ops);
                Some(Self {
                    _guard: guard,
                    slab,
                    previous,
                })
            }
        }

        fn view(&self) -> *mut ViewBase {
            unsafe { self.slab.add(VIEW_OFFSET).cast() }
        }

        fn spec(&self) -> *mut ViewSpec {
            unsafe { self.slab.add(SPEC_OFFSET).cast() }
        }

        fn resources(&self) -> *mut ResourceProvider {
            unsafe { self.slab.add(RESOURCES_OFFSET).cast() }
        }

        fn controller(&self) -> *mut u8 {
            unsafe { self.slab.add(CONTROLLER_OFFSET) }
        }

        fn parent(&self) -> *mut u8 {
            unsafe { self.slab.add(PARENT_OFFSET) }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(self.previous) };
        }
    }

    fn unavailable() -> bool {
        note_missing_u32_fixture("ui/view_base")
    }

    /// One entry per ops call, in arrival order.
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut LINKAGE_ARGS: (*mut ViewBase, *mut u8, u32) =
        (ptr::null_mut(), ptr::null_mut(), 0);
    static mut INITIALIZE_ARGS: (*mut ViewBase, *mut u8, *const ViewSpec) =
        (ptr::null_mut(), ptr::null_mut(), ptr::null());

    static mut WORD_44_CHANGE_COUNT: u32 = 0;
    static mut WORD_44_CHANGED_VIEW: *mut ViewBase = ptr::null_mut();
    static mut WORD_44_CHANGED_VALUE: u32 = 0;

    unsafe extern "C" fn recording_word_44_changed(view: *mut ViewBase) {
        unsafe {
            *(&raw mut WORD_44_CHANGE_COUNT) += 1;
            *(&raw mut WORD_44_CHANGED_VIEW) = view;
            *(&raw mut WORD_44_CHANGED_VALUE) =
                ptr::addr_of!((*view).word_44).read_volatile();
        }
    }

    struct Word44ChangedRestore {
        previous: ViewBaseWord44Changed,
    }

    impl Drop for Word44ChangedRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(VIEW_BASE_WORD_44_CHANGED).write_volatile(self.previous);
            }
        }
    }

    unsafe extern "C" fn recording_construct_linkage_base(
        view: *mut ViewBase,
        parent: *mut u8,
        create_link: u32,
    ) -> *mut ViewBase {
        unsafe {
            (*(&raw mut CALL_LOG)).push("linkage");
            (*(&raw mut LINKAGE_ARGS)) = (view, parent, create_link);
            // The real 0x08103a4c plants its own vtable 0x08980854
            // here; plant it too so the test proves the grand-base
            // vtable store comes after the chain, not instead of it.
            ptr::addr_of_mut!((*view).vtable).write_volatile(0x0898_0854);
        }
        view
    }

    unsafe extern "C" fn recording_initialize(
        view: *mut ViewBase,
        controller: *mut u8,
        spec: *const ViewSpec,
    ) {
        unsafe {
            (*(&raw mut CALL_LOG)).push("initialize");
            (*(&raw mut INITIALIZE_ARGS)) = (view, controller, spec);
            // Snapshot what must already be in place when the
            // initialiser runs (the original calls it last).
            assert_eq!(
                ptr::addr_of!((*view).vtable).read_volatile(),
                VIEW_BASE_VTABLE_ADDRESS,
                "initialiser runs after the vtable plant"
            );
            assert_eq!(
                ptr::addr_of!((*view).byte_a0).read_volatile(),
                0,
                "initialiser runs after the field clears"
            );
        }
    }

    fn recording_ops() -> ViewBaseOps {
        ViewBaseOps {
            construct_linkage_base: recording_construct_linkage_base,
            initialize: recording_initialize,
        }
    }

    fn fill_spec(spec: *mut ViewSpec, flags: u32, word_58: u32) {
        unsafe {
            ptr::addr_of_mut!((*spec).word_00).write_volatile(0x0000_1111);
            ptr::addr_of_mut!((*spec).class_code).write_volatile(0x5374_7220); // 'Str '
            ptr::addr_of_mut!((*spec).word_08).write_volatile(0x0808_0808);
            ptr::addr_of_mut!((*spec).word_0c).write_volatile(0x0c0c_0c0c);
            ptr::addr_of_mut!((*spec).word_10).write_volatile(0x1010_1010);
            ptr::addr_of_mut!((*spec).word_14).write_volatile(0x1414_1414);
            ptr::addr_of_mut!((*spec).flags).write_volatile(flags);
            for (i, b) in (*(&raw mut (*spec).geometry)).iter_mut().enumerate() {
                *b = i as u8;
            }
            ptr::addr_of_mut!((*spec).tail).write_volatile([0x7c; 0x0c]);
            ptr::addr_of_mut!((*spec).word_58).write_volatile(word_58);
        }
    }

    #[test]
    fn struct_layout_matches_target() {
        assert_eq!(core::mem::size_of::<ViewBase>(), 0xa4);
        assert_eq!(core::mem::size_of::<ViewSpec>(), 0x5c);
        assert_eq!(core::mem::align_of::<ViewBase>(), 4);
        assert_eq!(core::mem::align_of::<ViewSpec>(), 4);
    }

    #[test]
    fn constructs_all_fields_and_returns_view() {
        let Some(fixture) = Fixture::map(recording_ops()) else {
            assert!(unavailable());
            return;
        };
        unsafe {
            (*(&raw mut CALL_LOG)).clear();
            fill_spec(fixture.spec(), 0x0000_0002, 0x5858_5858);

            let result = view_base_construct(
                fixture.view(),
                fixture.resources(),
                fixture.controller(),
                fixture.parent(),
                fixture.spec(),
            );

            assert_eq!(result, fixture.view(), "returns the constructed view");
            let view = fixture.view();
            let spec = fixture.spec();
            assert_eq!(ptr::addr_of!((*view).vtable).read_volatile(), VIEW_BASE_VTABLE_ADDRESS);
            assert_eq!(
                ptr::addr_of!((*view).resources).read_volatile(),
                fixture.resources() as usize as u32
            );
            assert_eq!(ptr::addr_of!((*view).word_3c).read_volatile(), 0);
            assert_eq!(
                ptr::addr_of!((*view).class_code).read_volatile(),
                ptr::addr_of!((*spec).class_code).read_volatile()
            );
            assert_eq!(
                ptr::addr_of!((*view).word_44).read_volatile(),
                ptr::addr_of!((*spec).word_08).read_volatile()
            );
            assert_eq!(
                ptr::addr_of!((*view).flags).read_volatile(),
                ptr::addr_of!((*spec).flags).read_volatile()
            );
            assert_eq!(
                ptr::addr_of!((*view).word_4c).read_volatile(),
                ptr::addr_of!((*spec).word_10).read_volatile()
            );
            assert_eq!(
                ptr::addr_of!((*view).geometry).read_volatile(),
                ptr::addr_of!((*spec).geometry).read_volatile(),
                "the 0x30-byte block is copied verbatim"
            );
            for word in [
                ptr::addr_of!((*view).word_80),
                ptr::addr_of!((*view).word_84),
                ptr::addr_of!((*view).word_88),
                ptr::addr_of!((*view).word_8c),
            ] {
                assert_eq!(word.read_volatile(), 0);
            }
            assert_eq!(ptr::addr_of!((*view).byte_94).read_volatile(), 0);
            assert_eq!(ptr::addr_of!((*view).byte_a0).read_volatile(), 0);
            assert_eq!(
                ptr::addr_of!((*view).word_90).read_volatile(),
                0,
                "flags 0x00000002 covers neither mask: +0x90 clears"
            );
            // The constructor never touches the initialiser's words.
            assert_eq!(ptr::addr_of!((*view).word_98).read_volatile(), 0xa5a5_a5a5);
            assert_eq!(ptr::addr_of!((*view).word_9c).read_volatile(), 0xa5a5_a5a5);

            // Both ops ran, in order, with the original's arguments.
            assert_eq!(*(&raw const CALL_LOG), ["linkage", "initialize"]);
            let (v, parent, create_link) = *(&raw const LINKAGE_ARGS);
            assert_eq!(v, fixture.view());
            assert_eq!(parent, fixture.parent());
            assert_eq!(create_link, 0, "flag bit 0 clear -> no link");
            let (v, controller, s) = *(&raw const INITIALIZE_ARGS);
            assert_eq!(v, fixture.view());
            assert_eq!(controller, fixture.controller());
            assert_eq!(s, fixture.spec() as *const ViewSpec);
        }
    }

    #[test]
    fn flag_bit_zero_selects_link_creation() {
        let Some(fixture) = Fixture::map(recording_ops()) else {
            assert!(unavailable());
            return;
        };
        unsafe {
            (*(&raw mut CALL_LOG)).clear();
            fill_spec(fixture.spec(), 0xffff_fffe, 0);
            view_base_construct(
                fixture.view(),
                fixture.resources(),
                fixture.controller(),
                fixture.parent(),
                fixture.spec(),
            );
            assert_eq!((*(&raw const LINKAGE_ARGS)).2, 0);

            fill_spec(fixture.spec(), 0x0000_0001, 0);
            view_base_construct(
                fixture.view(),
                fixture.resources(),
                fixture.controller(),
                fixture.parent(),
                fixture.spec(),
            );
            assert_eq!((*(&raw const LINKAGE_ARGS)).2, 1, "spec +0x18 bit 0 -> create_link");
        }
    }

    /// +0x90 takes spec +0x58 when the flag word covers 0x38000 or
    /// 0x1c0000 in full, and clears otherwise — including partial
    /// masks, which the original's `bics` pair rejects.
    #[test]
    fn word_90_follows_the_full_mask_coverage() {
        let Some(fixture) = Fixture::map(recording_ops()) else {
            assert!(unavailable());
            return;
        };
        unsafe {
            let cases: [(u32, u32); 8] = [
                (0x0003_8000, 0x5858_5858), // exact 0x38000
                (0x001c_0000, 0x5858_5858), // exact 0x1c0000
                (0x001f_8000, 0x5858_5858), // both
                (0xffff_ffff, 0x5858_5858), // superset
                (0x0001_8000, 0),           // partial 0x38000
                (0x000c_0000, 0),           // partial 0x1c0000
                (0x0002_0000, 0),           // single bit of 0x38000
                (0x0000_0000, 0),           // none
            ];
            for (flags, expected) in cases {
                fill_spec(fixture.spec(), flags, 0x5858_5858);
                view_base_construct(
                    fixture.view(),
                    fixture.resources(),
                    fixture.controller(),
                    fixture.parent(),
                    fixture.spec(),
                );
                assert_eq!(
                    ptr::addr_of!((*fixture.view()).word_90).read_volatile(),
                    expected,
                    "flags {flags:#010x}"
                );
            }
        }
    }

    /// The +0x90 decision reloads the flag word from the view, not the
    /// spec: an initialiser-time value is irrelevant, but a linkage
    /// ctor that rewrote view +0x48 would be honoured. Prove the read
    /// happens after the +0x48 store by having the recording linkage
    /// ctor leave the vtable marker — covered above — and checking the
    /// store order through the call log: linkage strictly before
    /// initialize.
    #[test]
    fn linkage_chain_runs_before_any_field_store() {
        let Some(fixture) = Fixture::map(recording_ops()) else {
            assert!(unavailable());
            return;
        };
        unsafe {
            fill_spec(fixture.spec(), 0x0003_8000, 0x5858_5858);
            view_base_construct(
                fixture.view(),
                fixture.resources(),
                fixture.controller(),
                fixture.parent(),
                fixture.spec(),
            );
            // The recording linkage ctor planted 0x08980854; the final
            // vtable is the grand-base one, so this ctor's store came
            // strictly after the chain returned.
            assert_eq!(
                ptr::addr_of!((*fixture.view()).vtable).read_volatile(),
                VIEW_BASE_VTABLE_ADDRESS
            );
        }
    }
    #[test]
    fn word_44_changes_notify_once_after_the_store() {
        let _guard = TEST_LOCK.lock();
        let previous = unsafe {
            ptr::addr_of!(VIEW_BASE_WORD_44_CHANGED).read_volatile()
        };
        let _restore = Word44ChangedRestore { previous };
        let mut view: ViewBase = unsafe { core::mem::zeroed() };

        unsafe {
            ptr::addr_of_mut!(VIEW_BASE_WORD_44_CHANGED)
                .write_volatile(recording_word_44_changed);
            *(&raw mut WORD_44_CHANGE_COUNT) = 0;
            *(&raw mut WORD_44_CHANGED_VIEW) = ptr::null_mut();
            *(&raw mut WORD_44_CHANGED_VALUE) = 0;
            ptr::addr_of_mut!(view.word_44).write_volatile(0);
            ptr::addr_of_mut!(view.word_4c).write_volatile(0xa5a5_a5a5);

            view_base_set_word_44(ptr::addr_of_mut!(view), 0);
            assert_eq!(*(&raw const WORD_44_CHANGE_COUNT), 0);

            view_base_set_word_44(ptr::addr_of_mut!(view), u32::MAX);
            assert_eq!(
                ptr::addr_of!(view.word_44).read_volatile(),
                u32::MAX,
                "the callback sees the replacement value"
            );
            assert_eq!(*(&raw const WORD_44_CHANGE_COUNT), 1);
            assert_eq!(*(&raw const WORD_44_CHANGED_VIEW), ptr::addr_of_mut!(view));
            assert_eq!(*(&raw const WORD_44_CHANGED_VALUE), u32::MAX);

            view_base_set_word_44(ptr::addr_of_mut!(view), u32::MAX);
            assert_eq!(
                *(&raw const WORD_44_CHANGE_COUNT),
                1,
                "equal values return without dispatch"
            );

            view_base_set_word_44(ptr::addr_of_mut!(view), 0);
            assert_eq!(*(&raw const WORD_44_CHANGE_COUNT), 2);
            assert_eq!(*(&raw const WORD_44_CHANGED_VALUE), 0);
            assert_eq!(
                ptr::addr_of!(view.word_4c).read_volatile(),
                0xa5a5_a5a5,
                "the setter touches only +0x44"
            );
        }
    }
    struct ResourceOpsRestore {
        previous: ViewBaseResourceOps,
    }

    impl Drop for ResourceOpsRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(VIEW_BASE_RESOURCE_OPS).write_volatile(self.previous);
            }
        }
    }

    static mut RESOURCE_ALLOW_RESULT: u32 = 0;
    static mut RESOURCE_ALLOW_ARGS: (*mut ResourceProvider, *mut ResourceProvider) =
        (ptr::null_mut(), ptr::null_mut());
    static mut RESOURCE_ATTACH_ARGS: (*mut ResourceProvider, *mut ViewBase) =
        (ptr::null_mut(), ptr::null_mut());
    static mut RESOURCE_DETACH_ARGS: (*mut ResourceProvider, *mut ViewBase, u32) =
        (ptr::null_mut(), ptr::null_mut(), u32::MAX);
    static mut RESOURCE_CALLS: Vec<&'static str> = Vec::new();

    unsafe extern "C" fn resource_replacement_allowed(
        provider: *mut ResourceProvider,
        replacement: *mut ResourceProvider,
    ) -> u32 {
        unsafe {
            *(&raw mut RESOURCE_ALLOW_ARGS) = (provider, replacement);
            (*(&raw mut RESOURCE_CALLS)).push("allow");
            ptr::read_volatile(ptr::addr_of!(RESOURCE_ALLOW_RESULT))
        }
    }

    unsafe extern "C" fn resource_read_unused(
        _provider: *mut ResourceProvider,
        _kind: crate::app::resource_chain::ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn resource_find_unused(
        _provider: *mut ResourceProvider,
        _kind: crate::app::resource_chain::ResourceKind,
        _id: u32,
        _found: *mut *mut u8,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn resource_write_unused(
        _provider: *mut ResourceProvider,
        _kind: crate::app::resource_chain::ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    static RESOURCE_VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22],
        read: resource_read_unused,
        slot_5c: None,
        replacement_allowed: resource_replacement_allowed,
        find: resource_find_unused,
        write: resource_write_unused,
    };

    unsafe extern "C" fn recording_attach(
        provider: *mut ResourceProvider,
        view: *mut ViewBase,
    ) {
        unsafe {
            *(&raw mut RESOURCE_ATTACH_ARGS) = (provider, view);
            (*(&raw mut RESOURCE_CALLS)).push("attach");
        }
    }

    unsafe extern "C" fn recording_detach(
        provider: *mut ResourceProvider,
        view: *mut ViewBase,
        flags: u32,
    ) {
        unsafe {
            *(&raw mut RESOURCE_DETACH_ARGS) = (provider, view, flags);
            (*(&raw mut RESOURCE_CALLS)).push("detach");
        }
    }

    const RECORDING_RESOURCE_OPS: ViewBaseResourceOps = ViewBaseResourceOps {
        attach_view: recording_attach,
        detach_view: recording_detach,
    };

    #[test]
    fn resource_provider_setter_preserves_the_retail_acceptance_paths() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::VIEW_BASE_RESOURCE_PROVIDER, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("ui/view_base resource provider"));
            return;
        };

        let previous = unsafe { ptr::addr_of!(VIEW_BASE_RESOURCE_OPS).read_volatile() };
        let _restore = ResourceOpsRestore { previous };
        unsafe {
            ptr::addr_of_mut!(VIEW_BASE_RESOURCE_OPS).write_volatile(RECORDING_RESOURCE_OPS);
        }

        let view = slab.cast::<ViewBase>();
        let old = unsafe { slab.add(0x200).cast::<ResourceProvider>() };
        let replacement = unsafe { slab.add(0x280).cast::<ResourceProvider>() };

        unsafe fn reset(
            slab: *mut u8,
            old: *mut ResourceProvider,
            replacement: *mut ResourceProvider,
        ) {
            unsafe {
                ptr::write_bytes(slab, 0, SLAB_LEN);
                ptr::addr_of_mut!((*old).vtable).write(&RESOURCE_VTABLE);
                ptr::addr_of_mut!((*replacement).vtable).write(&RESOURCE_VTABLE);
                *(&raw mut RESOURCE_ALLOW_RESULT) = 0;
                *(&raw mut RESOURCE_ALLOW_ARGS) = (ptr::null_mut(), ptr::null_mut());
                *(&raw mut RESOURCE_ATTACH_ARGS) = (ptr::null_mut(), ptr::null_mut());
                *(&raw mut RESOURCE_DETACH_ARGS) = (ptr::null_mut(), ptr::null_mut(), u32::MAX);
                (*(&raw mut RESOURCE_CALLS)).clear();
            }
        }

        unsafe {
            // No installed provider: store first, attach once, and do not
            // touch a virtual slot.
            reset(slab, old, replacement);
            assert_eq!(view_base_set_resource_provider(view, replacement), view);
            assert_eq!(ptr::addr_of!((*view).resources).read_volatile(), replacement as usize as u32);
            assert_eq!(*(&raw const RESOURCE_CALLS), ["attach"]);
            assert_eq!(*(&raw const RESOURCE_ATTACH_ARGS), (replacement, view));

            // A non-zero +0x60 response detaches the provider re-read from
            // +0x38, then replaces it before attaching the requested one.
            reset(slab, old, replacement);
            ptr::addr_of_mut!((*view).resources).write_volatile(old as usize as u32);
            *(&raw mut RESOURCE_ALLOW_RESULT) = 7;
            assert_eq!(view_base_set_resource_provider(view, replacement), view);
            assert_eq!(ptr::addr_of!((*view).resources).read_volatile(), replacement as usize as u32);
            assert_eq!(*(&raw const RESOURCE_CALLS), ["allow", "detach", "attach"]);
            assert_eq!(*(&raw const RESOURCE_ALLOW_ARGS), (old, replacement));
            assert_eq!(*(&raw const RESOURCE_DETACH_ARGS), (old, view, 0));
            assert_eq!(*(&raw const RESOURCE_ATTACH_ARGS), (replacement, view));

            // A zero response deliberately does not replace or detach the
            // current provider, but the raw epilogue still attaches the
            // requested provider before invalidating the view.
            reset(slab, old, replacement);
            ptr::addr_of_mut!((*view).resources).write_volatile(old as usize as u32);
            assert_eq!(view_base_set_resource_provider(view, replacement), view);
            assert_eq!(ptr::addr_of!((*view).resources).read_volatile(), old as usize as u32);
            assert_eq!(*(&raw const RESOURCE_CALLS), ["allow", "attach"]);
            assert_eq!((*(&raw const RESOURCE_DETACH_ARGS)).0, ptr::null_mut());
            assert_eq!(*(&raw const RESOURCE_ATTACH_ARGS), (replacement, view));

            // Neither the entry store nor the attach call guards a NULL
            // replacement; the recorder makes that ABI-visible path safe to
            // exercise on the host.
            reset(slab, old, replacement);
            assert_eq!(view_base_set_resource_provider(view, ptr::null_mut()), view);
            assert_eq!(ptr::addr_of!((*view).resources).read_volatile(), 0);
            assert_eq!(*(&raw const RESOURCE_CALLS), ["attach"]);
            assert_eq!((*(&raw const RESOURCE_ATTACH_ARGS)).0, ptr::null_mut());
            assert_eq!((*(&raw const RESOURCE_ATTACH_ARGS)).1, view);
        }
    }
}
