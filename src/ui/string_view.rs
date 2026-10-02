//! The constructor of the string view widget — the retailOS screen
//! element that displays a resource-resolved string in a resource-
//! resolved typeface and re-evaluates itself on an embedded timer
//! (32 `bl` call sites, all unconditional).
//!
//! # What the class is
//!
//! A 0x220-byte subclass of the grand-base view (ctor @ 0x0826f26c,
//! the same base `ui/styled_text_view.rs` documents). Every call site
//! goes through a `new` wrapper (@ 0x082907a4: `operator_new(0x220)`
//! then this constructor, forwarding all four register arguments with
//! the spec stacked) or inlines that pair in a screen builder
//! (0x08218b98, 0x08228c68, 0x08234bd0, 0x08237a98, 0x0825d878, ...).
//!
//! The class identity rests on its resource wiring. The post-
//! construction resolve step @ 0x08290f6c feeds the spec tail (+0x58,
//! +0x5c, +0x60, +0x61, +0x64) to the resolver @ 0x08290d7c, which:
//!
//! - compares the view's class code (view+0x40, copied from spec+0x04
//!   by the base ctor) against the literal @ 0x08290f5c =
//!   `0x53747220` `'Str '` and resolves spec+0x58 as a `'Str '`
//!   resource when it matches, as a `'StSt'` (string-style) resource
//!   otherwise — landing in the three-word resource reference at
//!   view+0xf8;
//! - resolves spec+0x5c through the `'Type'` (typeface) fourcc
//!   (literal @ 0x08290f64 = `0x54797065`) into the same reference;
//! - sets the resolved flag byte at view+0x1f0.
//!
//! (fourccs binary-verified in osos.dec; the literals sit at
//! 0x08290f5c/0x08290f60/0x08290f64 in the resolver's pool.)
//!
//! The two StringObjects at +0x104/+0x10c hold the composed text, the
//! four owned pointers at +0x114..+0x120 are 0xc8-byte pair-header
//! service objects (the destructor @ 0x08291cd4 runs
//! `pair_header_destruct` @ 0x08124a5c + `operator delete` on each,
//! NULL-guarded), and the 0x2c-byte object at +0x1f4 is a timer this
//! constructor builds with the view itself as its config word — the
//! self-rearm hook the scrolling/expiry behaviour hangs off (the
//! `app/view_timer.rs` notes document the timer's config-word
//! convention).
//!
//! # Layout (544 bytes, the `operator_new(0x220)` at every call site)
//!
//! ```text
//! +0x000  vtable                (ROM literal 0x089a7178)
//! +0x004  base subobject        grand-base view ctor 0x0826f26c
//! +0x0a4  draw_state            0x54 bytes, ctor 0x0826467c
//! +0x0f8  resource_ref          3 words: 'Str '/'StSt' + 'Type' handles
//! +0x104  string_a              StringObject (ctor 0x08277440)
//! +0x10c  string_b              StringObject
//! +0x114  owned_headers[4]      pair-header service objects, born NULL
//! +0x124  pair_header_base      0xb8 bytes, ctor 0x0810ebbc
//! +0x1dc  word_1dc              cleared here, purpose unrecovered
//! +0x1e0  observers             16-byte ObservableArray, ctor 0x08271cec
//! +0x1f0  resources_resolved    byte, set by the resolve step
//! +0x1f4  timer                 0x2c bytes, ctor 0x0812c65c via the
//!                               timer_schedule_shim plumbing
//! ```
//!
//! The destructor @ 0x08291cd4 (unlisted by Ghidra; binary-verified)
//! confirms the layout: it replants the same vtable from its own
//! literal @ 0x08291d84, runs 0x0829169c on the view, deletes the four
//! +0x114..+0x120 pointers, then tears down the observable array
//! (0x08271d2c on +0x1e0), the pair-header base (0x0810ec10 on
//! +0x124), both strings (0x08277484 on +0x104/+0x10c) and the draw
//! state (0x082646ac on +0xa4), and chains to the base dtor. The
//! deleting variant @ 0x08291cbc NULL-guards, runs it, and tail-
//! branches to `operator delete` @ 0x082aad24.

use crate::app::resource_chain::ResourceProvider;
use crate::cxx::draw_state::draw_state_construct;
use crate::cxx::observable_array::{observable_array_construct, ObservableArray};
use crate::cxx::pair_header::pair_header_base_construct;
use crate::cxx::string_object::string_default_construct;
use crate::drivers::timer::timer_schedule_shim;
use crate::ui::resource_ref_clear::resource_ref_clear;

/// The ROM address of this class's vtable (the constructor's literal-
/// pool word @ 0x08291cb8, binary-verified; the destructor @ 0x08291cd4
/// replants the same value from its own literal @ 0x08291d84).
///
/// Stored as the `u32` the original stores. The words the image carries
/// at 0x089a7178 are stale RW init data — they decode as mid-function
/// fragments, not entry points — the same finding
/// `ui/styled_text_view.rs` records for its own vtable literal, so
/// there are no slots to model and nothing here dispatches through it.
pub const STRING_VIEW_VTABLE_ADDRESS: u32 = 0x089a_7178;

/// The 104-byte view spec. The constructor never dereferences it — it
/// is forwarded to the base ctor and the resolve step — so only the
/// tail the resolver @ 0x08290f6c/0x08290d7c reads is broken out, from
/// those two functions' field accesses.
#[repr(C)]
pub struct StringViewSpec {
    /// spec +0x00..+0x58 — the generic view fields (class code at
    /// +0x04, flag word at +0x18, the 0x30-byte block at +0x1c) that
    /// the grand-base ctor 0x0826f26c reads.
    pub generic: [u8; 0x58],
    /// spec +0x58 — resource id resolved as `'Str '` when the view's
    /// class code is `'Str '`, as `'StSt'` otherwise.
    pub string_id: u32,
    /// spec +0x5c — resource id resolved through the `'Type'`
    /// (typeface) fourcc.
    pub typeface_id: u32,
    /// spec +0x60 — byte the resolver selects when the view flag
    /// 0x8000000 is clear (chosen byte forwarded to 0x08290d7c).
    pub byte_60: u8,
    /// spec +0x61 — byte selected when the view flag 0x8000000 is set.
    pub byte_61: u8,
    /// spec +0x62..+0x64 — alignment (never read by the resolve path).
    pub padding_after_bytes: [u8; 2],
    /// spec +0x64 — word forwarded verbatim to 0x08290d7c's seventh
    /// slot; role unrecovered.
    pub word_64: u32,
}

/// The constructed view. Pointer-typed members are modelled as `u32`
/// target words or fixed byte arrays so the layout is exact on both the
/// 32-bit target and 64-bit hosts (the `ui/styled_text_view.rs`
/// convention): the constructor only ever stores 0 in the owned words,
/// and the StringObject/timer subobjects are reached through byte
/// offsets so their ported constructors see the target addresses.
#[repr(C)]
pub struct StringView {
    /// +0x00 — vtable, see [`STRING_VIEW_VTABLE_ADDRESS`].
    pub vtable: u32,
    /// +0x04..+0xa4 — the grand-base view subobject, owned by the
    /// 0x0826f26c ctor.
    pub base: [u8; 0xa0],
    /// +0xa4..+0xf8 — the scoped draw-state record (0x54 bytes) that
    /// [`draw_state_construct`] builds.
    pub draw_state: [u8; 0x54],
    /// +0xf8..+0x104 — the three-word resource reference the resolve
    /// step fills in (the `'Str '`/`'StSt'` handle, the `'Type'`
    /// handle, and a third word the resolver also writes). Zero at
    /// construction.
    pub resource_ref: [u32; 3],
    /// +0x104..+0x10c — first StringObject (8 target bytes; reached by
    /// byte offset so [`string_default_construct`] sees the exact
    /// target address on any host).
    pub string_a: [u8; 8],
    /// +0x10c..+0x114 — second StringObject.
    pub string_b: [u8; 8],
    /// +0x114..+0x124 — the four owned pair-header service objects
    /// (target pointers), NULL until the view populates them; the
    /// destructor deletes each through `pair_header_destruct` +
    /// `operator delete`.
    pub owned_headers: [u32; 4],
    /// +0x124..+0x1dc — the 0xb8-byte PairHeaderBase subobject that
    /// [`pair_header_base_construct`] builds.
    pub pair_header_base: [u8; 0xb8],
    /// +0x1dc — word this constructor clears; untouched by the
    /// destructor, purpose unrecovered.
    pub word_1dc: u32,
    /// +0x1e0..+0x1f0 — the 16-byte observer list
    /// ([`ObservableArray`] is all-`u32`, exact on both hosts).
    pub observers: ObservableArray,
    /// +0x1f0 — set to 1 by the resolve step once `resource_ref` is
    /// filled; not written by this constructor.
    pub resources_resolved: u8,
    /// +0x1f1..+0x1f4 — alignment.
    pub padding_after_resolved: [u8; 3],
    /// +0x1f4..+0x220 — the embedded 0x2c-byte timer (the size
    /// `app::view_timer`'s `operator_new(0x2c)` establishes for timer
    /// objects), constructed by `timer_schedule_shim` with the view as
    /// its config word.
    pub timer: [u8; 0x2c],
}

const _: [u8; 0x220] = [0; core::mem::size_of::<StringView>()];
const _: [u8; 0x68] = [0; core::mem::size_of::<StringViewSpec>()];
const _: [u8; 0xa4] = [0; core::mem::offset_of!(StringView, draw_state)];
const _: [u8; 0xf8] = [0; core::mem::offset_of!(StringView, resource_ref)];
const _: [u8; 0x104] = [0; core::mem::offset_of!(StringView, string_a)];
const _: [u8; 0x10c] = [0; core::mem::offset_of!(StringView, string_b)];
const _: [u8; 0x114] = [0; core::mem::offset_of!(StringView, owned_headers)];
const _: [u8; 0x124] = [0; core::mem::offset_of!(StringView, pair_header_base)];
const _: [u8; 0x1dc] = [0; core::mem::offset_of!(StringView, word_1dc)];
const _: [u8; 0x1e0] = [0; core::mem::offset_of!(StringView, observers)];
const _: [u8; 0x1f0] = [0; core::mem::offset_of!(StringView, resources_resolved)];
const _: [u8; 0x1f4] = [0; core::mem::offset_of!(StringView, timer)];

/// Indirect dispatch for the constructor's dependencies.
#[derive(Clone, Copy)]
pub struct StringViewOps {
    /// Base-class constructor @ 0x0826f26c `(view, resources,
    /// controller, parent, spec)`: plants the grand-base vtable,
    /// stores `resources` at view+0x38, copies the class code to
    /// view+0x40 and the flag word to view+0x48, unpacks the generic
    /// spec fields, and returns `view`. Not yet ported.
    pub construct_base: unsafe extern "C" fn(
        view: *mut StringView,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
        spec: *const StringViewSpec,
    ) -> *mut StringView,
    /// Resource-reference clear @ 0x081e170c `(ref)`: three word
    /// stores, `ref[0..3] = 0`, returning its argument. A fully
    /// decoded 12-byte leaf (no literal pool, no callees), so the
    /// default below reproduces it exactly rather than stubbing it.
    pub clear_resource_ref: unsafe extern "C" fn(resource_ref: *mut u32) -> *mut u32,
    /// Ported spec-tail adapter; the third ABI word is ignored, not
    /// forwarded to the seven-argument resource resolver.
    pub resolve_resources: unsafe extern "C" fn(
        view: *mut StringView,
        spec: *const StringViewSpec,
        flags: u32,
    ),
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_base(
    view: *mut StringView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const StringViewSpec,
) -> *mut StringView {
    let construct_base: unsafe extern "C" fn(
        *mut StringView,
        *mut ResourceProvider,
        *mut u8,
        *mut u8,
        *const StringViewSpec,
    ) -> *mut StringView = unsafe { core::mem::transmute(0x0826_f26cusize) };
    unsafe { construct_base(view, resources, controller, parent, spec) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_base(
    _view: *mut StringView,
    _resources: *mut ResourceProvider,
    _controller: *mut u8,
    _parent: *mut u8,
    _spec: *const StringViewSpec,
) -> *mut StringView {
    panic!("string_view_construct requires base view ctor 0x0826f26c")
}

/// Resource lookup/update @ 0x08290d7c. Its first stacked arguments
/// are the two sign-extended spec bytes, followed by the option word.
pub type StringViewResourceResolver = unsafe extern "C" fn(
    *mut StringView, *mut ResourceProvider, u32, u32, i32, i32, u32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resolve_resource_ids(
    view: *mut StringView, resources: *mut ResourceProvider,
    string_id: u32, typeface_id: u32, first: i32, second: i32, options: u32,
) {
    let resolve: StringViewResourceResolver =
        unsafe { core::mem::transmute(0x0829_0d7cusize) };
    unsafe { resolve(view, resources, string_id, typeface_id, first, second, options) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve_resource_ids(
    _view: *mut StringView, _resources: *mut ResourceProvider,
    _string_id: u32, _typeface_id: u32, _first: i32, _second: i32, _options: u32,
) {
    panic!("string_view_resolve_resources requires resource lookup 0x08290d7c")
}

/// Firmware lookup on target; host tests replace it under
/// `STRING_VIEW_OPS_TEST_LOCK`, just like the constructor's dispatch.
#[cfg(target_os = "none")]
pub static mut STRING_VIEW_RESOURCE_RESOLVER: StringViewResourceResolver =
    firmware_resolve_resource_ids;
#[cfg(not(target_os = "none"))]
pub static mut STRING_VIEW_RESOURCE_RESOLVER: StringViewResourceResolver =
    missing_resolve_resource_ids;

/// string_view_resolve_resources — `FUN_08290f6c` @ 0x08290f6c.
/// True size: 80 bytes, next function at 0x08290fbc. Raw-word BL count:
/// one outgoing plain BL to 0x08290d7c; incoming one plain BL at
/// 0x08291c98 and one BLNE at 0x08291634.
///
/// Resolve spec string/typeface IDs with a null resource provider.
/// If view+0x48 bit 27 is clear, pass (0, signed spec+0x60);
/// otherwise pass (signed spec+0x60, signed spec+0x61). Forward
/// spec+0x64 unchanged. The apparent third argument and extra stacked
/// arguments in Ghidra are saved registers, not resolver inputs.
/// Deliberate deviation: call the unported lookup through a replaceable
/// typed seam instead of a fixed BL. Retain the ignored third ABI word
/// for existing constructor callers; it has no observable effect.
///
/// # Safety
/// `view` and `spec` must be aligned readable objects and accepted by
/// the installed resolver, which may mutate the view.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_view_resolve_resources(
    view: *mut StringView, spec: *const StringViewSpec, _flags: u32,
) {
    let flags = unsafe { view.cast::<u32>().add(0x48 / 4).read() };
    let byte_60 = unsafe { core::ptr::addr_of!((*spec).byte_60).read() } as i8 as i32;
    let (first, second) = if flags & 0x0800_0000 != 0 {
        (byte_60, unsafe { core::ptr::addr_of!((*spec).byte_61).read() } as i8 as i32)
    } else {
        (0, byte_60)
    };
    let resolve = unsafe {
        core::ptr::addr_of!(STRING_VIEW_RESOURCE_RESOLVER).read_volatile()
    };
    unsafe {
        resolve(view, core::ptr::null_mut(), (*spec).string_id,
            (*spec).typeface_id, first, second, (*spec).word_64);
    }
}

/// Wired defaults (the `event_list.rs` split: firmware addresses on
/// target, panics on host — except the fully decoded
/// [`resource_ref_clear`]).
pub const DEFAULT_STRING_VIEW_OPS: StringViewOps = StringViewOps {
    #[cfg(target_os = "none")]
    construct_base: firmware_construct_base,
    #[cfg(not(target_os = "none"))]
    construct_base: missing_construct_base,
    clear_resource_ref: resource_ref_clear,
    resolve_resources: string_view_resolve_resources,
};

/// The active dispatch table. Written once at init on target; host
/// tests swap in recorders and restore the defaults.
pub static mut STRING_VIEW_OPS: StringViewOps = DEFAULT_STRING_VIEW_OPS;

/// string_view_construct — original: `FUN_08291c24` @ 0x08291c24
/// (148 bytes of code, ending in `ldmia sp!, {r3, r4, r5, pc}` @
/// 0x08291cb4, plus the 4-byte vtable literal @ 0x08291cb8 =
/// 0x089a7178; the next function — the deleting destructor @
/// 0x08291cbc — starts immediately after, so the extent is exact.
/// 32 `bl` call sites and no predicated or tail form, verified by
/// decoding every B/BL word in osos.dec; one site is the `new` wrapper
/// @ 0x082907a4 which allocates the 0x220 bytes and forwards all four
/// register arguments with the spec stacked).
///
/// Chains the grand-base view ctor with the caller's five arguments
/// unchanged (the original re-stores the stacked spec into its own
/// outgoing argument slot), plants the class vtable, then builds every
/// embedded member in address order: draw state at +0xa4, the cleared
/// resource reference at +0xf8, the two StringObjects at +0x104/+0x10c,
/// the four NULL owned-pointer words at +0x114..+0x120, the
/// PairHeaderBase at +0x124, the cleared word at +0x1dc and the
/// observable array at +0x1e0. It then resolves the spec tail into the
/// resource reference (0x08290f6c, flags 0), constructs the embedded
/// timer at +0x1f4 with the view itself as the config word
/// (`timer_schedule_shim(view, view+0x1f4, 0, 0)`), and returns `view`.
///
/// Deliberate deviations:
///
/// - Ghidra types this `int FUN_08291c24(void)`; the assembly takes
///   four register arguments plus the stacked spec (forwarded to the
///   base ctor and used again for the resolve) and the closing
///   `sub r4, r0, #0x1e0` / `mov r0, r4` leaves `view` in r0 across
///   the return, so the port takes the five arguments and returns
///   `view` (the `styled_text_view_construct` precedent).
/// - Every callee returns its argument, so the original threads r0
///   through the chain and recovers `view` by byte arithmetic
///   (`sub r0, r0, #0x10c` after the second string, `sub r0, r0,
///   #0x124`, `sub r4, r0, #0x1e0`). The port keeps `view` in hand and
///   addresses members through `addr_of_mut!` — the same dataflow, but
///   correct on a 64-bit host where the struct is wider than the
///   target's 0x220 bytes in pointer-typed members
///   (`heap::pool_client::pool_parent_construct` precedent).
/// - The original relies on the StringObject ctor's two target-width
///   stores; the ported `string_default_construct` writes two
///   host-width pointers, so in 64-bit host tests each string's
///   payload store overlaps the following member and is overwritten by
///   the later construction steps — string_b's vtable store lands
///   where string_a's payload was, and string_b's payload store is
///   covered by the +0x114 owned-word clears that follow it in both
///   the original and the port. The final state is identical on the
///   target and deterministic on the host; only the intermediate
///   +0x108/+0x110 words differ (host pointer high halves vs target
///   NULL payloads).
/// - The vtable is the `u32` ROM address
///   [`STRING_VIEW_VTABLE_ADDRESS`] rather than a modeled static:
///   nothing here dispatches through it, and the image's data at that
///   address is stale (see the constant's docs).
/// - The 0x081e170c resource-reference clear rides the ops seam through
///   [`resource_ref_clear`]; the leaf is fully decoded, so there is
///   nothing to stub.
///
/// # Safety
/// `view` must point at a writable, 4-byte-aligned [`StringView`],
/// `spec` at a readable [`StringViewSpec`], and the installed
/// [`STRING_VIEW_OPS`] and `drivers::timer::TIMER_OPS` must accept
/// them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_view_construct(
    view: *mut StringView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const StringViewSpec,
) -> *mut StringView {
    // Read each slot directly rather than the whole table (the
    // timer_schedule_shim sibcall gotcha).
    let construct_base = core::ptr::addr_of!(STRING_VIEW_OPS.construct_base).read_volatile();
    let clear_resource_ref =
        core::ptr::addr_of!(STRING_VIEW_OPS.clear_resource_ref).read_volatile();
    let resolve_resources =
        core::ptr::addr_of!(STRING_VIEW_OPS.resolve_resources).read_volatile();

    construct_base(view, resources, controller, parent, spec);
    core::ptr::addr_of_mut!((*view).vtable).write_volatile(STRING_VIEW_VTABLE_ADDRESS);
    draw_state_construct(core::ptr::addr_of_mut!((*view).draw_state).cast());
    clear_resource_ref(core::ptr::addr_of_mut!((*view).resource_ref).cast());
    string_default_construct(core::ptr::addr_of_mut!((*view).string_a).cast());
    string_default_construct(core::ptr::addr_of_mut!((*view).string_b).cast());
    for owned in 0..4 {
        core::ptr::addr_of_mut!((*view).owned_headers[owned]).write_volatile(0);
    }
    pair_header_base_construct(core::ptr::addr_of_mut!((*view).pair_header_base).cast());
    core::ptr::addr_of_mut!((*view).word_1dc).write_volatile(0);
    observable_array_construct(core::ptr::addr_of_mut!((*view).observers));
    resolve_resources(view, spec, 0);
    timer_schedule_shim(
        view as usize as u32,
        core::ptr::addr_of_mut!((*view).timer).cast(),
        0,
        0,
    );
    view
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use crate::drivers::timer::{TimerOps, TIMER_OPS};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, STRING_VIEW_OPS_TEST_LOCK,
        TIMER_OPS_TEST_LOCK,
    };
    use core::ptr;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// PairHeaderBase's vtable literal (the private
    /// `PAIR_HEADER_BASE_VTABLE` in `cxx/pair_header.rs`, = the image
    /// word its constructor plants at the subobject's +0x00).
    const PAIR_HEADER_BASE_VTABLE: u32 = 0x0898_1630;

    const SLAB_LEN: usize = 0x1000;
    // The view sits at slab+4, not slab: the ported
    // `string_default_construct` writes two host-width pointers per
    // StringObject and aborts on a misaligned dereference unless
    // view+0x104/+0x10c are 8-aligned. Every member of `StringView`
    // is `u32`/`u8`, so the +4 shift costs nothing else.
    const VIEW_OFFSET: usize = 4;
    const SPEC_OFFSET: usize = 0x400;
    const RESOURCES_OFFSET: usize = 0x600;
    const CONTROLLER_OFFSET: usize = 0x680;
    const PARENT_OFFSET: usize = 0x700;


    struct Fixture {
        view: *mut StringView,
        spec: *const StringViewSpec,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
    }

    fn fixture() -> Option<Fixture> {
        let base = try_map_u32_slab(hints::STRING_VIEW, SLAB_LEN)?;
        unsafe { base.write_bytes(0, SLAB_LEN) };
        Some(Fixture {
            view: unsafe { base.add(VIEW_OFFSET) }.cast::<StringView>(),
            spec: unsafe { base.add(SPEC_OFFSET) }.cast::<StringViewSpec>(),
            resources: unsafe { base.add(RESOURCES_OFFSET) }.cast::<ResourceProvider>(),
            controller: unsafe { base.add(CONTROLLER_OFFSET) },
            parent: unsafe { base.add(PARENT_OFFSET) },
        })
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        ConstructBase(usize, usize, usize, usize, usize),
        ClearResourceRef(usize),
        ResolveResources(usize, usize, u32),
        ConstructTimer(usize, u32, u32, usize),
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    fn record(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }

    fn events() -> Vec<Event> {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    unsafe extern "C" fn recording_construct_base(
        view: *mut StringView,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
        spec: *const StringViewSpec,
    ) -> *mut StringView {
        record(Event::ConstructBase(
            view as usize,
            resources as usize,
            controller as usize,
            parent as usize,
            spec as usize,
        ));
        view
    }

    unsafe extern "C" fn recording_clear_resource_ref(resource_ref: *mut u32) -> *mut u32 {
        record(Event::ClearResourceRef(resource_ref as usize));
        resource_ref_clear(resource_ref)
    }

    unsafe extern "C" fn recording_resolve_resources(
        view: *mut StringView,
        spec: *const StringViewSpec,
        flags: u32,
    ) {
        record(Event::ResolveResources(view as usize, spec as usize, flags));
    }

    unsafe extern "C" fn recording_construct_timer(
        timer: *mut u8,
        init_arg: u32,
        config_word: u32,
        callback_handle: usize,
    ) {
        record(Event::ConstructTimer(
            timer as usize,
            init_arg,
            config_word,
            callback_handle,
        ));
    }

    /// Restores both shared seams while their locks are held.
    struct OpsRestore {
        string_view_ops: StringViewOps,
        timer_ops: TimerOps,
    }

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STRING_VIEW_OPS).write_volatile(self.string_view_ops);
                ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.timer_ops);
            }
        }
    }

    unsafe fn install_recording_ops() -> OpsRestore {
        let string_view_ops = unsafe { ptr::addr_of!(STRING_VIEW_OPS).read_volatile() };
        let timer_ops = unsafe { ptr::addr_of!(TIMER_OPS).read_volatile() };
        let mut recorded_timer_ops = timer_ops;
        recorded_timer_ops.construct_timer = recording_construct_timer;
        unsafe {
            ptr::addr_of_mut!(STRING_VIEW_OPS).write_volatile(StringViewOps {
                construct_base: recording_construct_base,
                clear_resource_ref: recording_clear_resource_ref,
                resolve_resources: recording_resolve_resources,
            });
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer_ops);
        }
        OpsRestore {
            string_view_ops,
            timer_ops,
        }
    }

    fn word(view: *mut StringView, byte_offset: usize) -> u32 {
        unsafe { (view.cast::<u8>().add(byte_offset) as *const u32).read_unaligned() }
    }

    #[test]
    fn constructs_members_in_address_order_and_returns_view() {
        let _string_view_lock = STRING_VIEW_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("ui::string_view"));
            return;
        };
        let _restore = unsafe { install_recording_ops() };
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();

        let result = unsafe {
            string_view_construct(
                fixture.view,
                fixture.resources,
                fixture.controller,
                fixture.parent,
                fixture.spec,
            )
        };

        assert_eq!(result, fixture.view, "the constructor returns view");

        let view = fixture.view as usize;
        assert_eq!(
            events(),
            std::vec![
                Event::ConstructBase(
                    view,
                    fixture.resources as usize,
                    fixture.controller as usize,
                    fixture.parent as usize,
                    fixture.spec as usize,
                ),
                Event::ClearResourceRef(view + 0xf8),
                Event::ResolveResources(view, fixture.spec as usize, 0),
                Event::ConstructTimer(view + 0x1f4, 0, view as u32, 0),
            ],
            "base first, resolve after all members, timer last with the \
             view as its config word",
        );

        // The class vtable replaces whatever the base ctor planted.
        assert_eq!(word(fixture.view, 0x00), STRING_VIEW_VTABLE_ADDRESS);

        // The resource reference is cleared before the resolve step.
        assert_eq!(word(fixture.view, 0xf8), 0);
        assert_eq!(word(fixture.view, 0xfc), 0);
        assert_eq!(word(fixture.view, 0x100), 0);

        // Both StringObjects are constructed: each holds the class
        // vtable pointer in its first (host-width) word.
        unsafe {
            assert_eq!(
                (fixture.view.cast::<u8>().add(0x104) as *const usize).read(),
                &STRING_OBJECT_VTABLE as *const _ as usize,
                "string_a vtable",
            );
            assert_eq!(
                (fixture.view.cast::<u8>().add(0x10c) as *const usize).read(),
                &STRING_OBJECT_VTABLE as *const _ as usize,
                "string_b vtable",
            );
        }

        // The four owned pointers, the +0x1dc word and the observer
        // list are born empty.
        for offset in [0x114usize, 0x118, 0x11c, 0x120, 0x1dc] {
            assert_eq!(word(fixture.view, offset), 0, "born-NULL at +{offset:#x}");
        }
        unsafe {
            let observers = ptr::addr_of!((*fixture.view).observers);
            assert_eq!(
                ptr::addr_of!((*observers).base.vtable).read(),
                OBSERVABLE_ARRAY_VTABLE
            );
            assert_eq!(ptr::addr_of!((*observers).len).read(), 0);
            assert_eq!(ptr::addr_of!((*observers).storage).read(), 0);
        }

        // The PairHeaderBase chain planted its vtable at +0x124.
        assert_eq!(word(fixture.view, 0x124), PAIR_HEADER_BASE_VTABLE);
    }

    #[test]
    fn resource_ref_clear_is_the_stock_leaf() {
        // The 0x081e170c port is behaviour-identical to the stock leaf:
        // three word clears, returns its argument.
        let mut buffer = [0xdead_beefu32; 4];
        let returned = unsafe { resource_ref_clear(buffer.as_mut_ptr()) };
        assert_eq!(returned, buffer.as_mut_ptr());
        assert_eq!(buffer, [0, 0, 0, 0xdead_beef]);
    }

}

#[cfg(test)]
mod resolve_spec_tests {
    use super::*;
    use core::ptr;

    unsafe extern "C" fn apply_selected_bytes(
        view: *mut StringView, resources: *mut ResourceProvider,
        _string_id: u32, _typeface_id: u32, first: i32, second: i32, _options: u32,
    ) {
        assert!(resources.is_null());
        // The real lookup stores these at view+0xea/+0xeb. Record the
        // full values as well so loss of ARM LDRSB sign extension fails.
        (*view).resource_ref = [first as u32, second as u32, 0];
        view.cast::<u8>().add(0xea).write(first as u8);
        view.cast::<u8>().add(0xeb).write(second as u8);
    }

    struct Restore(StringViewResourceResolver);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(STRING_VIEW_RESOURCE_RESOLVER).write_volatile(self.0) }
        }
    }

    #[test]
    fn selects_signed_bytes_by_only_bit_27() {
        let _lock = crate::testing::STRING_VIEW_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(ptr::addr_of!(STRING_VIEW_RESOURCE_RESOLVER).read_volatile());
            ptr::addr_of_mut!(STRING_VIEW_RESOURCE_RESOLVER).write_volatile(apply_selected_bytes);
            let mut view: StringView = core::mem::zeroed();
            let mut spec: StringViewSpec = core::mem::zeroed();
            for flags in [0, 0xf7ff_ffff, 0x0800_0000, u32::MAX] {
                ptr::addr_of_mut!(view).cast::<u32>().add(0x48 / 4).write(flags);
                for a in [0u8, 127, 128, 255] {
                    for b in [0u8, 127, 128, 255] {
                        spec.byte_60 = a;
                        spec.byte_61 = b;
                        string_view_resolve_resources(&mut view, &spec, 0xdead_beef);
                        let expected = if flags & 0x0800_0000 == 0 {
                            [0, a as i8 as i32]
                        } else {
                            [a as i8 as i32, b as i8 as i32]
                        };
                        assert_eq!(&view.resource_ref[..2],
                            &[expected[0] as u32, expected[1] as u32]);
                        assert_eq!(ptr::addr_of!(view).cast::<u8>().add(0xea).read(),
                            expected[0] as u8);
                        assert_eq!(ptr::addr_of!(view).cast::<u8>().add(0xeb).read(),
                            expected[1] as u8);
                    }
                }
            }
        }
    }
}
