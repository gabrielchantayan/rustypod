//! The constructor of the styled-text view widget — the retailOS screen
//! element that draws one line of text in a resource-selected style,
//! optionally over a graphic named by its spec (109 `bl` call sites).
//!
//! # What the class is
//!
//! Views in this firmware are built from a **104-byte spec** that the
//! screen builder copies out of ROM onto its stack, patches, and hands
//! to a widget constructor. The generic part of the spec belongs to the
//! grand-base view ctor @ 0x0826f26c, which reads spec +0x04 (a
//! four-char class code, kept at view +0x40), +0x08, +0x10, +0x18 (the
//! view flag word, kept at view +0x48), the 0x30-byte block at +0x1c
//! and +0x58. This class owns the **tail**, spec +0x5c..+0x68, and
//! copies it verbatim into view +0x224..+0x230.
//!
//! Those four fields are exactly what the rest of the class does:
//!
//! - The draw path @ 0x0819b80c builds the row's string, then picks
//!   **`text_style`** or **`text_style_alt`** according to bit 3 of the
//!   view flag word at +0x48, applies it with 0x08262d70, and — when
//!   the chosen style code is 0x21 — passes `&view.text_color` to
//!   0x0826319c. It then fits the text by looping 0x0826c574 /
//!   0x082a2340 until it stops overflowing (the ellipsis loop).
//! - The lazy resolve @ 0x0819b724 turns **`graphic_id`** into the
//!   0x44-byte drawable cached at **`graphic`** (+0x220), guarded by
//!   the **`graphic_resolved`** byte (+0x164). It looks the id up
//!   through [`resource_chain_find`] on the provider the object keeps
//!   at +0x38: `'Draw'` first when the view's class code is `'Draw'`,
//!   `'BMap'` when it is `'BMap'` or when the `'Draw'` lookup missed
//!   (the four-char codes are the literal-pool words @ 0x0819b7d0 =
//!   0x424d6170 and 0x0819b7d4 = 0x44726177, binary-verified). The
//!   drawable is then handed to the same 0x08262bdc text blitter the
//!   base's own drawable at +0x15c would have served.
//!
//! # Layout (560 bytes, the `operator_new(0x230)` at every call site)
//!
//! ```text
//! +0x000  vtable                (ROM literal 0x0898a764)
//! +0x004  base subobject        ctor 0x0810b29c -> 0x0826f26c -> 0x08103a4c
//! +0x164  graphic_resolved: u8
//! +0x168  graphic_attributes    second instance of the 0xb8-byte class the
//!                               base itself embeds at +0xa4 (ctor 0x0810ebbc)
//! +0x220  graphic: u32          0x44-byte drawable, NULL until resolved
//! +0x224  text_style: u8
//! +0x225  text_style_alt: u8
//! +0x228  graphic_id: u32
//! +0x22c  text_color: [u8; 4]
//! ```
//!
//! The destructor @ 0x0819ba64 confirms the ownership: it deletes
//! `graphic` (dtor 0x082646ac then `operator delete` @ 0x082aad24) when
//! it is non-NULL, runs 0x0810ec10 on the +0x168 subobject and chains
//! to the base dtor @ 0x0810b2f0.

use crate::app::resource_chain::ResourceProvider;

/// The ROM address of this class's vtable (the literal-pool word @
/// 0x0819ba48, binary-verified; the destructor @ 0x0819ba64 re-plants
/// the same value from its own literal @ 0x0819ba9c).
///
/// It is stored as the `u32` the original stores. The 0x089xxxxx data
/// the image carries at that address is stale RW init data — the same
/// finding `heap/pool_client.rs` records for its vtable literals — so
/// there are no slots to model, and nothing in this constructor
/// dispatches through it.
pub const STYLED_TEXT_VIEW_VTABLE_ADDRESS: u32 = 0x0898_a764;

/// The 104-byte view spec. Only the tail belongs to this class; the
/// prefix is the grand-base view ctor's business and is passed through
/// untouched.
#[repr(C)]
pub struct StyledTextSpec {
    /// spec +0x00..+0x5c — the generic view fields (class code, flags,
    /// geometry) that 0x0826f26c reads.
    pub generic: [u8; 0x5c],
    /// spec +0x5c — style code used when view flag bit 3 is clear.
    pub text_style: u8,
    /// spec +0x5d — style code used when view flag bit 3 is set.
    pub text_style_alt: u8,
    /// spec +0x5e — never read by the constructor (the fields on either
    /// side are a byte pair and a word, so these two bytes are the
    /// compiler's alignment padding).
    pub reserved: [u8; 2],
    /// spec +0x60 — `'Draw'`/`'BMap'` resource id of the row graphic,
    /// 0 for a plain text row.
    pub graphic_id: u32,
    /// spec +0x64 — colour applied when the chosen style code is 0x21.
    pub text_color: [u8; 4],
}

/// The constructed view. `graphic` is the target's 4-byte pointer kept
/// as a `u32`: the constructor only ever stores 0 there, and modelling
/// it as a host pointer would move every field behind it.
#[repr(C)]
pub struct StyledTextView {
    /// +0x00 — vtable, see [`STYLED_TEXT_VIEW_VTABLE_ADDRESS`].
    pub vtable: u32,
    /// +0x04..+0x164 — the base subobject, owned by 0x0810b29c.
    pub base: [u8; 0x160],
    /// +0x164 — set once `graphic` has been looked up (whether or not
    /// the lookup found anything).
    pub graphic_resolved: u8,
    /// +0x165..+0x168 — alignment.
    pub padding_after_resolved: [u8; 3],
    /// +0x168..+0x220 — the 0xb8-byte subobject 0x0810ebbc constructs;
    /// the resolve path passes its address to the graphic constructor
    /// @ 0x082645a0 as the drawable's attribute source.
    pub graphic_attributes: [u8; 0xb8],
    /// +0x220 — the resolved 0x44-byte drawable (target pointer).
    pub graphic: u32,
    /// +0x224 — see [`StyledTextSpec::text_style`].
    pub text_style: u8,
    /// +0x225 — see [`StyledTextSpec::text_style_alt`].
    pub text_style_alt: u8,
    /// +0x226..+0x228 — alignment (never written by the constructor).
    pub padding_after_styles: [u8; 2],
    /// +0x228 — see [`StyledTextSpec::graphic_id`].
    pub graphic_id: u32,
    /// +0x22c — see [`StyledTextSpec::text_color`].
    pub text_color: [u8; 4],
}

/// Indirect dispatch for this constructor's two unported callees (the
/// `PairHeaderOps` precedent in `cxx/pair_header.rs`, which models the
/// very same 0x0810ebbc subobject ctor).
#[derive(Clone, Copy)]
pub struct StyledTextViewOps {
    /// Base-class constructor @ 0x0810b29c `(view, resources,
    /// controller, parent, spec)`. Plants its own vtable at view+0xa4,
    /// runs 0x0810ebbc on the subobject there, clears view+0xa1 and
    /// view+0x15c, and chains up to 0x0826f26c (which stores
    /// `resources` at view+0x38 and unpacks the generic spec fields).
    /// Returns `view`. Not yet ported.
    pub construct_base: unsafe extern "C" fn(
        view: *mut StyledTextView,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
        spec: *const StyledTextSpec,
    ) -> *mut StyledTextView,
    /// Subobject constructor @ 0x0810ebbc `(subobject)`: vtable store,
    /// grand-base chain @ 0x0813eee0, 0x94-byte clear and the field
    /// clears through +0xb4. Returns its argument. Not yet ported —
    /// same callee as `cxx::pair_header`'s slot, typed for this
    /// class's subobject.
    pub construct_graphic_attributes: unsafe extern "C" fn(attributes: *mut u8) -> *mut u8,
}

/// Default base ctor: preserves the return-`view` dataflow and touches
/// nothing. On real hardware [`STYLED_TEXT_VIEW_OPS`] must be installed
/// before this port runs.
unsafe extern "C" fn missing_construct_base(
    view: *mut StyledTextView,
    _resources: *mut ResourceProvider,
    _controller: *mut u8,
    _parent: *mut u8,
    _spec: *const StyledTextSpec,
) -> *mut StyledTextView {
    view
}

/// Default subobject ctor: the same documented no-op-but-return-its-
/// argument stub `cxx::pair_header` installs for this callee.
unsafe extern "C" fn missing_construct_graphic_attributes(attributes: *mut u8) -> *mut u8 {
    attributes
}

/// Wired defaults.
pub const DEFAULT_STYLED_TEXT_VIEW_OPS: StyledTextViewOps = StyledTextViewOps {
    construct_base: missing_construct_base,
    construct_graphic_attributes: missing_construct_graphic_attributes,
};

/// The active dispatch table. Written once at init on target; host
/// tests swap in recorders and restore the defaults.
pub static mut STYLED_TEXT_VIEW_OPS: StyledTextViewOps = DEFAULT_STYLED_TEXT_VIEW_OPS;

/// styled_text_view_construct — original: `FUN_0819b9e0` @ 0x0819b9e0
/// (108 bytes: 104 code, ending in `ldmia sp!, {r3, r4, r5, pc}` @
/// 0x0819ba44, plus the 4-byte vtable literal @ 0x0819ba48; 109 `bl`
/// call sites and no `b`, binary-scanned by decoding every B/BL word in
/// osos.dec — 61 of them in the screen builder @ 0x08204714 alone, one
/// in the `new` wrapper @ 0x0819b614 which allocates the 0x230 bytes
/// and forwards all four arguments).
///
/// Runs the base constructor with the caller's five arguments unchanged
/// (the original re-stores the stacked `spec` into its own outgoing
/// argument slot), plants the class vtable, constructs the graphic-
/// attribute subobject at +0x168, then establishes this class's own
/// state: no graphic resolved yet (+0x164 and +0x220 both zero) and the
/// spec's four style/graphic fields copied into +0x224..+0x230.
/// Returns `view`.
///
/// Deliberate deviations:
///
/// - Ghidra types this `void`; the assembly's closing
///   `sub r0, r0, #0x168` leaves `view` in r0 across the return, so the
///   port returns it (the `pool_parent_construct` precedent).
/// - Both callees return their argument, so the port keeps `view` in
///   hand instead of reconstructing it from their return values by byte
///   arithmetic — which would be wrong on a 64-bit host, where the
///   struct is wider than the target's 0x230 bytes. Same reasoning as
///   `heap::pool_client::pool_parent_construct`.
/// - The vtable is the `u32` ROM address
///   [`STYLED_TEXT_VIEW_VTABLE_ADDRESS`] rather than a modeled static:
///   nothing here dispatches through it, and the image's data at that
///   address is stale.
/// - The original copies +0x64..+0x68 as four separate `ldrb`/`strb`
///   pairs (ADS scheduling them into r2/r3/ip/lr); the port copies the
///   4-byte array, and LLVM folds it into one word load/store. Same
///   bytes, but it needs `spec + 0x64` and `view + 0x22c` word-aligned
///   — which they are: both offsets are multiples of 4, the specs are
///   word-aligned stack copies and the views come from
///   `operator_new(0x230)`.
///
/// # Safety
/// `view` must point at a writable, 4-byte-aligned [`StyledTextView`],
/// `spec` at a readable [`StyledTextSpec`], and the installed
/// [`STYLED_TEXT_VIEW_OPS`] must accept them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn styled_text_view_construct(
    view: *mut StyledTextView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const StyledTextSpec,
) -> *mut StyledTextView {
    // Read each slot directly rather than the whole table (the
    // timer_schedule_shim sibcall gotcha).
    let construct_base = core::ptr::addr_of!(STYLED_TEXT_VIEW_OPS.construct_base).read_volatile();
    let construct_graphic_attributes =
        core::ptr::addr_of!(STYLED_TEXT_VIEW_OPS.construct_graphic_attributes).read_volatile();

    construct_base(view, resources, controller, parent, spec);
    core::ptr::addr_of_mut!((*view).vtable).write(STYLED_TEXT_VIEW_VTABLE_ADDRESS);
    construct_graphic_attributes(core::ptr::addr_of_mut!((*view).graphic_attributes).cast());

    core::ptr::addr_of_mut!((*view).graphic_resolved).write(0);
    core::ptr::addr_of_mut!((*view).graphic).write(0);
    core::ptr::addr_of_mut!((*view).text_style).write((*spec).text_style);
    core::ptr::addr_of_mut!((*view).text_style_alt).write((*spec).text_style_alt);
    core::ptr::addr_of_mut!((*view).graphic_id).write((*spec).graphic_id);
    core::ptr::addr_of_mut!((*view).text_color).write((*spec).text_color);
    view
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::mem::{align_of, offset_of, size_of};
    use std::boxed::Box;
    use std::sync::Mutex as StdMutex;

    /// Ops-table swaps are global; serialize the tests.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: StyledTextViewOps) -> Self {
            unsafe { core::ptr::addr_of_mut!(STYLED_TEXT_VIEW_OPS).write_volatile(ops) };
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STYLED_TEXT_VIEW_OPS)
                    .write_volatile(DEFAULT_STYLED_TEXT_VIEW_OPS)
            };
        }
    }

    fn blank_view() -> Box<StyledTextView> {
        // 0xcd everywhere, so every field the constructor writes is
        // visibly written and every field it must not touch is visibly
        // untouched.
        Box::new(unsafe { core::mem::transmute([0xcdu8; size_of::<StyledTextView>()]) })
    }

    fn spec(text_style: u8, text_style_alt: u8, graphic_id: u32, text_color: [u8; 4]) -> StyledTextSpec {
        StyledTextSpec {
            generic: [0x5a; 0x5c],
            text_style,
            text_style_alt,
            reserved: [0xee; 2],
            graphic_id,
            text_color,
        }
    }

    /// The two structs must reproduce the target's byte offsets, which
    /// is the whole reason they are `#[repr(C)]` byte arrays: the spec
    /// is 104 bytes at the `0x68` memcpy call sites and the view is 560
    /// at the `operator_new(0x230)` ones.
    #[test]
    fn layout_matches_the_target() {
        assert_eq!(size_of::<StyledTextSpec>(), 0x68);
        assert_eq!(offset_of!(StyledTextSpec, text_style), 0x5c);
        assert_eq!(offset_of!(StyledTextSpec, text_style_alt), 0x5d);
        assert_eq!(offset_of!(StyledTextSpec, graphic_id), 0x60);
        assert_eq!(offset_of!(StyledTextSpec, text_color), 0x64);

        assert_eq!(size_of::<StyledTextView>(), 0x230);
        assert_eq!(align_of::<StyledTextView>(), 4);
        assert_eq!(offset_of!(StyledTextView, vtable), 0x000);
        assert_eq!(offset_of!(StyledTextView, graphic_resolved), 0x164);
        assert_eq!(offset_of!(StyledTextView, graphic_attributes), 0x168);
        assert_eq!(offset_of!(StyledTextView, graphic), 0x220);
        assert_eq!(offset_of!(StyledTextView, text_style), 0x224);
        assert_eq!(offset_of!(StyledTextView, text_style_alt), 0x225);
        assert_eq!(offset_of!(StyledTextView, graphic_id), 0x228);
        assert_eq!(offset_of!(StyledTextView, text_color), 0x22c);
    }

    #[test]
    fn plants_vtable_clears_graphic_state_and_copies_the_spec_tail() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(DEFAULT_STYLED_TEXT_VIEW_OPS);

        let mut view = blank_view();
        let spec = spec(0x21, 0x20, 0x1234_5678, [0x11, 0x22, 0x33, 0x44]);
        let this = &mut *view as *mut StyledTextView;
        let ret = unsafe {
            styled_text_view_construct(
                this,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &spec,
            )
        };

        assert_eq!(ret, this);
        assert_eq!(view.vtable, STYLED_TEXT_VIEW_VTABLE_ADDRESS);
        assert_eq!(view.graphic_resolved, 0);
        assert_eq!(view.graphic, 0);
        assert_eq!(view.text_style, 0x21);
        assert_eq!(view.text_style_alt, 0x20);
        assert_eq!(view.graphic_id, 0x1234_5678);
        assert_eq!(view.text_color, [0x11, 0x22, 0x33, 0x44]);

        // The base subobject and the graphic attributes belong to the
        // callees; the stubs left them alone and so did this port.
        assert!(view.base.iter().all(|&b| b == 0xcd));
        assert!(view.graphic_attributes.iter().all(|&b| b == 0xcd));
        // The padding bytes the original never writes stay untouched.
        assert_eq!(view.padding_after_resolved, [0xcd; 3]);
        assert_eq!(view.padding_after_styles, [0xcd; 2]);
    }

    /// A spec with no graphic still clears +0x164/+0x220 — the resolve
    /// path's `graphic_id == 0` early-out depends on the copied zero,
    /// not on a separate flag.
    #[test]
    fn plain_text_row_copies_a_zero_graphic_id() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(DEFAULT_STYLED_TEXT_VIEW_OPS);

        let mut view = blank_view();
        let spec = spec(0, 0, 0, [0; 4]);
        unsafe {
            styled_text_view_construct(
                &mut *view,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &spec,
            )
        };
        assert_eq!(view.graphic_id, 0);
        assert_eq!(view.graphic, 0);
        assert_eq!(view.graphic_resolved, 0);
    }

    /// The base ctor sees all five arguments unchanged, and the
    /// subobject ctor sees `view + 0x168`. Both run before the derived
    /// fields land, so a base ctor that writes the tail is overwritten
    /// — which is what makes the copy the class's own state.
    #[test]
    fn callees_receive_the_original_arguments_and_run_first() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut SEEN: [usize; 6] = [0; 6];

        unsafe extern "C" fn recording_base(
            view: *mut StyledTextView,
            resources: *mut ResourceProvider,
            controller: *mut u8,
            parent: *mut u8,
            spec: *const StyledTextSpec,
        ) -> *mut StyledTextView {
            let seen = core::ptr::addr_of_mut!(SEEN);
            (*seen)[0] = view as usize;
            (*seen)[1] = resources as usize;
            (*seen)[2] = controller as usize;
            (*seen)[3] = parent as usize;
            (*seen)[4] = spec as usize;
            // Scribble on the derived tail: the port must overwrite it.
            core::ptr::addr_of_mut!((*view).text_style).write(0xff);
            core::ptr::addr_of_mut!((*view).graphic).write(0xdead_beef);
            view
        }

        unsafe extern "C" fn recording_attributes(attributes: *mut u8) -> *mut u8 {
            (*core::ptr::addr_of_mut!(SEEN))[5] = attributes as usize;
            attributes
        }

        let _guard = OpsGuard::install(StyledTextViewOps {
            construct_base: recording_base,
            construct_graphic_attributes: recording_attributes,
        });

        let mut view = blank_view();
        let spec = spec(7, 8, 9, [1, 2, 3, 4]);
        let this = &mut *view as *mut StyledTextView;
        let resources = 0x1234usize as *mut ResourceProvider;
        let controller = 0x5678usize as *mut u8;
        let parent = 0x9abcusize as *mut u8;
        unsafe { styled_text_view_construct(this, resources, controller, parent, &spec) };

        let seen = unsafe { core::ptr::addr_of!(SEEN).read() };
        assert_eq!(seen[0], this as usize);
        assert_eq!(seen[1], resources as usize);
        assert_eq!(seen[2], controller as usize);
        assert_eq!(seen[3], parent as usize);
        assert_eq!(seen[4], &spec as *const _ as usize);
        assert_eq!(seen[5], this as usize + 0x168);

        // The derived fields won over the base ctor's scribbles.
        assert_eq!(view.text_style, 7);
        assert_eq!(view.graphic, 0);
    }
}
