//! `draw_state_construct` — original: `FUN_0826467c` @ 0x0826467c
//! (44 bytes of code, 0x0826467c..0x082646a8, plus the 4-byte literal
//! pool word @ 0x082646a8; 50 `bl` call sites, 0 `b`, binary-scanned).
//!
//! The constructor of retailOS's scoped **draw-state record** — a
//! 0x44-byte, trivially destructible value object every drawing call
//! builds on its stack, fills in, hands to a draw routine, and destroys
//! at scope exit. The class is unidentified; the name is evidence-based
//! (the pair_header.rs precedent):
//!
//! - The record is constructed on the caller's stack
//!   (`add r0, sp, #N; bl 0x0826467c`), consumed by the draw-setup
//!   routines 0x0826e250 / 0x0826eb5c, and destroyed by the shared
//!   empty destructor `trivial_destructor` @ 0x082646ac — the module
//!   sibling — at scope exit (e.g. 0x0810245c..0x081024ec, the exact
//!   stack-temporary shape that module documents). The stack frames
//!   size it: at 0x0810242c the record sits at sp+0x30 inside a 0x74
//!   frame, 0x30 + 0x44 = 0x74.
//! - Its consumers establish the layout: 0x0826e250 stores a bitmap
//!   surface (the render context's +0x5c surface word) at +0x1c and a
//!   clip rect at +0x34 through the setter 0x08264550; the style-byte
//!   setter 0x08262d70 writes +0x10; the draw call 0x08262bdc offsets
//!   two rects by the record's +0x2c/+0x30 origin and invokes the
//!   text/layout draw engine 0x080f1600 with the surface pointers
//!   `*(this+0x1c) + 4`, the two colors at +0x11/+0x15, the style byte
//!   at +0x10 and the clip rect at +0x34.
//!
//! Decoded from the raw ARM at 0x0826467c:
//!
//! ```text
//! push {r4, lr}
//! add  r0, r0, #0x20
//! bl   0x081598a4        ; embedded_pair_construct(this + 0x20)
//! sub  r4, r0, #0x20     ; this = return - 0x20 (container-of)
//! mov  r0, r4
//! bl   0x082630f0        ; body_init(this)
//! ldr  r1, [0x82646a8]   ; = 0x08a77c3c, the default draw-target surface
//! mov  r0, r4
//! bl   0x08264518        ; surface_attach(this, surface)
//! mov  r0, r4            ; return this
//! pop  {r4, pc}
//! ```
//!
//! The constructor chains three member initializers:
//!
//! - `embedded_pair_construct` @ 0x081598a4 (12 bytes, fully decoded:
//!   `mov r1,#0; str r1,[r0]; str r1,[r0,#4]; bx lr`) zeroes the
//!   embedded two-word member at +0x20/+0x24 and returns its argument
//!   in r0 — which is exactly why the parent recovers `this` by
//!   subtracting 0x20 from the callee's return rather than keeping its
//!   own r0. The port reproduces that dataflow (the
//!   string_id_record.rs return-minus-one-word precedent): the member
//!   constructor's return minus 0x20 is what the later initializers and
//!   the return value use.
//! - `body_init` @ 0x082630f0 fills the 0x44-byte body: +0x00/+0x04 =
//!   0, +0x08/+0x0c = 1, style byte +0x10 and the first color = 0, the
//!   second color = five 0xff bytes at +0x14..+0x18, +0x1c = 0, the
//!   +0x20/+0x24 pair re-copied from a global word pair, and
//!   +0x28..+0x43 = 0.
//! - `surface_attach` @ 0x08264518 stores the draw-target surface
//!   pointer at +0x1c and copies the surface's +0x98 rect — translated
//!   to the origin by the ported `rect_move_to_origin` @ 0x0826c2e8 —
//!   into +0x34..+0x40. The surface argument is this constructor's
//!   literal-pool constant, the default-target descriptor @ 0x08a77c3c
//!   (binary-verified from osos.dec).
//!
//! Deviations: all three callees are unported, so they ride the
//! [`DRAW_STATE_CONSTRUCT_OPS`] dispatch slots (the settings.rs
//! `SETTINGS_CTOR` pattern). The `embedded_pair_construct` default is
//! faithful — the callee is 12 bytes and fully decoded. The `body_init`
//! default is a documented zeroing stub (the real constant pattern is
//! the callee's to write, not this caller's) and the `surface_attach`
//! default stores only the surface identity at +0x1c, skipping the rect
//! copy, which needs the firmware global's +0x98 contents a host cannot
//! read; on a 64-bit host that store is a pointer-sized word (the
//! pfr_face_done face-word model). **Not hook-ready** until the two
//! larger callees are ported and wired in as defaults: with the stubs,
//! the record carries zeroed flags/colors and no clip rect. There is no
//! NULL guard on `this`, matching the original's unconditional
//! `add r0, r0, #0x20`.

/// Byte size of the draw-state record (the +0x40 word is the highest
/// field `body_init` writes; call-site stack frames confirm — see the
/// module header).
pub const DRAW_STATE_SIZE: usize = 0x44;

/// Byte offset of the embedded two-word member the constructor
/// zero-initializes first (`add r0, r0, #0x20` / `sub r4, r0, #0x20`).
pub const DRAW_STATE_EMBEDDED_PAIR_OFFSET: usize = 0x20;

/// Byte offset of the draw-target surface pointer (`surface_attach`'s
/// store; the setter 0x08264550 writes the same offset).
pub const DRAW_STATE_SURFACE_OFFSET: usize = 0x1c;

/// The default draw-target surface descriptor: the literal-pool word @
/// 0x082646a8 holds 0x08a77c3c (binary-verified against osos.dec). An
/// address identity, not host-callable — the descriptor lives in the
/// firmware's RW data region and carries the default clip rect at its
/// own +0x98.
pub const DRAW_STATE_DEFAULT_SURFACE_ADDRESS: usize = 0x08a77c3c;

/// Faithful default for the fully decoded embedded pair constructor @
/// 0x081598a4: zero the two words, return the argument. Pointer-sized
/// words on host (the pfr_face_done face-word model).
unsafe extern "C" fn embedded_pair_construct_stub(member: *mut u8) -> *mut u8 {
    (member as *mut usize).write(0);
    (member as *mut usize).add(1).write(0);
    member
}

/// Zeroing stub for the unported body initializer @ 0x082630f0 (the
/// settings.rs `SETTINGS_CTOR` zeroing-stub precedent). Deterministic,
/// but NOT the original's constant pattern — see the module header.
unsafe extern "C" fn body_init_stub(this: *mut u8) {
    core::ptr::write_bytes(this, 0, DRAW_STATE_SIZE);
}

/// Stub for the unported surface attach @ 0x08264518: stores the
/// surface identity at +0x1c (the one effect independent of the
/// firmware global's contents) and skips the origin-moved clip-rect
/// copy a host cannot reproduce.
unsafe extern "C" fn surface_attach_stub(this: *mut u8, surface: usize) {
    (this.add(DRAW_STATE_SURFACE_OFFSET) as *mut usize).write(surface);
}

/// Indirect dispatch for the three member initializers
/// [`draw_state_construct`] chains (the settings.rs `SETTINGS_CTOR`
/// pattern). Host tests install recording mocks; a later port of each
/// callee replaces its default without changing this caller.
#[derive(Clone, Copy)]
pub struct DrawStateConstructOps {
    /// Original 0x081598a4: construct the embedded two-word member at
    /// this+0x20; returns the member pointer, from which the caller
    /// recovers `this`.
    pub embedded_pair_construct: unsafe extern "C" fn(member: *mut u8) -> *mut u8,
    /// Original 0x082630f0: initialize the 0x44-byte record body.
    pub body_init: unsafe extern "C" fn(this: *mut u8),
    /// Original 0x08264518: attach the draw-target surface (store at
    /// +0x1c, copy its +0x98 rect origin-moved into +0x34).
    pub surface_attach: unsafe extern "C" fn(this: *mut u8, surface: usize),
}

/// Wired defaults: the faithful embedded-pair stub and the two
/// documented partial stubs (see the module header).
pub const DEFAULT_DRAW_STATE_CONSTRUCT_OPS: DrawStateConstructOps = DrawStateConstructOps {
    embedded_pair_construct: embedded_pair_construct_stub,
    body_init: body_init_stub,
    surface_attach: surface_attach_stub,
};

/// The active initializer set. Host tests install recording mocks.
pub static mut DRAW_STATE_CONSTRUCT_OPS: DrawStateConstructOps =
    DEFAULT_DRAW_STATE_CONSTRUCT_OPS;

#[inline(always)]
unsafe fn embedded_pair_construct_op() -> unsafe extern "C" fn(*mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        DRAW_STATE_CONSTRUCT_OPS.embedded_pair_construct
    ))
}

#[inline(always)]
unsafe fn body_init_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_CONSTRUCT_OPS.body_init))
}

#[inline(always)]
unsafe fn surface_attach_op() -> unsafe extern "C" fn(*mut u8, usize) {
    core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_CONSTRUCT_OPS.surface_attach))
}

/// draw_state_construct — original: `FUN_0826467c` @ 0x0826467c
/// (44 bytes; 50 `bl` call sites, binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/025/0826467c_FUN_0826467c.c`.
///
/// Constructs the scoped draw-state record at `this`: zero-initializes
/// the embedded two-word member at +0x20, recovers `this` from that
/// constructor's return minus 0x20, initializes the record body, then
/// attaches the default draw-target surface
/// [`DRAW_STATE_DEFAULT_SURFACE_ADDRESS`], and returns `this` — the
/// recovered pointer, not the entry argument. No NULL guard on `this`,
/// matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_construct(this: *mut u8) -> *mut u8 {
    let member = embedded_pair_construct_op()(this.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET));
    let this = member.sub(DRAW_STATE_EMBEDDED_PAIR_OFFSET);
    body_init_op()(this);
    surface_attach_op()(this, DRAW_STATE_DEFAULT_SURFACE_ADDRESS);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the dispatch slots and their recorders.
    static DRAW_STATE_OPS_LOCK: Mutex<()> = Mutex::new(());
    /// The initializer sequence observed by the recording mocks, as
    /// ("pair"/"body"/"surface", this-or-member, surface-or-zero).
    static mut INIT_CALLS: Vec<(&'static str, usize, usize)> = Vec::new();
    /// Canned return for the embedded-pair recorder.
    static mut PAIR_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_pair_construct(member: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(INIT_CALLS)).push(("pair", member as usize, 0));
        core::ptr::read_volatile(core::ptr::addr_of!(PAIR_RESULT))
    }

    unsafe extern "C" fn recording_body_init(this: *mut u8) {
        (*core::ptr::addr_of_mut!(INIT_CALLS)).push(("body", this as usize, 0));
    }

    unsafe extern "C" fn recording_surface_attach(this: *mut u8, surface: usize) {
        (*core::ptr::addr_of_mut!(INIT_CALLS)).push(("surface", this as usize, surface));
    }

    /// Restores the stub boundary even when a test panics.
    struct DrawStateOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DrawStateOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DRAW_STATE_CONSTRUCT_OPS)
                    .write_volatile(DEFAULT_DRAW_STATE_CONSTRUCT_OPS);
            }
        }
    }

    fn draw_state_bench(pair_result: *mut u8) -> DrawStateOpsGuard {
        let lock = DRAW_STATE_OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(INIT_CALLS)).clear();
            core::ptr::addr_of_mut!(PAIR_RESULT).write(pair_result);
            core::ptr::addr_of_mut!(DRAW_STATE_CONSTRUCT_OPS).write_volatile(
                DrawStateConstructOps {
                    embedded_pair_construct: recording_pair_construct,
                    body_init: recording_body_init,
                    surface_attach: recording_surface_attach,
                },
            );
        }
        DrawStateOpsGuard { _lock: lock }
    }

    fn init_calls() -> Vec<(&'static str, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(INIT_CALLS)).clone() }
    }

    #[test]
    fn construct_chains_pair_body_surface_in_order_and_returns_this() {
        let mut record = [0xa5u8; DRAW_STATE_SIZE];
        let this = record.as_mut_ptr();
        let _bench = draw_state_bench(unsafe { this.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) });

        let returned = unsafe { draw_state_construct(this) };

        assert_eq!(returned, this, "the constructor returns this");
        assert_eq!(
            init_calls(),
            std::vec![
                ("pair", unsafe { this.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) } as usize, 0),
                ("body", this as usize, 0),
                ("surface", this as usize, DRAW_STATE_DEFAULT_SURFACE_ADDRESS),
            ],
            "member at this+0x20 first, then body, then the default surface"
        );
        assert_eq!(
            DRAW_STATE_DEFAULT_SURFACE_ADDRESS, 0x08a77c3c,
            "the literal-pool word @ 0x082646a8, binary-verified"
        );
    }

    #[test]
    fn construct_recovers_this_from_the_pair_ctor_return_not_its_argument() {
        // The original keeps only the callee's r0 (`sub r4, r0, #0x20`):
        // a member constructor returning member+8 must shift every later
        // use by the same 8 bytes. This is the string_id_record.rs
        // return-derivation contract.
        let mut record = [0xa5u8; DRAW_STATE_SIZE + 0x10];
        let this = record.as_mut_ptr();
        let shifted = unsafe { this.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET + 8) };
        let _bench = draw_state_bench(shifted);

        let returned = unsafe { draw_state_construct(this) };

        let expected_this = unsafe { shifted.sub(DRAW_STATE_EMBEDDED_PAIR_OFFSET) };
        assert_eq!(returned, expected_this);
        assert_eq!(
            init_calls(),
            std::vec![
                // The member slot always receives entry-this + 0x20; only
                // the RETURN-derived this propagates onward.
                ("pair", unsafe { this.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) } as usize, 0),
                ("body", expected_this as usize, 0),
                ("surface", expected_this as usize, DRAW_STATE_DEFAULT_SURFACE_ADDRESS),
            ],
            "this is the member constructor's return minus 0x20"
        );
    }

    #[test]
    fn default_stubs_zero_the_record_and_store_only_the_surface_identity() {
        // No bench: the wired defaults. The faithful pair stub zeroes
        // +0x20/+0x24, the body stub zeroes the 0x44-byte body, and the
        // surface stub stores the default-surface identity at +0x1c
        // (pointer-sized on host) — and nothing else.
        let mut record = [0xa5u8; DRAW_STATE_SIZE + 0x10];
        let this = record.as_mut_ptr();

        let returned = unsafe { draw_state_construct(this) };

        assert_eq!(returned, this);
        let mut expected = [0u8; DRAW_STATE_SIZE + 0x10];
        let surface_slot = DRAW_STATE_SURFACE_OFFSET;
        expected[surface_slot..surface_slot + core::mem::size_of::<usize>()]
            .copy_from_slice(&DRAW_STATE_DEFAULT_SURFACE_ADDRESS.to_ne_bytes());
        // The guard bytes past the record stay 0xa5.
        expected[DRAW_STATE_SIZE..].copy_from_slice(&[0xa5u8; 0x10]);
        assert_eq!(record, expected);
    }
}
