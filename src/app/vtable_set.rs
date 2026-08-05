//! `vtable_set_50_kind4` — original: `FUN_0811d68c` @ 0x0811d68c (64
//! bytes; **21 `bl` call sites**, grep on `decomp/osos.asm`: the 5-site
//! cluster 0x0811c60c..0x0811c710, 0x0811e8c8, the 3-site cluster
//! 0x081b0094..0x081b0120, 0x081bc700, the 6-site cluster
//! 0x081d1408..0x081d14e4 and the 5-site cluster
//! 0x082713e0..0x08271448).
//!
//! The three-stage guarded property-write dispatcher of the Silver UI
//! framework's kind-4 vtable message family (the same family as
//! `util/vtable_query.rs`'s `vtable_query_4c_kind4`, which routes kind 4
//! through vtable slot +0x4c; this whole block routes through the
//! identical-shaped slot **+0x50** dispatcher `FUN_0811d7fc`):
//!
//! ```text
//! 0811d68c  push {r4, r5, r6, lr}
//! 0811d690  mov  r6, r2               @ save value (arg3)
//! 0811d694  mov  r5, r1               @ save selector (arg2)
//! 0811d698  mov  r4, r0               @ save handle (arg1)
//! 0811d69c  bl   0x0811d458           @ open(handle, selector)
//! 0811d6a0  cmp  r0, #0
//! 0811d6a4  popne {r4, r5, r6, pc}    @ bail with open's error
//! 0811d6a8  mov  r1, r6
//! 0811d6ac  mov  r0, r4
//! 0811d6b0  bl   0x0811d56c           @ write(handle, value)
//! 0811d6b4  cmp  r0, #0
//! 0811d6b8  moveq r1, r5
//! 0811d6bc  moveq r0, r4
//! 0811d6c0  popeq {r4, r5, r6, lr}
//! 0811d6c4  beq   0x0811d340          @ tail: commit(handle, selector)
//! 0811d6c8  pop   {r4, r5, r6, pc}
//! ```
//!
//! Every stage returns an error code (`0` = success); the first nonzero
//! result short-circuits and propagates, exactly as the callers use it
//! (`cmp r0, #0; bne fail` at every call site). The argument routing is
//! the subtle part: **arg2 (r1, the selector) feeds stages 1 and 3**,
//! **arg3 (r2, a pointer to the caller's value word) feeds stage 2** —
//! `r5 = r1` is restored into r1 only for the tail call, `r6 = r2`
//! becomes r1 of the middle call.
//!
//! # The three stages (all unported, modeled by [`VTABLE_SET_50_KIND4_OPS`])
//!
//! - **open** — `FUN_0811d458` @ 0x0811d458 (20 bytes; ported in
//!   this module as [`vtable_set_50_open_kind4`], with the
//!   [`VTABLE_SET_50_KIND4_OPS`] default `vtable_set_open` still
//!   modeling the identical body):
//!   `push {r0, r1, r4, lr}; add r2, sp, #4; mov r1, #4; bl 0x0811d7fc`
//!   sends the **bare selector** by pointer: `dispatch(handle, 4,
//!   &selector)`.
//! - **write** — `FUN_0811d56c` @ 0x0811d56c (64 bytes; ported in
//!   this module as [`vtable_set_50_write_kind4`], with the
//!   [`VTABLE_SET_50_KIND4_OPS`] default `vtable_set_write` still
//!   modeling the identical body): reuses its
//!   `push {r2, r3, ...}` spill slots as a two-word message —
//!   `[sp+4] = 4`, `[sp+0] = *value` — then sends the kind word first
//!   (`dispatch(handle, 4, &4)`) and, only when that returns 0, the
//!   two-word `{*value, 4}` message (`dispatch(handle, 4, sp)`),
//!   returning the last result.
//! - **commit** — `FUN_0811d340` @ 0x0811d340 (32 bytes; ported in
//!   this module as [`vtable_set_50_commit_kind4`], with the
//!   [`VTABLE_SET_50_KIND4_OPS`] default `vtable_set_commit` still
//!   modeling the identical body): `push {r0, r1, r4, lr};
//!   orr [sp+4], #0x80000000; mov r1, #4; bl 0x0811d7fc` sends the
//!   selector with the top bit set: `dispatch(handle, 4,
//!   &(selector | 0x80000000))`.
//!
//! The tag bits are a family convention: the neighbours 0x0811d6ec /
//! 0x0811d6cc are the identical one-dispatch thunks OR-ing the selector
//! with 0x40000000 / 0xc0000000 (callers use 0x0811d6ec as a
//! "supported?" probe before calling this function — e.g. the
//! 0x0811c6f0 probe site in the 0x0811c6f0 → 0x0811c710 write →
//! 0x0811c724 commit-probe sequence), and the sibling
//! 0x0811d64c is the same three-stage shape as this function with the
//! u16/kind-2 write stage 0x0811d52c (`ldrh`) in place of the
//! u32/kind-4 0x0811d56c — i.e. kind encodes the value width. The exact
//! protocol meaning of the tag bits beyond that is not established; the
//! stage names (`open`/`write`/`commit`) describe their position and
//! payload, nothing more. The 0xc0000000 neighbour is ported in this
//! module as [`vtable_set_50_commit_probe_kind4`], the 0x40000000 one
//! (0x0811d6ec) as [`vtable_set_50_probe_kind4`].
//!
//! All three stages bottom out in `FUN_0811d7fc` @ 0x0811d7fc (28
//! bytes; **15 `bl` call sites**, all inside this message-family thunk
//! cluster 0x0811d358..0x0811d890; ported in this module as
//! [`vtable_slot_50_dispatch`]), the slot +0x50 twin of
//! [`vtable_slot_4c_dispatch`] (`FUN_0811d7b0` @ 0x0811d7b0, ported
//! in this module):
//!
//! ```text
//! stmdb sp!, {r3, lr}     @ spill the caller's 4th argument
//! ldr   r0, [r0]          @ object = *handle
//! ldr   r3, [r0]          @ vtable = *object
//! ldr   r12, [r3, #0x50]  @ method = vtable->slot_50
//! mov   r3, sp            @ extra = &spilled_r3
//! blx   r12               @ method(object, kind, data, extra)
//! ldmia sp!, {r12, pc}    @ return the method's r0
//! ```
//!
//! # Deviations
//!
//! - **The three callees are unported** and sit behind the
//!   [`VTABLE_SET_50_KIND4_OPS`] seam (the `app/class_6800.rs`
//!   `CLASS_6800_OPS` pattern, read through `read_volatile`). Unlike
//!   inert stubs, the wired defaults **model each callee's exact body**,
//!   so an unswapped table reproduces the original call chain.
//! - **The slot +0x50 dispatcher 0x0811d7fc is ported** in this module
//!   as [`vtable_slot_50_dispatch`] and stays the wired default of the
//!   [`VTABLE_SLOT_50_DISPATCH`] seam (the `util/vtable_query.rs`
//!   `VTABLE_SLOT_4C_DISPATCH` pattern): its `blx` targets are firmware
//!   vtable methods, so the seam is retained for hookability and the
//!   three siblings keep routing through it — rewiring them to direct
//!   calls is a deliberate follow-up (one function per commit; the
//!   `app/class_6800.rs` precedent calls ported callees directly).
//!   Host tests install a recording mock through the seam, or call the
//!   ported body directly on a fake vtable.
//! - **The caller's r3 is forwarded verbatim to every stage** (none of
//!   the bodies between this function's entry and each dispatcher's
//!   `stmdb sp!, {r3}` spill touches r3), so — the
//!   `vtable_query_4c_kind4` precedent — it is modeled as a fourth
//!   parameter `forwarded` and each dispatch hands the method a pointer
//!   to a stack local holding it. No call site sets r3 deliberately.
//! - **The reference C is not followed where it mis-decompiles**:
//!   `decomp/c/010/0811d68c_FUN_0811d68c.c` inlines the commit thunk as
//!   `FUN_0811d7fc(param_1, 4, &stack0xfffffff4)` (correct shape, but
//!   it hides the `| 0x80000000` tag applied inside 0x0811d340) and
//!   drops the first stage's selector argument and the r3 forwarding
//!   entirely. The port follows the disassembly.

/// Byte offset of the dispatched method inside the object's vtable.
const VTABLE_SLOT_50: usize = 0x50;

/// Byte offset of the queried method inside the object's vtable — the
/// slot [`vtable_slot_4c_dispatch`] (`FUN_0811d7b0` @ 0x0811d7b0)
/// loads; the +0x4c twin of [`VTABLE_SLOT_50`].
const VTABLE_SLOT_4C: usize = 0x4c;

/// The message kind this whole block binds (the value width, 4 bytes —
/// the sibling 0x0811d64c/0x0811d52c pair binds kind 2 for u16 values).
const MESSAGE_KIND_4: u32 = 4;

/// The message kind the kind-2 sibling binds (the value width, 2
/// bytes) — the message word and the SECOND dispatch of
/// [`vtable_set_50_write_kind2`] (0x0811d52c); its first dispatch
/// still goes out with kind 4, exactly like the kind-4 sibling.
const MESSAGE_KIND_2: u32 = 2;

/// The top-bit tag the commit stage (0x0811d340) ORs into the selector.
const COMMIT_TAG: u32 = 0x8000_0000;

/// The "supported?" probe tag [`vtable_set_50_probe_kind4`]
/// (0x0811d6ec) ORs into the selector.
const PROBE_TAG: u32 = 0x4000_0000;

/// The both-high-bits tag [`vtable_set_50_commit_probe_kind4`]
/// (0x0811d6cc) ORs into the selector: [`COMMIT_TAG`] plus the
/// 0x40000000 tag of the "supported?" probe thunk
/// [`vtable_set_50_probe_kind4`] (0x0811d6ec).
const COMMIT_PROBE_TAG: u32 = 0xc000_0000;

/// The vtable method signature at slot +0x50: `method(object, kind,
/// data, extra)`, returning an error code (0 = success). `data` is a
/// pointer to the message word(s); `extra` points at the dispatcher's
/// spilled r3 (see [`vtable_slot_50_dispatch`]).
type VtableSlot50Method =
    unsafe extern "C" fn(object: *mut u8, kind: u32, data: usize, extra: *const usize) -> u32;

/// The vtable method signature at slot +0x4c: identical in shape to
/// [`VtableSlot50Method`] — `method(object, kind, data, extra)`,
/// returning an error code (0 = success); see
/// [`vtable_slot_4c_dispatch`].
type VtableSlot4cMethod =
    unsafe extern "C" fn(object: *mut u8, kind: u32, data: usize, extra: *const usize) -> u32;

/// vtable_slot_50_dispatch — original: `FUN_0811d7fc` @ 0x0811d7fc (28
/// bytes; **15 `bl` call sites**, grep on `decomp/osos.asm`, all inside
/// this message-family thunk cluster: the commit stage 0x0811d340, the
/// eight sites 0x0811d390..0x0811d440 in the multi-message routine
/// 0x0811d360, the open stage 0x0811d458, the kind-2 / kind-4 write
/// stages 0x0811d52c / 0x0811d56c, the tag thunks 0x0811d6cc /
/// 0x0811d6ec and the two sites 0x0811d890 / 0x0811d8a4 in
/// [`vtable_set_50_write_indirect_kind4`] (0x0811d874)).
///
/// The shared vtable dispatcher of the slot +0x50 message family — the
/// slot +0x50 twin of [`vtable_slot_4c_dispatch`] (`FUN_0811d7b0` @
/// 0x0811d7b0, ported in this module), which differs only in the slot
/// offset:
///
/// ```text
/// 0811d7fc  stmdb sp!, {r3, lr}     @ spill the caller's 4th argument
/// 0811d800  ldr   r0, [r0, #0x0]    @ object = *handle
/// 0811d804  ldr   r3, [r0, #0x0]    @ vtable = *object
/// 0811d808  ldr   r12, [r3, #0x50]  @ method = vtable->slot_50
/// 0811d80c  mov   r3, sp            @ extra = &spilled_r3
/// 0811d810  blx   r12               @ method(object, kind, data, extra)
/// 0811d814  ldmia sp!, {r12, pc}    @ return the method's r0
/// ```
///
/// A double dereference — handle to object to vtable — then the method
/// pointer at vtable slot +0x50 is invoked as
/// `method(object, kind, data, &spilled_r3)` and its error code
/// (0 = success) returns verbatim. The spilled r3 is whatever the
/// caller happened to carry: no call site sets it deliberately — every
/// caller is one of the message thunks, which forward their own
/// caller's r3 untouched (see the module header).
///
/// # Deviations
///
/// - **The r3 spill is collapsed into the `extra` parameter.** The
///   original receives the caller's r3 *by value* and spills it itself
///   (`stmdb sp!, {r3}` / `mov r3, sp`); this port's callers pre-spill
///   the forwarded word and pass its address (the
///   `util/vtable_query.rs` `VTABLE_SLOT_4C_DISPATCH` precedent), so
///   `extra` arrives as the pointer and reaches the method verbatim —
///   the word the method observes through it is identical. One
///   consequence: this export is **not** ABI-hookable at 0x0811d7fc,
///   where r3 arrives by value, not as a pointer (no hook targets it).
/// - **The `blx` target remains a seam.** The vtable methods are
///   firmware code, so this body stays the wired default of
///   [`VTABLE_SLOT_50_DISPATCH`] and the three ported siblings still
///   reach it through the seam; rewiring them to a direct call is a
///   deliberate follow-up (one function per commit — the
///   `app/class_6800.rs` precedent calls ported callees directly).
/// - **The slot load uses `read_unaligned`** so the layout stays
///   byte-exact on a 64-bit host: 0x50 is 4-aligned but not 8-aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_50_dispatch(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 {
    let object = handle.read();
    let vtable = (object as *const *const u8).read();
    let method =
        (vtable.add(VTABLE_SLOT_50) as *const VtableSlot50Method).read_unaligned();
    method(object, kind, data, extra)
}

/// Indirect dispatch for the vtable slot +0x50 dispatcher, wired to
/// the ported [`vtable_slot_50_dispatch`] (original: `FUN_0811d7fc` @
/// 0x0811d7fc; the util/vtable_query.rs `VTABLE_SLOT_4C_DISPATCH`
/// pattern). The seam is retained for hookability — the dispatcher's
/// `blx` targets are firmware vtable methods — so the three ported
/// siblings keep routing through it; host tests install a recording
/// mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_SLOT_50_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_50_dispatch;

/// vtable_slot_4c_dispatch — original: `FUN_0811d7b0` @ 0x0811d7b0
/// (28 bytes; **16 call sites**, grep on `decomp/osos.asm`: 15 `bl`
/// — the 8-site cluster 0x0811d230..0x0811d2e0, 0x0811d4a0, the
/// 4-site cluster 0x0811d5c4..0x0811d634, and the two sites
/// 0x0811d830 / 0x0811d85c in the unported query-clamp-write routine
/// at 0x0811d818 — plus the tail `b` at 0x0811d474 from the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` thunk 0x0811d46c).
///
/// The shared vtable dispatcher of the slot +0x4c message family —
/// the slot +0x4c twin of this module's [`vtable_slot_50_dispatch`]
/// (`FUN_0811d7fc` @ 0x0811d7fc), differing only in the slot offset:
///
/// ```text
/// 0811d7b0  stmdb sp!, {r3, lr}     @ spill the caller's 4th argument
/// 0811d7b4  ldr   r0, [r0, #0x0]    @ object = *handle
/// 0811d7b8  ldr   r3, [r0, #0x0]    @ vtable  = *object
/// 0811d7bc  ldr   r12, [r3, #0x4c]  @ method  = vtable->slot_4c
/// 0811d7c0  mov   r3, sp            @ extra = &spilled_r3
/// 0811d7c4  blx   r12               @ method(object, kind, data, extra)
/// 0811d7c8  ldmia sp!, {r12, pc}    @ return the method's r0
/// ```
///
/// A double dereference — handle to object to vtable — then the
/// method pointer at vtable slot +0x4c is invoked as
/// `method(object, kind, data, &spilled_r3)` and its error code
/// returns verbatim. Unlike [`vtable_slot_50_dispatch`], whose
/// callers all bind kind 4 themselves, this dispatcher is generic in
/// `kind`: r1 passes through untouched and the kind-4 binding lives
/// in the callers — `vtable_query_4c_kind4` (0x0811d46c) and the
/// routine at 0x0811d818, which calls it twice with kind 4 and a
/// stack out-slot, treating **5** as "unsupported — bail silently"
/// (`cmp r0, #0x5; beq`) and any other nonzero as a hard error.
/// The spilled r3 is whatever the caller happened to carry — no call
/// site sets it deliberately.
///
/// # Deviations
///
/// - **The r3 spill is collapsed into the `extra` parameter** — the
///   [`vtable_slot_50_dispatch`] deviation verbatim: the original
///   receives the caller's r3 *by value* and spills it itself
///   (`stmdb sp!, {r3}` / `mov r3, sp`); this port's callers
///   pre-spill the forwarded word and pass its address, so `extra`
///   arrives as the pointer and reaches the method verbatim. One
///   consequence: this export is **not** ABI-hookable at 0x0811d7b0,
///   where r3 arrives by value, not as a pointer (no hook targets
///   it).
/// - **No new seam.** The one ported caller,
///   `util/vtable_query.rs`'s `vtable_query_4c_kind4`, routes
///   through that module's `VTABLE_SLOT_4C_DISPATCH` static, still
///   wired to its private stub of this same body; pointing that
///   seam at this export is a deliberate follow-up (one function
///   per commit).
/// - **The slot load uses `read_unaligned`** so the layout stays
///   byte-exact on a 64-bit host: 0x4c is 4-aligned but not
///   8-aligned.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d7b0_FUN_0811d7b0.c` drops all four call
///   arguments (`(**(code **)(*(int *)*param_1 + 0x4c))()`), showing
///   a void call of a no-arg method — the dispatcher consumes
///   r0..r3. The port follows the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_4c_dispatch(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 {
    let object = handle.read();
    let vtable = (object as *const *const u8).read();
    let method =
        (vtable.add(VTABLE_SLOT_4C) as *const VtableSlot4cMethod).read_unaligned();
    method(object, kind, data, extra)
}

/// The open stage (`FUN_0811d458` @ 0x0811d458): sends the bare
/// selector by pointer.
pub type VtableSetOpen =
    unsafe extern "C" fn(handle: *mut *mut u8, selector: u32, forwarded: usize) -> u32;

/// The write stage (`FUN_0811d56c` @ 0x0811d56c): sends the kind word,
/// then the two-word `{*value, kind}` message.
pub type VtableSetWrite =
    unsafe extern "C" fn(handle: *mut *mut u8, value: *const u32, forwarded: usize) -> u32;

/// The commit stage (`FUN_0811d340` @ 0x0811d340): sends the selector
/// OR-ed with [`COMMIT_TAG`], by pointer.
pub type VtableSetCommit =
    unsafe extern "C" fn(handle: *mut *mut u8, selector: u32, forwarded: usize) -> u32;

/// The unported direct callees of [`vtable_set_50_kind4`], modeled as
/// an ops table (the app/class_6800.rs `CLASS_6800_OPS` pattern). The
/// wired defaults are the exact bodies of the three stages, not stubs.
#[derive(Clone, Copy)]
pub struct VtableSet50Kind4Ops {
    /// `FUN_0811d458` @ 0x0811d458 — bare-selector message.
    pub open: VtableSetOpen,
    /// `FUN_0811d56c` @ 0x0811d56c — kind word + `{*value, kind}`.
    pub write: VtableSetWrite,
    /// `FUN_0811d340` @ 0x0811d340 — tagged-selector message.
    pub commit: VtableSetCommit,
}

/// Default open stage: the exact body of `FUN_0811d458` @ 0x0811d458.
/// The original spills `{r0, r1}` and passes `sp + 4` — a pointer to
/// the spilled selector — as the message data; the dispatcher then
/// spills the (here forwarded) r3 and hands the method its address.
unsafe extern "C" fn vtable_set_open(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let selector_slot = selector;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(selector_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// Default write stage: the exact body of `FUN_0811d56c` @ 0x0811d56c.
/// The original reuses its `push {r2, r3}` spill slots as the two-word
/// message — `[sp+4] = 4`, `[sp+0] = *value` — sends the kind word
/// first and, only when that returns 0, the two-word `{*value, 4}`
/// message starting at `sp`.
unsafe extern "C" fn vtable_set_write(
    handle: *mut *mut u8,
    value: *const u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let mut message = [0u32; 2];
    message[1] = MESSAGE_KIND_4;
    message[0] = value.read();
    let forwarded_slot = forwarded;
    let mut result = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(message[1]) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if result == 0 {
        result = dispatch(
            handle,
            MESSAGE_KIND_4,
            core::ptr::addr_of!(message[0]) as usize,
            core::ptr::addr_of!(forwarded_slot),
        );
    }
    result
}

/// Default commit stage: the exact body of `FUN_0811d340` @ 0x0811d340.
/// The original spills `{r0, r1}`, ORs the spilled selector with
/// 0x80000000 and passes `sp + 4` as the message data.
unsafe extern "C" fn vtable_set_commit(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let tagged_slot = selector | COMMIT_TAG;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(tagged_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// Wired defaults for [`VTABLE_SET_50_KIND4_OPS`]: the modeled bodies
/// of the three original callees.
pub const DEFAULT_VTABLE_SET_50_KIND4_OPS: VtableSet50Kind4Ops = VtableSet50Kind4Ops {
    open: vtable_set_open,
    write: vtable_set_write,
    commit: vtable_set_commit,
};

/// Active seams for the unported direct callees of
/// [`vtable_set_50_kind4`]. Host tests replace the table (or individual
/// stages) with recording mocks; on firmware the defaults reproduce the
/// original chain.
pub static mut VTABLE_SET_50_KIND4_OPS: VtableSet50Kind4Ops =
    DEFAULT_VTABLE_SET_50_KIND4_OPS;

/// vtable_set_50_kind4 — original: `FUN_0811d68c` @ 0x0811d68c (64
/// bytes; 21 `bl` call sites).
///
/// Delivers a kind-4 property write to the object behind `handle` as a
/// three-stage sequence, bailing with the first nonzero error code:
///
/// 1. `open(handle, selector)` — the bare selector by pointer;
/// 2. `write(handle, value)` — the kind word, then `{*value, kind}`;
/// 3. tail-call `commit(handle, selector)` — the selector with the
///    top bit set; its return becomes this function's.
///
/// `value` is the caller's arg3 (a pointer to its value word) and
/// reaches **only** stage 2; `selector` is arg2 and reaches stages 1
/// and 3 (the original's `r5 = r1` / `r6 = r2` routing). `forwarded` is
/// the caller's r3, forwarded verbatim through every stage into the
/// dispatcher's `stmdb sp!, {r3}` spill (no call site sets it
/// deliberately); see the module deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_kind4(
    handle: *mut *mut u8,
    selector: u32,
    value: *const u32,
    forwarded: usize,
) -> u32 {
    // Volatile table read — the inner_state.rs rationale: the seams are
    // meant to be swapped at runtime, and a build in which nothing
    // swaps them must not constant-fold the defaults in.
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SET_50_KIND4_OPS));
    let result = (ops.open)(handle, selector, forwarded);
    if result != 0 {
        return result;
    }
    let result = (ops.write)(handle, value, forwarded);
    if result != 0 {
        return result;
    }
    (ops.commit)(handle, selector, forwarded)
}

/// vtable_set_50_commit_probe_kind4 — original: `FUN_0811d6cc` @
/// 0x0811d6cc (32 bytes; **14 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x0810aa30, the 3-site cluster
/// 0x0811c724..0x0811c788, the 3-site cluster 0x08136640..0x08136694,
/// 0x081b0134, 0x081b015c, 0x081bc714, 0x081d0e80, the 2-site cluster
/// 0x081d1504..0x081d1518, 0x08285864).
///
/// The one-dispatch commit+probe thunk of the kind-4 vtable message
/// family — the exact shape of this module's commit stage 0x0811d340,
/// with both high tag bits in place of the lone top bit:
///
/// ```text
/// 0811d6cc  stmdb sp!, {r0, r1, r4, lr}  @ spill handle, selector
/// 0811d6d0  ldr   r1, [sp, #0x4]         @ r1 = selector
/// 0811d6d4  add   r2, sp, #0x4           @ r2 = &spilled selector
/// 0811d6d8  orr   r1, r1, #0xc0000000    @ tag commit | probe bits
/// 0811d6dc  str   r1, [sp, #0x4]         @ spilled selector = tagged
/// 0811d6e0  mov   r1, #0x4               @ kind 4
/// 0811d6e4  bl    0x0811d7fc             @ dispatch(handle, 4, &tagged)
/// 0811d6e8  ldmia sp!, {r2, r3, r4, pc}  @ return dispatch's r0
/// ```
///
/// A single message to the slot +0x50 dispatcher: the handle passes
/// through in r0 untouched, kind 4 in r1, and r2 points at the stack
/// slot holding `selector | 0xc0000000` ([`COMMIT_PROBE_TAG`] — the
/// 0x80000000 commit tag of the sibling's third stage together with
/// the 0x40000000 "supported?" probe tag of the neighbour
/// [`vtable_set_50_probe_kind4`] (0x0811d6ec); the tag bits' exact
/// protocol meaning is not established, see the module header). Callers issue it after
/// successful writes — e.g. the 0x0811c6f0 probe → 0x0811c710
/// three-stage [`vtable_set_50_kind4`] → 0x0811c724 this-call sequence
/// — and always branch on the returned error code (`cmp r0, #0`).
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; the call still routes through the
///   [`VTABLE_SLOT_50_DISPATCH`] seam (retained for hookability —
///   rewiring to a direct call is a follow-up), exactly as the three
///   stages of [`vtable_set_50_kind4`] do (this function's body IS the
///   0x0811d340 stage shape with a wider tag, so no new seam is
///   needed).
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the `vtable_query_4c_kind4` /
///   [`vtable_set_50_kind4`] precedent. No call site sets r3
///   deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d6cc_FUN_0811d6cc.c` invents a phantom fifth
///   argument (`FUN_0811d7fc(param_1, 4, &local_c, param_4, param_1)`)
///   — the dispatcher consumes r0..r3 only. The port follows the
///   disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_commit_probe_kind4(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let tagged_slot = selector | COMMIT_PROBE_TAG;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(tagged_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// vtable_set_50_probe_kind4 — original: `FUN_0811d6ec` @ 0x0811d6ec
/// (32 bytes; **16 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0810a9c4, the 3-site cluster 0x0811c5ec..0x0811c6f0, 0x0811e8b0,
/// the 3-site cluster 0x081365b0..0x08136654, the 2-site cluster
/// 0x081b004c..0x081b0070, 0x081bc6b0, 0x081d0e34, the 2-site cluster
/// 0x081d13f0..0x081d149c, 0x082713c8, 0x08285804).
///
/// The "supported?" probe thunk of the kind-4 vtable message family —
/// the exact shape of [`vtable_set_50_commit_probe_kind4`]
/// (0x0811d6cc, one instruction earlier) with the lone 0x40000000
/// probe bit in place of the both-high-bits tag:
///
/// ```text
/// 0811d6ec  stmdb sp!, {r0, r1, r4, lr}  @ spill handle, selector
/// 0811d6f0  ldr   r1, [sp, #0x4]         @ r1 = selector
/// 0811d6f4  add   r2, sp, #0x4           @ r2 = &spilled selector
/// 0811d6f8  orr   r1, r1, #0x40000000    @ tag the probe bit
/// 0811d6fc  str   r1, [sp, #0x4]         @ spilled selector = tagged
/// 0811d700  mov   r1, #0x4               @ kind 4
/// 0811d704  bl    0x0811d7fc             @ dispatch(handle, 4, &tagged)
/// 0811d708  ldmia sp!, {r2, r3, r4, pc}  @ return dispatch's r0
/// ```
///
/// A single message to the slot +0x50 dispatcher: the handle passes
/// through in r0 untouched, kind 4 in r1, and r2 points at the stack
/// slot holding `selector | 0x40000000` ([`PROBE_TAG`]; the tag bits'
/// exact protocol meaning is not established, see the module header).
/// Callers issue it as a probe before the guarded write — e.g. the
/// 0x0811c6f0 this-call → 0x0811c710 three-stage
/// [`vtable_set_50_kind4`] → 0x0811c724 commit-probe sequence — and
/// always branch on the returned error code (`cmp r0, #0`).
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; the call still routes through the
///   [`VTABLE_SLOT_50_DISPATCH`] seam (retained for hookability —
///   rewiring to a direct call is a follow-up), exactly as
///   [`vtable_set_50_commit_probe_kind4`] does (the two bodies differ
///   only in the `orr` immediate, so no new seam is needed).
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the
///   [`vtable_set_50_commit_probe_kind4`] precedent. No call site sets
///   r3 deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d6ec_FUN_0811d6ec.c` invents a phantom fifth
///   argument (`FUN_0811d7fc(param_1, 4, &local_c, param_4, param_1)`)
///   — the dispatcher consumes r0..r3 only. The port follows the
///   disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_probe_kind4(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let tagged_slot = selector | PROBE_TAG;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(tagged_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// vtable_set_50_commit_kind4 — original: `FUN_0811d340` @ 0x0811d340
/// (32 bytes; **4 conditional-branch sites, no `bl` callers** — grep
/// on `decomp/osos.asm`; every reach is a tail `beq`/`bleq`:
/// 0x0811d338 from `FUN_0811d2f8`'s third stage, 0x0811d450 (`bleq`)
/// from the multi-message routine `FUN_0811d360`, 0x0811d684 from the
/// kind-2 three-stage sibling `FUN_0811d64c`, and 0x0811d6c4, the
/// tail call of [`vtable_set_50_kind4`] (0x0811d68c).
///
/// The commit thunk of the kind-4 vtable message family — the exact
/// shape of [`vtable_set_50_commit_probe_kind4`] (0x0811d6cc) and
/// [`vtable_set_50_probe_kind4`] (0x0811d6ec) with the lone top commit
/// bit in place of their wider/narrower tags:
///
/// ```text
/// 0811d340  stmdb sp!, {r0, r1, r4, lr}  @ spill handle, selector
/// 0811d344  ldr   r1, [sp, #0x4]         @ r1 = selector
/// 0811d348  add   r2, sp, #0x4           @ r2 = &spilled selector
/// 0811d34c  orr   r1, r1, #0x80000000    @ tag the commit bit
/// 0811d350  str   r1, [sp, #0x4]         @ spilled selector = tagged
/// 0811d354  mov   r1, #0x4               @ kind 4
/// 0811d358  bl    0x0811d7fc             @ dispatch(handle, 4, &tagged)
/// 0811d35c  ldmia sp!, {r2, r3, r4, pc}  @ return dispatch's r0
/// ```
///
/// A single message to the slot +0x50 dispatcher: the handle passes
/// through in r0 untouched, kind 4 in r1, and r2 points at the stack
/// slot holding `selector | 0x80000000` ([`COMMIT_TAG`]; the tag bits'
/// exact protocol meaning is not established, see the module header).
/// This is the third and final stage of the guarded write —
/// [`vtable_set_50_kind4`] tail-calls it after a successful open and
/// write (its `beq 0x0811d340` at 0x0811d6c4), as does the kind-2
/// sibling — and its error code returns unbranched.
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; the call still routes through the
///   [`VTABLE_SLOT_50_DISPATCH`] `read_volatile` seam (retained for
///   hookability — rewiring to a direct call is a follow-up), exactly
///   as the two ported tag-thunk siblings do (the three bodies differ
///   only in the `orr` immediate, so no new seam is needed).
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the
///   [`vtable_set_50_commit_probe_kind4`] precedent. No call site sets
///   r3 deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d340_FUN_0811d340.c` invents a phantom fifth
///   argument (`FUN_0811d7fc(param_1, 4, &local_c, param_4, param_1)`)
///   — the dispatcher consumes r0..r3 only. The port follows the
///   disassembly.
/// - **This export duplicates the [`VTABLE_SET_50_KIND4_OPS`] commit
///   default** `vtable_set_commit` (both are the exact body above);
///   the private model stays wired as that table's default for now —
///   pointing the table at this export is a deliberate follow-up (one
///   function per commit).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_commit_kind4(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let tagged_slot = selector | COMMIT_TAG;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(tagged_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// vtable_set_50_open_kind4 — original: `FUN_0811d458` @ 0x0811d458
/// (20 bytes; **4 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0811d30c, the first stage of the three-stage routine
/// `FUN_0811d2f8`; 0x0811d370, from the multi-message routine
/// `FUN_0811d360`; 0x0811d65c, the first stage of the kind-2
/// three-stage sibling `FUN_0811d64c`; and 0x0811d69c, the first
/// stage of [`vtable_set_50_kind4`] (0x0811d68c)).
///
/// The open thunk of the kind-4 vtable message family — the smallest
/// family member: the exact shape of [`vtable_set_50_commit_kind4`]
/// (0x0811d340) and the two tag thunks minus their `ldr`/`orr`/`str`
/// tag sequence, so the selector goes out **bare**:
///
/// ```text
/// 0811d458  stmdb sp!, {r0, r1, r4, lr}  @ spill handle, selector
/// 0811d45c  add   r2, sp, #0x4           @ r2 = &spilled selector
/// 0811d460  mov   r1, #0x4               @ kind 4
/// 0811d464  bl    0x0811d7fc             @ dispatch(handle, 4, &selector)
/// 0811d468  ldmia sp!, {r2, r3, r4, pc}  @ return dispatch's r0
/// ```
///
/// A single message to the slot +0x50 dispatcher: the handle passes
/// through in r0 untouched, kind 4 in r1, and r2 points at the stack
/// slot holding the **untagged** selector — no `orr`, unlike every
/// sibling (see the module header for the tag-bit family
/// convention). This is the first stage of the guarded write —
/// [`vtable_set_50_kind4`] calls it before the write stage and
/// propagates its error code (`cmp r0, #0; popne`) — and its error
/// code returns unbranched to direct callers.
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; the call still routes through the
///   [`VTABLE_SLOT_50_DISPATCH`] `read_volatile` seam (retained for
///   hookability — rewiring to a direct call is a follow-up), exactly
///   as the ported tag-thunk siblings do (this body is their shape
///   minus the tag sequence, so no new seam is needed).
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the
///   [`vtable_set_50_commit_kind4`] precedent. No call site sets r3
///   deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d458_FUN_0811d458.c` invents a phantom fifth
///   argument (`FUN_0811d7fc(param_1, 4, &uStack_c, param_4, param_1)`)
///   — the dispatcher consumes r0..r3 only. The port follows the
///   disassembly.
/// - **This export duplicates the [`VTABLE_SET_50_KIND4_OPS`] open
///   default** `vtable_set_open` (both are the exact body above);
///   the private model stays wired as that table's default for now —
///   pointing the table at this export is a deliberate follow-up (one
///   function per commit).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_open_kind4(
    handle: *mut *mut u8,
    selector: u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let selector_slot = selector;
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(selector_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

/// vtable_set_50_write_kind4 — original: `FUN_0811d56c` @ 0x0811d56c
/// (64 bytes; **1 `bl` call site** — grep on `decomp/osos.asm`:
/// 0x0811d6b0, the second stage of [`vtable_set_50_kind4`]
/// (0x0811d68c). The 0x0811d590 noted in the cluster ledger is the
/// `bl 0x0811d7fc` **inside** this body — `decomp/functions.csv`
/// lists no function there, so it is not a separate entry point).
///
/// The write thunk of the kind-4 vtable message family — the only
/// two-dispatch member: it reuses its `push {r2, r3}` spill slots as a
/// two-word message and sends the kind word ahead of the value:
///
/// ```text
/// 0811d56c  stmdb sp!, {r2, r3, r4, lr}  @ spill slots become the message
/// 0811d570  mov   r4, r0                 @ save handle
/// 0811d574  mov   r0, #0x4
/// 0811d578  str   r0, [sp, #0x4]         @ message[1] = kind word 4
/// 0811d57c  ldr   r0, [r1, #0x0]         @ r0 = *value
/// 0811d580  mov   r1, #0x4               @ kind 4
/// 0811d584  str   r0, [sp, #0x0]         @ message[0] = *value
/// 0811d588  mov   r0, r4
/// 0811d58c  add   r2, sp, #0x4           @ r2 = &message[1]
/// 0811d590  bl    0x0811d7fc             @ dispatch(handle, 4, &kind)
/// 0811d594  cmp   r0, #0x0
/// 0811d598  moveq r2, sp                 @ r2 = &message[0]
/// 0811d59c  moveq r1, #0x4               @ kind 4
/// 0811d5a0  moveq r0, r4
/// 0811d5a4  bleq  0x0811d7fc             @ dispatch(handle, 4, &{*value, 4})
/// 0811d5a8  ldmia sp!, {r2, r3, r4, pc}  @ return the last result
/// ```
///
/// Two messages to the slot +0x50 dispatcher: first the kind word
/// alone (r2 points at the stack slot holding 4), then — only when
/// that returns 0 — the two-word `{*value, 4}` message starting at
/// `sp` (the value itself arrives by pointer in r1 and is loaded
/// once, `ldr r0, [r1]`, before the first dispatch). A nonzero first
/// result short-circuits and returns verbatim; otherwise the second
/// dispatch's error code returns. [`vtable_set_50_kind4`] branches on
/// it (`cmp r0, #0` at 0x0811d6b4): nonzero skips the commit tail
/// call and propagates to the caller.
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; both calls still route through the
///   [`VTABLE_SLOT_50_DISPATCH`] `read_volatile` seam (retained for
///   hookability — rewiring to a direct call is a follow-up), exactly
///   as the ported siblings do.
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the
///   [`vtable_set_50_open_kind4`] precedent. No call site sets r3
///   deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d56c_FUN_0811d56c.c` invents phantom fourth and
///   fifth arguments on the first call (`FUN_0811d7fc(param_1, 4,
///   &local_c, param_4, *param_2)`) and drops the second call's
///   message pointer entirely (`FUN_0811d7fc(param_1, 4)`) — the
///   dispatcher consumes r0..r3 only. The port follows the
///   disassembly.
/// - **This export duplicates the [`VTABLE_SET_50_KIND4_OPS`] write
///   default** `vtable_set_write` (both are the exact body above);
///   the private model stays wired as that table's default for now —
///   pointing the table at this export is a deliberate follow-up (one
///   function per commit).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_write_kind4(
    handle: *mut *mut u8,
    value: *const u32,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let mut message = [0u32; 2];
    message[1] = MESSAGE_KIND_4;
    message[0] = value.read();
    let forwarded_slot = forwarded;
    let mut result = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(message[1]) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if result == 0 {
        result = dispatch(
            handle,
            MESSAGE_KIND_4,
            core::ptr::addr_of!(message[0]) as usize,
            core::ptr::addr_of!(forwarded_slot),
        );
    }
    result
}

/// vtable_set_50_write_kind2 — original: `FUN_0811d52c` @ 0x0811d52c
/// (64 bytes; **1 `bl` call site** — grep on `decomp/osos.asm`:
/// 0x0811d670, the second stage of the kind-2 three-stage sibling
/// [`vtable_set_50_kind2`] (`FUN_0811d64c`, ported in this module —
/// open 0x0811d458 → this call → tail commit
/// 0x0811d340, the [`vtable_set_50_kind4`] shape with this u16 write
/// stage in place of the u32 0x0811d56c). The 0x0811d550 noted in the
/// cluster ledger is the `bl 0x0811d7fc` **inside** this body —
/// `decomp/functions.csv` lists no function there, so it is not a
/// separate entry point).
///
/// The write thunk of the kind-2 (u16) vtable message family — the
/// exact 64-byte shape of [`vtable_set_50_write_kind4`] (0x0811d56c,
/// one instruction later), with three deltas:
///
/// ```text
/// 0811d52c  stmdb sp!, {r2, r3, r4, lr}  @ spill slots become the message
/// 0811d530  mov   r4, r0                 @ save handle
/// 0811d534  mov   r0, #0x2               @ (was #0x4)
/// 0811d538  str   r0, [sp, #0x4]         @ message[1] = kind word 2
/// 0811d53c  ldrh  r0, [r1, #0x0]         @ r0 = *value (u16, was ldr)
/// 0811d540  mov   r1, #0x4               @ kind 4 — UNCHANGED!
/// 0811d544  add   r2, sp, #0x4           @ r2 = &message[1]
/// 0811d548  str   r0, [sp, #0x0]         @ message[0] = zero-extended *value
/// 0811d54c  mov   r0, r4
/// 0811d550  bl    0x0811d7fc             @ dispatch(handle, 4, &kind2)
/// 0811d554  cmp   r0, #0x0
/// 0811d558  moveq r2, sp                 @ r2 = &message[0]
/// 0811d55c  moveq r1, #0x2               @ kind 2 (was #0x4)
/// 0811d560  moveq r0, r4
/// 0811d564  bleq  0x0811d7fc             @ dispatch(handle, 2, &{*value, 2})
/// 0811d568  ldmia sp!, {r2, r3, r4, pc}  @ return the last result
/// ```
///
/// Two messages to the slot +0x50 dispatcher, exactly as the kind-4
/// sibling: first the kind word alone (r2 points at the stack slot
/// holding 2), then — only when that returns 0 — the two-word
/// `{*value, 2}` message starting at `sp`. The value arrives by
/// pointer in r1 and is loaded ONCE as a HALFWORD (`ldrh`,
/// zero-extended into the 32-bit message word) before the first
/// dispatch. The subtle part: the FIRST dispatch's r1 stays kind 4 in
/// both siblings — where the kind-4 body cannot distinguish "first
/// kind = 4" from "first kind = the message word", this body's
/// `mov r1, #0x4` beside `mov r0, #0x2` proves the first dispatch
/// binds a fixed command kind 4 while the width kind travels in the
/// message payload; only the SECOND dispatch's r1 carries the width
/// (`moveq r1, #0x2`). A nonzero first result short-circuits and
/// returns verbatim; otherwise the second dispatch's error code
/// returns. The one caller, `FUN_0811d64c`, branches on it
/// (`cmp r0, #0` at 0x0811d674): nonzero skips the commit tail call
/// and propagates.
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; both calls still route through the
///   [`VTABLE_SLOT_50_DISPATCH`] `read_volatile` seam (retained for
///   hookability — rewiring to a direct call is a follow-up), exactly
///   as the ported siblings do.
/// - **The caller's r3 is forwarded verbatim** (nothing between entry
///   and the dispatcher's `stmdb sp!, {r3}` spill touches it), modeled
///   as a third parameter `forwarded` — the
///   [`vtable_set_50_write_kind4`] precedent. No call site sets r3
///   deliberately.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d52c_FUN_0811d52c.c` invents phantom fourth and
///   fifth arguments on the first call (`FUN_0811d7fc(param_1, 4,
///   &local_c, param_4, *param_2)`) and drops the second call's
///   message pointer entirely (`FUN_0811d7fc(param_1, 2)`) — the
///   dispatcher consumes r0..r3 only. The port follows the
///   disassembly. (Its `undefined2 *param_2` does catch the u16 value
///   pointer.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_write_kind2(
    handle: *mut *mut u8,
    value: *const u16,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let mut message = [0u32; 2];
    message[1] = MESSAGE_KIND_2;
    message[0] = value.read() as u32;
    let forwarded_slot = forwarded;
    let mut result = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(message[1]) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if result == 0 {
        result = dispatch(
            handle,
            MESSAGE_KIND_2,
            core::ptr::addr_of!(message[0]) as usize,
            core::ptr::addr_of!(forwarded_slot),
        );
    }
    result
}

/// vtable_set_50_kind2 — original: `FUN_0811d64c` @ 0x0811d64c (64
/// bytes; **2 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x081365cc and 0x081366d4 — both set r1 to a small property
/// selector (0x34 / 0x38), r2 to a pointer into a live structure
/// (object + 0x1c / r5 + 0x18), r0 to a stack handle, and both branch
/// on the returned status (`movs r4, r0; bne`).
///
/// The kind-2 (u16) twin of this module's [`vtable_set_50_kind4`]
/// (0x0811d68c, one instruction later): the identical three-stage
/// guarded property-write pipeline — open → write → tail-call commit,
/// the first nonzero status short-circuiting and propagating — with
/// the u16 write stage [`vtable_set_50_write_kind2`] (0x0811d52c,
/// `ldrh`) in place of the u32 0x0811d56c:
///
/// ```text
/// 0811d64c  stmdb sp!, {r4, r5, r6, lr}
/// 0811d650  mov   r6, r2            @ save value pointer (arg3)
/// 0811d654  mov   r5, r1            @ save selector (arg2)
/// 0811d658  mov   r4, r0            @ save handle (arg1)
/// 0811d65c  bl    0x0811d458        @ open(handle, selector)
/// 0811d660  cmp   r0, #0x0
/// 0811d664  ldmiane sp!, {r4, r5, r6, pc}  @ bail: open's status
/// 0811d668  mov   r1, r6
/// 0811d66c  mov   r0, r4
/// 0811d670  bl    0x0811d52c        @ write_kind2(handle, value)
/// 0811d674  cmp   r0, #0x0
/// 0811d678  moveq r1, r5            @ selector -> commit's arg2
/// 0811d67c  moveq r0, r4
/// 0811d680  ldmiaeq sp!, {r4, r5, r6, lr}
/// 0811d684  beq   0x0811d340        @ tail: commit(handle, selector)
/// 0811d688  ldmia sp!, {r4, r5, r6, pc}    @ write's status returns
/// ```
///
/// The argument routing is the kind-4 twin's exactly: **arg2 (r1, the
/// selector) reaches stages 1 and 3**, **arg3 (r2, a pointer to the
/// caller's u16 value) reaches only stage 2** (`r5 = r1` is restored
/// into r1 only for the tail call, `r6 = r2` becomes r1 of the middle
/// call); the write stage loads the value as a HALFWORD and
/// zero-extends it into the 32-bit message word — kind encodes the
/// value width (see the module header).
///
/// # Deviations
///
/// - **All three callees are ported in this module and called
///   DIRECTLY** — [`vtable_set_50_open_kind4`] (0x0811d458),
///   [`vtable_set_50_write_kind2`] (0x0811d52c) and
///   [`vtable_set_50_commit_kind4`] (0x0811d340); no new seam is
///   introduced (the [`vtable_set_50_indirect_kind4`] precedent — the
///   older [`vtable_set_50_kind4`] port routes through
///   [`VTABLE_SET_50_KIND4_OPS`] only because its stages were unported
///   at the time). The stages still reach the dispatcher through the
///   retained [`VTABLE_SLOT_50_DISPATCH`] seam, so host tests observe
///   every stage by swapping that one static.
/// - **Each stage's forwarded r3 is modeled EXACTLY, not as one
///   `forwarded` parameter** (the [`vtable_set_50_indirect_kind4`]
///   refinement): at entry r3 is the caller's and nothing touches it
///   before open's `bl`, so open's dispatcher spill exposes the
///   caller's r3 verbatim; open's epilogue (`ldmia sp!, {r2, r3, r4,
///   pc}`) reloads r3 from its spilled r1, so the write stage's entry
///   r3 is the **selector**; the write stage's epilogue reloads r3
///   from its [sp+4] spill slot, which its own `str r0, [sp, #0x4]`
///   overwrote with the kind word, so the commit's entry r3 is **2**
///   ([`MESSAGE_KIND_2`]).
/// - **The return type is `u32`**, not the reference C's `void`: both
///   call sites branch on r0 (`movs r4, r0; bne`), and the original
///   returns the failing stage's status — or the commit's, via the
///   tail call — in r0.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d64c_FUN_0811d64c.c` drops the open call's
///   arguments and inlines the commit tail call as
///   `FUN_0811d7fc(param_1, 4, &stack0xfffffff4)`, hiding the
///   0x0811d340 thunk and its `| 0x80000000` tag. The port follows
///   the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_kind2(
    handle: *mut *mut u8,
    selector: u32,
    value: *const u16,
    forwarded: usize,
) -> u32 {
    // r3 is untouched up to open's `bl`, so open's dispatcher spill
    // exposes the caller's r3 verbatim.
    let result = vtable_set_50_open_kind4(handle, selector, forwarded);
    if result != 0 {
        return result;
    }
    // open's epilogue reloads r3 from its spilled r1: the write
    // stage's forwarded r3 is the selector.
    let result = vtable_set_50_write_kind2(handle, value, selector as usize);
    if result != 0 {
        return result;
    }
    // The write stage's epilogue reloads r3 from its [sp+4] spill
    // slot, overwritten with the kind word: the commit's forwarded r3
    // is MESSAGE_KIND_2.
    vtable_set_50_commit_kind4(handle, selector, MESSAGE_KIND_2 as usize)
}

/// vtable_set_50_write_indirect_kind4 — original: `FUN_0811d874` @
/// 0x0811d874 (56 bytes; **1 `bl` call site**, grep on
/// `decomp/osos.asm`: 0x0811d324, the middle stage of the unported
/// three-stage routine `FUN_0811d2f8` — open 0x0811d458 → this call →
/// tail commit 0x0811d340, the [`vtable_set_50_kind4`] shape with
/// this routine in place of the by-value write stage 0x0811d56c. The
/// caller passes its own arg4 as this function's arg2 and its own
/// arg3 — a pointer from an accessor — as arg3). There is NO
/// reference C for this function (`decomp/c/010/` has no `0811d874`
/// file); the port follows the disassembly.
///
/// The indirect (by-pointer) write stage of the kind-4 vtable message
/// family — the second two-dispatch member after
/// [`vtable_set_50_write_kind4`], and the slot +0x50 mirror of this
/// module's [`vtable_query_4c_kind4_read`] (0x0811d818): a first
/// kind-4 message carrying the selector by pointer, then — only on
/// success — a generic dispatch whose middle argument is the selector
/// itself (not a kind constant) and whose data is the caller's
/// pointer:
///
/// ```text
/// 0811d874  stmdb sp!, {r3, r4, r5, r6, r7, lr}  @ spill arg4 (r3)
/// 0811d878  mov   r6, r2            @ save data (arg3)
/// 0811d87c  mov   r4, r1            @ save selector (arg2)
/// 0811d880  str   r1, [sp, #0x0]    @ selector OVERWRITES the r3 spill slot
/// 0811d884  mov   r1, #0x4          @ kind 4
/// 0811d888  mov   r2, sp            @ data = &selector
/// 0811d88c  mov   r5, r0            @ save handle
/// 0811d890  bl    0x0811d7fc        @ dispatch(handle, 4, &selector, r3)
/// 0811d894  cmp   r0, #0x0
/// 0811d898  moveq r2, r6            @ data = arg3 pointer
/// 0811d89c  moveq r1, r4            @ kind = selector
/// 0811d8a0  moveq r0, r5
/// 0811d8a4  bleq  0x0811d7fc        @ dispatch(handle, selector, data, r3)
/// 0811d8a8  ldmia sp!, {r3, r4, r5, r6, r7, pc}  @ return the last result
/// ```
///
/// Two messages to the slot +0x50 dispatcher: first kind 4 with a
/// pointer to the selector (the open stage 0x0811d458's exact
/// message), then — only when that returns 0 — a generic dispatch
/// with the **selector as the middle (kind) argument** and the
/// caller's arg3 pointer as the data (the shape of
/// [`vtable_query_4c_kind4_read`]'s read dispatch, whose middle
/// argument carries the clamped size). A nonzero first result
/// short-circuits and returns verbatim; otherwise the second
/// dispatch's error code returns. The one caller,
/// `FUN_0811d2f8`, branches on it (`cmp r0, #0` at 0x0811d328):
/// nonzero skips the commit tail call and propagates.
///
/// # Deviations
///
/// - **The callee 0x0811d7fc is ported** in this module as
///   [`vtable_slot_50_dispatch`]; both calls route through the
///   [`VTABLE_SLOT_50_DISPATCH`] `read_volatile` seam (retained for
///   hookability — rewiring to a direct call is a follow-up), exactly
///   as the ported siblings do.
/// - **The caller's r3 (arg4) reaches ONLY the first dispatch**,
///   modeled as a fourth parameter `forwarded` — the family
///   convention. Nothing between entry and the first `bl` touches r3,
///   so the first dispatcher's `stmdb sp!, {r3}` spill exposes it
///   verbatim. For the **second** dispatch r3 is DEAD: the first
///   dispatch's `blx` method clobbers r0–r3 (and the dispatcher's
///   `ldmia sp!, {r12, pc}` epilogue restores the spilled word into
///   r12, not r3), nothing reloads r3 before the `bleq`, and the
///   entry spill slot it came from was overwritten with the selector
///   (`str r1, [sp, #0x0]`) — so the second dispatcher spills
///   whatever the first method happened to leave in r3. The port
///   passes a pointer to a zero stack word for that unobservable
///   argument (the [`vtable_query_4c_kind4_read`] `_unused`
///   precedent).
/// - **arg3 is typed `*const u8`** (the [`vtable_query_4c_kind4_read`]
///   `buffer: *mut u8` mirror, direction reversed: the second
///   dispatch's method reads the payload the caller's accessor
///   produced). It is only ever consumed as an address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_write_indirect_kind4(
    handle: *mut *mut u8,
    selector: u32,
    data: *const u8,
    forwarded: usize,
) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    // `str r1, [sp, #0x0]`: the selector overwrites the entry r3 spill
    // slot; `mov r2, sp` makes it the first message's data word.
    let selector_slot = selector;
    let forwarded_slot = forwarded;
    let mut result = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(selector_slot) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if result == 0 {
        // r3 is dead across the first dispatch (method-clobbered, and
        // the spill slot it came from was overwritten with the
        // selector); 0 stands in for the unobservable fourth argument
        // — the query_read `_unused` precedent.
        let dead_slot = 0usize;
        result = dispatch(
            handle,
            selector,
            data as usize,
            core::ptr::addr_of!(dead_slot),
        );
    }
    result
}

/// vtable_set_50_indirect_kind4 — original: `FUN_0811d2f8` @
/// 0x0811d2f8 (72 bytes; **4 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x08136600, 0x081b00fc, 0x081bc6e4 and
/// 0x08271478 — all four set r1 to a small property selector
/// (0x35 / 0x44 / 0x3e / 0x3c), r2 to a pointer returned by the
/// accessor 0x082a50b0, r3 to a value word returned by 0x08275e20 /
/// 0x082770e0, and all branch on the returned status).
///
/// The INDIRECT-write variant of this module's
/// [`vtable_set_50_kind4`] (0x0811d68c): the identical three-stage
/// guarded property-write pipeline — open → write → tail-call
/// commit, the first nonzero status short-circuiting and propagating
/// — with the by-pointer write stage
/// [`vtable_set_50_write_indirect_kind4`] (0x0811d874) in place of
/// the by-value 0x0811d56c, and **arg4 (r3) feeding the write stage
/// as its selector argument**:
///
/// ```text
/// 0811d2f8  stmdb sp!, {r4, r5, r6, r7, r8, lr}
/// 0811d2fc  mov   r7, r3            @ save write-selector (arg4)
/// 0811d300  mov   r6, r2            @ save data pointer (arg3)
/// 0811d304  mov   r5, r1            @ save selector (arg2)
/// 0811d308  mov   r4, r0            @ save handle (arg1)
/// 0811d30c  bl    0x0811d458        @ open(handle, selector)
/// 0811d310  cmp   r0, #0x0
/// 0811d314  ldmiane sp!, {r4, r5, r6, r7, r8, pc}  @ bail: open's status
/// 0811d318  mov   r2, r6            @ data (arg3) -> write's arg3
/// 0811d31c  mov   r1, r7            @ write-selector (arg4) -> write's arg2
/// 0811d320  mov   r0, r4
/// 0811d324  bl    0x0811d874        @ write_indirect(handle, arg4, arg3)
/// 0811d328  cmp   r0, #0x0
/// 0811d32c  moveq r1, r5            @ selector -> commit's arg2
/// 0811d330  moveq r0, r4
/// 0811d334  ldmiaeq sp!, {r4, r5, r6, r7, r8, lr}
/// 0811d338  beq   0x0811d340        @ tail: commit(handle, selector)
/// 0811d33c  ldmia sp!, {r4, r5, r6, r7, r8, pc}  @ write's status returns
/// ```
///
/// The argument routing mirrors [`vtable_set_50_kind4`]'s with one
/// twist: **arg2 (r1, the selector) reaches stages 1 and 3**, **arg3
/// (r2, the caller's data pointer) reaches only stage 2 as its data
/// argument**, and **arg4 (r3) reaches stage 2 as its SELECTOR
/// argument** (`mov r1, r7`) — the by-pointer write binds the
/// caller's value word as its second dispatch's kind, where the
/// by-value sibling dereferences its arg3 instead.
///
/// # Deviations
///
/// - **All three callees are ported in this module and called
///   DIRECTLY** — [`vtable_set_50_open_kind4`] (0x0811d458),
///   [`vtable_set_50_write_indirect_kind4`] (0x0811d874) and
///   [`vtable_set_50_commit_kind4`] (0x0811d340). This deliberately
///   diverges from [`vtable_set_50_kind4`]'s shape: that port routes
///   its stages through the [`VTABLE_SET_50_KIND4_OPS`] seam because
///   they were unported at the time (its notes flag rewiring as a
///   follow-up); here no new seam is introduced (the
///   `app/class_6800.rs` precedent calls ported callees directly).
///   The thunks still reach the dispatcher through the retained
///   [`VTABLE_SLOT_50_DISPATCH`] seam, so host tests observe every
///   stage by swapping that one static.
/// - **Each stage's forwarded r3 is modeled EXACTLY, not as one
///   `forwarded` parameter** — tracing the register through the
///   callees' epilogues: at entry r3 = arg4 and nothing touches it
///   before open's `bl`, so open's dispatcher spill exposes **arg4**
///   verbatim; open's epilogue (`ldmia sp!, {r2, r3, r4, pc}`)
///   reloads r3 from its spilled r1, so the write stage's entry r3
///   is the **selector**; the write stage's epilogue (`ldmia sp!,
///   {r3, ...}`) reloads r3 from its entry spill slot, which its own
///   `str r1, [sp, #0x0]` overwrote with its arg2, so the commit's
///   entry r3 is **arg4** again. (This refines the sibling's
///   "forwarded verbatim to every stage" approximation.)
/// - **The return type is `u32`**, not the reference C's `void`:
///   every call site branches on r0 (`movs r4, r0; bne` / `cmp r0,
///   #0`), and the original returns the failing stage's status — or
///   the commit's, via the tail call — in r0.
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d2f8_FUN_0811d2f8.c` drops every argument of
///   the open call and inlines the commit tail call as
///   `FUN_0811d7fc(param_1, 4, &stack0xfffffff4)`, hiding the
///   0x0811d340 thunk and its `| 0x80000000` tag. The port follows
///   the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_indirect_kind4(
    handle: *mut *mut u8,
    selector: u32,
    data: *const u8,
    write_selector: u32,
) -> u32 {
    // r3 (arg4) is untouched up to open's `bl`, so open's dispatcher
    // spill exposes it verbatim.
    let result = vtable_set_50_open_kind4(handle, selector, write_selector as usize);
    if result != 0 {
        return result;
    }
    // open's epilogue reloads r3 from its spilled r1: the write
    // stage's forwarded r3 is the selector.
    let result = vtable_set_50_write_indirect_kind4(
        handle,
        write_selector,
        data,
        selector as usize,
    );
    if result != 0 {
        return result;
    }
    // The write stage's epilogue reloads r3 from its overwritten
    // spill slot: the commit's forwarded r3 is arg4 again.
    vtable_set_50_commit_kind4(handle, selector, write_selector as usize)
}

/// The status [`vtable_query_4c_kind4_read`] treats as "unsupported —
/// bail silently" (`cmp r0, #0x5; beq`): it returns verbatim, exactly
/// like any hard error, but the caller convention distinguishes it
/// (see [`vtable_slot_4c_dispatch`]).
const STATUS_UNSUPPORTED: u32 = 5;

/// Indirect dispatch for the two slot +0x4c dispatches of
/// [`vtable_query_4c_kind4_read`], wired to this module's ported
/// [`vtable_slot_4c_dispatch`] (original: `FUN_0811d7b0` @ 0x0811d7b0;
/// the [`VTABLE_SLOT_50_DISPATCH`] pattern — the seam is retained for
/// hookability, the dispatcher's `blx` targets are firmware vtable
/// methods). The name is role-specific because
/// `util/vtable_query.rs`'s `VTABLE_SLOT_4C_DISPATCH` already claims
/// the family name at the crate root (both modules are glob
/// re-exported in `lib.rs`); host tests install a recording mock via
/// `core::ptr::addr_of_mut!`.
pub static mut VTABLE_QUERY_4C_READ_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// Indirect dispatch for the closing query-thunk call of
/// [`vtable_query_4c_kind4_read`], wired to the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` (original:
/// `FUN_0811d46c` @ 0x0811d46c). Routing the call through a seam local
/// to this module (instead of calling the export directly) keeps host
/// tests able to intercept it without swapping util's
/// `VTABLE_SLOT_4C_DISPATCH` static — which would race util's own
/// parallel tests.
pub static mut VTABLE_QUERY_4C_READ_FINISH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    out: *mut u32,
    unused: usize,
    forwarded: usize,
) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;

/// vtable_query_4c_kind4_read — original: `FUN_0811d818` @ 0x0811d818
/// (92 bytes; **3 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x08136784, 0x081bc7f0 and 0x08271504 — all three pass a capacity
/// in r1 (0x40, 0x40, 0x100), a pointer to the caller's stack buffer
/// in r2 (`add r2, sp, #0x4`) and the handle in r0; none sets r3).
/// There is NO reference C for this function (`decomp/c/010/` has no
/// `0811d818` file); the port follows the disassembly.
///
/// The query-size-then-read routine of the slot +0x4c message family
/// — the only caller that drives [`vtable_slot_4c_dispatch`]
/// (0x0811d7b0) twice, and the mirror of this module's slot +0x50
/// sibling [`vtable_set_50_write_indirect_kind4`] (0x0811d874 — same
/// two-dispatch shape through [`vtable_slot_50_dispatch`], direction
/// reversed: it sends the selector first, then writes):
///
/// ```text
/// 0811d818  stmdb sp!, {r2, r3, r4, r5, r6, lr}  @ pair = {buffer, r3}
/// 0811d81c  mov   r6, r2            @ save buffer (arg3)
/// 0811d820  mov   r4, r1            @ save capacity (arg2)
/// 0811d824  mov   r1, #0x4          @ kind 4
/// 0811d828  add   r2, sp, #0x4      @ out-slot = &pair[1]
/// 0811d82c  mov   r5, r0            @ save handle
/// 0811d830  bl    0x0811d7b0        @ size query: dispatch(handle, 4, &pair[1])
/// 0811d834  cmp   r0, #0x5
/// 0811d838  beq   0x0811d870        @ unsupported -> return status
/// 0811d83c  cmp   r0, #0x0
/// 0811d840  bne   0x0811d870        @ hard error -> return status
/// 0811d844  ldr   r0, [sp, #0x4]    @ size = pair[1] (method-written)
/// 0811d848  mov   r2, r6            @ data = buffer
/// 0811d84c  cmp   r0, r4
/// 0811d850  strhi r4, [sp, #0x4]    @ pair[1] = min(size, capacity) UNSIGNED
/// 0811d854  ldr   r1, [sp, #0x4]    @ r1 = clamped size
/// 0811d858  mov   r0, r5
/// 0811d85c  bl    0x0811d7b0        @ read: dispatch(handle, size, buffer)
/// 0811d860  cmp   r0, #0x0
/// 0811d864  moveq r1, sp            @ out = &pair[0]
/// 0811d868  moveq r0, r5
/// 0811d86c  bleq  0x0811d46c        @ finish: vtable_query_4c_kind4(handle, &pair)
/// 0811d870  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// ```
///
/// The entry `stmdb` spills arg3 (r2, the caller's buffer pointer) and
/// arg4 (r3) into the two-word stack pair at `sp+0`/`sp+4`. The first
/// dispatch sends kind 4 with `&pair[1]` as the out-slot: the method
/// answers with the available size. The size is clamped to the
/// caller's capacity with an UNSIGNED compare (`strhi`), then the
/// second dispatch performs the read — the generic dispatcher's
/// middle argument carries the clamped size (not a kind constant) and
/// its data argument is the buffer pointer. Only when the read
/// returns 0 does the closing `bleq` fire: 0x0811d46c is the PORTED
/// kind-4 query thunk `util/vtable_query.rs`
/// `vtable_query_4c_kind4` (`mov r2, r1; mov r1, #4; b 0x0811d7b0`),
/// NOT a block-copy helper — it re-dispatches kind 4 with the
/// two-word `{buffer, clamped_size}` pair as the message and its
/// error code becomes this function's return value. On every bail
/// path the status of the last executed call returns verbatim
/// (status 5 = "unsupported", indistinguishable in behavior from a
/// hard error here — both return untouched).
///
/// # Deviations
///
/// - **Both callees are ported** ([`vtable_slot_4c_dispatch`] in this
///   module, `vtable_query_4c_kind4` in util/vtable_query.rs); the
///   calls route through the new [`VTABLE_QUERY_4C_READ_DISPATCH`] /
///   [`VTABLE_QUERY_4C_READ_FINISH`] seams (the
///   [`VTABLE_SLOT_50_DISPATCH`] pattern — hookability plus host-test
///   interception without racing util's own seam).
/// - **arg4 (r3) is modeled as `forwarded`** — the family convention:
///   no call site sets r3 deliberately. Here it doubles as the
///   INITIAL CONTENT of the size out-slot `pair[1]` (the entry spill),
///   which the size-query method overwrites; it is also the word each
///   dispatcher's `stmdb sp!, {r3}` spill exposes to the methods.
/// - **r2 into the closing call is dead, not arg3.** The assignment
///   sketch's "arg3 forwarded to BOTH the second dispatch and the
///   copy-out" does NOT hold past the second `bl`: r2 is
///   method-clobbered across the read dispatch, and the thunk's first
///   instruction (`mov r2, r1`) discards it unconditionally. The
///   port passes 0 for the thunk's `_unused` parameter. arg3 reaches
///   exactly one place — the read dispatch's data argument.
/// - **`pair[1]` is only ever consumed as a 32-bit word** (ARM `ldr`),
///   so the port truncates it to `u32` on every read; `pair[0]` is
///   only ever consumed as an address. This keeps the stack-pair
///   semantics exact on a 64-bit host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_kind4_read(
    handle: *mut *mut u8,
    capacity: u32,
    buffer: *mut u8,
    forwarded: usize,
) -> u32 {
    let dispatch =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_READ_DISPATCH));
    let finish =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_READ_FINISH));
    // The entry `stmdb sp!, {r2, r3, ...}` spill: pair[0] = buffer
    // (sp+0), pair[1] = forwarded (sp+4, the out-slot's initial word).
    let mut pair = [buffer as usize, forwarded];
    let forwarded_slot = forwarded;
    let status = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(pair[1]) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if status == STATUS_UNSUPPORTED {
        return status;
    }
    if status != 0 {
        return status;
    }
    // ldr r0, [sp, #4] / cmp r0, r4 / strhi r4, [sp, #4]: the clamp is
    // unsigned (HI), so a size with the top bit set still clamps.
    let mut size = pair[1] as u32;
    if size > capacity {
        size = capacity;
        pair[1] = capacity as usize;
    }
    let status = dispatch(
        handle,
        size,
        buffer as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if status != 0 {
        return status;
    }
    // r2 is dead across the read dispatch and the thunk discards it
    // (`mov r2, r1`); 0 stands in for the unobservable third argument.
    finish(
        handle,
        core::ptr::addr_of_mut!(pair[0]) as *mut u32,
        0,
        forwarded,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    const MOCK_OK: u32 = 0;
    const OPEN_ERR: u32 = 0x0bad_0001;
    const WRITE_ERR: u32 = 0x0bad_0002;
    const COMMIT_CODE: u32 = 0x0bad_0003;
    const SELECTOR: u32 = 0x43;
    const VALUE_WORD: u32 = 0x1122_3344;
    const FORWARDED: usize = 0x5566_7788;

    /// Serializes the tests that swap `VTABLE_SET_50_KIND4_OPS` /
    /// `VTABLE_SLOT_50_DISPATCH` (the vtable_query.rs `SLOT_TEST_LOCK`
    /// precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores both seams on drop, even when a test panics.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VTABLE_SET_50_KIND4_OPS)
                    .write_volatile(DEFAULT_VTABLE_SET_50_KIND4_OPS);
                core::ptr::addr_of_mut!(VTABLE_SLOT_50_DISPATCH)
                    .write_volatile(vtable_slot_50_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_READ_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_READ_FINISH)
                    .write_volatile(crate::util::vtable_query::vtable_query_4c_kind4);
            }
        }
    }

    // ---- recording mocks for the three stage seams -------------------

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Stage {
        Open,
        Write,
        Commit,
    }

    static mut STAGE_LOG: [Stage; 8] = [Stage::Open; 8];
    static mut STAGE_CALLS: usize = 0;
    static mut STAGE_HANDLE: *mut *mut u8 = core::ptr::null_mut();
    static mut STAGE_SELECTOR: u32 = 0;
    static mut STAGE_VALUE: *const u32 = core::ptr::null();
    static mut STAGE_FORWARDED: usize = 0;
    static mut OPEN_RESULT: u32 = MOCK_OK;
    static mut WRITE_RESULT: u32 = MOCK_OK;
    static mut COMMIT_RESULT: u32 = MOCK_OK;

    unsafe fn record_stage(stage: Stage, handle: *mut *mut u8, forwarded: usize) {
        STAGE_LOG[STAGE_CALLS] = stage;
        STAGE_CALLS += 1;
        STAGE_HANDLE = handle;
        STAGE_FORWARDED = forwarded;
    }

    unsafe extern "C" fn recording_open(
        handle: *mut *mut u8,
        selector: u32,
        forwarded: usize,
    ) -> u32 {
        record_stage(Stage::Open, handle, forwarded);
        STAGE_SELECTOR = selector;
        OPEN_RESULT
    }

    unsafe extern "C" fn recording_write(
        handle: *mut *mut u8,
        value: *const u32,
        forwarded: usize,
    ) -> u32 {
        record_stage(Stage::Write, handle, forwarded);
        STAGE_VALUE = value;
        WRITE_RESULT
    }

    unsafe extern "C" fn recording_commit(
        handle: *mut *mut u8,
        selector: u32,
        forwarded: usize,
    ) -> u32 {
        record_stage(Stage::Commit, handle, forwarded);
        STAGE_SELECTOR = selector;
        COMMIT_RESULT
    }

    unsafe fn install_recording_ops() {
        STAGE_CALLS = 0;
        STAGE_HANDLE = core::ptr::null_mut();
        STAGE_SELECTOR = 0;
        STAGE_VALUE = core::ptr::null();
        STAGE_FORWARDED = 0;
        OPEN_RESULT = MOCK_OK;
        WRITE_RESULT = MOCK_OK;
        COMMIT_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_SET_50_KIND4_OPS).write_volatile(
            VtableSet50Kind4Ops {
                open: recording_open,
                write: recording_write,
                commit: recording_commit,
            },
        );
    }

    // ---- recording mock for the slot +0x50 dispatch seam -------------

    static mut DISPATCH_CALLS: usize = 0;
    static mut DISPATCH_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut DISPATCH_KIND: [u32; 8] = [0; 8];
    static mut DISPATCH_WORD0: [u32; 8] = [0; 8];
    static mut DISPATCH_WORD1: [u32; 8] = [0; 8];
    static mut DISPATCH_EXTRA: [usize; 8] = [0; 8];
    static mut DISPATCH_RESULTS: [u32; 8] = [MOCK_OK; 8];

    unsafe extern "C" fn recording_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = DISPATCH_CALLS;
        DISPATCH_CALLS += 1;
        DISPATCH_HANDLE[call] = handle;
        DISPATCH_KIND[call] = kind;
        // The data pointers handed to the dispatcher always point into a
        // live frame with at least one word past the message (the open /
        // commit frames place `forwarded_slot` there, the write frame's
        // two-word message is contiguous), so reading the neighbour word
        // of a live frame is in-bounds stack; the word is only asserted
        // on for the write stage's second message.
        DISPATCH_WORD0[call] = (data as *const u32).read();
        DISPATCH_WORD1[call] = (data as *const u32).add(1).read();
        DISPATCH_EXTRA[call] = extra.read();
        DISPATCH_RESULTS[call]
    }

    unsafe fn install_recording_dispatch() {
        DISPATCH_CALLS = 0;
        DISPATCH_RESULTS = [MOCK_OK; 8];
        core::ptr::addr_of_mut!(VTABLE_SLOT_50_DISPATCH)
            .write_volatile(recording_dispatch);
    }

    /// A stand-in handle: one pointer-sized slot pointing at a stand-in
    /// object (the vtable_query.rs `Fixture` precedent).
    struct Fixture {
        handle: usize,
        object: [u8; 8],
    }

    impl Fixture {
        fn new() -> Self {
            let mut fixture = Fixture { handle: 0, object: [0xa5; 8] };
            fixture.handle = fixture.object.as_mut_ptr() as usize;
            fixture
        }
        fn handle_ptr(&mut self) -> *mut *mut u8 {
            core::ptr::addr_of_mut!(self.handle) as *mut *mut u8
        }
    }

    // ---- stage-seam level: order, short-circuit, argument routing ----

    #[test]
    fn open_error_short_circuits_before_write_and_commit() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            install_recording_ops();
            OPEN_RESULT = OPEN_ERR;

            let result = vtable_set_50_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(result, OPEN_ERR, "open's error code propagates verbatim");
            assert_eq!(STAGE_CALLS, 1, "write and commit are never reached");
            assert_eq!(STAGE_LOG[0], Stage::Open);
            assert_eq!(STAGE_HANDLE, fixture.handle_ptr(), "handle forwarded verbatim");
            assert_eq!(STAGE_SELECTOR, SELECTOR, "arg2 (r1) routes to open");
            assert_eq!(STAGE_FORWARDED, FORWARDED, "the caller's r3 is forwarded");
        }
    }

    #[test]
    fn write_error_skips_commit_and_routes_value_pointer() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            install_recording_ops();
            WRITE_RESULT = WRITE_ERR;

            let result = vtable_set_50_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(result, WRITE_ERR, "write's error code propagates verbatim");
            assert_eq!(STAGE_CALLS, 2, "open ran, commit was skipped");
            assert_eq!(STAGE_LOG[0], Stage::Open);
            assert_eq!(STAGE_LOG[1], Stage::Write);
            assert_eq!(
                STAGE_VALUE,
                core::ptr::addr_of_mut!(value) as *const u32,
                "arg3 (r2) routes to write as its value pointer (r6 -> r1)"
            );
        }
    }

    #[test]
    fn success_runs_all_three_in_order_and_returns_commits_code() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            install_recording_ops();
            COMMIT_RESULT = COMMIT_CODE;

            let result = vtable_set_50_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(
                result, COMMIT_CODE,
                "the tail call's return becomes this function's"
            );
            assert_eq!(STAGE_CALLS, 3);
            assert_eq!(STAGE_LOG[0], Stage::Open);
            assert_eq!(STAGE_LOG[1], Stage::Write);
            assert_eq!(STAGE_LOG[2], Stage::Commit);
            assert_eq!(
                STAGE_SELECTOR, SELECTOR,
                "the selector is restored from r5 for the tail call"
            );
            assert_eq!(STAGE_FORWARDED, FORWARDED);
        }
    }

    // ---- default stage bodies against the dispatch seam --------------

    #[test]
    fn default_stages_reproduce_the_original_message_sequence() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            install_recording_dispatch();
            // DEFAULT ops stay wired: the modeled bodies of 0x0811d458 /
            // 0x0811d56c / 0x0811d340 run against the recording dispatch.

            let result = vtable_set_50_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 4, "open 1 + write 2 + commit 1");
            for call in 0..4 {
                assert_eq!(DISPATCH_HANDLE[call], fixture.handle_ptr());
                assert_eq!(DISPATCH_KIND[call], MESSAGE_KIND_4, "every stage binds kind 4");
                assert_eq!(
                    DISPATCH_EXTRA[call], FORWARDED,
                    "the caller's r3 reaches every dispatcher spill"
                );
            }
            assert_eq!(
                DISPATCH_WORD0[0], SELECTOR,
                "open sends the bare selector (0x0811d458)"
            );
            assert_eq!(
                DISPATCH_WORD0[1], MESSAGE_KIND_4,
                "write sends the kind word first (str r0,[sp,#4]; add r2,sp,#4)"
            );
            assert_eq!(
                DISPATCH_WORD0[2], VALUE_WORD,
                "write then sends {{*value, kind}} starting at sp"
            );
            assert_eq!(
                DISPATCH_WORD1[2], MESSAGE_KIND_4,
                "the second word of the two-word message is the kind"
            );
            assert_eq!(
                DISPATCH_WORD0[3],
                SELECTOR | COMMIT_TAG,
                "commit sends selector | 0x80000000 (0x0811d340)"
            );
        }
    }

    #[test]
    fn default_write_skips_its_second_dispatch_on_error() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[1] = WRITE_ERR; // write's kind-word dispatch fails

            let result = vtable_set_50_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(result, WRITE_ERR, "write's first error propagates");
            assert_eq!(
                DISPATCH_CALLS, 2,
                "open's one + write's first only; the {{value, kind}} message \
                 and commit are skipped (the original's bleq)"
            );
        }
    }

    // ---- end-to-end: the default dispatcher body on a fake vtable ----

    static mut METHOD_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut METHOD_KIND: u32 = 0;
    static mut METHOD_DATA_WORD: u32 = 0;
    static mut METHOD_CALLS: usize = 0;

    unsafe extern "C" fn recording_method(
        object: *mut u8,
        kind: u32,
        data: usize,
        _extra: *const usize,
    ) -> u32 {
        METHOD_OBJECT = object;
        METHOD_KIND = kind;
        METHOD_DATA_WORD = (data as *const u32).read();
        METHOD_CALLS += 1;
        MOCK_OK
    }

    #[test]
    fn default_dispatch_body_loads_slot_50_and_calls_it() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        // Object whose first word is its vtable; vtable is a raw byte
        // buffer so the +0x50 slot sits at a 4-aligned (not 8-aligned)
        // offset exactly as on the 32-bit target. The buffer is 0x60
        // bytes, not the 0x54 the slot needs on the target: on a 64-bit
        // host the method pointer written at +0x50 is 8 bytes wide.
        let mut vtable = [0u8; 0x60];
        let mut object: *const u8 = core::ptr::null();
        let mut handle: *mut u8 = core::ptr::null_mut();
        let mut value: u32 = VALUE_WORD;
        unsafe {
            (vtable.as_mut_ptr().add(VTABLE_SLOT_50) as *mut VtableSlot50Method)
                .write_unaligned(recording_method);
            object = vtable.as_ptr();
            handle = core::ptr::addr_of_mut!(object) as *mut u8;
            METHOD_CALLS = 0;

            let result = vtable_set_50_kind4(
                core::ptr::addr_of_mut!(handle) as *mut *mut u8,
                SELECTOR,
                core::ptr::addr_of_mut!(value),
                FORWARDED,
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(METHOD_CALLS, 4, "the whole chain reaches the method");
            assert_eq!(
                METHOD_OBJECT,
                core::ptr::addr_of_mut!(object) as *mut u8,
                "the method receives *handle (the double dereference)"
            );
            assert_eq!(METHOD_KIND, MESSAGE_KIND_4);
            assert_eq!(
                METHOD_DATA_WORD,
                SELECTOR | COMMIT_TAG,
                "the last call is the commit message"
            );
        }
    }

    // ---- vtable_set_50_commit_probe_kind4 (0x0811d6cc) --------------

    #[test]
    fn commit_probe_tags_selector_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_commit_probe_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 1, "exactly one dispatch (bl 0x0811d7fc)");
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "r1 is the kind word (mov r1, #0x4)");
            assert_eq!(
                DISPATCH_WORD0[0],
                SELECTOR | COMMIT_PROBE_TAG,
                "the message word is selector | 0xc0000000 (ldr/orr/str on the spill slot)"
            );
            assert_ne!(
                DISPATCH_WORD0[0], SELECTOR,
                "the raw selector is never sent - the data pointer reaches the \
                 tagged stack slot, not the argument (add r2, sp, #0x4 indirection)"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
        }
    }

    #[test]
    fn commit_probe_ors_instead_of_replacing_the_high_bits() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            // A selector that already carries each tag bit singly: the
            // original's `orr` keeps them and adds the missing one.
            vtable_set_50_commit_probe_kind4(fixture.handle_ptr(), SELECTOR | 0x8000_0000, 0);
            vtable_set_50_commit_probe_kind4(fixture.handle_ptr(), SELECTOR | 0x4000_0000, 0);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(DISPATCH_WORD0[0], SELECTOR | COMMIT_PROBE_TAG);
            assert_eq!(DISPATCH_WORD0[1], SELECTOR | COMMIT_PROBE_TAG);
        }
    }

    #[test]
    fn commit_probe_forwards_the_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = WRITE_ERR;

            let result =
                vtable_set_50_commit_probe_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(
                result, WRITE_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the dispatcher's r0 unbranched"
            );
        }
    }

    // ---- vtable_set_50_probe_kind4 (0x0811d6ec) --------------------

    #[test]
    fn probe_tags_selector_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_probe_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 1, "exactly one dispatch (bl 0x0811d7fc)");
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "r1 is the kind word (mov r1, #0x4)");
            assert_eq!(
                DISPATCH_WORD0[0],
                SELECTOR | PROBE_TAG,
                "the message word is selector | 0x40000000 (ldr/orr/str on the spill slot)"
            );
            assert_ne!(
                DISPATCH_WORD0[0], SELECTOR,
                "the raw selector is never sent - the data pointer reaches the \
                 tagged stack slot, not the argument (add r2, sp, #0x4 indirection)"
            );
            assert_ne!(
                DISPATCH_WORD0[0],
                SELECTOR | COMMIT_PROBE_TAG,
                "the probe sets ONLY 0x40000000, not the sibling's 0xc0000000"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
        }
    }

    #[test]
    fn probe_ors_instead_of_replacing_the_high_bits() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            // A selector that already carries the probe bit, and one
            // carrying the sibling's commit bit: the original's `orr`
            // keeps whatever is there and adds 0x40000000.
            vtable_set_50_probe_kind4(fixture.handle_ptr(), SELECTOR | 0x4000_0000, 0);
            vtable_set_50_probe_kind4(fixture.handle_ptr(), SELECTOR | 0x8000_0000, 0);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(DISPATCH_WORD0[0], SELECTOR | PROBE_TAG);
            assert_eq!(DISPATCH_WORD0[1], SELECTOR | COMMIT_PROBE_TAG);
        }
    }

    #[test]
    fn probe_forwards_the_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = OPEN_ERR;

            let result =
                vtable_set_50_probe_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(
                result, OPEN_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the dispatcher's r0 unbranched"
            );
        }
    }

    // ---- vtable_set_50_commit_kind4 (0x0811d340) -------------------

    #[test]
    fn commit_tags_selector_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_commit_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 1, "exactly one dispatch (bl 0x0811d7fc)");
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "r1 is the kind word (mov r1, #0x4)");
            assert_eq!(
                DISPATCH_WORD0[0],
                SELECTOR | COMMIT_TAG,
                "the message word is selector | 0x80000000 (ldr/orr/str on the spill slot)"
            );
            assert_ne!(
                DISPATCH_WORD0[0], SELECTOR,
                "the raw selector is never sent - the data pointer reaches the \
                 tagged stack slot, not the argument (add r2, sp, #0x4 indirection)"
            );
            assert_ne!(
                DISPATCH_WORD0[0],
                SELECTOR | COMMIT_PROBE_TAG,
                "the commit sets ONLY 0x80000000, not the sibling's 0xc0000000"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
        }
    }

    #[test]
    fn commit_ors_instead_of_replacing_the_high_bits() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            // A selector that already carries the commit bit, and one
            // carrying the sibling's probe bit: the original's `orr`
            // keeps whatever is there and adds 0x80000000.
            vtable_set_50_commit_kind4(fixture.handle_ptr(), SELECTOR | 0x8000_0000, 0);
            vtable_set_50_commit_kind4(fixture.handle_ptr(), SELECTOR | 0x4000_0000, 0);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(DISPATCH_WORD0[0], SELECTOR | COMMIT_TAG);
            assert_eq!(DISPATCH_WORD0[1], SELECTOR | COMMIT_PROBE_TAG);
        }
    }

    #[test]
    fn commit_forwards_the_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = WRITE_ERR;

            let result =
                vtable_set_50_commit_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(
                result, WRITE_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the dispatcher's r0 unbranched"
            );
        }
    }

    // ---- vtable_set_50_open_kind4 (0x0811d458) -------------------

    #[test]
    fn open_sends_the_bare_selector_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_open_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 1, "exactly one dispatch (bl 0x0811d7fc)");
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "r1 is the kind word (mov r1, #0x4)");
            assert_eq!(
                DISPATCH_WORD0[0], SELECTOR,
                "the message word is the bare selector - the 20-byte body has \
                 no ldr/orr/str tag sequence"
            );
            assert_ne!(
                DISPATCH_WORD0[0],
                SELECTOR | COMMIT_TAG,
                "open sets no commit tag, unlike the 0x0811d340 sibling"
            );
            assert_ne!(
                DISPATCH_WORD0[0],
                SELECTOR | PROBE_TAG,
                "open sets no probe tag, unlike the 0x0811d6ec sibling"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
        }
    }

    #[test]
    fn open_passes_even_tagged_selectors_through_untouched() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();

            // Selectors already carrying each sibling's tag bit: with
            // no `orr` in the body, whatever arrives goes out verbatim
            // (a commit sibling would add 0x80000000 to the second
            // call, a probe sibling 0x40000000 to the first).
            vtable_set_50_open_kind4(fixture.handle_ptr(), SELECTOR | COMMIT_TAG, 0);
            vtable_set_50_open_kind4(fixture.handle_ptr(), SELECTOR | PROBE_TAG, 0);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(DISPATCH_WORD0[0], SELECTOR | COMMIT_TAG);
            assert_eq!(DISPATCH_WORD0[1], SELECTOR | PROBE_TAG);
        }
    }

    #[test]
    fn open_forwards_the_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = OPEN_ERR;

            let result =
                vtable_set_50_open_kind4(fixture.handle_ptr(), SELECTOR, FORWARDED);

            assert_eq!(
                result, OPEN_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the dispatcher's r0 unbranched"
            );
        }
    }

    // ---- vtable_set_50_write_kind4 (0x0811d56c) -------------------

    #[test]
    fn write_sends_kind_word_then_value_message_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u32 = VALUE_WORD;
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_write_kind4(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(
                DISPATCH_CALLS, 2,
                "two dispatches (bl 0x0811d7fc + bleq 0x0811d7fc)"
            );
            // First dispatch: the kind word alone (r2 = sp + 4).
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(
                DISPATCH_KIND[0], MESSAGE_KIND_4,
                "r1 is the kind word (mov r1, #0x4)"
            );
            assert_eq!(
                DISPATCH_WORD0[0], MESSAGE_KIND_4,
                "the first message is the kind word itself (str r0, [sp, #4] with r0 = 4)"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
            // Second dispatch: the two-word {*value, 4} message (r2 = sp).
            assert_eq!(DISPATCH_HANDLE[1], fixture.handle_ptr());
            assert_eq!(DISPATCH_KIND[1], MESSAGE_KIND_4);
            assert_eq!(
                DISPATCH_WORD0[1], VALUE_WORD,
                "message word 0 is *value (ldr r0, [r1])"
            );
            assert_eq!(
                DISPATCH_WORD1[1], MESSAGE_KIND_4,
                "message word 1 is the kind word ([sp+4] = 4)"
            );
            assert_eq!(DISPATCH_EXTRA[1], FORWARDED);
        }
    }

    #[test]
    fn write_short_circuits_the_value_message_on_a_first_error() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u32 = VALUE_WORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = WRITE_ERR;

            let result =
                vtable_set_50_write_kind4(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(
                result, WRITE_ERR,
                "a nonzero first result returns verbatim (cmp r0, #0; no bleq)"
            );
            assert_eq!(
                DISPATCH_CALLS, 1,
                "the {{*value, 4}} message is gated on the first dispatch's success"
            );
            assert_eq!(DISPATCH_WORD0[0], MESSAGE_KIND_4);
        }
    }

    #[test]
    fn write_forwards_the_second_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u32 = VALUE_WORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[1] = WRITE_ERR;

            let result =
                vtable_set_50_write_kind4(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(
                result, WRITE_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the second dispatch's r0"
            );
        }
    }

    // ---- vtable_set_50_write_kind2 (0x0811d52c) -------------------

    const VALUE_HALFWORD: u16 = 0x3344;

    #[test]
    fn write_kind2_sends_kind_word_then_value_message_and_routes_arguments() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_write_kind2(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(
                DISPATCH_CALLS, 2,
                "two dispatches (bl 0x0811d7fc + bleq 0x0811d7fc)"
            );
            // First dispatch: the kind word alone (r2 = sp + 4).
            assert_eq!(
                DISPATCH_HANDLE[0],
                fixture.handle_ptr(),
                "r0 (handle) passes through untouched"
            );
            assert_eq!(
                DISPATCH_KIND[0], MESSAGE_KIND_4,
                "r1 stays kind 4 (mov r1, #0x4) even beside the kind-2 message word"
            );
            assert_eq!(
                DISPATCH_WORD0[0], MESSAGE_KIND_2,
                "the first message is the kind-2 word itself (str r0, [sp, #4] with r0 = 2)"
            );
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches the dispatcher's spill"
            );
            // Second dispatch: the two-word {*value, 2} message (r2 = sp).
            assert_eq!(DISPATCH_HANDLE[1], fixture.handle_ptr());
            assert_eq!(
                DISPATCH_KIND[1], MESSAGE_KIND_2,
                "the second dispatch's r1 carries the width kind (moveq r1, #0x2)"
            );
            assert_eq!(
                DISPATCH_WORD0[1], VALUE_HALFWORD as u32,
                "message word 0 is *value zero-extended (ldrh r0, [r1])"
            );
            assert_eq!(
                DISPATCH_WORD1[1], MESSAGE_KIND_2,
                "message word 1 is the kind-2 word ([sp+4] = 2)"
            );
            assert_eq!(DISPATCH_EXTRA[1], FORWARDED);
        }
    }

    #[test]
    fn write_kind2_loads_a_halfword_not_a_word() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        // The word under the value pointer has junk in its high half;
        // an `ldr` port would leak it into the message, `ldrh` must not.
        let wide: u32 = 0xaabb_0000 | VALUE_HALFWORD as u32;
        let value: *const u16 = core::ptr::addr_of!(wide) as *const u16;
        unsafe {
            install_recording_dispatch();

            let result = vtable_set_50_write_kind2(fixture.handle_ptr(), value, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(
                DISPATCH_WORD0[1], VALUE_HALFWORD as u32,
                "ldrh zero-extends: no high-half junk in message word 0"
            );
        }
    }

    #[test]
    fn write_kind2_short_circuits_the_value_message_on_a_first_error() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = WRITE_ERR;

            let result =
                vtable_set_50_write_kind2(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(
                result, WRITE_ERR,
                "a nonzero first result returns verbatim (cmp r0, #0; no bleq)"
            );
            assert_eq!(
                DISPATCH_CALLS, 1,
                "the {{*value, 2}} message is gated on the first dispatch's success"
            );
            assert_eq!(DISPATCH_WORD0[0], MESSAGE_KIND_2);
        }
    }

    #[test]
    fn write_kind2_forwards_the_second_dispatch_return_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[1] = WRITE_ERR;

            let result =
                vtable_set_50_write_kind2(fixture.handle_ptr(), &value, FORWARDED);

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(
                result, WRITE_ERR,
                "ldmia sp!, {{r2, r3, r4, pc}} returns the second dispatch's r0"
            );
        }
    }

    // ---- vtable_slot_50_dispatch (0x0811d7fc) direct, fake vtable ----

    const METHOD_ERR: u32 = 0x0bad_0009;

    static mut DIRECT_CALLS: usize = 0;
    static mut DIRECT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut DIRECT_KIND: u32 = 0;
    static mut DIRECT_DATA_WORD: u32 = 0;
    static mut DIRECT_EXTRA_PTR: *const usize = core::ptr::null();
    static mut DIRECT_RESULT: u32 = MOCK_OK;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn direct_method(
        object: *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        DIRECT_CALLS += 1;
        DIRECT_OBJECT = object;
        DIRECT_KIND = kind;
        DIRECT_DATA_WORD = (data as *const u32).read();
        DIRECT_EXTRA_PTR = extra;
        DIRECT_RESULT
    }

    /// Decoy for the slots neighbouring +0x50: any call through it
    /// proves the dispatcher loaded the wrong offset.
    unsafe extern "C" fn wrong_slot_method(
        _object: *mut u8,
        _kind: u32,
        _data: usize,
        _extra: *const usize,
    ) -> u32 {
        WRONG_SLOT_CALLS += 1;
        0xdead_0000
    }

    /// A fake handle -> object -> vtable chain (the
    /// `default_dispatch_body_loads_slot_50_and_calls_it` precedent).
    /// The vtable is a raw byte buffer so the +0x50 slot sits at a
    /// 4-aligned (not 8-aligned) offset exactly as on the 32-bit
    /// target; the buffer is 0x60 bytes, not the 0x54 the slot needs
    /// on the target, because on a 64-bit host each method pointer
    /// written into it is 8 bytes wide.
    struct FakeChain {
        vtable: [u8; 0x60],
        object: *const u8,
        handle: *mut u8,
    }

    impl FakeChain {
        fn new() -> Self {
            FakeChain {
                vtable: [0; 0x60],
                object: core::ptr::null(),
                handle: core::ptr::null_mut(),
            }
        }
        /// Writes `method` into the vtable at byte offset `slot`.
        fn install(&mut self, slot: usize, method: VtableSlot50Method) {
            unsafe {
                (self.vtable.as_mut_ptr().add(slot) as *mut VtableSlot50Method)
                    .write_unaligned(method);
            }
        }
        /// (Re)links object -> vtable and handle -> \&object. MUST run
        /// after the fixture reaches its final stack home: the handle
        /// slot points at the `object` field.
        fn link(&mut self) {
            self.object = self.vtable.as_ptr();
            self.handle = core::ptr::addr_of_mut!(self.object) as *mut u8;
        }
        fn handle_ptr(&mut self) -> *mut *mut u8 {
            core::ptr::addr_of_mut!(self.handle) as *mut *mut u8
        }
    }

    unsafe fn reset_direct_log() {
        DIRECT_CALLS = 0;
        DIRECT_OBJECT = core::ptr::null_mut();
        DIRECT_KIND = 0;
        DIRECT_DATA_WORD = 0;
        DIRECT_EXTRA_PTR = core::ptr::null();
        DIRECT_RESULT = MOCK_OK;
        WRONG_SLOT_CALLS = 0;
    }

    // The ported dispatcher is called directly, never through the
    // seams, so no SlotGuard is needed; the lock only serializes the
    // DIRECT_* recording statics.

    #[test]
    fn dispatch_double_dereferences_and_loads_slot_50_exactly() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_50, direct_method);
        // Decoys at the adjacent non-overlapping host slots: method
        // pointers are 8 bytes wide on the 64-bit host, so the twin
        // dispatcher's +0x4c slot (FUN_0811d7b0) cannot hold a decoy —
        // an 8-byte write there would overlap the +0x50 pointer.
        chain.install(VTABLE_SLOT_50 - 8, wrong_slot_method);
        chain.install(VTABLE_SLOT_50 + 8, wrong_slot_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            let result = vtable_slot_50_dispatch(
                chain.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(DIRECT_CALLS, 1, "exactly one blx");
            assert_eq!(
                WRONG_SLOT_CALLS, 0,
                "only vtable slot +0x50 is loaded (ldr r12, [r3, #0x50])"
            );
            assert_eq!(
                DIRECT_OBJECT,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "the method receives *handle (ldr r0, [r0])"
            );
            // vtable = *object (ldr r3, [r0]) is proven by the chain
            // itself: only the method installed in the vtable buffer
            // could have run.
            assert_eq!(DIRECT_KIND, MESSAGE_KIND_4, "r1 passes through verbatim");
            assert_eq!(DIRECT_DATA_WORD, VALUE_WORD, "r2 (data) passes through verbatim");
        }
    }

    #[test]
    fn dispatch_forwards_the_spilled_r3_pointer_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_50, direct_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            vtable_slot_50_dispatch(
                chain.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );

            // The original spills the incoming r3 and hands the method
            // &spilled_r3 (stmdb sp!, {r3} / mov r3, sp); the port's
            // callers pre-spill (see the function's deviations), so the
            // collapsed spill-and-point is a verbatim pointer
            // pass-through: same pointer in, same word observed.
            assert_eq!(
                DIRECT_EXTRA_PTR,
                core::ptr::addr_of!(forwarded),
                "the extra pointer reaches the method untouched"
            );
            assert_eq!(
                DIRECT_EXTRA_PTR.read(),
                FORWARDED,
                "the word the method observes through it is the forwarded r3"
            );
        }
    }

    #[test]
    fn dispatch_returns_the_methods_error_code_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_50, direct_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            DIRECT_RESULT = MOCK_OK;
            let ok = vtable_slot_50_dispatch(
                chain.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );
            DIRECT_RESULT = METHOD_ERR;
            let err = vtable_slot_50_dispatch(
                chain.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );

            assert_eq!(ok, MOCK_OK);
            assert_eq!(
                err, METHOD_ERR,
                "ldmia sp!, {{r12, pc}} returns the method's r0 unbranched"
            );
            assert_eq!(DIRECT_CALLS, 2);
        }
    }

    // ---- vtable_slot_4c_dispatch (0x0811d7b0) direct, fake vtable ----

    /// The "unsupported" status the caller at 0x0811d818 bails on
    /// silently (`cmp r0, #0x5; beq 0x0811d870`).
    const UNSUPPORTED_ERR: u32 = 0x5;

    /// A kind other than 4: unlike the slot +0x50 callers, this
    /// dispatcher's callers bind the kind themselves, so r1 must pass
    /// through generically.
    const OTHER_KIND: u32 = 7;

    #[test]
    fn dispatch_4c_double_dereferences_and_loads_slot_4c_exactly() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_4C, direct_method);
        // Decoys at the adjacent non-overlapping host slots: method
        // pointers are 8 bytes wide on the 64-bit host (an 8-byte
        // write at +0x4c spans 0x4c..0x54), so +0x44 and +0x54 are
        // the nearest decoy offsets that cannot overlap the slot
        // under test.
        chain.install(VTABLE_SLOT_4C - 8, wrong_slot_method);
        chain.install(VTABLE_SLOT_4C + 8, wrong_slot_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            let result = vtable_slot_4c_dispatch(
                chain.handle_ptr(),
                OTHER_KIND,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(DIRECT_CALLS, 1, "exactly one blx");
            assert_eq!(
                WRONG_SLOT_CALLS, 0,
                "only vtable slot +0x4c is loaded (ldr r12, [r3, #0x4c])"
            );
            assert_eq!(
                DIRECT_OBJECT,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "the method receives *handle (ldr r0, [r0])"
            );
            // vtable = *object (ldr r3, [r0]) is proven by the chain
            // itself: only the method installed in the vtable buffer
            // could have run.
            assert_eq!(
                DIRECT_KIND, OTHER_KIND,
                "r1 passes through verbatim — the dispatcher is generic in kind"
            );
            assert_eq!(DIRECT_DATA_WORD, VALUE_WORD, "r2 (data) passes through verbatim");
        }
    }

    #[test]
    fn dispatch_4c_forwards_the_spilled_r3_pointer_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_4C, direct_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            vtable_slot_4c_dispatch(
                chain.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of!(data_word) as usize,
                core::ptr::addr_of!(forwarded),
            );

            // The original spills the incoming r3 and hands the method
            // &spilled_r3 (stmdb sp!, {r3} / mov r3, sp); the port's
            // callers pre-spill (see the function's deviations), so
            // the collapsed spill-and-point is a verbatim pointer
            // pass-through: same pointer in, same word observed.
            assert_eq!(
                DIRECT_EXTRA_PTR,
                core::ptr::addr_of!(forwarded),
                "the extra pointer reaches the method untouched"
            );
            assert_eq!(
                DIRECT_EXTRA_PTR.read(),
                FORWARDED,
                "the word the method observes through it is the forwarded r3"
            );
        }
    }

    #[test]
    fn dispatch_4c_returns_the_methods_status_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_4C, direct_method);
        chain.link();
        let data_word: u32 = VALUE_WORD;
        let forwarded: usize = FORWARDED;
        unsafe {
            reset_direct_log();

            let mut results = [0u32; 3];
            for (i, status) in [MOCK_OK, UNSUPPORTED_ERR, METHOD_ERR]
                .iter()
                .enumerate()
            {
                DIRECT_RESULT = *status;
                results[i] = vtable_slot_4c_dispatch(
                    chain.handle_ptr(),
                    MESSAGE_KIND_4,
                    core::ptr::addr_of!(data_word) as usize,
                    core::ptr::addr_of!(forwarded),
                );
            }

            assert_eq!(results[0], MOCK_OK, "0 = success, the ok path");
            assert_eq!(
                results[1], UNSUPPORTED_ERR,
                "5 = \"unsupported\", the status the caller at 0x0811d818 \
                 bails on silently (cmp r0, #0x5; beq)"
            );
            assert_eq!(
                results[2], METHOD_ERR,
                "any other status returns verbatim (ldmia sp!, {{r12, pc}})"
            );
            assert_eq!(DIRECT_CALLS, 3);
        }
    }

    // ---- recording mocks for the query-4c-read seams ------------------

    const READ_ERR: u32 = 0x0bad_000a;
    const FINISH_CODE: u32 = 0x0bad_000b;
    const CAPACITY: u32 = 0x40;

    static mut QUERY_CALLS: usize = 0;
    static mut QUERY_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut QUERY_KIND: [u32; 8] = [0; 8];
    static mut QUERY_DATA: [usize; 8] = [0; 8];
    static mut QUERY_DATA_WORD: [u32; 8] = [0; 8];
    static mut QUERY_EXTRA: [usize; 8] = [0; 8];
    static mut QUERY_RESULTS: [u32; 8] = [MOCK_OK; 8];
    /// The available size the size query answers through the out-slot.
    static mut QUERY_SIZE: u32 = 0;

    unsafe extern "C" fn recording_read_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = QUERY_CALLS;
        QUERY_CALLS += 1;
        QUERY_HANDLE[call] = handle;
        QUERY_KIND[call] = kind;
        QUERY_DATA[call] = data;
        // Call 0's data is the out-slot (its entry word is the spilled
        // r3); call 1's data is the caller's buffer, which the tests
        // back with a real array — both reads are in-bounds.
        QUERY_DATA_WORD[call] = (data as *const u32).read();
        QUERY_EXTRA[call] = extra.read();
        if call == 0 {
            // The size query answers through the out-slot (a 32-bit
            // store, as the firmware method's `str` would be).
            (data as *mut u32).write(QUERY_SIZE);
        }
        QUERY_RESULTS[call]
    }

    static mut FINISH_CALLS: usize = 0;
    static mut FINISH_HANDLE: *mut *mut u8 = core::ptr::null_mut();
    static mut FINISH_OUT: *mut u32 = core::ptr::null_mut();
    static mut FINISH_BUFFER: usize = 0;
    static mut FINISH_SIZE: usize = 0;
    static mut FINISH_UNUSED: usize = 0;
    static mut FINISH_FORWARDED: usize = 0;
    static mut FINISH_RESULT: u32 = MOCK_OK;

    unsafe extern "C" fn recording_finish(
        handle: *mut *mut u8,
        out: *mut u32,
        unused: usize,
        forwarded: usize,
    ) -> u32 {
        FINISH_CALLS += 1;
        FINISH_HANDLE = handle;
        FINISH_OUT = out;
        // `out` addresses the {buffer, clamped_size} stack pair, whose
        // words are pointer-sized on this 64-bit host — step in usize.
        FINISH_BUFFER = (out as *const usize).read();
        FINISH_SIZE = (out as *const usize).add(1).read();
        FINISH_UNUSED = unused;
        FINISH_FORWARDED = forwarded;
        FINISH_RESULT
    }

    unsafe fn install_read_mocks() {
        QUERY_CALLS = 0;
        QUERY_RESULTS = [MOCK_OK; 8];
        QUERY_SIZE = 0;
        FINISH_CALLS = 0;
        FINISH_HANDLE = core::ptr::null_mut();
        FINISH_OUT = core::ptr::null_mut();
        FINISH_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_READ_DISPATCH)
            .write_volatile(recording_read_dispatch);
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_READ_FINISH)
            .write_volatile(recording_finish);
    }

    // ---- vtable_query_4c_kind4_read (0x0811d818) ----------------------

    #[test]
    fn query_read_unsupported_status_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            QUERY_RESULTS[0] = UNSUPPORTED_ERR;

            let status = vtable_query_4c_kind4_read(
                fixture.handle_ptr(),
                CAPACITY,
                buffer.as_mut_ptr(),
                FORWARDED,
            );

            assert_eq!(
                status, UNSUPPORTED_ERR,
                "cmp r0, #0x5; beq — the unsupported status returns verbatim"
            );
            assert_eq!(QUERY_CALLS, 1, "no read dispatch after a 5");
            assert_eq!(FINISH_CALLS, 0, "no finish call after a 5");
        }
    }

    #[test]
    fn query_read_query_error_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            QUERY_RESULTS[0] = METHOD_ERR;

            let status = vtable_query_4c_kind4_read(
                fixture.handle_ptr(),
                CAPACITY,
                buffer.as_mut_ptr(),
                FORWARDED,
            );

            assert_eq!(
                status, METHOD_ERR,
                "cmp r0, #0x0; bne — a hard error returns verbatim"
            );
            assert_eq!(QUERY_CALLS, 1, "no read dispatch after an error");
            assert_eq!(FINISH_CALLS, 0, "no finish call after an error");
        }
    }

    #[test]
    fn query_read_first_dispatch_args_and_initial_out_slot() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            QUERY_SIZE = 0x20;

            let status = vtable_query_4c_kind4_read(
                fixture.handle_ptr(),
                CAPACITY,
                buffer.as_mut_ptr(),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(QUERY_KIND[0], MESSAGE_KIND_4, "mov r1, #0x4");
            assert_eq!(QUERY_HANDLE[0], fixture.handle_ptr(), "r0 passes through");
            assert_eq!(
                QUERY_DATA_WORD[0], FORWARDED as u32,
                "the out-slot's initial word is the entry r3 spill (stmdb {{r2, r3, ...}})"
            );
            assert_eq!(
                QUERY_EXTRA[0], FORWARDED,
                "the dispatcher's stmdb sp!, {{r3}} spill forwards the same word"
            );
        }
    }

    #[test]
    fn query_read_clamps_the_size_unsigned_and_routes_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            // (reported size, capacity, expected read size): equal and
            // below pass through unchanged, above clamps, and a size
            // with the top bit set still clamps — the `strhi` compare
            // is unsigned.
            for (reported, capacity, expected) in [
                (0x40u32, 0x40u32, 0x40u32),
                (0x20, 0x40, 0x20),
                (0x41, 0x40, 0x40),
                (0x8000_0000, 0x40, 0x40),
                (0, 0x40, 0),
            ] {
                QUERY_CALLS = 0;
                FINISH_CALLS = 0;
                QUERY_SIZE = reported;

                let status = vtable_query_4c_kind4_read(
                    fixture.handle_ptr(),
                    capacity,
                    buffer.as_mut_ptr(),
                    FORWARDED,
                );

                assert_eq!(status, MOCK_OK, "reported {reported:#x}");
                assert_eq!(QUERY_CALLS, 2, "query then read, reported {reported:#x}");
                assert_eq!(
                    QUERY_KIND[1], expected,
                    "ldr r1, [sp, #4] — the read's middle argument is the \
                     clamped size (reported {reported:#x}, capacity {capacity:#x})"
                );
                assert_eq!(
                    QUERY_DATA[1],
                    buffer.as_mut_ptr() as usize,
                    "mov r2, r6 — the read's data is the caller's buffer (arg3)"
                );
                assert_eq!(QUERY_HANDLE[1], fixture.handle_ptr());
                assert_eq!(QUERY_EXTRA[1], FORWARDED);
                assert_eq!(FINISH_CALLS, 1);
                assert_eq!(
                    FINISH_SIZE, expected as usize,
                    "the pair's size word the finish message carries is clamped too"
                );
            }
        }
    }

    #[test]
    fn query_read_read_error_skips_the_finish() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            QUERY_SIZE = 0x20;
            QUERY_RESULTS[1] = READ_ERR;

            let status = vtable_query_4c_kind4_read(
                fixture.handle_ptr(),
                CAPACITY,
                buffer.as_mut_ptr(),
                FORWARDED,
            );

            assert_eq!(
                status, READ_ERR,
                "the read dispatch's error returns verbatim"
            );
            assert_eq!(QUERY_CALLS, 2);
            assert_eq!(
                FINISH_CALLS, 0,
                "bleq — the finish fires only on a zero read status"
            );
        }
    }

    #[test]
    fn query_read_finish_args_and_final_return() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 0x100];
        unsafe {
            install_read_mocks();
            QUERY_SIZE = 0x20;
            FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_kind4_read(
                fixture.handle_ptr(),
                CAPACITY,
                buffer.as_mut_ptr(),
                FORWARDED,
            );

            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the function's return value"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r5");
            assert!(!FINISH_OUT.is_null(), "moveq r1, sp — out is the pair base");
            assert_eq!(
                FINISH_BUFFER,
                buffer.as_mut_ptr() as usize,
                "pair[0] is the entry r2 spill — the caller's buffer pointer"
            );
            assert_eq!(FINISH_SIZE, 0x20, "pair[1] is the clamped size");
            assert_eq!(
                FINISH_UNUSED, 0,
                "r2 is dead across the read dispatch and the thunk discards \
                 it (mov r2, r1); the port passes 0"
            );
            assert_eq!(FINISH_FORWARDED, FORWARDED);
        }
    }

    // ---- vtable_set_50_write_indirect_kind4 (0x0811d874) -------------

    #[test]
    fn indirect_write_first_dispatch_error_skips_the_second() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = OPEN_ERR;

            let result = vtable_set_50_write_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                FORWARDED,
            );

            assert_eq!(
                result, OPEN_ERR,
                "a nonzero first status returns verbatim (cmp r0, #0x0; no bleq)"
            );
            assert_eq!(
                DISPATCH_CALLS, 1,
                "the second dispatch fires only on a zero first status"
            );
        }
    }

    #[test]
    fn indirect_write_success_redispatches_with_exact_args() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();

            let result = vtable_set_50_write_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                FORWARDED,
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 2, "select message, then the write");
            // First dispatch: the open-shaped kind-4 message carrying
            // the selector by pointer (str r1, [sp]; mov r2, sp).
            assert_eq!(DISPATCH_HANDLE[0], fixture.handle_ptr(), "moveq/mov r0, r5");
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "mov r1, #0x4");
            assert_eq!(
                DISPATCH_WORD0[0], SELECTOR,
                "the first message word is the bare selector"
            );
            // Second dispatch: generic — the selector is the middle
            // (kind) argument, arg3 the data pointer (moveq r1, r4 /
            // moveq r2, r6).
            assert_eq!(DISPATCH_HANDLE[1], fixture.handle_ptr());
            assert_eq!(
                DISPATCH_KIND[1], SELECTOR,
                "the selector doubles as the second dispatch's kind"
            );
            assert_eq!(
                DISPATCH_WORD0[1], payload[0],
                "the data argument is the caller's arg3 pointer, verbatim"
            );
            assert_eq!(DISPATCH_WORD1[1], payload[1]);
        }
    }

    #[test]
    fn indirect_write_arg4_spill_reaches_only_the_first_dispatch() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();

            vtable_set_50_write_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                FORWARDED,
            );

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "nothing before the first bl touches r3 — the entry arg4 is \
                 forwarded into the first dispatcher's stmdb {{r3}} spill"
            );
            assert_eq!(
                DISPATCH_EXTRA[1], 0,
                "r3 is dead across the first dispatch (method-clobbered; its \
                 entry spill slot was overwritten with the selector) — the \
                 port passes a zero word for the unobservable argument"
            );
        }
    }

    #[test]
    fn indirect_write_forwards_the_second_status_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[1] = WRITE_ERR;

            let result = vtable_set_50_write_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                FORWARDED,
            );

            assert_eq!(DISPATCH_CALLS, 2);
            assert_eq!(
                result, WRITE_ERR,
                "ldmia sp!, {{r3, r4, r5, r6, r7, pc}} returns the last \
                 dispatch's r0 verbatim"
            );
        }
    }
    // ---- vtable_set_50_indirect_kind4 (0x0811d2f8) -------------------

    const WRITE_SELECTOR: u32 = 0x0dec_0ade;

    #[test]
    fn indirect_pipeline_open_error_short_circuits_before_write_and_commit() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = OPEN_ERR;

            let result = vtable_set_50_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                WRITE_SELECTOR,
            );

            assert_eq!(result, OPEN_ERR, "open's status propagates verbatim");
            assert_eq!(DISPATCH_CALLS, 1, "write and commit are not reached");
            assert_eq!(DISPATCH_HANDLE[0], fixture.handle_ptr());
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4);
            assert_eq!(DISPATCH_WORD0[0], SELECTOR, "open receives arg2 (r1)");
            assert_eq!(
                DISPATCH_EXTRA[0],
                WRITE_SELECTOR as usize,
                "entry arg4 (r3) reaches open's dispatcher spill"
            );
        }
    }

    #[test]
    fn indirect_pipeline_write_error_skips_commit() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[2] = WRITE_ERR;

            let result = vtable_set_50_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                WRITE_SELECTOR,
            );

            assert_eq!(result, WRITE_ERR, "write's status propagates verbatim");
            assert_eq!(
                DISPATCH_CALLS, 3,
                "open plus both write dispatches run; commit is skipped"
            );
            assert_eq!(DISPATCH_KIND[2], WRITE_SELECTOR);
            assert_eq!(
                DISPATCH_WORD0[2], payload[0],
                "arg3 (r2) routes to write's data argument"
            );
        }
    }

    #[test]
    fn indirect_pipeline_runs_in_order_with_exact_argument_routing() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let payload = [VALUE_WORD, 0xa5a5_a5a5];
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[3] = COMMIT_CODE;

            let result = vtable_set_50_indirect_kind4(
                fixture.handle_ptr(),
                SELECTOR,
                payload.as_ptr() as *const u8,
                WRITE_SELECTOR,
            );

            assert_eq!(
                result, COMMIT_CODE,
                "the commit tail call's status becomes this function's return"
            );
            assert_eq!(DISPATCH_CALLS, 4, "open 1 + indirect write 2 + commit 1");
            for call in 0..4 {
                assert_eq!(DISPATCH_HANDLE[call], fixture.handle_ptr());
            }

            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "open binds kind 4");
            assert_eq!(DISPATCH_WORD0[0], SELECTOR, "arg2 routes to open");
            assert_eq!(
                DISPATCH_EXTRA[0],
                WRITE_SELECTOR as usize,
                "entry arg4 is open's forwarded r3"
            );

            assert_eq!(
                DISPATCH_KIND[1], MESSAGE_KIND_4,
                "the indirect write's first message binds kind 4"
            );
            assert_eq!(
                DISPATCH_WORD0[1], WRITE_SELECTOR,
                "arg4 routes to the indirect write's selector message"
            );
            assert_eq!(
                DISPATCH_EXTRA[1], SELECTOR as usize,
                "open's pop reloads r3 from its selector spill before the write"
            );

            assert_eq!(
                DISPATCH_KIND[2], WRITE_SELECTOR,
                "the indirect write routes arg4 as its generic-dispatch kind"
            );
            assert_eq!(
                DISPATCH_WORD0[2], payload[0],
                "arg3 routes as the indirect write's data pointer"
            );
            assert_eq!(DISPATCH_WORD1[2], payload[1]);
            assert_eq!(
                DISPATCH_EXTRA[2], 0,
                "the indirect write's second dispatch models its dead r3"
            );

            assert_eq!(DISPATCH_KIND[3], MESSAGE_KIND_4, "commit binds kind 4");
            assert_eq!(
                DISPATCH_WORD0[3],
                SELECTOR | COMMIT_TAG,
                "the original selector is restored for the tagged commit"
            );
            assert_eq!(
                DISPATCH_EXTRA[3],
                WRITE_SELECTOR as usize,
                "the write's overwritten entry spill restores arg4 into r3"
            );
        }
    }

    // ---- vtable_set_50_kind2 (0x0811d64c): three-stage u16 pipeline ----

    #[test]
    fn kind2_open_error_short_circuits_before_write_and_commit() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[0] = OPEN_ERR;

            let result =
                vtable_set_50_kind2(fixture.handle_ptr(), SELECTOR, &value, FORWARDED);

            assert_eq!(result, OPEN_ERR, "open's status propagates verbatim");
            assert_eq!(DISPATCH_CALLS, 1, "write and commit are not reached");
            assert_eq!(DISPATCH_HANDLE[0], fixture.handle_ptr());
            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "open binds kind 4");
            assert_eq!(DISPATCH_WORD0[0], SELECTOR, "arg2 (r1) routes to open");
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 reaches open's dispatcher spill verbatim"
            );
        }
    }

    #[test]
    fn kind2_write_error_skips_commit_and_routes_the_value_pointer() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[1] = WRITE_ERR;

            let result =
                vtable_set_50_kind2(fixture.handle_ptr(), SELECTOR, &value, FORWARDED);

            assert_eq!(result, WRITE_ERR, "write's status propagates verbatim");
            assert_eq!(
                DISPATCH_CALLS, 2,
                "open plus the write's kind-word dispatch run; the value message \
                 and the commit are skipped"
            );
            assert_eq!(DISPATCH_KIND[1], MESSAGE_KIND_4);
            assert_eq!(
                DISPATCH_WORD0[1], MESSAGE_KIND_2,
                "the write's first message is the kind-2 word"
            );
            assert_eq!(
                DISPATCH_EXTRA[1], SELECTOR as usize,
                "open's pop reloads r3 from its selector spill before the write"
            );
        }
    }

    #[test]
    fn kind2_loads_the_value_as_a_halfword() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        // The word under the value pointer has junk in its high half; a
        // word-loading (`ldr`) pipeline would leak it into the message,
        // the original's `ldrh` write stage must not.
        let wide: u32 = 0xaabb_0000 | VALUE_HALFWORD as u32;
        let value: *const u16 = core::ptr::addr_of!(wide) as *const u16;
        unsafe {
            install_recording_dispatch();

            let result =
                vtable_set_50_kind2(fixture.handle_ptr(), SELECTOR, value, FORWARDED);

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 4);
            assert_eq!(
                DISPATCH_WORD0[2], VALUE_HALFWORD as u32,
                "the value message word is zero-extended: no high-half junk"
            );
        }
    }

    #[test]
    fn kind2_runs_in_order_with_exact_argument_routing() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let value: u16 = VALUE_HALFWORD;
        unsafe {
            install_recording_dispatch();
            DISPATCH_RESULTS[3] = COMMIT_CODE;

            let result =
                vtable_set_50_kind2(fixture.handle_ptr(), SELECTOR, &value, FORWARDED);

            assert_eq!(
                result, COMMIT_CODE,
                "the commit tail call's status becomes this function's return"
            );
            assert_eq!(DISPATCH_CALLS, 4, "open 1 + kind-2 write 2 + commit 1");
            for call in 0..4 {
                assert_eq!(DISPATCH_HANDLE[call], fixture.handle_ptr());
            }

            assert_eq!(DISPATCH_KIND[0], MESSAGE_KIND_4, "open binds kind 4");
            assert_eq!(DISPATCH_WORD0[0], SELECTOR, "arg2 routes to open");
            assert_eq!(
                DISPATCH_EXTRA[0], FORWARDED,
                "the caller's r3 is open's forwarded spill"
            );

            assert_eq!(
                DISPATCH_KIND[1], MESSAGE_KIND_4,
                "the kind-2 write's first dispatch still binds kind 4"
            );
            assert_eq!(
                DISPATCH_WORD0[1], MESSAGE_KIND_2,
                "its message is the kind-2 word"
            );
            assert_eq!(
                DISPATCH_EXTRA[1], SELECTOR as usize,
                "open's epilogue leaves the selector in r3 for the write"
            );

            assert_eq!(
                DISPATCH_KIND[2], MESSAGE_KIND_2,
                "the value dispatch carries the width kind"
            );
            assert_eq!(
                DISPATCH_WORD0[2], VALUE_HALFWORD as u32,
                "arg3 (r2) reaches only stage 2, loaded as a halfword"
            );
            assert_eq!(DISPATCH_WORD1[2], MESSAGE_KIND_2);
            assert_eq!(DISPATCH_EXTRA[2], SELECTOR as usize);

            assert_eq!(DISPATCH_KIND[3], MESSAGE_KIND_4, "commit binds kind 4");
            assert_eq!(
                DISPATCH_WORD0[3],
                SELECTOR | COMMIT_TAG,
                "the original selector is restored for the tagged commit"
            );
            assert_eq!(
                DISPATCH_EXTRA[3],
                MESSAGE_KIND_2 as usize,
                "the write's kind-word store overwrites its r3 spill slot"
            );
        }
    }
}

