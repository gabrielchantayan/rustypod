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
//! - **open** — `FUN_0811d458` @ 0x0811d458 (16 bytes):
//!   `push {r0, r1, r4, lr}; add r2, sp, #4; mov r1, #4; bl 0x0811d7fc`
//!   sends the **bare selector** by pointer: `dispatch(handle, 4,
//!   &selector)`.
//! - **write** — `FUN_0811d56c` @ 0x0811d56c (64 bytes): reuses its
//!   `push {r2, r3, ...}` spill slots as a two-word message —
//!   `[sp+4] = 4`, `[sp+0] = *value` — then sends the kind word first
//!   (`dispatch(handle, 4, &4)`) and, only when that returns 0, the
//!   two-word `{*value, 4}` message (`dispatch(handle, 4, sp)`),
//!   returning the last result.
//! - **commit** — `FUN_0811d340` @ 0x0811d340 (28 bytes; the tail-call
//!   thunk Ghidra's reference C shows inlined as
//!   `FUN_0811d7fc(param_1, 4, &stack)`): `push {r0, r1, r4, lr};
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
//! `FUN_0811d7b0`:
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

/// The message kind this whole block binds (the value width, 4 bytes —
/// the sibling 0x0811d64c/0x0811d52c pair binds kind 2 for u16 values).
const MESSAGE_KIND_4: u32 = 4;

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

/// vtable_slot_50_dispatch — original: `FUN_0811d7fc` @ 0x0811d7fc (28
/// bytes; **15 `bl` call sites**, grep on `decomp/osos.asm`, all inside
/// this message-family thunk cluster: the commit stage 0x0811d340, the
/// eight sites 0x0811d390..0x0811d440 in the multi-message routine
/// 0x0811d360, the open stage 0x0811d458, the kind-2 / kind-4 write
/// stages 0x0811d52c / 0x0811d56c, the tag thunks 0x0811d6cc /
/// 0x0811d6ec and the routine at 0x0811d880).
///
/// The shared vtable dispatcher of the slot +0x50 message family — the
/// slot +0x50 twin of the still-unported `FUN_0811d7b0` @ 0x0811d7b0
/// (`util/vtable_query.rs`), which differs only in the slot offset:
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
}

