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

/// Byte offset of the dispose method inside the object's vtable — the
/// slot [`vtable_slot_04_dispose`] (`FUN_0811d7cc` @ 0x0811d7cc)
/// loads; the teardown counterpart of the message-dispatch slots
/// [`VTABLE_SLOT_4C`] / [`VTABLE_SLOT_50`].
const VTABLE_SLOT_04: usize = 0x4;

/// The message kind this whole block binds (the value width, 4 bytes —
/// the sibling 0x0811d64c/0x0811d52c pair binds kind 2 for u16 values).
const MESSAGE_KIND_4: u32 = 4;

/// The message kind the kind-2 sibling binds (the value width, 2
/// bytes) — the message word and the SECOND dispatch of
/// [`vtable_set_50_write_kind2`] (0x0811d52c); its first dispatch
/// still goes out with kind 4, exactly like the kind-4 sibling.
const MESSAGE_KIND_2: u32 = 2;
/// The byte-wide message kind used by
/// [`vtable_set_50_write_eight_byte_record`].
const MESSAGE_KIND_1: u32 = 1;

/// The selector opened and committed by
/// [`vtable_set_50_write_eight_byte_record`].
const EIGHT_BYTE_RECORD_SELECTOR: u32 = 0x12;

/// The number of payload bytes serialized by
/// [`vtable_set_50_write_eight_byte_record`].
const EIGHT_BYTE_RECORD_PAYLOAD_LEN: u32 = 8;

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

/// The vtable method signature at slot +0x4: `dispose(object)`. The
/// original's `blx r1` passes only r0 (the object) — r1 holds the
/// method pointer itself and r2/r3 are the caller's leftovers (the
/// frame spills `{r4, lr}` only, so unlike the dispatcher siblings
/// nothing is forwarded) — and any method return value is discarded
/// (r0 is reloaded with 0), so the method is modeled as a
/// single-argument, unit-returning call.
type VtableSlot04Method = unsafe extern "C" fn(object: *mut u8);

/// vtable_slot_04_dispose — original: `FUN_0811d7cc` @ 0x0811d7cc
/// (48 bytes; **14 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0810ab00, 0x0811b278, 0x0811c798, 0x0811d8c8 — inside the
/// wrapper thunk [`vtable_file_record_dispose`] (0x0811d8c0, ported
/// in this module), which disposes and then returns the handle —
/// 0x08136840, 0x0815e904, 0x081affb4,
/// 0x081b0174, 0x081bc82c and the 5-site cluster
/// 0x08285738..0x08285938; several sit in the same routines that
/// drive this family's kind-4 probe/set thunks — this is the
/// family's teardown counterpart).
///
/// The NULL-guarded dispose thunk sitting between the two ported
/// dispatchers [`vtable_slot_4c_dispatch`] (0x0811d7b0) and
/// [`vtable_slot_50_dispatch`] (0x0811d7fc) — not a third dispatch
/// variant (it binds no kind and sends no message) but the handle
/// teardown the message-family callers run when they are done:
///
/// ```text
/// 0811d7cc  stmdb sp!, {r4, lr}   @ frame
/// 0811d7d0  mov   r4, r0          @ save handle
/// 0811d7d4  ldr   r0, [r0, #0x0]  @ object = *handle
/// 0811d7d8  cmp   r0, #0x0
/// 0811d7dc  beq   0x0811d7f4      @ NULL handle -> skip, return 0
/// 0811d7e0  ldr   r1, [r0, #0x0]  @ vtable = *object
/// 0811d7e4  ldr   r1, [r1, #0x4]  @ method = vtable->slot_04
/// 0811d7e8  blx   r1              @ dispose(object)
/// 0811d7ec  mov   r0, #0x0
/// 0811d7f0  str   r0, [r4, #0x0]  @ *handle = NULL
/// 0811d7f4  mov   r0, #0x0        @ return 0 (both paths)
/// 0811d7f8  ldmia sp!, {r4, pc}
/// ```
///
/// If `*handle` is non-NULL: the same double dereference as the
/// dispatchers — handle to object to vtable — then the method at
/// vtable slot **+0x4** is invoked with the object in r0, the handle
/// is NULLed (`str r0, [r4]`) AFTER the call, and 0 returns. A NULL
/// `*handle` skips the call and the store entirely (`beq` straight
/// to the `mov r0, #0` epilogue) and still returns 0. Every observed
/// call site ignores the return value (the 0x0811d8c0 wrapper
/// overwrites r0 with the handle; the others branch on nothing).
///
/// # Deviations
///
/// - **The slot +0x4 method is modeled as a single-argument,
///   unit-returning call.** At the `blx` only r0 is meaningful (r1
///   holds the method pointer itself, r2/r3 are the caller's
///   leftovers — the frame spills no r3, so there is no `forwarded`
///   parameter, unlike the dispatcher siblings), and any method
///   return value is discarded: r0 is reloaded with 0.
/// - **The slot load uses `read_unaligned`** so the layout stays
///   byte-exact on a 64-bit host: 0x4 is 4-aligned but not 8-aligned
///   (the [`vtable_slot_50_dispatch`] precedent).
/// - **No seam.** No ported caller exists; host tests call the body
///   directly on a fake vtable (the dispatcher-test precedent).
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d7cc_FUN_0811d7cc.c` drops the object
///   argument of the indirect call (`(**(code **)(*(int *)*param_1 +
///   4))()`), showing a no-arg method — the disassembly loads
///   r0 = *param_1 (the object) before `blx r1`. The port follows
///   the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_04_dispose(handle: *mut *mut u8) -> u32 {
    let object = handle.read();
    if !object.is_null() {
        let vtable = (object as *const *const u8).read();
        let method =
            (vtable.add(VTABLE_SLOT_04) as *const VtableSlot04Method).read_unaligned();
        method(object);
        handle.write(core::ptr::null_mut());
    }
    0
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

/// vtable_set_50_write_eight_byte_record — original: `FUN_0811d360` @
/// 0x0811d360 (248 bytes; **3 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x0813662c, 0x0813666c, and 0x081d147c).
///
/// Serializes the eight payload bytes of a padded record through the
/// slot +0x50 message protocol. It opens selector 0x12, sends a kind-4
/// payload-length word of 8, sends the five byte fields at offsets
/// 0..4 as kind-1 messages, sends the u16 field at offset 6 as kind 2,
/// sends the final byte at offset 8 as kind 1, then commits selector
/// 0x12. Every call is guarded: its first nonzero status returns
/// verbatim and prevents every later message and the commit.
///
/// The eight direct dispatch sites are 0x0811d390 (kind 4, `&8`),
/// 0x0811d3a8..0x0811d408 (kind 1, `record + 0` through
/// `record + 4`), 0x0811d428 (kind 2, `&u16(record + 6)`), and
/// 0x0811d440 (kind 1, `record + 8`). The callers at 0x0813662c /
/// 0x0813666c pass records ten bytes apart, confirming the skipped
/// padding at offsets 5 and 9.
///
/// # Deviations
///
/// - **Ported callees are called directly.**
///   [`vtable_set_50_open_kind4`] (0x0811d458) and
///   [`vtable_set_50_commit_kind4`] (0x0811d340) are already ported;
///   the eight original `bl 0x0811d7fc` calls use the retained
///   [`VTABLE_SLOT_50_DISPATCH`] seam, so host tests observe the full
///   sequence without a new seam.
/// - **The fourth-register forwarding is modeled explicitly.** Open's
///   dispatcher sees the caller's r3 (`forwarded`); its epilogue
///   reloads r3 with selector 0x12, which reaches the length dispatch.
///   Thereafter each dispatcher leaves r3 method-clobbered, so the
///   remaining messages and commit receive a zero `dead_slot`, as in
///   [`vtable_set_50_write_indirect_kind4`]'s unobservable-r3
///   precedent.
/// - **The return type is `u32`, not the reference C's `void`.** All
///   three callers branch on r0, and the assembly keeps each failing
///   result in r0 or replaces a final zero with commit's result.
///   `decomp/c/010/0811d360_FUN_0811d360.c` also mistakes the entry
///   r2/r3 spills for live local parameters; r2 is overwritten before
///   use. The port follows the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_set_50_write_eight_byte_record(
    handle: *mut *mut u8,
    record: *const u8,
    forwarded: usize,
) -> u32 {
    let result = vtable_set_50_open_kind4(handle, EIGHT_BYTE_RECORD_SELECTOR, forwarded);
    if result != 0 {
        return result;
    }

    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_50_DISPATCH));
    let payload_len = EIGHT_BYTE_RECORD_PAYLOAD_LEN;
    // Open's `ldmia sp!, {r2, r3, r4, pc}` reloads its spilled selector
    // into r3, so the first direct dispatch sees 0x12 in its spill.
    let selector_slot = EIGHT_BYTE_RECORD_SELECTOR as usize;
    let result = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of!(payload_len) as usize,
        core::ptr::addr_of!(selector_slot),
    );
    if result != 0 {
        return result;
    }

    // `vtable_slot_50_dispatch` hands r3 to a vtable method and pops
    // into r12, leaving later r3 values method-clobbered.
    let dead_slot = 0usize;
    for offset in 0..5 {
        let result = dispatch(
            handle,
            MESSAGE_KIND_1,
            record.add(offset) as usize,
            core::ptr::addr_of!(dead_slot),
        );
        if result != 0 {
            return result;
        }
    }

    let halfword_slot = record.add(6).cast::<u16>().read_unaligned();
    let result = dispatch(
        handle,
        MESSAGE_KIND_2,
        core::ptr::addr_of!(halfword_slot) as usize,
        core::ptr::addr_of!(dead_slot),
    );
    if result != 0 {
        return result;
    }

    let result = dispatch(
        handle,
        MESSAGE_KIND_1,
        record.add(8) as usize,
        core::ptr::addr_of!(dead_slot),
    );
    if result != 0 {
        return result;
    }

    vtable_set_50_commit_kind4(handle, EIGHT_BYTE_RECORD_SELECTOR, dead_slot)
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
/// (object + 0x1c / r5 + 0x18), r0 to a stack handle, and both test
/// the returned status (`movs r4, r0`, then `bne` at the first site,
/// `strbeq` + `beq` at the second).
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

/// Indirect dispatch for the two slot +0x4c dispatches of
/// [`vtable_query_4c_read_scalar_kind4`], wired to this module's
/// ported [`vtable_slot_4c_dispatch`] (original: `FUN_0811d7b0` @
/// 0x0811d7b0; the [`VTABLE_QUERY_4C_READ_DISPATCH`] pattern — the
/// seam is retained for hookability, the dispatcher's `blx` targets
/// are firmware vtable methods, and a role-specific name keeps host
/// tests from racing the sibling's parallel tests).
pub static mut VTABLE_QUERY_4C_SCALAR_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// Indirect dispatch for the closing query-thunk call of
/// [`vtable_query_4c_read_scalar_kind4`], wired to the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` (original:
/// `FUN_0811d46c` @ 0x0811d46c; the [`VTABLE_QUERY_4C_READ_FINISH`]
/// pattern — a module-local seam keeps host tests able to intercept
/// it without swapping util's `VTABLE_SLOT_4C_DISPATCH` static, which
/// would race util's own parallel tests).
pub static mut VTABLE_QUERY_4C_SCALAR_FINISH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    out: *mut u32,
    unused: usize,
    forwarded: usize,
) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;

/// vtable_query_4c_read_scalar_body — original: shared scalar-read
/// body @ 0x0811d5ac (80 bytes, 0x0811d5ac–0x0811d5fb; **Ghidra-
/// missed** — absent from `decomp/functions.csv`, its bytes folded
/// into the `FUN_0811d718` csv row (92 bytes = this body + the
/// 12-byte kind-4 entry thunk) and decompiled inline under both
/// `decomp/c/010/0811d70c_FUN_0811d70c.c` /
/// `0811d718_FUN_0811d718.c`; **0 `bl` call sites**, exactly 2 tail
/// `b 0x0811d5ac` sites, grep on `decomp/osos.asm`: 0x0811d714 from
/// [`vtable_query_4c_read_scalar_kind2`] and 0x0811d720 from
/// [`vtable_query_4c_read_scalar_kind4`]).
///
/// The shared body BOTH scalar-read entry thunks tail-call after
/// binding the read's kind in r1 (2 = u16 property, 4 = u32
/// property — the write stages' kind-encodes-value-width
/// convention):
///
/// ```text
/// 0811d5ac  stmdb sp!, {r2, r3, r4, r5, r6, lr}  @ pair = {out, r3}
/// 0811d5b0  mov   r6, r2            @ save out
/// 0811d5b4  mov   r5, r1            @ save the thunk-bound kind
/// 0811d5b8  mov   r1, #0x4          @ kind 4 — probe is ALWAYS kind 4
/// 0811d5bc  add   r2, sp, #0x4      @ probe out-slot = &pair[1]
/// 0811d5c0  mov   r4, r0            @ save handle
/// 0811d5c4  bl    0x0811d7b0        @ probe: dispatch(handle, 4, &pair[1])
/// 0811d5c8  cmp   r0, #0x5
/// 0811d5cc  beq   0x0811d5f8        @ unsupported -> return status
/// 0811d5d0  cmp   r0, #0x0
/// 0811d5d4  bne   0x0811d5f8        @ hard error -> return status
/// 0811d5d8  mov   r2, r6            @ data = out
/// 0811d5dc  mov   r1, r5            @ kind = thunk-bound
/// 0811d5e0  mov   r0, r4
/// 0811d5e4  bl    0x0811d7b0        @ read: dispatch(handle, kind, out)
/// 0811d5e8  cmp   r0, #0x0
/// 0811d5ec  moveq r1, sp            @ message = &pair[0]
/// 0811d5f0  moveq r0, r4
/// 0811d5f4  bleq  0x0811d46c        @ finish: vtable_query_4c_kind4(handle, &pair)
/// 0811d5f8  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// ```
///
/// Three messages to the slot +0x4c dispatcher
/// ([`vtable_slot_4c_dispatch`], 0x0811d7b0). The **probe** sends
/// kind 4 (hardcoded `mov r1, #0x4` — only the read carries the
/// thunk-bound width) with `&pair[1]` — the entry r3 spill slot —
/// as a scratch out-slot whose word is never read back; status **5**
/// means "unsupported" and bails, any other nonzero is a hard error,
/// both returning verbatim. The **read** re-dispatches with the
/// thunk-bound kind (`mov r1, r5`) and the caller's `out` pointer
/// as data; the method stores the property word through it. Only on
/// a zero read status does the **finish** `bleq` fire: 0x0811d46c is
/// the PORTED kind-4 query thunk `util/vtable_query.rs`
/// `vtable_query_4c_kind4`, re-dispatching kind 4 with the one-word
/// `{out}` pair as the message; its error code becomes the return
/// value.
///
/// # Deviations
///
/// - **Both callees are ported** ([`vtable_slot_4c_dispatch`] in this
///   module, `vtable_query_4c_kind4` in util/vtable_query.rs); the
///   calls route through the existing
///   [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] seams (the
///   [`VTABLE_SLOT_50_DISPATCH`] precedent — the seams are retained
///   for hookability, wired to the ported implementations).
/// - **arg3 (r3) is modeled as `forwarded`** — the family convention:
///   no call site sets r3 deliberately. It doubles as the INITIAL
///   content of the probe out-slot `pair[1]` (the entry spill), which
///   the probe method may overwrite, and as the word the probe
///   dispatcher's `stmdb sp!, {r3}` spill exposes to the method.
/// - **r3 is DEAD for the read dispatch and the finish call** (the
///   [`vtable_set_50_write_indirect_kind4`] refinement): the probe
///   method clobbers r0–r3 across the first `bl`, nothing reloads r3,
///   and the spill slot it came from is the probe's (method-written)
///   out-slot — so the port passes a pointer to a zero stack word for
///   the read's extra and 0 for the thunk's `forwarded` / `_unused`
///   (r2 is likewise dead and the thunk discards it with `mov r2,
///   r1`).
/// - **The return type is `u32`** (r0 carries the failing dispatch's
///   status — or the finish's — back through the tail-calling thunk
///   to the call site, which branches on it).
/// - **The `kind` parameter is r1 as the thunks leave it** — the
///   probe overwrites r1 with the hardcoded 4 BEFORE saving anything
///   else (`mov r5, r1` runs first), so the bound width survives
///   only in r5; the port takes it as an explicit argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_read_scalar_body(
    handle: *mut *mut u8,
    kind: u32,
    out: *mut u32,
    forwarded: usize,
) -> u32 {
    let dispatch =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_SCALAR_DISPATCH));
    let finish =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_SCALAR_FINISH));
    // The entry `stmdb sp!, {r2, r3, ...}` spill: pair[0] = out
    // (sp+0), pair[1] = forwarded (sp+4, the probe out-slot's initial
    // word).
    let mut pair = [out as usize, forwarded];
    let forwarded_slot = forwarded;
    // Probe: dispatch(handle, 4, &pair[1]) — kind 4 is hardcoded
    // (`mov r1, #0x4`); the out word is never read back. 5 =
    // "unsupported", any other nonzero a hard error — both return
    // the status verbatim.
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
    // Read: dispatch(handle, kind, out) — r1 = r5 is the calling
    // thunk's bound kind (2 or 4). r3 is dead across the probe
    // (method-clobbered, and its spill slot was the probe's
    // method-written out-slot); a zero word stands in for the
    // unobservable extra (the 0x0811d874 dead-slot precedent).
    let dead_slot = 0usize;
    let status = dispatch(handle, kind, out as usize, core::ptr::addr_of!(dead_slot));
    if status != 0 {
        return status;
    }
    // Finish: vtable_query_4c_kind4(handle, &pair[0]); r2/r3 are dead
    // across the read dispatch (the thunk discards r2 with `mov r2,
    // r1`), so 0 stands in for both unobservable arguments.
    finish(handle, core::ptr::addr_of_mut!(pair[0]) as *mut u32, 0, 0)
}

/// Indirect dispatch for the two slot +0x4c dispatches of
/// [`vtable_query_4c_read_buffer_size_out`], wired to this module's
/// ported [`vtable_slot_4c_dispatch`] (original: `FUN_0811d7b0` @
/// 0x0811d7b0; the [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] pattern — the
/// seam is retained for hookability, the dispatcher's `blx` targets
/// are firmware vtable methods, and a role-specific name keeps host
/// tests from racing the siblings' parallel tests).
pub static mut VTABLE_QUERY_4C_BUFFER_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// Indirect dispatch for the closing query-thunk call of
/// [`vtable_query_4c_read_buffer_size_out`], wired to the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` (original:
/// `FUN_0811d46c` @ 0x0811d46c; the [`VTABLE_QUERY_4C_SCALAR_FINISH`]
/// pattern — a module-local seam keeps host tests able to intercept
/// it without swapping util's `VTABLE_SLOT_4C_DISPATCH` static, which
/// would race util's own parallel tests).
pub static mut VTABLE_QUERY_4C_BUFFER_FINISH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    out: *mut u32,
    unused: usize,
    forwarded: usize,
) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;

/// vtable_query_4c_read_buffer_size_out — original: `FUN_0811d5fc` @
/// 0x0811d5fc (80 bytes; **1 `bl` call site**, grep on
/// `decomp/osos.asm`: 0x0811afeb8 in `FUN_081afdb8` — it passes the
/// handle in r0 (`param_1 + 0xd`), the buffer capacity 0x100 in r1, a
/// pointer to the caller's 0x100-byte stack buffer in r2 and a
/// pointer to the caller's size word in r3 (`&local_140`), then
/// NUL-terminates the buffer at the reported size
/// (`auStack_13c[local_140] = 0`) — the size IS a byte count).
/// Reference C `decomp/c/010/0811d5fc_FUN_0811d5fc.c` is accurate.
///
/// The unclamped, size-reporting sibling of this module's
/// [`vtable_query_4c_kind4_read`] (0x0811d818): the same
/// probe→read→finish shape through the slot +0x4c dispatcher, but
/// the probe's out-slot is the CALLER's `size_out` pointer (r3
/// doubles as the probe's data argument — `mov r2, r3`), the probed
/// size feeds the read UNCLAMPED (`ldr r1, [r4]` — no `strhi`
/// clamp), and the capacity argument is never consulted:
///
/// ```text
/// 0811d5fc  stmdb sp!, {r3, r4, r5, r6, r7, lr}  @ spill = size_out
/// 0811d600  mov   r6, r2            @ save buffer (arg3)
/// 0811d604  mov   r2, r3            @ probe data = size_out
/// 0811d608  mov   r5, r0            @ save handle
/// 0811d60c  mov   r4, r3            @ save size_out
/// 0811d610  mov   r1, #0x4          @ kind 4 — r1 (capacity) DIES here
/// 0811d614  bl    0x0811d7b0        @ probe: dispatch(handle, 4, size_out)
/// 0811d618  cmp   r0, #0x5
/// 0811d61c  beq   0x0811d648        @ unsupported -> return status
/// 0811d620  cmp   r0, #0x0
/// 0811d624  bne   0x0811d648        @ hard error -> return status
/// 0811d628  ldr   r1, [r4, #0x0]    @ size = *size_out (method-written)
/// 0811d62c  mov   r2, r6            @ data = buffer
/// 0811d630  mov   r0, r5
/// 0811d634  bl    0x0811d7b0        @ read: dispatch(handle, size, buffer)
/// 0811d638  cmp   r0, #0x0
/// 0811d63c  moveq r1, sp            @ message = &spill (holds size_out)
/// 0811d640  moveq r0, r5
/// 0811d644  bleq  0x0811d46c        @ finish: vtable_query_4c_kind4(handle, &spill)
/// 0811d648  ldmia sp!, {r3, r4, r5, r6, r7, pc}
/// ```
///
/// Three messages to the slot +0x4c dispatcher
/// ([`vtable_slot_4c_dispatch`], 0x0811d7b0), exactly the
/// [`vtable_query_4c_read_scalar_body`] (0x0811d5ac) flow with the
/// out-slot promoted to a real argument. The **probe** sends kind 4
/// (hardcoded `mov r1, #0x4`) with the caller's `size_out` pointer
/// as the out-slot; the method answers with the property's byte
/// count. Status **5** means "unsupported" and bails, any other
/// nonzero is a hard error, both returning verbatim. The **read**
/// re-dispatches with the PROBED size as the middle argument (`ldr
/// r1, [r4]` — a byte count, not a kind constant) and the caller's
/// buffer as data; the method stores the bytes through it. Only on
/// a zero read status does the **finish** `bleq` fire: 0x0811d46c is
/// the PORTED kind-4 query thunk `util/vtable_query.rs`
/// `vtable_query_4c_kind4`, re-dispatching kind 4 with the one-word
/// `{size_out}` spill as the message; its error code becomes the
/// return value.
///
/// # Deviations
///
/// - **Both callees are ported** ([`vtable_slot_4c_dispatch`] in this
///   module, `vtable_query_4c_kind4` in util/vtable_query.rs); the
///   calls route through the new
///   [`VTABLE_QUERY_4C_BUFFER_DISPATCH`] /
///   [`VTABLE_QUERY_4C_BUFFER_FINISH`] seams (the
///   [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] precedent — hookability plus
///   host-test interception without racing the siblings' or util's
///   own parallel tests).
/// - **arg2 (r1, the caller's capacity) is DEAD** — `mov r1, #0x4`
///   overwrites it before anything reads it and nothing saves it.
///   The sole call site passes the buffer capacity 0x100, but unlike
///   the clamping sibling [`vtable_query_4c_kind4_read`] this
///   function never consults it: the probed size drives the read
///   unclamped. It is modeled as `_capacity` to document the
///   call-site contract.
/// - **arg4 (r3) is a REAL argument** (`size_out`), breaking the
///   family's "no call site sets r3" convention — the sole caller
///   deliberately passes `&local_140`. It triples as the probe's
///   data argument (`mov r2, r3`), the word this function's entry
///   `stmdb sp!, {r3, ...}` spill exposes (the finish message and,
///   by value, the probe dispatcher's own `stmdb sp!, {r3}` extra),
///   and the probed-size source for the read (`ldr r1, [r4]`).
/// - **r3 is DEAD for the read dispatch and the finish call** (the
///   [`vtable_query_4c_read_scalar_body`] refinement): the probe
///   method clobbers r0–r3 across the first `bl` and nothing
///   reloads r3, so the port passes a pointer to a zero stack word
///   for the read's extra and 0 for the thunk's `forwarded` /
///   `_unused` (r2 is likewise dead and the thunk discards it with
///   `mov r2, r1`).
/// - **The return type is `u32`** (r0 carries the failing dispatch's
///   status — or the finish's — back to the call site, which
///   branches on it).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_read_buffer_size_out(
    handle: *mut *mut u8,
    _capacity: u32,
    buffer: *mut u8,
    size_out: *mut u32,
) -> u32 {
    let dispatch =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_BUFFER_DISPATCH));
    let finish =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_BUFFER_FINISH));
    // The entry `stmdb sp!, {r3, ...}` spill: one word holding
    // size_out — by value the probe dispatcher's extra content, by
    // address (moveq r1, sp) the finish message.
    let mut spill = size_out as usize;
    // Probe: dispatch(handle, 4, size_out) — kind 4 is hardcoded
    // (`mov r1, #0x4`); the method answers with the property's byte
    // count through size_out. 5 = "unsupported", any other nonzero a
    // hard error — both return the status verbatim.
    let status = dispatch(
        handle,
        MESSAGE_KIND_4,
        size_out as usize,
        core::ptr::addr_of!(spill),
    );
    if status == STATUS_UNSUPPORTED {
        return status;
    }
    if status != 0 {
        return status;
    }
    // Read: dispatch(handle, *size_out, buffer) — `ldr r1, [r4]` is
    // the probed byte count, UNCLAMPED (no `strhi` here, unlike the
    // 0x0811d818 sibling). r3 is dead across the probe
    // (method-clobbered); a zero word stands in for the unobservable
    // extra (the 0x0811d874 dead-slot precedent).
    let size = *size_out;
    let dead_slot = 0usize;
    let status = dispatch(handle, size, buffer as usize, core::ptr::addr_of!(dead_slot));
    if status != 0 {
        return status;
    }
    // Finish: vtable_query_4c_kind4(handle, &spill); r2/r3 are dead
    // across the read dispatch (the thunk discards r2 with `mov r2,
    // r1`), so 0 stands in for both unobservable arguments.
    finish(handle, core::ptr::addr_of_mut!(spill) as *mut u32, 0, 0)
}

/// vtable_query_4c_read_scalar_kind2 — original: `FUN_0811d70c` @
/// 0x0811d70c (12 bytes per `decomp/functions.csv`: the kind-2 entry
/// thunk only; the shared 80-byte body at 0x0811d5ac it tail-calls
/// belongs to the kind-4 sibling's csv row; **1 `bl` call site**,
/// grep on `decomp/osos.asm`: 0x08136810 in `FUN_08136520` — it
/// passes the handle in r0 (`add r0, sp, #0x48`) and a pointer to
/// the caller's out word in r1 (`add r1, r5, #0x18`), does not set
/// r3, branches on a zero status (`movs r4, r0; beq`) and maps the
/// unsupported status 5 to success (`cmp r4, #0x5; moveq r4, #0x0`).
///
/// The u16-width sibling of [`vtable_query_4c_read_scalar_kind4`] —
/// the kind-encodes-value-width convention of the write stages
/// [`vtable_set_50_write_kind4`] / [`vtable_set_50_write_kind2`]
/// applied to the scalar (single-word) property read of the slot
/// +0x4c message family. The 12-byte entry thunk binds kind 2 and
/// tail-calls the same shared 80-byte body the kind-4 sibling binds
/// kind 4 into:
///
/// ```text
/// 0811d70c  mov   r2, r1            @ arg2 (out) -> body's r2
/// 0811d710  mov   r1, #0x2          @ bind kind 2
/// 0811d714  b     0x0811d5ac        @ tail: shared scalar-read body
/// ```
///
/// The shared body (disassembled in
/// [`vtable_query_4c_read_scalar_body`]'s header) is identical for
/// both entries: the probe's `mov r1, #0x4` is hardcoded there, so
/// only the **read** dispatch carries the thunk-bound width — here
/// kind 2, telling the method to deliver a u16 property through the
/// caller's out word. Probe → dispatch → finish-thunk shape, status
/// 5 = "unsupported" and any other nonzero probe status a hard
/// error (both returning verbatim), and the closing
/// `bleq 0x0811d46c` finish (the ported kind-4 query thunk
/// `util/vtable_query.rs` `vtable_query_4c_kind4`) firing only on a
/// zero read status — exactly as the kind-4 sibling.
///
/// # Deviations
///
/// - **The thunk is the bare 12-byte entry**: it binds kind 2 and
///   tail-calls the ported shared body
///   [`vtable_query_4c_read_scalar_body`] (0x0811d5ac), which routes
///   its two dispatches and the finish through the existing
///   [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] seams (the
///   [`VTABLE_SLOT_50_DISPATCH`] precedent — seams retained, wired to
///   the ported implementations).
/// - **The read dispatch binds kind 2** (`mov r1, r5` with r5 = the
///   thunk's `mov r1, #0x2`); the probe still binds kind 4
///   (hardcoded in the shared body).
/// - **arg3 (r3) is modeled as `forwarded`** — the family
///   convention: the single call site does not set r3 deliberately.
///   It doubles as the INITIAL content of the probe out-slot
///   `pair[1]` (the entry spill) and as the word the probe
///   dispatcher's `stmdb sp!, {r3}` spill exposes to the method.
/// - **r3 is DEAD for the read dispatch and the finish call** (the
///   [`vtable_set_50_write_indirect_kind4`] refinement): the probe
///   method clobbers r0–r3 across the first `bl`, nothing reloads
///   r3, and the spill slot it came from is the probe's
///   (method-written) out-slot — so the port passes a pointer to a
///   zero stack word for the read's extra and 0 for the thunk's
///   `forwarded` / `_unused` (r2 is likewise dead and the thunk
///   discards it with `mov r2, r1`).
/// - **The return type is `u32`**, not the reference C's `void`:
///   the call site branches on r0 (`movs r4, r0; beq`), and the
///   original returns the failing dispatch's status — or the
///   finish's — in r0.
/// - **The reference C is followed only where it matches the
///   disassembly**: `decomp/c/010/0811d70c_FUN_0811d70c.c` gets the
///   shape right (scratch probe out-slot, hardcoded kind-4 probe,
///   kind-2 read) but types `param_2` as `undefined4` — the
///   disassembly's `mov r2, r6` data path and the call site's
///   `add r1, r5, #0x18` show a pointer — and hides the entry thunk
///   / shared-body split (it decompiles the 0x0811d5ac body under
///   this entry's name).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_read_scalar_kind2(
    handle: *mut *mut u8,
    out: *mut u32,
    forwarded: usize,
) -> u32 {
    // The 12-byte entry thunk: mov r2, r1; mov r1, #0x2; b 0x0811d5ac
    // — bind kind 2 and tail-call the ported shared body (r3 passes
    // through untouched).
    vtable_query_4c_read_scalar_body(handle, MESSAGE_KIND_2, out, forwarded)
}

/// vtable_query_4c_read_scalar_kind4 — original: `FUN_0811d718` @
/// 0x0811d718 (92 bytes per `decomp/functions.csv`: the 12-byte
/// kind-4 entry thunk at 0x0811d718 plus the shared 80-byte body at
/// 0x0811d5ac it tail-calls; **15 `bl` call sites**, grep on
/// `decomp/osos.asm`: the 5-site cluster 0x0811b008..0x0811b1c0,
/// 0x0811e914, the 3-site cluster 0x081afe70..0x081aff7c, 0x081bc790,
/// 0x081d10d8, 0x081d1584 and the 3-site cluster
/// 0x08271528..0x08271560 — every site passes the handle in r0 and a
/// pointer to the caller's out word in r1 (`&local_34`,
/// `local_20 + 8`...), none sets r3; e.g. `FUN_081afdb8` reads
/// `local_34` as the delivered value after a zero status).
///
/// The scalar (single-word) property read of the slot +0x4c message
/// family — the little sibling of this module's
/// [`vtable_query_4c_kind4_read`] (0x0811d818, the sized-buffer
/// read): the same probe → dispatch → finish-thunk shape through
/// [`vtable_slot_4c_dispatch`] (0x0811d7b0) minus the size clamp,
/// with the read's kind bound by a 12-byte entry thunk exactly the
/// way the write stages [`vtable_set_50_write_kind4`] /
/// [`vtable_set_50_write_kind2`] bind theirs:
///
/// ```text
/// 0811d718  mov   r2, r1            @ arg2 (out) -> body's r2
/// 0811d71c  mov   r1, #0x4          @ bind kind 4
/// 0811d720  b     0x0811d5ac        @ tail: shared scalar-read body
///
/// 0811d5ac  stmdb sp!, {r2, r3, r4, r5, r6, lr}  @ pair = {out, r3}
/// 0811d5b0  mov   r6, r2            @ save out
/// 0811d5b4  mov   r5, r1            @ save the thunk-bound kind
/// 0811d5b8  mov   r1, #0x4          @ kind 4 — probe is ALWAYS kind 4
/// 0811d5bc  add   r2, sp, #0x4      @ probe out-slot = &pair[1]
/// 0811d5c0  mov   r4, r0            @ save handle
/// 0811d5c4  bl    0x0811d7b0        @ probe: dispatch(handle, 4, &pair[1])
/// 0811d5c8  cmp   r0, #0x5
/// 0811d5cc  beq   0x0811d5f8        @ unsupported -> return status
/// 0811d5d0  cmp   r0, #0x0
/// 0811d5d4  bne   0x0811d5f8        @ hard error -> return status
/// 0811d5d8  mov   r2, r6            @ data = out
/// 0811d5dc  mov   r1, r5            @ kind = thunk-bound (4 here)
/// 0811d5e0  mov   r0, r4
/// 0811d5e4  bl    0x0811d7b0        @ read: dispatch(handle, 4, out)
/// 0811d5e8  cmp   r0, #0x0
/// 0811d5ec  moveq r1, sp            @ message = &pair[0]
/// 0811d5f0  moveq r0, r4
/// 0811d5f4  bleq  0x0811d46c        @ finish: vtable_query_4c_kind4(handle, &pair)
/// 0811d5f8  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// ```
///
/// Three messages to the slot +0x4c dispatcher. The **probe** sends
/// kind 4 with `&pair[1]` — the entry r3 spill slot — as a scratch
/// out-slot whose word is never read back; status **5** means
/// "unsupported" and bails, any other nonzero is a hard error, both
/// returning verbatim (the [`vtable_query_4c_kind4_read`] convention).
/// The **read** re-dispatches with the thunk-bound kind (4 via this
/// entry; the ported 12-byte sibling thunk
/// [`vtable_query_4c_read_scalar_kind2`] @ 0x0811d70c binds kind 2
/// for u16 values — the same kind-encodes-
/// width convention as the write stages, and the probe's `mov r1,
/// #0x4` is hardcoded in the shared body, so only the read carries
/// the width) and the caller's `out` pointer as data; the method
/// stores the property word through it. Only on a zero read status
/// does the **finish** `bleq` fire: 0x0811d46c is the PORTED kind-4
/// query thunk `util/vtable_query.rs` `vtable_query_4c_kind4`,
/// re-dispatching kind 4 with the one-word `{out}` pair as the
/// message; its error code becomes this function's return value.
///
/// # Deviations
///
/// - **The thunk is the bare 12-byte entry**: it binds kind 4 and
///   tail-calls the ported shared body
///   [`vtable_query_4c_read_scalar_body`] (0x0811d5ac, disassembled
///   below), which routes both callees — [`vtable_slot_4c_dispatch`]
///   in this module and `util/vtable_query.rs`'s
///   `vtable_query_4c_kind4` — through the
///   [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] seams (the
///   [`VTABLE_QUERY_4C_READ_DISPATCH`] / [`VTABLE_QUERY_4C_READ_FINISH`]
///   pattern — hookability plus host-test interception without racing
///   the sibling's or util's own parallel tests).
/// - **arg3 (r3) is modeled as `forwarded`** — the family convention:
///   no call site sets r3 deliberately. It doubles as the INITIAL
///   content of the probe out-slot `pair[1]` (the entry spill), which
///   the probe method may overwrite, and as the word the probe
///   dispatcher's `stmdb sp!, {r3}` spill exposes to the method.
/// - **r3 is DEAD for the read dispatch and the finish call** (the
///   [`vtable_set_50_write_indirect_kind4`] refinement): the probe
///   method clobbers r0–r3 across the first `bl`, nothing reloads r3,
///   and the spill slot it came from is the probe's (method-written)
///   out-slot — so both the read dispatcher's spill and the finish
///   thunk's r3 expose method leftovers. The port passes a pointer to
///   a zero stack word for the read's extra and 0 for the thunk's
///   `forwarded`, and 0 for the thunk's `_unused` (r2 is likewise
///   dead and the thunk discards it with `mov r2, r1`).
/// - **The return type is `u32`**, not the reference C's `void`:
///   every call site branches on r0 (`iVar3 = FUN_0811d718(...); if
///   (iVar3 == 0)`), and the original returns the failing dispatch's
///   status — or the finish's — in r0.
/// - **The reference C is followed only where it matches the
///   disassembly**: `decomp/c/010/0811d718_FUN_0811d718.c` gets the
///   shape right (including the probe's scratch out-slot and the
///   kind-4 constants) but types `param_2` as `undefined4` — the
///   disassembly's `mov r2, r6` / `blx` data path and every call
///   site (`&local_34`) show a pointer — and hides the entry thunk /
///   shared-body split (it decompiles the 0x0811d5ac body under this
///   entry's name).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_read_scalar_kind4(
    handle: *mut *mut u8,
    out: *mut u32,
    forwarded: usize,
) -> u32 {
    // The 12-byte entry thunk: mov r2, r1; mov r1, #0x4; b 0x0811d5ac
    // — bind kind 4 and tail-call the ported shared body (r3 passes
    // through untouched).
    vtable_query_4c_read_scalar_body(handle, MESSAGE_KIND_4, out, forwarded)
}

/// Byte offset of the allocate method inside the object's vtable —
/// the slot [`vtable_query_4c_walk_alloc`] loads for its bare-selector
/// branch (`ldr r3, [r2, #0x54]`); one slot past [`VTABLE_SLOT_50`].
const VTABLE_SLOT_54: usize = 0x54;

/// The top-byte mask [`vtable_query_4c_walk_alloc`] splits its
/// selector word with (`and`/`bic #0xff000000`): the family's tag
/// bits ([`PROBE_TAG`], [`COMMIT_TAG`], [`COMMIT_PROBE_TAG`]) live in
/// the top byte.
const MESSAGE_TAG_MASK: u32 = 0xff00_0000;

/// The vtable method signature at slot +0x54: `method(object, size,
/// mode)`, returning an error code (0 = success). The original's
/// `blx r3` passes r0 = the object, r1 = the queried size + 4 and r2
/// = the constant 1; r3 holds the method pointer itself at the `blx`
/// (dead — the [`VtableSlot04Method`] precedent).
type VtableSlot54Method = unsafe extern "C" fn(object: *mut u8, size: u32, mode: u32) -> u32;

/// Indirect dispatch for the bare-branch size query of
/// [`vtable_query_4c_walk_alloc`], wired to this module's ported
/// [`vtable_slot_4c_dispatch`] (original: `FUN_0811d7b0` @ 0x0811d7b0;
/// the [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] pattern — the seam is
/// retained for hookability, the dispatcher's `blx` targets are
/// firmware vtable methods, and a role-specific name keeps host tests
/// from racing the siblings' parallel tests).
pub static mut VTABLE_QUERY_4C_WALK_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// Indirect dispatch for the walk-loop query-thunk call of
/// [`vtable_query_4c_walk_alloc`], wired to the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` (original:
/// `FUN_0811d46c` @ 0x0811d46c; the [`VTABLE_QUERY_4C_SCALAR_FINISH`]
/// pattern — a module-local seam keeps host tests able to intercept
/// it without swapping util's `VTABLE_SLOT_4C_DISPATCH` static, which
/// would race util's own parallel tests).
pub static mut VTABLE_QUERY_4C_WALK_QUERY: unsafe extern "C" fn(
    handle: *mut *mut u8,
    out: *mut u32,
    unused: usize,
    forwarded: usize,
) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;

/// vtable_query_4c_walk_alloc — original: `FUN_0811d478` @ 0x0811d478
/// (180 bytes; **11 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0810aac4, 0x0811e954, 0x08136824, 0x081affa0, 0x081bc810,
/// 0x081d0f10, 0x081d110c, 0x081d15e4, 0x08271590 and 0x0828595c —
/// plus the recursive self-call at 0x0811d4f4 inside its own body.
/// It is NOT called from the multi-message routine 0x0811d360: that
/// cluster's eight 0x0811d390..0x0811d440 sites all target the slot
/// +0x50 dispatcher 0x0811d7fc. The stream-walking callers share one
/// pattern — query a journal word, return 0 when its tag byte is
/// 0xc0000000 (e.g. 0x0811e930..0x0811e954, 0x081d15cc..0x081d15e4,
/// 0x0828592c..0x0828595c), otherwise call THIS function with the
/// word in r1 and branch on the status. Reference C
/// `decomp/c/010/0811d478_FUN_0811d478.c` is accurate in shape.)
///
/// The recursive tagged-word walker of the slot +0x4c message family
/// — the largest family member, sitting between the query thunk
/// 0x0811d46c and the kind-2 write stage 0x0811d52c:
///
/// ```text
/// 0811d478  stmdb sp!, {r2, r3, r4, r5, r6, lr}  @ pair = {arg3, arg4}
/// 0811d47c  mov   r5, r0            @ save handle
/// 0811d480  mov   r0, #0x0
/// 0811d484  str   r0, [sp, #0x4]    @ pair[1] = 0 (arg4's slot dies)
/// 0811d488  ands  r0, r1, #0xff000000  @ tag = selector's top byte
/// 0811d48c  bic   r4, r1, #0xff000000  @ r4 = 24-bit selector
/// 0811d490  bne   0x0811d4d0        @ tagged -> walk branch
/// 0811d494  add   r2, sp, #0x4      @ out-slot = &pair[1]
/// 0811d498  mov   r1, #0x4          @ kind 4
/// 0811d49c  mov   r0, r5
/// 0811d4a0  bl    0x0811d7b0        @ size query: dispatch(handle, 4, &pair[1])
/// 0811d4a4  cmp   r0, #0x0
/// 0811d4a8  bne   0x0811d4cc        @ any nonzero status returns verbatim
/// 0811d4ac  ldr   r0, [sp, #0x4]    @ size = pair[1] (method-written)
/// 0811d4b0  add   r1, r0, #0x4      @ size + 4
/// 0811d4b4  str   r1, [sp, #0x4]    @ pair[1] = size + 4
/// 0811d4b8  ldr   r0, [r5, #0x0]    @ object = *handle
/// 0811d4bc  ldr   r2, [r0, #0x0]    @ vtable = *object
/// 0811d4c0  ldr   r3, [r2, #0x54]   @ method = vtable->slot_54
/// 0811d4c4  mov   r2, #0x1
/// 0811d4c8  blx   r3                @ method(object, size + 4, 1)
/// 0811d4cc  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// 0811d4d0  cmp   r0, #0x40000000   @ tag == PROBE_TAG?
/// 0811d4d4  bne   0x0811d524        @ no -> return 0, no message
/// 0811d4d8  b     0x0811d500
/// 0811d4dc  ldr   r1, [sp, #0x0]    @ word = pair[0] (queried)
/// 0811d4e0  and   r0, r1, #0xff000000
/// 0811d4e4  bic   r1, r1, #0xff000000
/// 0811d4e8  b     0x0811d518
/// 0811d4ec  ldr   r1, [sp, #0x0]    @ the FULL tagged word
/// 0811d4f0  mov   r0, r5
/// 0811d4f4  bl    0x0811d478        @ recurse: self(handle, word)
/// 0811d4f8  cmp   r0, #0x0
/// 0811d4fc  ldmiane sp!, {r2, r3, r4, r5, r6, pc}
/// 0811d500  mov   r1, sp            @ out = &pair[0]
/// 0811d504  mov   r0, r5
/// 0811d508  bl    0x0811d46c        @ query: vtable_query_4c_kind4(handle, &pair[0])
/// 0811d50c  cmp   r0, #0x0
/// 0811d510  beq   0x0811d4dc        @ success -> examine the word
/// 0811d514  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// 0811d518  cmp   r0, #0xc0000000   @ word's tag == COMMIT_PROBE_TAG...
/// 0811d51c  cmpeq r1, r4            @ ...and selector matches?
/// 0811d520  bne   0x0811d4ec        @ no -> recurse into the word
/// 0811d524  mov   r0, #0x0          @ match / other tag -> return 0
/// 0811d528  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// ```
///
/// The selector word is split into its top-byte tag (`ands
/// #0xff000000`) and the remaining 24-bit selector (`bic`), and the
/// tag picks the branch:
///
/// - **tag 0 (bare selector)** — one kind-4 size query through the
///   slot +0x4c dispatcher with `&pair[1]` as the out-slot; on a zero
///   status the method-written size is bumped by 4 (`pair[1]` updated
///   too) and the object's vtable slot **+0x54** method is invoked
///   DIRECTLY as `method(object, size + 4, 1)` — the only family
///   member that calls a vtable method without the dispatcher. The
///   method's r0 returns; any nonzero query status returns verbatim
///   (status 5 gets NO special case here, unlike the read siblings).
/// - **tag 0x40000000 ([`PROBE_TAG`])** — a walk loop: query the next
///   journal word through the kind-4 query thunk 0x0811d46c with
///   `&pair[0]` as the out-slot; a nonzero status returns verbatim. A
///   word tagged 0xc0000000 ([`COMMIT_PROBE_TAG`]) whose 24-bit
///   selector matches this call's selector ends the walk with 0 —
///   the matching commit+probe marker closes the scope the probe tag
///   opened (the set family's probe → ... → commit+probe sequence,
///   replayed); every other word is RECURSED into with the full
///   tagged word as the new selector (`r1 = pair[0]` verbatim), its
///   error propagating.
/// - **any other tag** — return 0 with no message sent (the
///   0x80000000/0xc0000000 terminators the callers already filter).
///
/// # Deviations
///
/// - **The ported callees route through new role-specific seams** —
///   the size query's dispatcher 0x0811d7b0 (ported in this module as
///   [`vtable_slot_4c_dispatch`]) behind
///   [`VTABLE_QUERY_4C_WALK_DISPATCH`] and the walk loop's query
///   thunk 0x0811d46c (ported in `util/vtable_query.rs` as
///   `vtable_query_4c_kind4`) behind [`VTABLE_QUERY_4C_WALK_QUERY`]
///   (the [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] precedent — hookability plus
///   host-test interception without racing the siblings' or util's
///   own parallel tests).
/// - **The slot +0x54 method has no seam** — it is one more firmware
///   vtable method reached by `blx`, exactly like the dispatcher's
///   own targets; host tests install it on a fake vtable (the
///   [`vtable_slot_04_dispose`] no-seam precedent). Its slot load
///   uses `read_unaligned` so the layout stays byte-exact on a 64-bit
///   host (0x54 is 4-aligned but not 8-aligned — the
///   [`vtable_slot_50_dispatch`] precedent).
/// - **arg3 (r2) is modeled as `scratch`** — it is only the INITIAL
///   content of the query out-slot `pair[0]` (the entry spill), which
///   the walk-loop query method overwrites on every iteration; it is
///   never read back. No observed call site sets r2 deliberately.
/// - **arg4 (r3) is modeled as `forwarded` and reaches only two
///   places** — the bare branch's size-query dispatch and the walk
///   loop's FIRST query (nothing between entry and either `bl`
///   touches r3, so the dispatcher's `stmdb sp!, {r3}` spill exposes
///   it verbatim). Its spill slot itself is zeroed at entry: the
///   size out-slot `pair[1]` starts at 0, not at arg4. For later
///   loop iterations and the recursive call r3 is DEAD (the query
///   thunk's method clobbers r0–r3 across the first `bl` and nothing
///   reloads it), so 0 stands in for those unobservable arguments
///   (the [`vtable_set_50_write_indirect_kind4`] dead-slot
///   precedent); r2 into the recursion is likewise dead
///   (method-clobbered, and the thunk discards r2 with `mov r2, r1`),
///   so the recursion passes `scratch = 0`.
/// - **The pair is modeled as two `u32` words** — both slots are only
///   ever consumed as 32-bit words (ARM `ldr`/`str`), unlike
///   [`vtable_query_4c_kind4_read`]'s pair whose first word held an
///   address.
/// - **The recursion is a direct self-call** — the original's
///   `bl 0x0811d478` at 0x0811d4f4 targets this same entry; no seam
///   (the ported body IS the callee).
/// - **The reference C is followed — it is accurate**:
///   `decomp/c/010/0811d478_FUN_0811d478.c` catches the tag split,
///   the size + 4 bump, the slot +0x54 call, the walk loop and the
///   recursion; it only hides the r2/r3 register routing above (its
///   `local_18 = param_3` initial store is the `pair[0]` spill).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_walk_alloc(
    handle: *mut *mut u8,
    selector: u32,
    scratch: usize,
    forwarded: usize,
) -> u32 {
    let dispatch =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_WALK_DISPATCH));
    let query = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_WALK_QUERY));
    // The entry `stmdb sp!, {r2, r3, ...}` spill: pair[0] = arg3
    // (sp+0, the query out-slot's initial content), pair[1] = arg4's
    // slot (sp+4), immediately zeroed by `str r0, [sp, #0x4]`.
    let mut pair = [scratch as u32, 0u32];
    let tag = selector & MESSAGE_TAG_MASK;
    // r4 = bic r1, #0xff000000: the 24-bit selector under the tag.
    let bare_selector = selector & !MESSAGE_TAG_MASK;
    if tag == 0 {
        // Bare selector: size query dispatch(handle, 4, &pair[1]).
        // r3 is the caller's arg4 here (nothing touches it before the
        // bl), so the dispatcher's spill exposes `forwarded`.
        let forwarded_slot = forwarded;
        let status = dispatch(
            handle,
            MESSAGE_KIND_4,
            core::ptr::addr_of!(pair[1]) as usize,
            core::ptr::addr_of!(forwarded_slot),
        );
        if status != 0 {
            return status;
        }
        // Bump the method-written size by 4 (pair[1] updated too),
        // then method(object, size + 4, 1) through vtable slot +0x54.
        let size = pair[1].wrapping_add(4);
        pair[1] = size;
        let object = handle.read();
        let vtable = (object as *const *const u8).read();
        let method =
            (vtable.add(VTABLE_SLOT_54) as *const VtableSlot54Method).read_unaligned();
        method(object, size, 1)
    } else if tag == PROBE_TAG {
        // Probe-tagged: walk the journal until the matching
        // commit+probe marker, recursing into every other word. r3
        // reaches the FIRST query verbatim; afterwards it is dead
        // (method-clobbered across the query), so 0 stands in (the
        // dead-slot precedent).
        let mut query_forwarded = forwarded;
        loop {
            let status =
                query(handle, core::ptr::addr_of_mut!(pair[0]), 0, query_forwarded);
            if status != 0 {
                return status;
            }
            query_forwarded = 0;
            let word = pair[0];
            if word & MESSAGE_TAG_MASK == COMMIT_PROBE_TAG
                && word & !MESSAGE_TAG_MASK == bare_selector
            {
                return 0;
            }
            // Recurse with the FULL tagged word; r2/r3 are dead
            // across the query (method-clobbered, and the thunk
            // discards r2 with `mov r2, r1`), so 0 stands in for both.
            let status = vtable_query_4c_walk_alloc(handle, word, 0, 0);
            if status != 0 {
                return status;
            }
        }
    } else {
        // COMMIT_TAG / COMMIT_PROBE_TAG / any other tag: no message,
        // return 0 (the callers already filter those terminators).
        0
    }
}

/// Indirect dispatch for the eight slot +0x4c dispatches of
/// [`vtable_query_4c_read_eight_byte_record`], wired to this module's
/// ported [`vtable_slot_4c_dispatch`] (original: `FUN_0811d7b0` @
/// 0x0811d7b0; the [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] pattern — the
/// seam is retained for hookability, the dispatcher's `blx` targets
/// are firmware vtable methods, and a role-specific name keeps host
/// tests from racing the siblings' parallel tests).
pub static mut VTABLE_QUERY_4C_RECORD_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    data: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// Indirect dispatch for the closing query-thunk call of
/// [`vtable_query_4c_read_eight_byte_record`], wired to the ported
/// `util/vtable_query.rs` `vtable_query_4c_kind4` (original:
/// `FUN_0811d46c` @ 0x0811d46c; the [`VTABLE_QUERY_4C_SCALAR_FINISH`]
/// pattern — a module-local seam keeps host tests able to intercept
/// it without swapping util's `VTABLE_SLOT_4C_DISPATCH` static, which
/// would race util's own parallel tests).
pub static mut VTABLE_QUERY_4C_RECORD_FINISH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    out: *mut u32,
    unused: usize,
    forwarded: usize,
) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;

/// vtable_query_4c_read_eight_byte_record — original: `FUN_0811d21c`
/// @ 0x0811d21c (220 bytes; **2 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x081367e4 and 0x081d15ac — both pass the
/// handle in r0 (`add r0, sp, #0x48` / `mov r0, r7`) and a record
/// pointer in r1 (`param + 0x8` / `+ 0x12` at the first site,
/// `r4 + 0x24` at the second), neither sets r2/r3 deliberately, and
/// both branch on the returned status (`movs r4, r0; bne` /
/// `cmp r0, #0; beq`).
///
/// The multi-message record READ of the slot +0x4c message family —
/// the exact slot +0x4c mirror of this module's slot +0x50
/// [`vtable_set_50_write_eight_byte_record`] (0x0811d360), direction
/// reversed: where the write twin SERIALIZES the eight payload bytes
/// of a record (five kind-1 byte fields at offsets 0..4, the u16
/// field at offset 6 as kind 2, the final byte at offset 8), this
/// routine QUERIES them back through eight guarded dispatches, every
/// stage short-circuiting on the first nonzero status:
///
/// ```text
/// 0811d21c  stmdb sp!, {r1, r2, r3, r4, r5, lr}  @ triple = {record, arg3, arg4}
/// 0811d220  mov   r4, r1            @ save record (arg2)
/// 0811d224  mov   r1, #0x4          @ kind 4
/// 0811d228  add   r2, sp, #0x8      @ out-slot = &triple[2] (the arg4 spill)
/// 0811d22c  mov   r5, r0            @ save handle
/// 0811d230  bl    0x0811d7b0        @ dispatch(handle, 4, &triple[2])
/// 0811d234  cmp   r0, #0x0
/// 0811d238  bne   0x0811d2f4        @ bail: status returns verbatim
/// 0811d23c  mov   r2, r4            @ record + 0
/// 0811d240  mov   r1, #0x1          @ kind 1
/// 0811d244  mov   r0, r5
/// 0811d248  bl    0x0811d7b0        @ dispatch(handle, 1, record + 0)
/// 0811d24c  cmp   r0, #0x0
/// 0811d250  bne   0x0811d2f4
///   ...                              @ kind-1 dispatches at record + 1 .. + 4
/// 0811d2b4  mov   r2, sp            @ out-slot = &triple[0] (the record spill!)
/// 0811d2b8  mov   r1, #0x2          @ kind 2
/// 0811d2bc  mov   r0, r5
/// 0811d2c0  bl    0x0811d7b0        @ dispatch(handle, 2, &triple[0])
/// 0811d2c4  ldrh  r1, [sp, #0x0]    @ low half of the method-written word
/// 0811d2c8  cmp   r0, #0x0
/// 0811d2cc  strh  r1, [r4, #0x6]    @ record + 6 = the u16 — UNCONDITIONAL
/// 0811d2d0  bne   0x0811d2f4
/// 0811d2d4  add   r2, r4, #0x8      @ record + 8
/// 0811d2d8  mov   r1, #0x1          @ kind 1
/// 0811d2dc  mov   r0, r5
/// 0811d2e0  bl    0x0811d7b0        @ dispatch(handle, 1, record + 8)
/// 0811d2e4  cmp   r0, #0x0
/// 0811d2e8  addeq r1, sp, #0x4      @ message = &triple[1] (the arg3 spill)
/// 0811d2ec  moveq r0, r5
/// 0811d2f0  bleq  0x0811d46c        @ finish: vtable_query_4c_kind4(handle, &triple[1])
/// 0811d2f4  ldmia sp!, {r1, r2, r3, r4, r5, pc}
/// ```
///
/// Eight messages to the slot +0x4c dispatcher
/// ([`vtable_slot_4c_dispatch`], 0x0811d7b0): a kind-4 query whose
/// out-slot is the entry arg4 spill `triple[2]` (sp+8 — the word is
/// never read back, a scratch out-slot like the scalar read's
/// `pair[1]` probe slot), then the five byte fields at record+0..4
/// as kind-1 messages, then the kind-2 dispatch whose out-slot is
/// the entry RECORD spill `triple[0]` (sp+0) — the SAME stack word
/// whose low half is then stored at record+6 (`ldrh [sp]` / `strh
/// [r4, #6]`), and finally the byte at record+8 as kind 1. Only on a
/// zero status from the last byte does the closing `bleq` fire:
/// 0x0811d46c is the PORTED kind-4 query thunk
/// `util/vtable_query.rs` `vtable_query_4c_kind4`, re-dispatching
/// kind 4 with the one-word `triple[1]` (arg3) spill as the message;
/// its error code becomes the return value. Every bail returns the
/// failing dispatch's status verbatim. The two subtle orderings:
/// **the u16 store runs BEFORE the status branch** (`strh` sits
/// between `cmp` and `bne` — even a failing kind-2 dispatch leaves
/// its out-slot's low half at record+6), and the record spill slot
/// doubles as the kind-2 out-slot (the pointer value is dead by then
/// — r4 saved it at entry).
///
/// # Deviations
///
/// - **Both callees are ported** ([`vtable_slot_4c_dispatch`] in this
///   module, `vtable_query_4c_kind4` in util/vtable_query.rs); the
///   calls route through the new
///   [`VTABLE_QUERY_4C_RECORD_DISPATCH`] /
///   [`VTABLE_QUERY_4C_RECORD_FINISH`] seams (the
///   [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] /
///   [`VTABLE_QUERY_4C_SCALAR_FINISH`] precedent — hookability plus
///   host-test interception without racing the siblings' or util's
///   own parallel tests).
/// - **The `{r1, r2, r3}` entry spill is modeled as a three-word
///   stack triple** — `triple[0]` = record (sp+0), `triple[1]` = arg3
///   (sp+4), `triple[2]` = arg4 (sp+8) — exactly the
///   [`vtable_query_4c_kind4_read`] / [`vtable_query_4c_walk_alloc`]
///   stack-pair convention widened by one slot. `triple[0]` doubles
///   as the kind-2 out-slot: after the dispatch only its low 16 bits
///   are consumed (`ldrh`), so the port reads `triple[0] as u16` —
///   byte-exact on a 64-bit host, where the method's 32-bit answer
///   store lands in the word's low half.
/// - **arg3 (r2) is modeled as `scratch`** — only the INITIAL content
///   of the finish out-slot `triple[1]` (the entry spill), never read
///   back (the [`vtable_query_4c_walk_alloc`] `scratch` precedent).
///   Neither call site sets r2 deliberately.
/// - **arg4 (r3) is modeled as `forwarded`** — the family convention:
///   no call site sets r3 deliberately. It doubles as the INITIAL
///   content of the kind-4 out-slot `triple[2]` (the entry spill),
///   and — nothing touching r3 between entry and the first `bl` — as
///   the word the first dispatcher's `stmdb sp!, {r3}` spill exposes
///   verbatim. For every LATER dispatch and the finish call r3 is
///   DEAD (method-clobbered across each `bl`, nothing reloads it), so
///   a zero stack word stands in for those extras and 0 for the
///   thunk's `forwarded` / `_unused` (the
///   [`vtable_set_50_write_eight_byte_record`] `dead_slot` /
///   [`vtable_query_4c_read_scalar_body`] precedents; the thunk
///   discards r2 with `mov r2, r1`).
/// - **The return type is `u32`**, not the reference C's `void`:
///   both call sites branch on r0, and the original returns the
///   failing dispatch's status — or the finish thunk's, via the
///   `bleq` — in r0.
/// - **The reference C is accurate here, unlike its mangled
///   siblings**: `decomp/c/010/0811d21c_FUN_0811d21c.c`'s
///   `local_18`/`uStack_14`/`uStack_10` DO match the disassembly's
///   sp+0/sp+4/sp+8 triple (the kind-2 dispatch's `&local_18` IS the
///   record spill slot and the `(undefined2)local_18` store at
///   `param_2 + 6` reads that same word), and it catches the
///   unconditional u16 store ahead of the status branch. Only the
///   `void` return and the untyped `undefined4` parameters deviate.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_read_eight_byte_record(
    handle: *mut *mut u8,
    record: *mut u8,
    scratch: usize,
    forwarded: usize,
) -> u32 {
    let dispatch =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_RECORD_DISPATCH));
    let finish =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_RECORD_FINISH));
    // The entry `stmdb sp!, {r1, r2, r3, ...}` spill: triple[0] =
    // record (sp+0), triple[1] = arg3 (sp+4), triple[2] = arg4 (sp+8).
    let mut triple = [record as usize, scratch, forwarded];
    let forwarded_slot = forwarded;
    // Kind-4 query: dispatch(handle, 4, &triple[2]) — the out-slot is
    // the arg4 spill (add r2, sp, #0x8); its word is never read back.
    // r3 is the caller's arg4 here (nothing touches it before the
    // bl), so the dispatcher's spill exposes `forwarded`.
    let status = dispatch(
        handle,
        MESSAGE_KIND_4,
        core::ptr::addr_of_mut!(triple[2]) as usize,
        core::ptr::addr_of!(forwarded_slot),
    );
    if status != 0 {
        return status;
    }
    // r3 is dead across the first dispatch (method-clobbered, nothing
    // reloads it); a zero word stands in for the unobservable extra
    // of every later message (the 0x0811d360 dead_slot precedent).
    let dead_slot = 0usize;
    for offset in 0..5 {
        let status = dispatch(
            handle,
            MESSAGE_KIND_1,
            record.add(offset) as usize,
            core::ptr::addr_of!(dead_slot),
        );
        if status != 0 {
            return status;
        }
    }
    // Kind-2 query: dispatch(handle, 2, &triple[0]) — the out-slot is
    // the RECORD spill slot itself (mov r2, sp; the pointer is dead,
    // r4 saved it at entry).
    let status = dispatch(
        handle,
        MESSAGE_KIND_2,
        core::ptr::addr_of_mut!(triple[0]) as usize,
        core::ptr::addr_of!(dead_slot),
    );
    // ldrh r1, [sp]; strh r1, [r4, #6]: the low half of the
    // method-written word lands at record+6 BEFORE the status branch
    // (the strh sits between cmp and bne — unconditional).
    record.add(6).cast::<u16>().write_unaligned(triple[0] as u16);
    if status != 0 {
        return status;
    }
    let status = dispatch(
        handle,
        MESSAGE_KIND_1,
        record.add(8) as usize,
        core::ptr::addr_of!(dead_slot),
    );
    if status != 0 {
        return status;
    }
    // Finish: vtable_query_4c_kind4(handle, &triple[1]); r2/r3 are
    // dead across the last dispatch (the thunk discards r2 with
    // `mov r2, r1`), so 0 stands in for both unobservable arguments.
    finish(handle, core::ptr::addr_of_mut!(triple[1]) as *mut u32, 0, 0)
}

/// The store-object size [`vtable_file_open`] allocates (`mov r0,
/// #0x34` ahead of the `bl 0x082aadd4`).
const STORE_OBJECT_SIZE: usize = 0x34;

/// Byte offset of the inner file object inside the store object — the
/// pointer [`vtable_file_open`] reads its open status through (`ldr
/// r1, [r0, #0x30]`).
const STORE_INNER_OFFSET: usize = 0x30;

/// Byte offset of the open-status word inside the inner file object
/// (`ldr r7, [r1, #0x1c]`; zero = the open succeeded).
const STORE_STATUS_OFFSET: usize = 0x1c;

/// The flags word [`vtable_file_open`] hands the store-object
/// constructor as its fifth (stacked) argument (`mov r3, #0x8000; str
/// r3, [sp]`).
const STORE_OPEN_FLAGS: u32 = 0x8000;

/// The pre-open remove @ 0x08084d58: [`vtable_file_open`] calls it with
/// the path in r0 and a zeroed r1 (`mov r1, #0x0`) only on a write-mode
/// open, and discards the result. The callee is a mutex-guarded
/// (0x08206e40/0x08206e6c lock pair) indirect call through an object
/// from 0x0818a0bc — vtable slot +0x5c with the path in r1; it consumes
/// only r0 (its r1..r3 spills are its own lock frame), so `zero` models
/// the call site's deliberate r1 clear. The write-mode-only call-site
/// pattern is delete-before-recreate; the exact operation is not
/// established.
pub static mut VTABLE_FILE_OPEN_REMOVE: unsafe extern "C" fn(
    path: *const u8,
    zero: u32,
) -> u32 = store_remove_unported;

/// Default remove stub: a no-op returning 0 (the discarded result the
/// original's callers never observe). The real 0x08084d58 is a
/// filesystem-facade subsystem; until it is ported there is nothing to
/// remove, so the stub does nothing — the ft/system.rs
/// `FT_PLATFORM_FILE_CTOR` fail-closed policy.
unsafe extern "C" fn store_remove_unported(_path: *const u8, _zero: u32) -> u32 {
    0
}

/// The store-object constructor @ 0x08149cec (88 bytes): builds the
/// 0x34-byte store object over the raw `operator_new` block — base
/// constructor 0x0816bfe4 with `flags`, derived vtable store, an inner
/// `operator_new(0x54)` file object opened via 0x08278e8c(inner, path,
/// read_only, 0, {0x400, 1, 0}) and stashed at +0x30 — and returns
/// `this`. The original NEVER null-checks the result
/// ([`vtable_file_open`] dereferences it unconditionally), so the
/// contract is "always returns the object"; `read_only` is the open's
/// mode bit ([`vtable_file_open`] computes it as `write_mode == 0`),
/// `zero` the original's r3 immediate, `flags` the stacked fifth
/// argument ([`STORE_OPEN_FLAGS`]).
pub static mut VTABLE_FILE_OPEN_CTOR: unsafe extern "C" fn(
    this: *mut u8,
    path: *const u8,
    read_only: u32,
    zero: u32,
    flags: u32,
) -> *mut u8 = store_ctor_unported;

/// No-op dispose filling slot +0x04 of the fail-closed default's
/// vtable — the slot [`vtable_slot_04_dispose`] reads on
/// [`vtable_file_open`]'s failure path.
unsafe extern "C" fn stub_store_dispose(_object: *mut u8) {}

/// The fail-closed default's vtable: word 0 unused, slot +0x04 the
/// no-op dispose.
/// The fail-closed default's vtable: word 0 unused, slot +0x04 the
/// no-op dispose. A raw byte buffer written at runtime (the FakeChain
/// precedent) — static initializers cannot hold a function pointer
/// beside a null word without const-eval pointer casts.
static mut STUB_STORE_VTABLE: [u8; 0x10] = [0; 0x10];

/// The fail-closed default's inner block: the status word at +0x1c
/// ([`STORE_STATUS_OFFSET`] / 4 = word 7) is a hard failure, so the
/// ported open takes its dispose-and-null path.
static STUB_STORE_INNER: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

/// The fail-closed default's store object, laid out at runtime (static
/// initializers cannot take sibling statics' addresses).
static mut STUB_STORE_OBJECT: [u8; 0x40] = [0; 0x40];

/// Default store-ctor stub: fails the open closed (the ft/system.rs
/// `FT_PLATFORM_FILE_CTOR` policy) by returning a stand-in object whose
/// status word is a hard failure, so the ported open disposes it
/// through the no-op vtable and reports the error. The real 0x08149cec
/// is a whole C++ file-class subsystem; until it is ported, succeeding
/// here would hand the message family a bogus object. The `this` block
/// is left untouched (the original would have constructed over it; the
/// leaked 0x34 block is the allocator's, exactly the cxx/release.rs
/// default-stub leak policy).
unsafe extern "C" fn store_ctor_unported(
    _this: *mut u8,
    _path: *const u8,
    _read_only: u32,
    _zero: u32,
    _flags: u32,
) -> *mut u8 {
    let object = core::ptr::addr_of_mut!(STUB_STORE_OBJECT).cast::<u8>();
    let vtable = core::ptr::addr_of_mut!(STUB_STORE_VTABLE).cast::<u8>();
    vtable
        .add(VTABLE_SLOT_04)
        .cast::<usize>()
        .write(stub_store_dispose as usize);
    object.cast::<usize>().write(vtable as usize);
    object
        .add(STORE_INNER_OFFSET)
        .cast::<usize>()
        .write(core::ptr::addr_of!(STUB_STORE_INNER) as usize);
    object
}

/// vtable_file_open — original: `FUN_0811d724` @ 0x0811d724 (140 bytes;
/// **9 `bl` call sites**, grep on `decomp/osos.asm`: 0x0810a99c,
/// 0x0811af90, 0x0811c5cc, 0x08136580, 0x0815e8b8, 0x081afe0c,
/// 0x081b0028, 0x081bc680 and 0x082857c0 — every site passes a
/// six-byte record (a feature-state field `param_1 + 0x6c` / `+ 0x84` /
/// `+ 0x54` ... or a stack record) in r0, a path the 0x08279284 builder
/// produced (`"iPod_Control/Device/radio_..."`, `PlayCounts`, `Users`)
/// in r1 and a write-mode flag (0 or 1) in r2; none sets r3
/// deliberately, and every site branches on the returned status.
///
/// The file-open entry of the vtable message family — the routine that
/// creates the file-backed property-store object the family's query
/// ([`vtable_query_4c_read_scalar_kind4`], [`vtable_query_4c_kind4_read`])
/// and set ([`vtable_set_50_kind4`]) thunks then drive through the SAME
/// record pointer (e.g. `FUN_0811af5c` calls this on `param_1 + 0x6c`,
/// then queries `param_1 + 0x6c`):
///
/// ```text
/// 0811d724  stmdb sp!, {r3, r4, r5, r6, r7, lr}  @ spill r3 (dead)
/// 0811d728  movs  r5, r2            @ write_mode (arg3), set flags
/// 0811d72c  mov   r7, r1            @ save path (arg2)
/// 0811d730  mov   r6, #0x1          @ read_only = 1
/// 0811d734  mov   r4, r0            @ save record (arg1)
/// 0811d738  beq   0x0811d74c        @ read mode -> skip the remove
/// 0811d73c  mov   r1, #0x0
/// 0811d740  mov   r0, r7
/// 0811d744  bl    0x08084d58        @ remove(path, 0) — result discarded
/// 0811d748  mov   r6, #0x0          @ write mode -> read_only = 0
/// 0811d74c  mov   r0, #0x34
/// 0811d750  bl    0x082aadd4        @ operator_new(0x34)
/// 0811d754  mov   r3, #0x8000
/// 0811d758  str   r3, [sp, #0x0]    @ stacked arg5 = 0x8000 (overwrites
///                                   @  the dead r3 spill)
/// 0811d75c  mov   r3, #0x0
/// 0811d760  mov   r2, r6            @ read_only
/// 0811d764  mov   r1, r7            @ path
/// 0811d768  bl    0x08149cec        @ ctor(this, path, read_only, 0, 0x8000)
/// 0811d76c  str   r0, [r4, #0x0]    @ record.object = store
/// 0811d770  ldr   r1, [r0, #0x30]   @ inner = store->inner
/// 0811d774  mov   r6, #0x0
/// 0811d778  ldr   r7, [r1, #0x1c]   @ status = inner->status
/// 0811d77c  cmp   r7, #0x0
/// 0811d780  beq   0x0811d798        @ success -> keep the object
/// 0811d784  cmp   r0, #0x0
/// 0811d788  ldrne r1, [r0, #0x0]    @ vtable = *object
/// 0811d78c  ldrne r1, [r1, #0x4]    @ method = vtable->slot_04
/// 0811d790  blxne r1                @ dispose(object)
/// 0811d794  str   r6, [r4, #0x0]    @ record.object = NULL
/// 0811d798  movs  r0, r5
/// 0811d79c  movne r0, #0x1
/// 0811d7a0  strb  r6, [r4, #0x4]    @ record.flags = 0
/// 0811d7a4  strb  r0, [r4, #0x5]    @ record.write = (write_mode != 0)
/// 0811d7a8  mov   r0, r7            @ return the status
/// 0811d7ac  ldmia sp!, {r3, r4, r5, r6, r7, pc}
/// ```
///
/// On a write-mode open the path is first handed to the pre-open remove
/// (0x08084d58, result discarded) and the store constructor receives
/// `read_only = 0`; on a read-mode open the remove is skipped and
/// `read_only = 1`. The constructor's result is stored into the record
/// UNCONDITIONALLY, then the inner object's status word decides: zero
/// keeps the object, nonzero disposes it through vtable slot +0x04 (the
/// exact [`vtable_slot_04_dispose`] sequence, inlined) and NULLs the
/// record. Either way the record's trailing bytes are written — +0x04
/// cleared, +0x05 the write-mode flag — and the status returns verbatim
/// (callers `cmp r0, #0`).
///
/// # Deviations
///
/// - **The two unported callees sit behind seams** — the pre-open
///   remove 0x08084d58 behind [`VTABLE_FILE_OPEN_REMOVE`] (no-op
///   default) and the store constructor 0x08149cec behind
///   [`VTABLE_FILE_OPEN_CTOR`] (fail-closed default: a stand-in object
///   with a hard-failure status word, so the wired defaults report a
///   failed open instead of handing the family a bogus object — the
///   ft/system.rs `FT_PLATFORM_FILE_CTOR` policy). Unlike
///   [`VTABLE_SET_50_KIND4_OPS`], the defaults do NOT model the exact
///   bodies: the callees are a filesystem facade and a C++ file-class
///   subsystem, not message thunks.
/// - **`operator_new` (0x082aadd4) is called directly** — the ported
///   `crate::heap::veneers::operator_new` (the app/singletons.rs
///   precedent).
/// - **The failure-path dispose calls the ported
///   [`vtable_slot_04_dispose`] directly**, although the original
///   INLINES that body (no `bl 0x0811d7cc`): the guard, the slot +0x04
///   call and the NULL store are identical, so the call is
///   behaviorally exact (the app/class_6800.rs
///   ported-callees-called-directly precedent).
/// - **arg4 (r3) is DEAD — no `forwarded` parameter**, breaking the
///   family convention: the entry spill slot is overwritten with
///   [`STORE_OPEN_FLAGS`] (`str r3, [sp]`) before anything reads it,
///   and the epilogue restores r3 as 0x8000. No call site sets r3
///   deliberately.
/// - **The record's first word is stored and read pointer-sized** (the
///   32-bit `str`/`ldr`), so on a 64-bit host the trailing byte stores
///   at +0x04/+0x05 overwrite the object pointer's high half — the
///   [`vtable_query_4c_kind4_read`] host-representation note. On the
///   failure path the word is NULLed before the byte stores, so no
///   live pointer is ever truncated.
/// - **The constructor result is dereferenced without a NULL check**
///   (`ldr r1, [r0, #0x30]` unconditional): the original's contract is
///   that 0x08149cec always returns the object; the fail-closed
///   default honors it. The port reproduces the unguarded read.
/// - **The reference C is followed only where it matches the
///   disassembly**: `decomp/c/010/0811d724_FUN_0811d724.c` is largely
///   accurate — it catches the `param_3 == 0` mode inversion and the
///   trailing bool — but passes a phantom `param_4` into
///   `FUN_08084d58` (r3 is dead, see above) and types `param_1` as
///   `int *`, hiding the record's trailing mode bytes at +0x04/+0x05.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_open(
    record: *mut u8,
    path: *const u8,
    write_mode: u32,
) -> u32 {
    if write_mode != 0 {
        let remove = core::ptr::addr_of!(VTABLE_FILE_OPEN_REMOVE).read_volatile();
        remove(path, 0);
    }
    let ctor = core::ptr::addr_of!(VTABLE_FILE_OPEN_CTOR).read_volatile();
    let object = ctor(
        crate::heap::veneers::operator_new(STORE_OBJECT_SIZE),
        path,
        (write_mode == 0) as u32,
        0,
        STORE_OPEN_FLAGS,
    );
    record.cast::<*mut u8>().write(object);
    let status = object
        .add(STORE_INNER_OFFSET)
        .cast::<*mut u8>()
        .read()
        .add(STORE_STATUS_OFFSET)
        .cast::<u32>()
        .read();
    if status != 0 {
        vtable_slot_04_dispose(record.cast::<*mut u8>());
    }
    record.add(4).write(0);
    record.add(5).write((write_mode != 0) as u8);
    status
}

/// vtable_file_record_init — original: `FUN_0811d8ac` @ 0x0811d8ac
/// (20 bytes; **7 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0810a94c, 0x0811c874, 0x0813653c, 0x0815e968, 0x081b0268,
/// 0x081bc63c and 0x082859d8 — every site clears a six-byte record
/// (a feature-state field like `param_1 + 0x6c` / `+ 0x54` ... or a
/// stack record) immediately before handing the SAME pointer to
/// [`vtable_file_open`] (0x0811d724), e.g. `FUN_08136520` does
/// `init(auStack_28); ...; vtable_file_open(auStack_28, path, mode)`,
/// and `FUN_081b0240` / `FUN_0811c7fc` / `FUN_0815e934` /
/// `FUN_08285988` init a record field inside a freshly built object.
/// No site passes anything but the record pointer, and several
/// consume the return value as the record pointer).
///
/// The initializer of the six-byte file-open record
/// [`vtable_file_open`] fills — a leaf thunk that zeroes all three
/// fields (the object word, the flags byte, the write-mode byte):
///
/// ```text
/// 0811d8ac  mov  r1, #0x0
/// 0811d8b0  str  r1, [r0, #0x0]   @ record.object = NULL
/// 0811d8b4  strb r1, [r0, #0x4]   @ record.flags  = 0
/// 0811d8b8  strb r1, [r0, #0x5]   @ record.write  = 0
/// 0811d8bc  bx   lr
/// ```
///
/// # Deviations
///
/// - **The return type is `*mut u8`, not the reference C's `void`**:
///   the body never writes r0, so the argument falls through to the
///   caller — and callers rely on it (`iVar2 = FUN_0811d8ac(puVar1 +
///   2)` at 0x081b0268, `iVar3 = FUN_0811d8ac(iVar3 + 0x10)` at
///   0x082859d8, ...). `decomp/c/011/0811d8ac_FUN_0811d8ac.c` is
///   otherwise exact (one `undefined4` store, two `undefined1`
///   stores).
/// - **The first store is a 32-bit `str`, modeled as a `u32` write**
///   (not pointer-sized): byte-exact on a 64-bit host, where a
///   pointer-sized store would clobber bytes 4..8 before the trailing
///   byte stores — the inverse of [`vtable_file_open`]'s
///   host-representation note.
/// - **The adjacent sibling `FUN_0811d8c0` @ 0x0811d8c0 (20 bytes) is
///   a SEPARATE routine**, not one body split by Ghidra: this
///   function ends in a real `bx lr` at 0x0811d8bc. The sibling is
///   the dispose-and-return-handle wrapper (`push {r4, lr}; mov r4,
///   r0; bl 0x0811d7cc; mov r0, r4; pop {r4, pc}`) already documented
///   under [`vtable_slot_04_dispose`]; it is ported below as
///   [`vtable_file_record_dispose`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_init(record: *mut u8) -> *mut u8 {
    record.cast::<u32>().write(0);
    record.add(4).write(0);
    record.add(5).write(0);
    record
}

/// vtable_file_record_dispose — original: `FUN_0811d8c0` @ 0x0811d8c0
/// (20 bytes; **8 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0810a96c, 0x0810ab08, 0x0811c9cc, 0x08136558, 0x08136848,
/// 0x0815eb58, 0x081bc658 and 0x081bc834 — the teardown
/// counterpart of [`vtable_file_record_init`]: 0x08136558 /
/// 0x08136848 sit in `FUN_08136520`, which inits the SAME
/// `auStack_28` record at 0x0813653c and opens it through
/// [`vtable_file_open`]; 0x081bc658 / 0x081bc834 do the same in
/// `FUN_081bc620` (init at 0x081bc63c); 0x0810a96c / 0x0810ab08
/// (`FUN_081010d0`) and 0x081bc658 run the raw
/// [`vtable_slot_04_dispose`] on the record FIRST and then this
/// wrapper, so the wrapper's NULL-handle path is exercised by real
/// callers; the remaining sites pass interior record pointers
/// (`FUN_0811c98c`: `iVar2 - 0x20`, `FUN_0815eb20`: `param_1 +
/// 0x21`) and consume the RETURNED pointer for further
/// container-of arithmetic (`FUN_0839ca74(iVar2 - 0x3c)`,
/// `FUN_081d0f58(iVar3 - 0x58)`).
///
/// The dispose-and-return-handle wrapper over
/// [`vtable_slot_04_dispose`] — a separate routine from its
/// predecessor [`vtable_file_record_init`] (0x0811d8ac), which
/// ends in a real `bx lr` at 0x0811d8bc:
///
/// ```text
/// 0811d8c0  stmdb sp!, {r4, lr}   @ frame
/// 0811d8c4  mov   r4, r0          @ save the handle/record pointer
/// 0811d8c8  bl    0x0811d7cc      @ vtable_slot_04_dispose(handle)
/// 0811d8cc  mov   r0, r4          @ discard the 0 status, return the handle
/// 0811d8d0  ldmia sp!, {r4, pc}
/// ```
///
/// The record's first word IS the handle word ([`vtable_file_open`]
/// stores the object at record +0x0), so the record pointer feeds
/// the dispose verbatim; the dispose's always-0 status is
/// overwritten by the saved pointer and the pointer returns.
///
/// # Deviations
///
/// - **The reference C is exact** (`decomp/c/011/
///   0811d8c0_FUN_0811d8c0.c`: `FUN_0811d7cc(); return param_1;`);
///   the port only gives the untyped `undefined4` its concrete
///   handle-pointer type, matching [`vtable_slot_04_dispose`].
/// - **The ported [`vtable_slot_04_dispose`] is called directly** —
///   the original itself is a `bl 0x0811d7cc`, so the direct call
///   reproduces the call chain exactly (the app/class_6800.rs
///   ported-callees-called-directly precedent); no seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_dispose(
    handle: *mut *mut u8,
) -> *mut *mut u8 {
    vtable_slot_04_dispose(handle);
    handle
}

/// The tag byte [`vtable_file_record_construct_kind1`] writes at
/// record +0x00 (`mov r0, #0x1; strb r0, [r4]`) — the kind the
/// tag-dispatching dispose `FUN_0811d188` (unported) branches on.
const FILE_RECORD_TAG_KIND1: u8 = 1;

/// The allocation size feeding the registry constructor (`mov r0,
/// #0x28` ahead of the `bl 0x082aadd4`) — the
/// `app/class_registry.rs` `Registry` object's 0x28 bytes.
const REGISTRY_OBJECT_SIZE: usize = 0x28;

/// The registry construct behind the `bl 0x0812d2fc` site inside
/// [`vtable_file_record_construct_kind1`]. 0x0812d2fc is a 4-byte
/// thunk (`b 0x0810e64c`) tail-branching to the PORTED
/// `app/class_registry.rs` `class_registry_construct` (0x0810e64c), so
/// the wired default is the exact original call chain. The call still
/// routes through a seam — the [`VTABLE_SET_50_KIND4_OPS`]
/// host-test-interception pattern — because the real construct ends
/// in raw firmware-vtable dispatches (the observer attach and the
/// first change notification through the literal vtables 0x089910ac /
/// 0x08984770) that cannot run on a 64-bit host, and swapping
/// `CLASS_REGISTRY_OPS` from this module's tests would race
/// class_registry.rs's own parallel tests. Host tests install a
/// recording mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_KIND1_CTOR: unsafe extern "C" fn(
    allocation: *mut u8,
) -> *mut u8 = kind1_registry_ctor_default;

/// Default registry construct: the exact original chain — the
/// 0x0812d2fc thunk's bare tail branch into the ported
/// `class_registry_construct` (0x0810e64c), with the `operator_new`
/// block arriving in r0 as the constructor's `this` (the argument the
/// reference C drops).
unsafe extern "C" fn kind1_registry_ctor_default(allocation: *mut u8) -> *mut u8 {
    crate::app::class_registry::class_registry_construct(
        allocation.cast::<crate::app::registry::Registry>(),
    )
    .cast::<u8>()
}

/// The checked-construct guard @ 0x080edb74 (12 bytes; **8 `bl` call
/// sites**, grep on `decomp/osos.asm` — the surrounding constructor
/// cluster, including the kind-2 sibling `FUN_0811d104`'s site
/// 0x0811d13c and [`vtable_file_record_construct_kind1`]'s 0x0811d170):
///
/// ```text
/// 080edb74  cmp   r0, #0x0
/// 080edb78  ldreq r1, [0x80edb88]   @ diagnostic message pointer
/// 080edb7c  moveq r0, #0x4          @ failure code 4
/// 080edb80  beq   0x081b53e4        @ tail: report_allocation_failure(4, msg)
/// 080edb84  bx    lr
/// ```
///
/// A NULL construct result is reported to the unported
/// report_allocation_failure (0x081b53e4 — the `app/class_6800.rs`
/// `FRAMEWORK_BASE_INITIALIZE_OPS` slot) and the diagnostic's
/// fall-through continues exactly as the non-NULL path does; the
/// literal @ 0x080edb88 is a runtime-relocated pointer whose target
/// content is not established. The wired default is a no-op: the
/// non-NULL path IS a bare `bx lr`, and the NULL path's only
/// observable effect is the unported diagnostic (the class_6800.rs
/// `unported_report_allocation_failure` no-op precedent); the guard's
/// r0 is dead at every call site, so the seam returns nothing.
pub static mut VTABLE_FILE_RECORD_KIND1_GUARD: unsafe extern "C" fn(
    object: *mut u8,
) = construct_guard_unported;

/// Default guard stub: a no-op (see the seam's doc).
unsafe extern "C" fn construct_guard_unported(_object: *mut u8) {}

/// vtable_file_record_construct_kind1 — original: `FUN_0811d148` @
/// 0x0811d148 (64 bytes; **2 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x0815a808 and 0x081a0b70 — both allocate the
/// 0x1c-byte record with `operator_new(0x1c)` (0x082aadd4) immediately
/// before the call, and both consume the returned record pointer
/// (`str r0, [r4, #0xcc]` / `stmib r4, {r0, r5}`).
///
/// The kind-1 constructor of the tagged file-record family — the
/// sibling of the ported kind-2 constructor `FUN_0811d104` (68 bytes:
/// tag 2 and a 0x14 allocation feeding
/// [`vtable_file_record_construct_kind2_block`]) and of the
/// tag-dispatching dispose `FUN_0811d188` (128 bytes, unported),
/// operating on the SAME 0x1c-byte record layout:
///
/// ```text
/// 0811d148  stmdb sp!, {r4, r5, r6, lr}
/// 0811d14c  mov   r4, r0            @ save record (arg1)
/// 0811d150  mov   r0, #0x1
/// 0811d154  strb  r0, [r4, #0x0]    @ record.tag = 1 (kind 1)
/// 0811d158  mov   r5, #0x0
/// 0811d15c  mov   r0, #0x28
/// 0811d160  str   r5, [r4, #0x18]   @ record.+0x18 = NULL
/// 0811d164  bl    0x082aadd4        @ operator_new(0x28)
/// 0811d168  bl    0x0812d2fc        @ thunk -> class_registry_construct(block)
/// 0811d16c  str   r0, [r4, #0x4]    @ record.registry = construct result
/// 0811d170  bl    0x080edb74        @ checked-construct guard
/// 0811d174  str   r5, [r4, #0x8]    @ record.+0x08 = NULL
/// 0811d178  str   r5, [r4, #0x10]   @ record.+0x10 = NULL
/// 0811d17c  mov   r0, r4            @ return the record
/// 0811d180  strh  r5, [r4, #0x14]   @ record.+0x14 = 0 (u16)
/// 0811d184  ldmia sp!, {r4, r5, r6, pc}
/// ```
///
/// The record layout is 0x1c bytes: a kind tag at +0x00 (u8), the
/// registry pointer at +0x04, NULL words at +0x08, +0x10 and +0x18, a
/// zero halfword at +0x14 — and +0x0c is NEVER written (a gap the
/// caller's `operator_new(0x1c)` block carries in uninitialized). The
/// `operator_new(0x28)` result feeds the registry constructor as its
/// `this` (r0 passes straight through the 0x0812d2fc thunk's tail
/// branch); the constructor's result is stored at +0x04 and handed to
/// the checked-construct guard, and the record pointer returns
/// regardless of the guard's outcome.
///
/// # Deviations
///
/// - **`operator_new` (0x082aadd4) is called directly** — the ported
///   `crate::heap::veneers::operator_new` (the [`vtable_file_open`]
///   precedent).
/// - **The registry construct routes through the new
///   [`VTABLE_FILE_RECORD_KIND1_CTOR`] seam** — the original's `bl
///   0x0812d2fc` targets a 4-byte thunk (`b 0x0810e64c`) into the
///   ported `app/class_registry.rs` `class_registry_construct`, so
///   the wired default IS the exact call chain; the seam exists for
///   host-test interception (see the seam's doc).
/// - **The checked-construct guard 0x080edb74 is unported** and sits
///   behind the new [`VTABLE_FILE_RECORD_KIND1_GUARD`] seam (no-op
///   default; see the seam's doc). Its r0 is dead here — the
///   continuation overwrites r0 with the record pointer — so the
///   seam returns nothing.
/// - **Every field store keeps the original's width**: `strb` for the
///   tag, 32-bit `str` for the pointer and NULL words (the registry
///   pointer is truncated to its low 32 bits on a 64-bit host — the
///   [`vtable_file_record_init`] byte-exact precedent), `strh` for
///   the +0x14 halfword.
/// - **No `forwarded` parameter**: the entry `stmdb` spills no
///   argument registers and r1..r3 are never read — this is a record
///   constructor, not a message thunk (the [`vtable_file_open`]
///   dead-r3 precedent).
/// - **The reference C is followed only where it matches the
///   disassembly**: `decomp/c/010/0811d148_FUN_0811d148.c` gets the
///   stores and the return right but shows the allocation result as
///   discarded (`FUN_082aadd4(0x28);`) and the construct as
///   argument-less (`thunk_FUN_0810e64c()`) — the disassembly's `bl
///   0x0812d2fc` passes the fresh block straight through in r0. The
///   port follows the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_construct_kind1(record: *mut u8) -> *mut u8 {
    record.write(FILE_RECORD_TAG_KIND1);
    record.add(0x18).cast::<u32>().write(0);
    let ctor = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_KIND1_CTOR));
    let registry = ctor(crate::heap::veneers::operator_new(REGISTRY_OBJECT_SIZE));
    record.add(4).cast::<u32>().write(registry as u32);
    let guard = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_KIND1_GUARD));
    guard(registry);
    record.add(0x08).cast::<u32>().write(0);
    record.add(0x10).cast::<u32>().write(0);
    record.add(0x14).cast::<u16>().write(0);
    record
}

/// The tag byte [`vtable_file_record_construct_kind2`] writes at
/// record +0x00 (`mov r0, #0x2; strb r0, [r4]`) — the kind the
/// tag-dispatching dispose `FUN_0811d188` (unported) branches on.
const FILE_RECORD_TAG_KIND2: u8 = 2;

/// The allocation size feeding the kind-2 block constructor (`mov r0,
/// #0x14` ahead of the `bl 0x082aadd4`) — the five-word block
/// 0x0815bdbc fills.
const KIND2_BLOCK_SIZE: usize = 0x14;

/// The descriptor kind expected by
/// [`vtable_file_record_construct_kind2_block`]. A different value
/// reports a diagnostic but does not alter construction.
const KIND2_BLOCK_DESCRIPTOR_KIND: u32 = 3;

/// The literal diagnostic-message pointer loaded at 0x0815bdd4. The
/// relocated string content at 0x088f8c4c is not yet identified.
const KIND2_BLOCK_DIAGNOSTIC_MESSAGE: usize = 0x088f_8c4c;

/// The unported diagnostic `FUN_081b53e4` called only when a
/// descriptor's leading kind is not
/// [`KIND2_BLOCK_DESCRIPTOR_KIND`]. Its call does not affect this
/// constructor's stores or return value, so this narrow seam preserves
/// the observable diagnostic without inventing another constructor seam.
pub static mut VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC: unsafe extern "C" fn(
    code: u32,
    message: *const u8,
) = kind2_block_diagnostic_unported;

/// Default for [`VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC`]. The
/// diagnostic subsystem is unported; this has no caller-visible effect
/// beyond the missing report.
unsafe extern "C" fn kind2_block_diagnostic_unported(_code: u32, _message: *const u8) {}

/// vtable_file_record_construct_kind2_block — original: `FUN_0815bdbc`
/// @ 0x0815bdbc (72 bytes).
///
/// Constructs the plain five-word descriptor block owned by a kind-2
/// file record. It first stores `{descriptor, extra}`, diagnoses (but
/// continues after) a descriptor whose leading kind is not 3, then
/// stores the descriptor-relative data pointer, count, and payload
/// pointer: `{descriptor, extra, descriptor + descriptor[1],
/// descriptor[2], descriptor + 0xc}`. The allocation is plain data:
/// the kind-2 record destructor frees it directly rather than invoking
/// a destructor.
///
/// # Deviations
///
/// - All five fields remain 32-bit `stmia`/`str` words. Pointer-valued
///   fields therefore truncate to their low 32 bits on a 64-bit host.
/// - The unported `FUN_081b53e4` diagnostic is routed through
///   [`VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC`]. It receives code 0
///   and the exact literal pointer 0x088f8c4c only on a kind mismatch;
///   both ARM paths continue with identical stores and return `block`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_construct_kind2_block(
    block: *mut u8,
    descriptor: *const u32,
    extra: u32,
) -> *mut u8 {
    let words = block.cast::<u32>();
    words.write(descriptor as u32);
    words.add(1).write(extra);

    if descriptor.read() != KIND2_BLOCK_DESCRIPTOR_KIND {
        let diagnostic = core::ptr::read_volatile(core::ptr::addr_of!(
            VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC
        ));
        diagnostic(0, KIND2_BLOCK_DIAGNOSTIC_MESSAGE as *const u8);
    }

    words
        .add(2)
        .write((descriptor as u32).wrapping_add(descriptor.add(1).read()));
    words.add(3).write(descriptor.add(2).read());
    words.add(4).write((descriptor as u32).wrapping_add(0xc));
    block
}

/// Indirect dispatch for the checked-construct guard @ 0x080edb74
/// called by [`vtable_file_record_construct_kind2`], wired to the same
/// no-op default as [`VTABLE_FILE_RECORD_KIND1_GUARD`] (the
/// [`VTABLE_QUERY_4C_READ_DISPATCH`] / [`VTABLE_QUERY_4C_SCALAR_DISPATCH`]
/// role-specific-name precedent — see the kind-1 seam's doc for the
/// guard's disassembly and the no-op rationale; a module-local name
/// keeps host tests from racing the kind-1 sibling's parallel tests).
pub static mut VTABLE_FILE_RECORD_KIND2_GUARD: unsafe extern "C" fn(
    object: *mut u8,
) = construct_guard_unported;

/// vtable_file_record_construct_kind2 — original: `FUN_0811d104` @
/// 0x0811d104 (68 bytes; **21 `bl` call sites**, grep on
/// `decomp/osos.asm`, ALL inside the 0x081a0454..0x081a0a80 cluster:
/// 0x081a0488, 0x081a04cc, 0x081a050c, 0x081a054c, 0x081a058c,
/// 0x081a05cc, 0x081a060c, 0x081a064c, 0x081a068c, 0x081a06cc,
/// 0x081a070c, 0x081a074c, 0x081a078c, 0x081a07cc, 0x081a080c,
/// 0x081a0940, 0x081a0980, 0x081a09c0, 0x081a0a00, 0x081a0a40 and
/// 0x081a0a80 — every site allocates the 0x1c-byte record with
/// `operator_new(0x1c)` (0x082aadd4) immediately before the call,
/// loads arg2/arg3 from a per-site literal pair (`ldr r2, [lit]; ldr
/// r1, [lit]`) and consumes the returned record pointer (`mov r5,
/// r0`).
///
/// The kind-2 constructor of the tagged file-record family — the
/// sibling of the kind-1 constructor [`vtable_file_record_construct_kind1`]
/// (0x0811d148, ported above) and of the tag-dispatching dispose
/// `FUN_0811d188` (128 bytes, unported; its kind-2 branch
/// `operator_delete`s the +0x04 block via 0x082aad24 and disposes a
/// non-NULL +0x18 through 0x0812d300), operating on the SAME
/// 0x1c-byte record layout:
///
/// ```text
/// 0811d104  stmdb sp!, {r4, r5, r6, lr}
/// 0811d108  mov   r4, r0            @ save record (arg1)
/// 0811d10c  mov   r0, #0x2
/// 0811d110  strb  r0, [r4, #0x0]    @ record.tag = 2 (kind 2)
/// 0811d114  mov   r0, #0x0
/// 0811d118  str   r0, [r4, #0x18]   @ record.+0x18 = NULL
/// 0811d11c  mov   r0, #0x14
/// 0811d120  mov   r6, r2            @ save extra (arg3)
/// 0811d124  mov   r5, r1            @ save descriptor (arg2)
/// 0811d128  bl    0x082aadd4        @ operator_new(0x14)
/// 0811d12c  mov   r2, r6
/// 0811d130  mov   r1, r5
/// 0811d134  bl    0x0815bdbc        @ block_ctor(block, descriptor, extra)
/// 0811d138  str   r0, [r4, #0x4]    @ record.block = construct result
/// 0811d13c  bl    0x080edb74        @ checked-construct guard
/// 0811d140  mov   r0, r4            @ return the record
/// 0811d144  ldmia sp!, {r4, r5, r6, pc}
/// ```
///
/// The kind-1 sibling's exact prologue — tag byte at +0x00 (`strb`),
/// NULL word at +0x18 — then `operator_new(0x14)` whose block feeds
/// the 0x0815bdbc block constructor in r0 alongside the caller's
/// descriptor (arg2) and extra word (arg3); the construct result is
/// stored at +0x04 (32-bit `str`) and handed to the checked-construct
/// guard 0x080edb74, and the record pointer returns regardless of the
/// guard's outcome. Unlike kind 1 there are NO trailing field stores:
/// +0x08..+0x17 are never written (the caller's `operator_new(0x1c)`
/// block carries them in uninitialized).
///
/// # Deviations
///
/// - **`operator_new` (0x082aadd4) is called directly** — the ported
///   `crate::heap::veneers::operator_new` (the
///   [`vtable_file_record_construct_kind1`] precedent).
/// - **The block construct 0x0815bdbc is ported** as
///   [`vtable_file_record_construct_kind2_block`] and called directly.
///   Its sole unported dependency, the mismatch diagnostic 0x081b53e4,
///   remains behind
///   [`VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC`].
/// - **The checked-construct guard 0x080edb74 is unported** and sits
///   behind the new [`VTABLE_FILE_RECORD_KIND2_GUARD`] seam (the same
///   no-op default as the kind-1 sibling's guard seam; see its doc).
///   Its r0 is dead here — the continuation overwrites r0 with the
///   record pointer — so the seam returns nothing.
/// - **Every field store keeps the original's width**: `strb` for the
///   tag, 32-bit `str` for the pointer and NULL words (the block
///   pointer is truncated to its low 32 bits on a 64-bit host — the
///   [`vtable_file_record_init`] byte-exact precedent).
/// - **arg2 is typed `*const u32`** — the block constructor
///   dereferences it as words (`descriptor[0]` magic, `descriptor[1]`
///   offset, `descriptor[2]` count); every call site loads it from a
///   literal-pool entry. **arg3 is a verbatim `u32` word** — the
///   constructor only stores it (`stmia r0, {r1, r2}`); it is likewise
///   literal-loaded at every site.
/// - **No `forwarded` parameter**: the entry `stmdb` spills no
///   argument registers and r3 is never read — this is a record
///   constructor, not a message thunk (the
///   [`vtable_file_record_construct_kind1`] precedent).
/// - **The reference C is followed — it is accurate**:
///   `decomp/c/010/0811d104_FUN_0811d104.c` catches the tag store, the
///   +0x18 NULL, the allocation feeding `FUN_0815bdbc(alloc, param_2,
///   param_3)`, the +0x04 store, the guard and the return; only the
///   untyped `undefined4` parameters get concrete types.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_construct_kind2(
    record: *mut u8,
    descriptor: *const u32,
    extra: u32,
) -> *mut u8 {
    let block = vtable_file_record_construct_kind2_block(
        crate::heap::veneers::operator_new(KIND2_BLOCK_SIZE),
        descriptor,
        extra,
    );
    record.add(4).cast::<u32>().write(block as u32);
    let guard = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_KIND2_GUARD));
    guard(block);
    record
}

/// The caller tag [`vtable_file_record_teardown`] hands
/// `free_wrapper` for both node frees (`mov r1, #0x19` at 0x0811d03c
/// and 0x0811d04c).
const FILE_RECORD_NODE_FREE_TAG: usize = 0x19;

/// The word count of each iterator scratch object on the original's
/// 0x40-byte frame: the outer iterator at sp+0x24 abuts the key
/// out-slot at sp+0x3c, the inner iterator at sp+0x04 abuts the node
/// out-slot at sp+0x1c — six words each (word 0 the registry/bucket
/// pointer, the state object at iter+4).
const ITERATOR_WORDS: usize = 6;

/// The outer-iterator begin behind the `bl 0x08212a5c` at 0x0811d01c
/// inside [`vtable_file_record_teardown`]. 0x08212a5c is a 4-byte
/// thunk (`b 0x081dde18`) into `FUN_081dde18` @ 0x081dde18 (28 bytes;
/// **5 `bl` call sites**, grep on `decomp/osos.asm`; **unported**):
///
/// ```text
/// 081dde18  stmdb sp!, {r4, lr}
/// 081dde1c  mvn   r2, #0x1          @ r2 = 0xfffffffe
/// 081dde20  str   r1, [r0], #0x4    @ iter[0] = registry
/// 081dde24  bl    0x08155e80        @ state_init(iter + 4, registry, -2)
/// 081dde28  sub   r0, r0, #0x4      @ return iter
/// 081dde2c  ldmia sp!, {r4, pc}
/// ```
///
/// Stores the registry pointer in the iterator's first word and
/// initializes the state object at iter+4 through the unported
/// 0x08155e80; the returned iter pointer is discarded at this call
/// site. The wired default is a no-op: the state-machine init is an
/// unported registry-iterator subsystem, and paired with the
/// 0-returning [`VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT`] default it
/// yields an empty traversal (the `store_remove_unported` no-op
/// precedent). Host tests install a recording mock via
/// `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN: unsafe extern "C" fn(
    iter: *mut u32,
    registry: *mut u8,
) = teardown_outer_begin_unported;

/// Default outer-iterator begin: a no-op (see the seam's doc).
unsafe extern "C" fn teardown_outer_begin_unported(_iter: *mut u32, _registry: *mut u8) {}

/// The outer-iterator step behind the `bl 0x08212a4c` at 0x0811d07c
/// inside [`vtable_file_record_teardown`]. `FUN_08212a4c` @ 0x08212a4c
/// (16 bytes; **1 `bl` call site** — this function's; **unported**):
///
/// ```text
/// 08212a4c  stmdb sp!, {r3, lr}   @ spill slot = dead node out-slot
/// 08212a50  mov   r2, sp
/// 08212a54  bl    0x081ddde8      @ iterator_next(iter, key_out, &scratch)
/// 08212a58  ldmia sp!, {r12, pc}
/// ```
///
/// A spill-slot wrapper over the shared iterator step `FUN_081ddde8`
/// (see [`VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT`]): the node out-slot
/// is bound to the dead r3 spill because the outer loop consumes only
/// the key. Returns nonzero while keys remain. The wired default
/// returns 0 — no keys — so an unswapped table yields an empty
/// traversal (the `store_remove_unported` no-op precedent). Host tests
/// install a scripted mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT: unsafe extern "C" fn(
    iter: *mut u32,
    key_out: *mut u32,
) -> u32 = teardown_outer_next_unported;

/// Default outer-iterator step: returns 0, no keys (see the seam's
/// doc).
unsafe extern "C" fn teardown_outer_next_unported(_iter: *mut u32, _key_out: *mut u32) -> u32 {
    0
}

/// The inner-iterator begin behind the `bl 0x0821c4c8` at 0x0811d030
/// inside [`vtable_file_record_teardown`]. `FUN_0821c4c8` @ 0x0821c4c8
/// (36 bytes; **3 `bl` call sites**, grep on `decomp/osos.asm`;
/// **unported**):
///
/// ```text
/// 0821c4c8  stmdb sp!, {r4, lr}
/// 0821c4cc  mov   r4, r0            @ save iter
/// 0821c4d0  mov   r0, r1
/// 0821c4d4  mov   r1, r2
/// 0821c4d8  bl    0x0812d160        @ bucket = lookup(registry, key)
/// 0821c4dc  mov   r1, r0
/// 0821c4e0  mov   r0, r4
/// 0821c4e4  ldmia sp!, {r4, lr}
/// 0821c4e8  b     0x081dde18        @ tail: iterator_begin(iter, bucket)
/// ```
///
/// Looks the outer key up in the registry through the ported
/// [`vtable_file_record_lookup`] (0x0812d160) and tail-branches into
/// the shared iterator begin
/// `FUN_081dde18` (see [`VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN`])
/// over the resulting bucket. The wired default is a no-op (the
/// [`VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN`] rationale). Host tests
/// install a recording mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_INNER_BEGIN: unsafe extern "C" fn(
    iter: *mut u32,
    registry: *mut u8,
    key: u32,
) = teardown_inner_begin_unported;

/// Default inner-iterator begin: a no-op (see the seam's doc).
unsafe extern "C" fn teardown_inner_begin_unported(
    _iter: *mut u32,
    _registry: *mut u8,
    _key: u32,
) {
}

/// The inner-iterator step behind the `bl 0x081ddde8` at 0x0811d060
/// inside [`vtable_file_record_teardown`]. `FUN_081ddde8` @ 0x081ddde8
/// (48 bytes; **10 `bl` call sites**, grep on `decomp/osos.asm`, among
/// them the outer step wrapper 0x08212a4c's; **unported**):
///
/// ```text
/// 081ddde8  stmdb sp!, {r2, r3, r4, r5, r6, lr}  @ pair = out words
/// 081dddec  mov   r4, r1            @ save key_out
/// 081dddf0  mov   r1, sp
/// 081dddf4  mov   r5, r2            @ save node_out
/// 081dddf8  add   r0, r0, #0x4      @ step the state object
/// 081dddfc  bl    0x08155d6c        @ state_step(iter + 4, &pair)
/// 081dde00  cmp   r0, #0x0
/// 081dde04  ldrne r1, [sp, #0x0]
/// 081dde08  strne r1, [r4, #0x0]    @ *key_out = pair[0]
/// 081dde0c  ldrne r1, [sp, #0x4]
/// 081dde10  strne r1, [r5, #0x0]    @ *node_out = pair[1]
/// 081dde14  ldmia sp!, {r2, r3, r4, r5, r6, pc}
/// ```
///
/// Steps the state object at iter+4 through the unported 0x08155d6c
/// and, only on a nonzero status, copies the yielded key and node
/// words into the caller's out-slots. The wired default returns 0 —
/// the bucket is empty — so an unswapped table yields an empty
/// traversal (the `store_remove_unported` no-op precedent). `node_out`
/// is modeled pointer-sized (the [`vtable_file_record_teardown`]
/// host-representation deviation: the body dereferences the node).
/// Host tests install a scripted mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT: unsafe extern "C" fn(
    iter: *mut u32,
    key_out: *mut u32,
    node_out: *mut *mut u8,
) -> u32 = teardown_inner_next_unported;

/// Default inner-iterator step: returns 0, the bucket is empty (see
/// the seam's doc).
unsafe extern "C" fn teardown_inner_next_unported(
    _iter: *mut u32,
    _key_out: *mut u32,
    _node_out: *mut *mut u8,
) -> u32 {
    0
}

/// Indirect call to the unported observer-list release
/// `FUN_08271724`. The target walks the owner list at +0x0c and unlinks
/// `state` by its +0x10 next link; its return value is discarded.
///
/// The seam keeps that unported list implementation outside this one-function
/// port while retaining the target's `release(*state, state)` ABI.
pub static mut ITERATOR_STATE_RELEASE: unsafe extern "C" fn(
    owner: *mut u8,
    state: *mut u32,
) = iterator_state_release_unported;

/// Default for [`ITERATOR_STATE_RELEASE`]: the observer-list release is
/// unported, so it has no local effect.
unsafe extern "C" fn iterator_state_release_unported(_owner: *mut u8, _state: *mut u32) {}

/// iterator_state_cleanup — original: `FUN_08155ec0` @ 0x08155ec0 (48
/// bytes; 69 `bl` call sites).
///
/// Returns the iterator state object unchanged. Its state word at +0x08 is
/// a sentinel: when it is -5, no release occurs and the state remains
/// untouched. Otherwise it first calls `FUN_08271724(*state, state)`, then
/// writes -1 to that word. The release call's result is discarded; loading
/// word 0 before the call and returning the saved state pointer after it
/// matches the target's r0/r1 routing.
///
/// `FUN_08271724` is the sole unported callee. Its observer-list unlink is
/// represented by [`ITERATOR_STATE_RELEASE`], a narrow seam wired to a
/// no-op default. The vtable-file-record teardown seam and its two
/// container-teardown defaults call this port directly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iterator_state_cleanup(state: *mut u32) -> *mut u32 {
    if state.add(2).read() != (-5i32) as u32 {
        let release = core::ptr::read_volatile(core::ptr::addr_of!(ITERATOR_STATE_RELEASE));
        release(state.read() as *mut u8, state);
        state.add(2).write(u32::MAX);
    }
    state
}

/// The iterator-state cleanup behind the `bl 0x08155ec0` sites at
/// 0x0811d070 (inner, on sp+0x08) and 0x0811d08c (outer, on sp+0x28)
/// inside [`vtable_file_record_teardown`]. The ported
/// [`iterator_state_cleanup`] remains behind this role-specific seam so host
/// teardown tests can script the nested iteration independently.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP: unsafe extern "C" fn(
    state: *mut u32,
) -> *mut u32 = iterator_state_cleanup;

/// The registry dispose behind the `bl 0x0812d300` at 0x0811d09c
/// inside [`vtable_file_record_teardown`]. `FUN_0812d300` @ 0x0812d300
/// (24 bytes; **2 `bl` call sites**, grep on `decomp/osos.asm` — this
/// function's and 0x0811d1c4, the kind-2 branch of the tag-dispatching
/// dispose `FUN_0811d188`; **unported**):
///
/// ```text
/// 0812d300  stmdb sp!, {r4, lr}
/// 0812d304  mov   r4, r0
/// 0812d308  bl    0x0812d294        @ drain the remaining entries
/// 0812d30c  mov   r0, r4
/// 0812d310  ldmia sp!, {r4, lr}
/// 0812d314  b     0x0810e6b0        @ tail: object teardown
/// ```
///
/// 0x0812d294 walks the registry with the same begin/step pair
/// (`FUN_081dde18` / `FUN_081ddde8`) disposing each remaining entry
/// (0x0810e6b0 + `operator_delete`); the tail 0x0810e6b0 (a 4-byte
/// thunk, `b 0x08135380`) tears the object itself down (vtable-pointer
/// store, a vtable slot +0x1c call on the +0x24 member, the +0x1c
/// member freed and both words zeroed). The reference C's
/// "Subroutine does not return" on this callee is a Ghidra
/// mis-analysis: the tail chain returns (0x08135380 ends in its own
/// returning tail `b 0x08271d2c`), and the sibling call site runs
/// `bl 0x082aad24` immediately after it at 0x0811d1c8. The wired
/// default is a no-op — the registry-object subsystem is unported and
/// the object's words are unobservable until then (the
/// `construct_guard_unported` no-op precedent); the following
/// `operator_delete` still frees the block. Host tests install a
/// recording mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE: unsafe extern "C" fn(
    registry: *mut u8,
) = teardown_registry_dispose_unported;

/// Default registry dispose: a no-op (see the seam's doc).
unsafe extern "C" fn teardown_registry_dispose_unported(_registry: *mut u8) {}

/// vtable_file_record_teardown — original: `FUN_0811d008` @ 0x0811d008
/// (176 bytes; **1 `bl` call site**, grep on `decomp/osos.asm`:
/// 0x0811d200, the tail of the kind-1 branch of the tag-dispatching
/// dispose `FUN_0811d188` (128 bytes, unported), which first deletes a
/// non-NULL +0x08 (0x08212a60 + `operator_delete`) and a non-NULL
/// +0x10 (0x0821c4ec + `operator_delete`), then calls THIS function
/// and returns the record).
///
/// The teardown/destructor of the tagged 0x1c-byte file-record
/// family's registry half — the counterpart of the constructors
/// [`vtable_file_record_construct_kind1`] (0x0811d148) and
/// [`vtable_file_record_construct_kind2`] (0x0811d104) and the big
/// sibling of [`vtable_file_record_dispose`] (0x0811d8c0), operating
/// on the SAME 0x1c-byte record layout (tag at +0x00, registry at
/// +0x04):
///
/// ```text
/// 0811d008  stmdb sp!, {r4, lr}
/// 0811d00c  ldr   r1, [r0, #0x4]    @ registry = record.+0x04
/// 0811d010  sub   sp, sp, #0x40
/// 0811d014  mov   r4, r0            @ save record
/// 0811d018  add   r0, sp, #0x24     @ outer iterator (6 words)
/// 0811d01c  bl    0x08212a5c        @ outer_begin(&outer, registry)
/// 0811d020  b     0x0811d074
/// 0811d024  ldr   r1, [r4, #0x4]    @ registry (reloaded per key)
/// 0811d028  ldr   r2, [sp, #0x3c]   @ the yielded key
/// 0811d02c  add   r0, sp, #0x4      @ inner iterator (6 words)
/// 0811d030  bl    0x0821c4c8        @ inner_begin(&inner, registry, key)
/// 0811d034  b     0x0811d054
/// 0811d038  ldr   r0, [sp, #0x1c]   @ node
/// 0811d03c  mov   r1, #0x19
/// 0811d040  ldr   r0, [r0, #0x4]    @ node.+0x04 (the payload)
/// 0811d044  bl    0x080e7970        @ free_wrapper(payload, 0x19)
/// 0811d048  ldr   r0, [sp, #0x1c]
/// 0811d04c  mov   r1, #0x19
/// 0811d050  bl    0x080e7970        @ free_wrapper(node, 0x19)
/// 0811d054  add   r2, sp, #0x1c     @ &node
/// 0811d058  add   r1, sp, #0x20     @ &inner key (dead)
/// 0811d05c  add   r0, sp, #0x4
/// 0811d060  bl    0x081ddde8        @ inner_next(&inner, &ikey, &node)
/// 0811d064  cmp   r0, #0x0
/// 0811d068  bne   0x0811d038
/// 0811d06c  add   r0, sp, #0x8      @ inner state object (iter + 4)
/// 0811d070  bl    0x08155ec0        @ iter_cleanup(inner + 4)
/// 0811d074  add   r1, sp, #0x3c     @ &key
/// 0811d078  add   r0, sp, #0x24
/// 0811d07c  bl    0x08212a4c        @ outer_next(&outer, &key)
/// 0811d080  cmp   r0, #0x0
/// 0811d084  bne   0x0811d024
/// 0811d088  add   r0, sp, #0x28     @ outer state object (iter + 4)
/// 0811d08c  bl    0x08155ec0        @ iter_cleanup(outer + 4)
/// 0811d090  ldr   r0, [r4, #0x4]    @ registry (reloaded)
/// 0811d094  cmp   r0, #0x0
/// 0811d098  beq   0x0811d0a4        @ NULL -> skip dispose + delete
/// 0811d09c  bl    0x0812d300        @ registry_dispose(registry)
/// 0811d0a0  bl    0x082aad24        @ operator_delete(registry)
/// 0811d0a4  mov   r0, #0x0
/// 0811d0a8  str   r0, [r4, #0x4]    @ record.+0x04 = NULL
/// 0811d0ac  strb  r0, [r4, #0x0]    @ record.tag = 0
/// 0811d0b0  add   sp, sp, #0x40
/// 0811d0b4  ldmia sp!, {r4, pc}
/// ```
///
/// A nested walk of the registry at record +0x04: the OUTER iterator
/// (begin thunk 0x08212a5c → `FUN_081dde18`; step 0x08212a4c, a
/// spill-slot wrapper over the shared step `FUN_081ddde8` with a dead
/// node out-slot) yields each key; for every key the INNER iterator
/// (begin 0x0821c4c8 = key lookup 0x0812d160 + tail `FUN_081dde18`;
/// step `FUN_081ddde8` directly) walks that key's bucket, and every
/// node is freed TWICE through `free_wrapper` with caller tag 0x19 —
/// first the node's +0x04 payload word, then the node itself. Each
/// iterator is released by the cleanup 0x08155ec0 on its state object
/// (iter + 4). Finally, if record +0x04 is non-NULL, the registry
/// dispose 0x0812d300 runs and the object is `operator_delete`d; the
/// field and the tag byte are then zeroed on every path.
///
/// # Deviations
///
/// - **Five unported callees sit behind seams** — the outer begin
///   0x08212a5c behind [`VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN`],
///   the outer step 0x08212a4c behind
///   [`VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT`], the inner begin
///   0x0821c4c8 behind [`VTABLE_FILE_RECORD_TEARDOWN_INNER_BEGIN`],
///   the inner step `FUN_081ddde8` behind
///   [`VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT`], and the registry
///   dispose 0x0812d300 behind
///   [`VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE`]. The ported
///   [`iterator_state_cleanup`] remains behind
///   [`VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP`] for host-test
///   interception, wired directly as its default. The unported defaults
///   yield an EMPTY traversal (no-op begins/dispose and 0-returning
///   steps), so an unswapped table runs through cleanup then straight to
///   the guard/delete/zero tail (the `store_remove_unported` /
///   `construct_guard_unported` no-op precedent). Host tests install
///   scripted recording mocks.
/// - **`free_wrapper` (0x080e7970) and `operator_delete` (0x082aad24)
///   are called directly** — both ported in `heap/veneers.rs` (the
///   app/class_6800.rs ported-callees-called-directly precedent);
///   host tests observe the frees through the `HEAP_OPS.free` slot.
/// - **The node out-slot is modeled pointer-sized** (`*mut *mut u8`),
///   although the original's `ldr r0, [sp, #0x1c]` is a 32-bit load:
///   the body DEREFERENCES the node (`ldr r0, [r0, #0x4]`), so a
///   truncated host pointer would fault — the [`vtable_file_open`]
///   host-representation deviation. The node's +0x04 payload word is
///   only forwarded to `free_wrapper`, so it stays a byte-exact
///   32-bit read.
/// - **The record's +0x04 registry field stays a 32-bit word** (the
///   [`vtable_file_record_construct_kind1`] byte-exact precedent) —
///   on a 64-bit host the pointer truncates to its low 32 bits, the
///   exact inverse of the constructors' u32 store.
/// - **The return type is `()`** — the epilogue's r0 is the zero
///   immediate of the two clearing stores, and the sole caller
///   overwrites r0 with the record pointer (`mov r0, r4` at
///   0x0811d1fc) before the call.
/// - **No `forwarded` parameter**: the entry `stmdb` spills no
///   argument registers and r1..r3 are never read — this is a record
///   destructor, not a message thunk (the
///   [`vtable_file_record_construct_kind1`] precedent).
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d008_FUN_0811d008.c` gets the loop shape and
///   the double free right, but its "Subroutine does not return" on
///   `FUN_0812d300` is a Ghidra mis-analysis (the callee's tail chain
///   returns — see the [`VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE`]
///   doc — and the operator delete after it is live code here and at
///   the sibling site 0x0811d1c8), and its stack naming hides that
///   the outer step's node out-slot is the 0x08212a4c wrapper's dead
///   r3 spill. The port follows the disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_teardown(record: *mut u8) {
    // The original's 0x40-byte frame, modeled as locals: the outer
    // iterator (sp+0x24, six words), the outer key out-slot (sp+0x3c),
    // the inner iterator (sp+0x04, six words), the inner key out-slot
    // (sp+0x20, dead — nothing reads the inner key back) and the node
    // out-slot (sp+0x1c).
    let mut outer = [0u32; ITERATOR_WORDS];
    let mut key = 0u32;
    let mut inner = [0u32; ITERATOR_WORDS];
    let mut inner_key = 0u32;
    let mut node: *mut u8 = core::ptr::null_mut();

    let outer_begin =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN));
    outer_begin(
        outer.as_mut_ptr(),
        record.add(4).cast::<u32>().read() as *mut u8,
    );
    loop {
        let outer_next =
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT));
        if outer_next(outer.as_mut_ptr(), &mut key) == 0 {
            break;
        }
        let inner_begin =
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_INNER_BEGIN));
        inner_begin(
            inner.as_mut_ptr(),
            record.add(4).cast::<u32>().read() as *mut u8,
            key,
        );
        loop {
            let inner_next = core::ptr::read_volatile(core::ptr::addr_of!(
                VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT
            ));
            if inner_next(inner.as_mut_ptr(), &mut inner_key, &mut node) == 0 {
                break;
            }
            crate::heap::veneers::free_wrapper(
                node.add(4).cast::<u32>().read() as *mut u8,
                FILE_RECORD_NODE_FREE_TAG,
            );
            crate::heap::veneers::free_wrapper(node, FILE_RECORD_NODE_FREE_TAG);
        }
        let cleanup =
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP));
        cleanup(inner.as_mut_ptr().add(1));
    }
    let cleanup =
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP));
    cleanup(outer.as_mut_ptr().add(1));
    let registry = record.add(4).cast::<u32>().read() as *mut u8;
    if !registry.is_null() {
        let dispose = core::ptr::read_volatile(core::ptr::addr_of!(
            VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE
        ));
        dispose(registry);
        crate::heap::veneers::operator_delete(registry);
    }
    record.add(4).cast::<u32>().write(0);
    record.write(0);
}

/// The kind-1 +0x08 container teardown behind the `bl 0x08212a60` at
/// 0x0811d1e0 inside [`vtable_file_record_destruct`]. `FUN_08212a60` @
/// 0x08212a60 (16 bytes; **1 `bl` call site** — this function's; grep
/// on `decomp/osos.asm`; **unported**):
///
/// ```text
/// 08212a60  stmdb sp!, {r4, lr}
/// 08212a64  add   r0, r0, #0x4
/// 08212a68  bl    0x08155ec0        @ iter_cleanup(container + 4)
/// 08212a6c  sub   r0, r0, #0x4      @ return the container
/// 08212a70  ldmia sp!, {r4, pc}
/// ```
///
/// The +0x08 container is one more iterator scratch object: its state
/// object (container + 4) is released through the SAME iterator-state
/// cleanup `FUN_08155ec0` [`vtable_file_record_teardown`] uses
/// ([`VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP`]), and the container
/// pointer returns so the caller's following `operator_delete` frees
/// the block. The reference C's "Subroutine does not return" on this
/// callee is a Ghidra mis-analysis: the body ends in a real `ldmia
/// sp!, {r4, pc}` and the `bl 0x082aad24` after it (0x0811d1e4) is live
/// code. The wired default models the exact chain: it calls the ported
/// [`iterator_state_cleanup`] directly on the state object, then returns the
/// container so the caller's following `operator_delete` frees the right
/// block. It intentionally does not route through the teardown's
/// role-specific seam, which keeps host tests able to script those nested
/// calls independently (the [`VTABLE_QUERY_4C_SCALAR_DISPATCH`] precedent).
/// Host tests install a recording mock via `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN: unsafe extern "C" fn(
    container: *mut u8,
) -> *mut u8 = destruct_container_teardown_default;

/// The kind-1 +0x10 container teardown behind the `bl 0x0821c4ec` at
/// 0x0811d1f4 inside [`vtable_file_record_destruct`]. `FUN_0821c4ec` @
/// 0x0821c4ec (16 bytes; **2 `bl` call sites**, grep on
/// `decomp/osos.asm`: 0x0811cd44 in the unported `FUN_0811ccd0` and
/// this function's; **unported**) — the byte-identical twin of
/// `FUN_08212a60` (see [`VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN`]):
///
/// ```text
/// 0821c4ec  stmdb sp!, {r4, lr}
/// 0821c4f0  add   r0, r0, #0x4
/// 0821c4f4  bl    0x08155ec0        @ iter_cleanup(container + 4)
/// 0821c4f8  sub   r0, r0, #0x4      @ return the container
/// 0821c4fc  ldmia sp!, {r4, pc}
/// ```
///
/// Same shape, same default, same Ghidra "Subroutine does not return"
/// mis-analysis (the `bl 0x082aad24` at 0x0811d1f8 is live). A
/// separate role-specific seam — not a shared one — keeps host tests
/// able to tell the +0x08 call from the +0x10 call and to script them
/// independently (the [`VTABLE_FILE_RECORD_KIND1_GUARD`] /
/// [`VTABLE_FILE_RECORD_KIND2_GUARD`] two-seams-one-default
/// precedent). Host tests install a recording mock via
/// `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER10_TEARDOWN: unsafe extern "C" fn(
    container: *mut u8,
) -> *mut u8 = destruct_container_teardown_default;

/// Default kind-1 container teardown: the exact 16-byte body of
/// `FUN_08212a60` / `FUN_0821c4ec`. The ported
/// [`iterator_state_cleanup`] runs on the state object at container + 4,
/// then the container pointer returns so the caller's `operator_delete`
/// frees the right block. Shared by both kind-1 container seams (the
/// `construct_guard_unported` shared-default precedent).
unsafe extern "C" fn destruct_container_teardown_default(container: *mut u8) -> *mut u8 {
    iterator_state_cleanup(container.add(4).cast::<u32>());
    container
}

/// The kind-2 +0x18 dispose behind the `bl 0x0812d300` at 0x0811d1c4
/// inside [`vtable_file_record_destruct`]. `FUN_0812d300` @ 0x0812d300
/// (24 bytes; **2 `bl` call sites**, grep on `decomp/osos.asm` — this
/// function's and 0x0811d09c inside [`vtable_file_record_teardown`];
/// **unported**) is the registry dispose already documented under
/// [`VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE`]: it drains the
/// remaining entries (0x0812d294) and tail-branches to the object
/// teardown 0x0810e6b0 (`b 0x08135380`). The reference C's
/// "Subroutine does not return" is the same Ghidra mis-analysis — the
/// tail chain returns and the `bl 0x082aad24` at 0x0811d1c8 is live.
/// Wired to the SAME no-op default as the teardown sibling's seam
/// (the [`VTABLE_FILE_RECORD_KIND2_GUARD`] precedent — a
/// role-specific name keeps host tests from racing the sibling's
/// parallel tests). Host tests install a recording mock via
/// `core::ptr::addr_of_mut!`.
pub static mut VTABLE_FILE_RECORD_DESTRUCT_KIND2_DISPOSE: unsafe extern "C" fn(
    registry: *mut u8,
) = teardown_registry_dispose_unported;

/// vtable_file_record_destruct — original: `FUN_0811d188` @ 0x0811d188
/// (128 bytes; **2 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0815aa74 and 0x0819fdf8 — both are the destruct-then-free pair
/// `bl 0x0811d188; bl 0x082aad24` on a NULL-guarded record pointer
/// (`ldr r0, [r4, #0xcc]; cmp; beq` / two `ldrne`s and `cmpne; beq`),
/// so both consume the returned record pointer as `operator_delete`'s
/// argument).
///
/// The tag-dispatched destructor of the tagged 0x1c-byte file-record
/// family — the counterpart of the constructors
/// [`vtable_file_record_construct_kind1`] (0x0811d148) and
/// [`vtable_file_record_construct_kind2`] (0x0811d104), dispatching on
/// the tag byte they write at record +0x00:
///
/// ```text
/// 0811d188  stmdb sp!, {r4, lr}
/// 0811d18c  mov   r4, r0            @ save record
/// 0811d190  ldrb  r0, [r0, #0x0]    @ tag = record.+0x00
/// 0811d194  cmp   r0, #0x0
/// 0811d198  beq   0x0811d1cc        @ tag 0 -> return the record
/// 0811d19c  cmp   r0, #0x1
/// 0811d1a0  beq   0x0811d1d4        @ tag 1 -> kind-1 branch
/// 0811d1a4  cmp   r0, #0x2
/// 0811d1a8  bne   0x0811d1cc        @ unknown tag -> return the record
/// 0811d1ac  ldr   r0, [r4, #0x4]    @ kind 2: block = record.+0x04
/// 0811d1b0  cmp   r0, #0x0
/// 0811d1b4  blne  0x082aad24        @ operator_delete(block) — NO dispose
/// 0811d1b8  ldr   r0, [r4, #0x18]   @ registry = record.+0x18
/// 0811d1bc  cmp   r0, #0x0
/// 0811d1c0  beq   0x0811d1cc
/// 0811d1c4  bl    0x0812d300        @ registry_dispose(registry)
/// 0811d1c8  bl    0x082aad24        @ operator_delete(registry)
/// 0811d1cc  mov   r0, r4            @ return the record
/// 0811d1d0  ldmia sp!, {r4, pc}
/// 0811d1d4  ldr   r0, [r4, #0x8]    @ kind 1: container = record.+0x08
/// 0811d1d8  cmp   r0, #0x0
/// 0811d1dc  beq   0x0811d1e8
/// 0811d1e0  bl    0x08212a60        @ container08_teardown(container)
/// 0811d1e4  bl    0x082aad24        @ operator_delete(its return)
/// 0811d1e8  ldr   r0, [r4, #0x10]   @ container = record.+0x10
/// 0811d1ec  cmp   r0, #0x0
/// 0811d1f0  beq   0x0811d1fc
/// 0811d1f4  bl    0x0821c4ec        @ container10_teardown(container)
/// 0811d1f8  bl    0x082aad24        @ operator_delete(its return)
/// 0811d1fc  mov   r0, r4
/// 0811d200  bl    0x0811d008        @ vtable_file_record_teardown(record)
/// 0811d204  b     0x0811d1cc        @ return the record
/// ```
///
/// Tag 0 and any unknown tag are a straight no-op returning the
/// record. **Kind 1** tears the two iterator containers down in field
/// order — +0x08 first, then +0x10 — each only when non-NULL, each
/// teardown (0x08212a60 / 0x0821c4ec, the iterator-state-cleanup
/// wrappers) immediately followed by `operator_delete` on the
/// teardown's return value, then runs the shared registry-half
/// teardown [`vtable_file_record_teardown`] (0x0811d008, ported in
/// this module) on the whole record. **Kind 2** deletes the +0x04
/// block directly (NO dispose — the block is a plain five-word
/// allocation from [`vtable_file_record_construct_kind2`]'s
/// `operator_new(0x14)`, not an object) and, when +0x18 is non-NULL,
/// disposes it through 0x0812d300 before deleting it. This function
/// itself writes NOTHING back to the record — the tag and +0x04
/// clearing on the kind-1 path is the teardown's own tail.
///
/// # Deviations
///
/// - **The three unported callees sit behind seams** — 0x08212a60
///   behind [`VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN`],
///   0x0821c4ec behind
///   [`VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER10_TEARDOWN`] and
///   0x0812d300 behind [`VTABLE_FILE_RECORD_DESTRUCT_KIND2_DISPOSE`].
///   The container seams' wired default models the exact 16-byte bodies:
///   direct [`iterator_state_cleanup`] on container + 4, then return the
///   container so the following `operator_delete` frees the right block.
///   The kind-2 dispose seam shares the teardown sibling's no-op default
///   (see each seam's doc).
/// - **[`vtable_file_record_teardown`] is called DIRECTLY** (the
///   original's `bl 0x0811d008` at 0x0811d200 targets the ported
///   body — the app/class_6800.rs ported-callees-called-directly
///   precedent) and **`operator_delete` (0x082aad24) is called
///   directly** (ported in `heap/veneers.rs`); host tests observe the
///   deletes through the `HEAP_OPS.free` slot (the
///   [`vtable_file_record_teardown`] precedent).
/// - **The kind-1 deletes consume the teardown seams' RETURN value**
///   (`operator_delete(teardown(container))`): the original's `bl
///   0x082aad24` receives r0 straight from 0x08212a60 / 0x0821c4ec,
///   and both callees provably return their argument (`sub r0, r0,
///   #0x4` after the cleanup).
/// - **The kind-2 +0x18 delete gets the guarded word, not the
///   dispose's return** — the [`vtable_file_record_teardown`]
///   convention for the same `bl 0x0812d300; bl 0x082aad24` pair:
///   0x0812d300 reloads r0 with its argument (`mov r0, r4`) before
///   tail-branching into the object-teardown chain, whose return is
///   not established; the seam returns nothing and the registry
///   pointer is deleted.
/// - **Every field load keeps the original's width**: `ldrb` for the
///   tag, 32-bit `ldr` for the pointer words (on a 64-bit host the
///   pointers truncate to their low 32 bits — the
///   [`vtable_file_record_init`] byte-exact precedent).
/// - **No `forwarded` parameter**: the entry `stmdb` spills no
///   argument registers and r1..r3 are never read — this is a record
///   destructor, not a message thunk (the
///   [`vtable_file_record_construct_kind1`] precedent).
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d188_FUN_0811d188.c` marks all three
///   container/registry teardowns "Subroutine does not return" — the
///   disassembly shows real returns (0x08212a60 / 0x0821c4ec end in
///   `ldmia sp!, {r4, pc}`; 0x0812d300's tail chain returns — see
///   [`VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE`]) and the
///   `operator_delete` after each is live code — and it drops every
///   call argument (the teardowns receive the container in r0, the
///   deletes the teardown's return). The port follows the
///   disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_destruct(record: *mut u8) -> *mut u8 {
    let tag = record.read();
    if tag == FILE_RECORD_TAG_KIND1 {
        let container = record.add(8).cast::<u32>().read() as *mut u8;
        if !container.is_null() {
            let teardown = core::ptr::read_volatile(core::ptr::addr_of!(
                VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN
            ));
            crate::heap::veneers::operator_delete(teardown(container));
        }
        let container = record.add(0x10).cast::<u32>().read() as *mut u8;
        if !container.is_null() {
            let teardown = core::ptr::read_volatile(core::ptr::addr_of!(
                VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER10_TEARDOWN
            ));
            crate::heap::veneers::operator_delete(teardown(container));
        }
        vtable_file_record_teardown(record);
    } else if tag == FILE_RECORD_TAG_KIND2 {
        let block = record.add(4).cast::<u32>().read() as *mut u8;
        if !block.is_null() {
            crate::heap::veneers::operator_delete(block);
        }
        let registry = record.add(0x18).cast::<u32>().read() as *mut u8;
        if !registry.is_null() {
            let dispose = core::ptr::read_volatile(core::ptr::addr_of!(
                VTABLE_FILE_RECORD_DESTRUCT_KIND2_DISPOSE
            ));
            dispose(registry);
            crate::heap::veneers::operator_delete(registry);
        }
    }
    record
}

/// The node size [`vtable_file_record_insert`] allocates (`mov r0,
/// #0x8` ahead of the `bl 0x080eb67c`) — the two-word `{payload, data}`
/// node [`vtable_file_record_teardown`] later frees twice (the +0x04
/// data word, then the node itself).
const FILE_RECORD_NODE_SIZE: usize = 8;

/// The caller tag [`vtable_file_record_insert`] hands `malloc_wrapper`
/// (`mov r1, #0x19` at 0x0811d0cc) — the same 0x19
/// [`vtable_file_record_teardown`] frees the nodes with
/// ([`FILE_RECORD_NODE_FREE_TAG`]).
const FILE_RECORD_NODE_ALLOC_TAG: usize = 0x19;

/// The bucket lookup behind the `bl 0x0812d160` inside
/// [`vtable_file_record_insert`]'s inlined tail body — the ported
/// [`vtable_file_record_lookup`] (`FUN_0812d160` @ 0x0812d160, 24
/// bytes), which IS this seam's wired default (the
/// cell_size_ptr / get_varint promotion precedent: the port replaced
/// the private model, callers keep routing through the seam — no
/// rewiring). The seam is retained for host-test interception: on
/// firmware the lookup bottoms out in the registry's vtable
/// dispatches (+0x4c `index_of` / +0x3c `entry_at` inside
/// `registry_find`), so host tests install a scripted mock via
/// `core::ptr::addr_of_mut!` instead of running the default against a
/// real container.
pub static mut VTABLE_FILE_RECORD_INSERT_LOOKUP: unsafe extern "C" fn(
    registry: *mut u8,
    key: u32,
) -> *mut u8 = vtable_file_record_lookup;

/// vtable_file_record_lookup — original: `FUN_0812d160` @ 0x0812d160
/// (24 bytes; **6 `bl` call sites**, grep on `decomp/osos.asm`:
/// 0x0812d184 (the dispose-bucket wrapper `FUN_0812d178`), 0x0812d1cc
/// (the shared insert tail [`vtable_file_record_insert`] inlines),
/// 0x0812d218, 0x0812d240 and 0x0812d264 (the rest of the
/// registry-facade thunk cluster 0x0812d178..0x0812d254), and
/// 0x0821c4d8 in the inner-iterator begin `FUN_0821c4c8`
/// [`vtable_file_record_teardown`] documents).
///
/// The keyed registry lookup of the file-record family — a spill-slot
/// wrapper over the PORTED `app/registry.rs` `registry_lookup`
/// (0x0810e4c8):
///
/// ```text
/// 0812d160  stmdb sp!, {r3, lr}   @ spill slot = the value out-slot
/// 0812d164  mov   r2, sp          @ out = &slot (arg3 DIES here)
/// 0812d168  bl    0x0810e4c8      @ registry_lookup(registry, key, &slot)
/// 0812d16c  cmp   r0, #0x0
/// 0812d170  ldrne r0, [sp, #0x0]  @ hit -> r0 = the registered value
/// 0812d174  ldmia sp!, {r12, pc}  @ miss -> r0 stays 0 (NULL)
/// ```
///
/// Returns the value registered under `key`, or NULL on a miss.
///
/// # Deviations
///
/// - **The search 0x0810e4c8 is called DIRECTLY** — it is already
///   ported in `app/registry.rs` as `registry_lookup` (the
///   app/class_6800.rs ported-callees-called-directly precedent), so
///   no inner seam is introduced. The only unported remainder of the
///   original chain is the registry's firmware vtable methods
///   themselves, reached through `registry_find`'s dispatches.
/// - **arg3 (r2) is DEAD** — `mov r2, sp` overwrites it with the
///   out-slot pointer before the search; the reference C's `param_3`
///   is genuinely unused. The port drops the parameter.
/// - **arg4 (r3) seeds the out-slot** — the entry `stmdb sp!, {r3,
///   lr}` spill is the slot `registry_lookup` is pointed at, exactly
///   the family's r3-spill pattern the 0x0811d340 entry documents
///   (here the spill feeds the out-slot rather than a dispatcher's
///   `extra`). It is UNOBSERVABLE: `registry_lookup` writes the slot
///   on every nonzero-status path and the slot is only loaded then
///   (`ldrne`), while on a miss r0 is 0 regardless of the slot's
///   content — so the port's `value` local needs no seed (the
///   `app/registry.rs` zeroed-stack-pair deviation precedent). No
///   call site relies on it ([`vtable_file_record_insert`]'s inlined
///   tail happens to pass the node pointer in r3).
/// - **The reference C is accurate in shape**
///   (`decomp/c/011/0812d160_FUN_0812d160.c`: `local_8[0] = param_4`
///   is the r3 spill, the search gets `param_1`/`param_2` and the
///   slot, the value returns only on nonzero status); the port only
///   drops the dead `param_3` and gives the untyped parameters their
///   concrete registry/key types.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_lookup(registry: *mut u8, key: u32) -> *mut u8 {
    let mut value: *mut u8 = core::ptr::null_mut();
    let found = crate::app::registry::registry_lookup(registry.cast(), key, &mut value);
    if found != 0 { value } else { core::ptr::null_mut() }
}

/// vtable_file_record_insert — original: `FUN_0811d0b8` @ 0x0811d0b8
/// (160 bytes per `decomp/functions.csv`: the 76-byte body at
/// 0x0811d0b8 plus the 84-byte shared tail body at 0x0812d1b8 it
/// tail-branches into — see the deviations; **1 `bl` call site**, grep
/// on `decomp/osos.asm`: 0x0811ca40 in `FUN_0811c9f0`, which
/// `malloc_wrapper`s a byte-count-sized block, `memcpy`s (0x08037db0)
/// its arg4 into it and hands this function the block as arg4 and the
/// byte count as the stacked arg5 — arg4 is the node PAYLOAD pointer,
/// arg5 its length. The tag-0x1a sibling `FUN_0811cefc` reaches the
/// same shared tail with its own `b 0x0812d1b8` at 0x0811cf68, reading
/// the registry from its record's +0x18 instead of +0x04).
///
/// The insert/append operation of the tagged 0x1c-byte file-record
/// family — the counterpart of the constructors
/// [`vtable_file_record_construct_kind1`] (0x0811d148) /
/// [`vtable_file_record_construct_kind2`] (0x0811d104), the teardown
/// [`vtable_file_record_teardown`] (0x0811d008, which walks exactly
/// the two-level registry this function builds) and the destructor
/// [`vtable_file_record_destruct`] (0x0811d188):
///
/// ```text
/// 0811d0b8  stmdb sp!, {r4, r5, r6, r7, r8, r9, r10, lr}
/// 0811d0bc  mov   r7, r1            @ save key (arg2)
/// 0811d0c0  mov   r5, r0            @ save record (arg1)
/// 0811d0c4  ldr   r9, [sp, #0x20]   @ payload (arg5, the stacked word)
/// 0811d0c8  mov   r0, #0x8
/// 0811d0cc  mov   r1, #0x19
/// 0811d0d0  mov   r8, r2            @ save inner_key (arg3)
/// 0811d0d4  mov   r6, r3            @ save data (arg4)
/// 0811d0d8  bl    0x080eb67c        @ malloc_wrapper(8, 0x19)
/// 0811d0dc  mov   r4, r0            @ node
/// 0811d0e0  bl    0x080edb74        @ checked-alloc guard(node)
/// 0811d0e4  str   r6, [r4, #0x4]    @ node.+0x04 = data
/// 0811d0e8  str   r9, [r4, #0x0]    @ node.+0x00 = payload
/// 0811d0ec  ldr   r0, [r5, #0x4]    @ registry = record.+0x04
/// 0811d0f0  mov   r3, r4            @ arg4 = node
/// 0811d0f4  mov   r2, r8            @ arg3 = inner_key
/// 0811d0f8  mov   r1, r7            @ arg2 = key
/// 0811d0fc  ldmia sp!, {r4, r5, r6, r7, r8, r9, r10, lr}
/// 0811d100  b     0x0812d1b8        @ tail: the shared insert body
///
/// 0812d1b8  stmdb sp!, {r4, r5, r6, r7, r8, lr}
/// 0812d1bc  mov   r8, r3            @ save node
/// 0812d1c0  mov   r7, r2            @ save inner_key
/// 0812d1c4  mov   r6, r1            @ save key
/// 0812d1c8  mov   r5, r0            @ save registry
/// 0812d1cc  bl    0x0812d160        @ bucket = lookup(registry, key)
/// 0812d1d0  movs  r4, r0
/// 0812d1d4  bne   0x0812d1f8        @ hit -> insert straight away
/// 0812d1d8  mov   r0, #0x28
/// 0812d1dc  bl    0x082aadd4        @ miss: operator_new(0x28)
/// 0812d1e0  bl    0x0810e64c        @ bucket = class_registry_construct(block)
/// 0812d1e4  mov   r4, r0
/// 0812d1e8  mov   r2, r0
/// 0812d1ec  mov   r0, r5
/// 0812d1f0  mov   r1, r6
/// 0812d1f4  bl    0x0810e4ac        @ registry_insert(registry, key, bucket)
/// 0812d1f8  mov   r2, r8
/// 0812d1fc  mov   r1, r7
/// 0812d200  mov   r0, r4
/// 0812d204  ldmia sp!, {r4, r5, r6, r7, r8, lr}
/// 0812d208  b     0x0810e4ac        @ tail: registry_insert(bucket, inner_key, node)
/// ```
///
/// An 8-byte node is allocated through the checked wrapper
/// `malloc_wrapper(8, 0x19)` (0x080eb67c) and handed to the
/// checked-construct guard 0x080edb74, then filled: **arg4 (data) at
/// node +0x04, arg5 (payload) at node +0x00**. The registry at record
/// +0x04 is then looked up for the arg2 key through the thunk
/// 0x0812d160; on a miss a fresh 0x28 registry is allocated
/// (`operator_new`), constructed (0x0810e64c, the ported
/// `app/class_registry.rs` `class_registry_construct`) and itself
/// inserted into the outer registry keyed by arg2 (0x0810e4ac, the
/// ported `app/registry.rs` `registry_insert` — its vtable slot +0x1c
/// dispatch with the `{key, value}` pair on the stack). Either way the
/// node is finally inserted into the bucket keyed by arg3, through the
/// same `registry_insert` tail.
///
/// # Deviations
///
/// - **The port inlines the shared tail body 0x0812d1b8.**
///   `decomp/functions.csv` lumps it into this function's 160-byte row
///   (76 + 84) and Ghidra decompiles the pair as one C function; the
///   tail's only other reach is the tag-0x1a sibling's `b 0x0812d1b8`
///   at 0x0811cf68. One function per commit — the sibling stays
///   unported.
/// - **`malloc_wrapper` (0x080eb67c), `operator_new` (0x082aadd4) and
///   `registry_insert` (0x0810e4ac) are called DIRECTLY** — all three
///   ported (`heap/veneers.rs`, `app/registry.rs`; the
///   app/class_6800.rs ported-callees-called-directly precedent).
///   Host tests observe the allocations through the `HEAP_OPS.alloc`
///   slot and drive the insert's vtable +0x1c dispatch with fake
///   registry vtables.
/// - **The checked-alloc guard 0x080edb74 and the registry construct
///   0x0810e64c reuse the EXISTING [`VTABLE_FILE_RECORD_KIND1_GUARD`]
///   / [`VTABLE_FILE_RECORD_KIND1_CTOR`] seams** — the same callees
///   the kind-1 constructor seamed (no duplicate seam under a second
///   name). Note the original here `bl`s 0x0810e64c DIRECTLY (not
///   through the kind-1's 0x0812d2fc thunk), so the seam's wired
///   default — which calls the ported `class_registry_construct`
///   straight — models this call chain even more exactly than the
///   kind-1 one. The guard's r0 (the node) is dead after the call, so
///   the seam returns nothing (the kind-1 precedent).
/// - **The lookup thunk 0x0812d160 is ported** in this module as
///   [`vtable_file_record_lookup`], which is the wired default of the
///   [`VTABLE_FILE_RECORD_INSERT_LOOKUP`] seam (the cell_size_ptr /
///   get_varint promotion precedent); the call still routes through
///   the seam — retained for hookability — so host tests observe it
///   by swapping that one static.
/// - **The record's +0x04 registry field is read POINTER-SIZED**, a
///   host-representation deviation from the original's 32-bit `ldr
///   r0, [r5, #0x4]`: the miss path dereferences the registry through
///   `registry_insert`'s vtable read, so a truncated host pointer
///   would fault (the [`vtable_file_record_teardown`] node out-slot
///   precedent). On the 32-bit target the read is byte-identical.
/// - **The node field stores keep the original's 32-bit `str`
///   widths** (the [`vtable_file_record_init`] byte-exact precedent):
///   both words are plain data words — teardown forwards +0x04 to
///   `free_wrapper` and +0x00 is never dereferenced by the family.
/// - **The return type is `()`** — the tail chain leaves
///   `registry_insert`'s result in r0, but the sole call site
///   discards it (`ldmia sp!, {r3..r9, pc}` at 0x0811ca44 never
///   touches r0), and the reference C agrees (`void`).
/// - **No `forwarded` parameter**: the entry `stmdb` spills no
///   argument registers; r1..r3 are saved into r6..r8 and the stacked
///   fifth argument is a REAL argument (the [`vtable_file_open`]
///   record-function precedent, not a message thunk).
/// - **The reference C is not followed where it mis-decompiles**:
///   `decomp/c/010/0811d0b8_FUN_0811d0b8.c` gets the node shape right
///   but drops every argument of the inlined tail — `FUN_0812d160()`
///   takes the registry and the arg2 key, `FUN_0810e64c()` takes the
///   fresh `operator_new` block, `FUN_0810e4ac(uVar2, param_2,
///   piVar3)` is the OUTER insert of the new bucket under arg2 — and
///   its closing `(**(code **)(*piVar3 + 0x1c))(piVar3,
///   &stack0xfffffff0)` hides that there are TWO `registry_insert`
///   calls and that the final one's stack pair is `{arg3, node}`
///   built inside 0x0810e4ac itself. The port follows the
///   disassembly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_file_record_insert(
    record: *mut u8,
    key: u32,
    inner_key: u32,
    data: u32,
    payload: u32,
) {
    let node = crate::heap::veneers::malloc_wrapper(FILE_RECORD_NODE_SIZE, FILE_RECORD_NODE_ALLOC_TAG);
    let guard = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_KIND1_GUARD));
    guard(node);
    node.cast::<u32>().add(1).write(data);
    node.cast::<u32>().write(payload);
    let registry = record.add(4).cast::<*mut u8>().read();
    let lookup = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_INSERT_LOOKUP));
    let mut bucket = lookup(registry, key);
    if bucket.is_null() {
        let ctor = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FILE_RECORD_KIND1_CTOR));
        bucket = ctor(crate::heap::veneers::operator_new(REGISTRY_OBJECT_SIZE));
        crate::app::registry::registry_insert(registry.cast(), key, bucket);
    }
    crate::app::registry::registry_insert(bucket.cast(), inner_key, node);
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
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_SCALAR_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_SCALAR_FINISH)
                    .write_volatile(crate::util::vtable_query::vtable_query_4c_kind4);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_BUFFER_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_BUFFER_FINISH)
                    .write_volatile(crate::util::vtable_query::vtable_query_4c_kind4);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_WALK_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_WALK_QUERY)
                    .write_volatile(crate::util::vtable_query::vtable_query_4c_kind4);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_RECORD_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch);
                core::ptr::addr_of_mut!(VTABLE_QUERY_4C_RECORD_FINISH)
                    .write_volatile(crate::util::vtable_query::vtable_query_4c_kind4);
                core::ptr::addr_of_mut!(VTABLE_FILE_OPEN_REMOVE)
                    .write_volatile(store_remove_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_OPEN_CTOR)
                    .write_volatile(store_ctor_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_CTOR)
                    .write_volatile(kind1_registry_ctor_default);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_GUARD)
                    .write_volatile(construct_guard_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC)
                    .write_volatile(kind2_block_diagnostic_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND2_GUARD)
                    .write_volatile(construct_guard_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN)
                    .write_volatile(teardown_outer_begin_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT)
                    .write_volatile(teardown_outer_next_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_INNER_BEGIN)
                    .write_volatile(teardown_inner_begin_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT)
                    .write_volatile(teardown_inner_next_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP)
                    .write_volatile(iterator_state_cleanup);
                core::ptr::addr_of_mut!(ITERATOR_STATE_RELEASE)
                    .write_volatile(iterator_state_release_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE)
                    .write_volatile(teardown_registry_dispose_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN)
                    .write_volatile(destruct_container_teardown_default);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER10_TEARDOWN)
                    .write_volatile(destruct_container_teardown_default);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND2_DISPOSE)
                    .write_volatile(teardown_registry_dispose_unported);
                core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_INSERT_LOOKUP)
                    .write_volatile(vtable_file_record_lookup);
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
    static mut DISPATCH_HANDLE: [*mut *mut u8; 12] = [core::ptr::null_mut(); 12];
    static mut DISPATCH_KIND: [u32; 12] = [0; 12];
    static mut DISPATCH_WORD0: [u32; 12] = [0; 12];
    static mut DISPATCH_WORD1: [u32; 12] = [0; 12];
    static mut DISPATCH_EXTRA: [usize; 12] = [0; 12];
    static mut DISPATCH_RESULTS: [u32; 12] = [MOCK_OK; 12];

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
        // The fixtures reserve two readable words from every message
        // pointer. `read_unaligned` additionally lets record byte fields
        // at offsets 1..4 be observed without imposing host alignment.
        // The neighbour word is only asserted for two-word messages.
        DISPATCH_WORD0[call] = (data as *const u32).read_unaligned();
        DISPATCH_WORD1[call] = (data as *const u32).add(1).read_unaligned();
        DISPATCH_EXTRA[call] = extra.read();
        DISPATCH_RESULTS[call]
    }

    unsafe fn install_recording_dispatch() {
        DISPATCH_CALLS = 0;
        DISPATCH_RESULTS = [MOCK_OK; 12];
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

    // ---- iterator_state_cleanup (0x08155ec0) ------------------------

    static mut ITERATOR_RELEASE_CALLS: usize = 0;
    static mut ITERATOR_RELEASE_OWNER: *mut u8 = core::ptr::null_mut();
    static mut ITERATOR_RELEASE_STATE: *mut u32 = core::ptr::null_mut();
    static mut ITERATOR_RELEASE_STATE_WORD: u32 = 0;

    unsafe extern "C" fn recording_iterator_state_release(owner: *mut u8, state: *mut u32) {
        ITERATOR_RELEASE_CALLS += 1;
        ITERATOR_RELEASE_OWNER = owner;
        ITERATOR_RELEASE_STATE = state;
        ITERATOR_RELEASE_STATE_WORD = state.add(2).read();
    }

    unsafe fn install_recording_iterator_state_release() {
        ITERATOR_RELEASE_CALLS = 0;
        ITERATOR_RELEASE_OWNER = core::ptr::null_mut();
        ITERATOR_RELEASE_STATE = core::ptr::null_mut();
        ITERATOR_RELEASE_STATE_WORD = 0;
        core::ptr::addr_of_mut!(ITERATOR_STATE_RELEASE)
            .write_volatile(recording_iterator_state_release);
    }

    #[test]
    fn iterator_state_cleanup_sentinel_skips_release_and_returns_the_state() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut state = [0x1122_3344, 0xa5a5_a5a5, (-5i32) as u32];
        unsafe {
            install_recording_iterator_state_release();
            let state_ptr = state.as_mut_ptr();
            let returned = iterator_state_cleanup(state_ptr);

            assert_eq!(returned, state_ptr, "mov r0, r4 returns the input state");
            assert_eq!(ITERATOR_RELEASE_CALLS, 0, "cmn r0, #5; beq skips the release");
            assert_eq!(state, [0x1122_3344, 0xa5a5_a5a5, (-5i32) as u32]);
        }
    }

    #[test]
    fn iterator_state_cleanup_releases_owner_then_poisons_state_and_returns_it() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut state = [0x5566_7788, 0xa5a5_a5a5, 0x1234_5678];
        unsafe {
            install_recording_iterator_state_release();
            let state_ptr = state.as_mut_ptr();
            let returned = iterator_state_cleanup(state_ptr);

            assert_eq!(ITERATOR_RELEASE_CALLS, 1, "one non-sentinel release");
            assert_eq!(
                ITERATOR_RELEASE_OWNER as usize,
                0x5566_7788,
                "ldr r0, [r4] supplies release arg1"
            );
            assert_eq!(ITERATOR_RELEASE_STATE, state_ptr, "mov r1, r4 supplies release arg2");
            assert_eq!(
                ITERATOR_RELEASE_STATE_WORD, 0x1234_5678,
                "the release sees +0x08 before the following poison store"
            );
            assert_eq!(state[2], u32::MAX, "mvn r0, #0; str r0, [r4, #8]");
            assert_eq!(returned, state_ptr, "mov r0, r4 returns the input state");
        }
    }

    #[test]
    fn iterator_state_cleanup_is_the_wired_teardown_and_container_default() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut container = [0u32; 4];
        unsafe {
            let teardown_cleanup =
                core::ptr::addr_of!(VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP).read_volatile();
            assert_eq!(
                teardown_cleanup as usize,
                iterator_state_cleanup as usize,
                "the file-record teardown seam defaults to the ported cleanup"
            );

            let container_ptr = container.as_mut_ptr().cast::<u8>();
            let returned = destruct_container_teardown_default(container_ptr);
            assert_eq!(returned, container_ptr, "the wrapper returns the original container");
            assert_eq!(
                container[3],
                u32::MAX,
                "the direct default cleans state object at container + 4"
            );
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

    // ---- vtable_set_50_write_eight_byte_record (0x0811d360) -------

    #[test]
    fn eight_byte_record_serializes_every_field_in_protocol_order() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        // Five byte fields, skipped padding, a little-endian u16, final
        // byte, then padding so the recording mock can inspect words.
        let record = [
            0x10u8, 0x20, 0x30, 0x40, 0x50, 0xcc, 0x66, 0x77, 0x80, 0xdd, 0, 0, 0, 0,
            0, 0,
        ];
        unsafe {
            install_recording_dispatch();

            let result = vtable_set_50_write_eight_byte_record(
                fixture.handle_ptr(),
                record.as_ptr(),
                FORWARDED,
            );

            assert_eq!(result, MOCK_OK);
            assert_eq!(DISPATCH_CALLS, 10, "open + length + eight fields + commit");
            let expected_kinds = [
                MESSAGE_KIND_4,
                MESSAGE_KIND_4,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_2,
                MESSAGE_KIND_1,
                MESSAGE_KIND_4,
            ];
            for (call, expected_kind) in expected_kinds.iter().enumerate() {
                assert_eq!(DISPATCH_HANDLE[call], fixture.handle_ptr());
                assert_eq!(DISPATCH_KIND[call], *expected_kind, "message {call}");
            }
            assert_eq!(
                DISPATCH_WORD0[0], EIGHT_BYTE_RECORD_SELECTOR,
                "open sends selector 0x12 bare"
            );
            assert_eq!(
                DISPATCH_WORD0[1], EIGHT_BYTE_RECORD_PAYLOAD_LEN,
                "the first direct dispatch sends the eight-byte length"
            );
            for (field, expected) in [0x10u32, 0x20, 0x30, 0x40, 0x50].iter().enumerate() {
                assert_eq!(
                    DISPATCH_WORD0[field + 2] & 0xff,
                    *expected,
                    "kind-1 record field {field}"
                );
            }
            assert_eq!(
                DISPATCH_WORD0[7] & 0xffff,
                0x7766,
                "the offset-six field is loaded as a little-endian halfword"
            );
            assert_eq!(DISPATCH_WORD0[8] & 0xff, 0x80, "the final byte is at offset 8");
            assert_eq!(
                DISPATCH_WORD0[9],
                EIGHT_BYTE_RECORD_SELECTOR | COMMIT_TAG,
                "the successful batch commits selector 0x12"
            );
            assert_eq!(DISPATCH_EXTRA[0], FORWARDED, "open sees entry r3");
            assert_eq!(
                DISPATCH_EXTRA[1],
                EIGHT_BYTE_RECORD_SELECTOR as usize,
                "open reloads selector 0x12 into r3 for the length dispatch"
            );
            for call in 2..10 {
                assert_eq!(
                    DISPATCH_EXTRA[call], 0,
                    "later r3 values are method-clobbered and unobservable"
                );
            }
        }
    }

    #[test]
    fn eight_byte_record_propagates_field_error_and_skips_later_messages() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let record = [0u8; 16];
        unsafe {
            install_recording_dispatch();
            // Call 0 is open, 1 is the payload length, 2..6 are bytes,
            // and call 7 is the offset-six halfword.
            DISPATCH_RESULTS[7] = WRITE_ERR;

            let result = vtable_set_50_write_eight_byte_record(
                fixture.handle_ptr(),
                record.as_ptr(),
                FORWARDED,
            );

            assert_eq!(result, WRITE_ERR, "the first failing field status returns verbatim");
            assert_eq!(
                DISPATCH_CALLS, 8,
                "the final byte and commit are both skipped after the halfword error"
            );
            assert_eq!(DISPATCH_KIND[7], MESSAGE_KIND_2);
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
    /// target; the buffer is 0x68 bytes, not the 0x54 the slot needs
    /// on the target, because on a 64-bit host each method pointer
    /// written into it is 8 bytes wide — 0x68 leaves room for the
    /// slot +0x54 alloc method's pointer (0x54..0x5c) and an upper
    /// decoy at 0x5c.
    struct FakeChain {
        vtable: [u8; 0x68],
        object: *const u8,
        handle: *mut u8,
    }

    impl FakeChain {
        fn new() -> Self {
            FakeChain {
                vtable: [0; 0x68],
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

    // ---- vtable_slot_04_dispose (0x0811d7cc) direct, fake vtable ----

    static mut DISPOSE_CALLS: usize = 0;
    static mut DISPOSE_OBJECT: *mut u8 = core::ptr::null_mut();
    /// The `*handle` word observed from INSIDE the slot +0x4 method:
    /// non-NULL there proves the handle is NULLed only after the
    /// `blx` returns (`str r0, [r4]` follows `blx r1`).
    static mut DISPOSE_HANDLE_WORD_AT_CALL: *mut u8 = core::ptr::null_mut();
    static mut DISPOSE_HANDLE_PTR: *const *mut u8 = core::ptr::null();

    unsafe extern "C" fn dispose_method(object: *mut u8) {
        DISPOSE_CALLS += 1;
        DISPOSE_OBJECT = object;
        DISPOSE_HANDLE_WORD_AT_CALL = DISPOSE_HANDLE_PTR.read();
    }

    /// Decoy for the slots neighbouring +0x4: any call through it
    /// proves the thunk loaded the wrong offset.
    unsafe extern "C" fn wrong_slot_dispose(_object: *mut u8) {
        WRONG_SLOT_CALLS += 1;
    }

    impl FakeChain {
        /// Writes `method` into the vtable at byte offset `slot`,
        /// typed for the slot +0x4 dispose signature.
        fn install_dispose(&mut self, slot: usize, method: VtableSlot04Method) {
            unsafe {
                (self.vtable.as_mut_ptr().add(slot) as *mut VtableSlot04Method)
                    .write_unaligned(method);
            }
        }
        /// Writes `method` into the vtable at byte offset `slot`,
        /// typed for the slot +0x54 alloc signature.
        fn install_alloc(&mut self, slot: usize, method: VtableSlot54Method) {
            unsafe {
                (self.vtable.as_mut_ptr().add(slot) as *mut VtableSlot54Method)
                    .write_unaligned(method);
            }
        }
    }

    unsafe fn reset_dispose_log() {
        DISPOSE_CALLS = 0;
        DISPOSE_OBJECT = core::ptr::null_mut();
        DISPOSE_HANDLE_WORD_AT_CALL = core::ptr::null_mut();
        DISPOSE_HANDLE_PTR = core::ptr::null();
        WRONG_SLOT_CALLS = 0;
    }

    // The ported thunk is called directly (no seam), so no SlotGuard
    // is needed; the lock only serializes the recording statics.

    #[test]
    fn dispose_double_dereferences_and_loads_slot_04_exactly() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install_dispose(VTABLE_SLOT_04, dispose_method);
        // Decoy above the slot only: method pointers are 8 bytes wide
        // on the 64-bit host, so the slot-0x4 write spans 0x4..0xc
        // and a decoy at 0x0 (the target's preceding slot) would
        // overlap it; +0xc is the nearest non-overlapping offset.
        chain.install_dispose(VTABLE_SLOT_04 + 8, wrong_slot_dispose);
        chain.link();
        unsafe {
            reset_dispose_log();
            DISPOSE_HANDLE_PTR = chain.handle_ptr() as *const *mut u8;

            let result = vtable_slot_04_dispose(chain.handle_ptr());

            assert_eq!(result, 0, "mov r0, #0 — always returns 0");
            assert_eq!(DISPOSE_CALLS, 1, "exactly one blx");
            assert_eq!(
                WRONG_SLOT_CALLS, 0,
                "only vtable slot +0x4 is loaded (ldr r1, [r1, #0x4])"
            );
            assert_eq!(
                DISPOSE_OBJECT,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "the method receives *handle (ldr r0, [r0])"
            );
            // vtable = *object (ldr r1, [r0]) is proven by the chain
            // itself: only the method installed in the vtable buffer
            // could have run.
        }
    }

    #[test]
    fn dispose_nulls_the_handle_after_the_call() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install_dispose(VTABLE_SLOT_04, dispose_method);
        chain.link();
        unsafe {
            reset_dispose_log();
            DISPOSE_HANDLE_PTR = chain.handle_ptr() as *const *mut u8;

            vtable_slot_04_dispose(chain.handle_ptr());

            assert_eq!(
                DISPOSE_HANDLE_WORD_AT_CALL,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "the handle still points at the object DURING the blx"
            );
            assert_eq!(
                chain.handle_ptr().read(),
                core::ptr::null_mut(),
                "str r0, [r4] NULLs the handle after the method returns"
            );
        }
    }

    #[test]
    fn dispose_skips_the_call_on_a_null_handle_and_returns_zero() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut handle: *mut u8 = core::ptr::null_mut();
        unsafe {
            reset_dispose_log();

            let result = vtable_slot_04_dispose(core::ptr::addr_of_mut!(handle));

            assert_eq!(result, 0, "the beq path also returns 0 (mov r0, #0)");
            assert_eq!(DISPOSE_CALLS, 0, "cmp r0, #0; beq — no blx on a NULL handle");
            assert_eq!(
                handle,
                core::ptr::null_mut(),
                "the NULL store is skipped too (beq jumps past str r0, [r4])"
            );
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

    // ---- recording mocks for the scalar-read seams (0x0811d718) -----

    /// The property word the read method delivers through `out`.
    const SCALAR_VALUE: u32 = 0xcafe_f00d;

    static mut SCALAR_CALLS: usize = 0;
    static mut SCALAR_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut SCALAR_KIND: [u32; 8] = [0; 8];
    static mut SCALAR_DATA: [usize; 8] = [0; 8];
    static mut SCALAR_DATA_WORD: [u32; 8] = [0; 8];
    static mut SCALAR_EXTRA: [usize; 8] = [0; 8];
    static mut SCALAR_RESULTS: [u32; 8] = [MOCK_OK; 8];

    unsafe extern "C" fn recording_scalar_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = SCALAR_CALLS;
        SCALAR_CALLS += 1;
        SCALAR_HANDLE[call] = handle;
        SCALAR_KIND[call] = kind;
        SCALAR_DATA[call] = data;
        // Call 0's data is the probe's scratch out-slot (its entry
        // word is the spilled r3); call 1's data is the caller's out
        // word, which the tests back with a real local — both reads
        // are in-bounds.
        SCALAR_DATA_WORD[call] = (data as *const u32).read();
        SCALAR_EXTRA[call] = extra.read();
        if call == 1 {
            // The read method delivers the property word through the
            // caller's out pointer (a 32-bit store, as the firmware
            // method's `str` would be).
            (data as *mut u32).write(SCALAR_VALUE);
        }
        SCALAR_RESULTS[call]
    }

    unsafe fn install_scalar_mocks() {
        SCALAR_CALLS = 0;
        SCALAR_RESULTS = [MOCK_OK; 8];
        FINISH_CALLS = 0;
        FINISH_HANDLE = core::ptr::null_mut();
        FINISH_OUT = core::ptr::null_mut();
        FINISH_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_SCALAR_DISPATCH)
            .write_volatile(recording_scalar_dispatch);
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_SCALAR_FINISH)
            .write_volatile(recording_finish);
    }

    // ---- vtable_query_4c_read_scalar_kind4 (0x0811d718) -------------

    #[test]
    fn scalar_read_unsupported_status_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[0] = UNSUPPORTED_ERR;

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, UNSUPPORTED_ERR,
                "cmp r0, #0x5; beq — the unsupported status returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 1, "no read dispatch after a 5");
            assert_eq!(FINISH_CALLS, 0, "no finish call after a 5");
            assert_eq!(out, 0, "the out word is untouched");
        }
    }

    #[test]
    fn scalar_read_probe_error_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[0] = METHOD_ERR;

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, METHOD_ERR,
                "cmp r0, #0x0; bne — a hard error returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 1, "no read dispatch after an error");
            assert_eq!(FINISH_CALLS, 0, "no finish call after an error");
            assert_eq!(out, 0, "the out word is untouched");
        }
    }

    #[test]
    fn scalar_read_probe_args_and_initial_out_slot() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(SCALAR_KIND[0], MESSAGE_KIND_4, "mov r1, #0x4 — the probe is always kind 4");
            assert_eq!(SCALAR_HANDLE[0], fixture.handle_ptr(), "r0 passes through");
            assert_eq!(
                SCALAR_DATA_WORD[0], FORWARDED as u32,
                "the probe out-slot's initial word is the entry r3 spill \
                 (stmdb {{r2, r3, ...}})"
            );
            assert_eq!(
                SCALAR_EXTRA[0], FORWARDED,
                "the dispatcher's stmdb sp!, {{r3}} spill forwards the same word"
            );
        }
    }

    #[test]
    fn scalar_read_read_args_and_value_delivery() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(SCALAR_CALLS, 2, "probe then read");
            assert_eq!(
                SCALAR_KIND[1], MESSAGE_KIND_4,
                "mov r1, r5 — the read's kind is the entry thunk's binding (4)"
            );
            assert_eq!(SCALAR_HANDLE[1], fixture.handle_ptr());
            assert_eq!(
                SCALAR_DATA[1],
                core::ptr::addr_of_mut!(out) as usize,
                "mov r2, r6 — the read's data is the caller's out pointer (arg2)"
            );
            assert_eq!(
                SCALAR_EXTRA[1], 0,
                "r3 is dead across the probe (method-clobbered); a zero word \
                 stands in for the unobservable extra"
            );
            assert_eq!(
                out, SCALAR_VALUE,
                "the read method's store through the out pointer reaches the caller"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(
                FINISH_BUFFER,
                core::ptr::addr_of_mut!(out) as usize,
                "pair[0] is the entry r2 spill — the caller's out pointer"
            );
        }
    }

    #[test]
    fn scalar_read_read_error_skips_the_finish() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[1] = READ_ERR;

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, READ_ERR,
                "the read dispatch's error returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 2);
            assert_eq!(
                FINISH_CALLS, 0,
                "bleq — the finish fires only on a zero read status"
            );
        }
    }

    #[test]
    fn scalar_read_finish_args_and_final_return() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_read_scalar_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the function's return value"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r4");
            assert!(!FINISH_OUT.is_null(), "moveq r1, sp — out is the pair base");
            assert_eq!(
                FINISH_UNUSED, 0,
                "r2 is dead across the read dispatch and the thunk discards \
                 it (mov r2, r1); the port passes 0"
            );
            assert_eq!(
                FINISH_FORWARDED, 0,
                "r3 is likewise dead (method-clobbered across the read \
                 dispatch); the port passes 0"
            );
        }
    }

    // ---- vtable_query_4c_read_scalar_kind2 (0x0811d70c) -------------

    #[test]
    fn scalar_kind2_read_unsupported_status_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[0] = UNSUPPORTED_ERR;

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, UNSUPPORTED_ERR,
                "cmp r0, #0x5; beq — the unsupported status returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 1, "no read dispatch after a 5");
            assert_eq!(FINISH_CALLS, 0, "no finish call after a 5");
            assert_eq!(out, 0, "the out word is untouched");
        }
    }

    #[test]
    fn scalar_kind2_read_probe_error_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[0] = METHOD_ERR;

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, METHOD_ERR,
                "cmp r0, #0x0; bne — a hard error returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 1, "no read dispatch after an error");
            assert_eq!(FINISH_CALLS, 0, "no finish call after an error");
            assert_eq!(out, 0, "the out word is untouched");
        }
    }

    #[test]
    fn scalar_kind2_read_probe_args_and_initial_out_slot() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(
                SCALAR_KIND[0], MESSAGE_KIND_4,
                "mov r1, #0x4 — the probe is hardcoded kind 4 in the shared body"
            );
            assert_eq!(SCALAR_HANDLE[0], fixture.handle_ptr(), "r0 passes through");
            assert_eq!(
                SCALAR_DATA_WORD[0], FORWARDED as u32,
                "the probe out-slot's initial word is the entry r3 spill \
                 (stmdb {{r2, r3, ...}})"
            );
            assert_eq!(
                SCALAR_EXTRA[0], FORWARDED,
                "the dispatcher's stmdb sp!, {{r3}} spill forwards the same word"
            );
        }
    }

    #[test]
    fn scalar_kind2_read_read_args_and_value_delivery() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(SCALAR_CALLS, 2, "probe then read");
            assert_eq!(
                SCALAR_KIND[1], MESSAGE_KIND_2,
                "mov r1, r5 — the read's kind is THIS thunk's binding (2, u16)"
            );
            assert_eq!(SCALAR_HANDLE[1], fixture.handle_ptr());
            assert_eq!(
                SCALAR_DATA[1],
                core::ptr::addr_of_mut!(out) as usize,
                "mov r2, r6 — the read's data is the caller's out pointer (arg2)"
            );
            assert_eq!(
                SCALAR_EXTRA[1], 0,
                "r3 is dead across the probe (method-clobbered); a zero word \
                 stands in for the unobservable extra"
            );
            assert_eq!(
                out, SCALAR_VALUE,
                "the read method's store through the out pointer reaches the caller"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(
                FINISH_BUFFER,
                core::ptr::addr_of_mut!(out) as usize,
                "pair[0] is the entry r2 spill — the caller's out pointer"
            );
        }
    }

    #[test]
    fn scalar_kind2_read_read_error_skips_the_finish() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[1] = READ_ERR;

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, READ_ERR,
                "the read dispatch's error returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 2);
            assert_eq!(
                FINISH_CALLS, 0,
                "bleq — the finish fires only on a zero read status"
            );
        }
    }

    #[test]
    fn scalar_kind2_read_finish_args_and_final_return() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_read_scalar_kind2(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the function's return value"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r4");
            assert!(!FINISH_OUT.is_null(), "moveq r1, sp — out is the pair base");
            assert_eq!(
                FINISH_UNUSED, 0,
                "r2 is dead across the read dispatch and the thunk discards \
                 it (mov r2, r1); the port passes 0"
            );
            assert_eq!(
                FINISH_FORWARDED, 0,
                "r3 is likewise dead (method-clobbered across the read \
                 dispatch); the port passes 0"
            );
        }
    }

    // ---- vtable_query_4c_read_scalar_body (0x0811d5ac) -----------

    /// A kind neither thunk binds — proves the body passes its r1
    /// argument through to the read dispatch (`mov r1, r5`) instead
    /// of hardcoding a width.
    const KIND_ARBITRARY: u32 = 7;

    #[test]
    fn scalar_body_probe_unsupported_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[0] = UNSUPPORTED_ERR;

            let status = vtable_query_4c_read_scalar_body(
                fixture.handle_ptr(),
                MESSAGE_KIND_4,
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, UNSUPPORTED_ERR,
                "cmp r0, #0x5; beq — the unsupported status returns verbatim"
            );
            assert_eq!(SCALAR_CALLS, 1, "no read dispatch after a 5");
            assert_eq!(FINISH_CALLS, 0, "no finish call after a 5");
            assert_eq!(out, 0, "the out word is untouched");
        }
    }

    #[test]
    fn scalar_body_probe_args_and_initial_out_slot() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_body(
                fixture.handle_ptr(),
                KIND_ARBITRARY,
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(
                SCALAR_KIND[0], MESSAGE_KIND_4,
                "mov r1, #0x4 — the probe is hardcoded kind 4 in the body"
            );
            assert_eq!(SCALAR_HANDLE[0], fixture.handle_ptr(), "mov r4, r0 — r0 passes through");
            assert_eq!(
                SCALAR_DATA_WORD[0], FORWARDED as u32,
                "add r2, sp, #0x4 — the probe out-slot's initial word is \
                 the entry r3 spill (stmdb {{r2, r3, ...}})"
            );
            assert_eq!(
                SCALAR_EXTRA[0], FORWARDED,
                "the dispatcher's stmdb sp!, {{r3}} spill forwards the same word"
            );
        }
    }

    #[test]
    fn scalar_body_read_dispatch_routes_the_thunk_bound_kind() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = vtable_query_4c_read_scalar_body(
                fixture.handle_ptr(),
                KIND_ARBITRARY,
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(SCALAR_CALLS, 2, "probe then read");
            assert_eq!(
                SCALAR_KIND[1], KIND_ARBITRARY,
                "mov r1, r5 — the read's kind is the r1 argument the calling \
                 thunk bound, passed through verbatim (not hardcoded)"
            );
            assert_eq!(SCALAR_HANDLE[1], fixture.handle_ptr(), "mov r0, r4");
            assert_eq!(
                SCALAR_DATA[1],
                core::ptr::addr_of_mut!(out) as usize,
                "mov r2, r6 — the read's data is the caller's out pointer"
            );
            assert_eq!(
                SCALAR_EXTRA[1], 0,
                "r3 is dead across the probe (method-clobbered); a zero word \
                 stands in for the unobservable extra"
            );
            assert_eq!(
                out, SCALAR_VALUE,
                "the read method's store through the out pointer reaches the caller"
            );
        }
    }

    #[test]
    fn scalar_body_read_error_skips_the_finish() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            SCALAR_RESULTS[1] = READ_ERR;

            let status = vtable_query_4c_read_scalar_body(
                fixture.handle_ptr(),
                KIND_ARBITRARY,
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(status, READ_ERR, "the read dispatch's error returns verbatim");
            assert_eq!(SCALAR_CALLS, 2);
            assert_eq!(
                FINISH_CALLS, 0,
                "bleq — the finish fires only on a zero read status"
            );
        }
    }

    #[test]
    fn scalar_body_finish_routing_and_final_return() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();
            FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_read_scalar_body(
                fixture.handle_ptr(),
                KIND_ARBITRARY,
                core::ptr::addr_of_mut!(out),
                FORWARDED,
            );

            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the body's return value"
            );
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r4");
            assert!(!FINISH_OUT.is_null(), "moveq r1, sp — out is the pair base");
            assert_eq!(
                FINISH_BUFFER,
                core::ptr::addr_of_mut!(out) as usize,
                "pair[0] is the entry r2 spill — the caller's out pointer"
            );
            assert_eq!(
                FINISH_UNUSED, 0,
                "r2 is dead across the read dispatch and the thunk discards \
                 it (mov r2, r1); the port passes 0"
            );
            assert_eq!(
                FINISH_FORWARDED, 0,
                "r3 is likewise dead (method-clobbered across the read \
                 dispatch); the port passes 0"
            );
        }
    }

    /// End-to-end through both entry thunks: the thunk binds its
    /// width, tail-calls the body, and the probe → read → finish flow
    /// delivers the property word with the width only on the READ.
    fn assert_scalar_thunk_end_to_end(kind: u32, is_kind2: bool) {
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            install_scalar_mocks();

            let status = if is_kind2 {
                vtable_query_4c_read_scalar_kind2(
                    fixture.handle_ptr(),
                    core::ptr::addr_of_mut!(out),
                    FORWARDED,
                )
            } else {
                vtable_query_4c_read_scalar_kind4(
                    fixture.handle_ptr(),
                    core::ptr::addr_of_mut!(out),
                    FORWARDED,
                )
            };

            assert_eq!(status, MOCK_OK);
            assert_eq!(SCALAR_CALLS, 2, "probe then read through the shared body");
            assert_eq!(SCALAR_KIND[0], MESSAGE_KIND_4, "the probe is always kind 4");
            assert_eq!(SCALAR_KIND[1], kind, "the read carries the thunk-bound width");
            assert_eq!(out, SCALAR_VALUE, "the property word is delivered");
            assert_eq!(FINISH_CALLS, 1, "the finish fires on a zero read status");
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr());
        }
    }

    #[test]
    fn scalar_body_end_to_end_kind4_through_the_thunk() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        assert_scalar_thunk_end_to_end(MESSAGE_KIND_4, false);
    }

    #[test]
    fn scalar_body_end_to_end_kind2_through_the_thunk() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        assert_scalar_thunk_end_to_end(MESSAGE_KIND_2, true);
    }

    // ---- recording mocks for the record-read seams (0x0811d21c) ---

    /// The word the kind-4 query answers through its scratch out-slot.
    const RECORD_PROBE_WORD: u32 = 0x5a5a_5a5a;
    /// The bytes the six kind-1 field methods deliver (offsets 0..4,
    /// then 8).
    const RECORD_BYTES: [u8; 6] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
    /// The u16 the kind-2 method delivers through the record spill
    /// slot.
    const RECORD_HALFWORD: u16 = 0xbeef;

    static mut RECORD_CALLS: usize = 0;
    static mut RECORD_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut RECORD_KIND: [u32; 8] = [0; 8];
    static mut RECORD_DATA: [usize; 8] = [0; 8];
    static mut RECORD_DATA_WORD: [u32; 8] = [0; 8];
    static mut RECORD_EXTRA: [usize; 8] = [0; 8];
    static mut RECORD_RESULTS: [u32; 8] = [MOCK_OK; 8];

    unsafe extern "C" fn recording_record_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = RECORD_CALLS;
        RECORD_CALLS += 1;
        RECORD_HANDLE[call] = handle;
        RECORD_KIND[call] = kind;
        RECORD_DATA[call] = data;
        // Every data pointer is word-readable: calls 0/6 point at the
        // function's spill slots, calls 1..5/7 into the 16-byte record
        // the tests back — `read_unaligned` covers the byte offsets
        // 1..4 (the recording_dispatch precedent).
        RECORD_DATA_WORD[call] = (data as *const u32).read_unaligned();
        RECORD_EXTRA[call] = extra.read();
        match call {
            // The kind-4 query answers through its scratch out-slot (a
            // 32-bit store, as the firmware method's `str` would be).
            0 => (data as *mut u32).write(RECORD_PROBE_WORD),
            // The five kind-1 byte fields deliver one byte each.
            1..=5 => (data as *mut u8).write(RECORD_BYTES[call - 1]),
            // The kind-2 method delivers the u16 through the record
            // spill slot (a 32-bit store; the caller reads the low
            // half).
            6 => (data as *mut u32).write(RECORD_HALFWORD as u32),
            // The final kind-1 byte at offset 8.
            _ => (data as *mut u8).write(RECORD_BYTES[5]),
        }
        RECORD_RESULTS[call]
    }

    unsafe fn install_record_mocks() {
        RECORD_CALLS = 0;
        RECORD_RESULTS = [MOCK_OK; 8];
        FINISH_CALLS = 0;
        FINISH_HANDLE = core::ptr::null_mut();
        FINISH_OUT = core::ptr::null_mut();
        FINISH_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_RECORD_DISPATCH)
            .write_volatile(recording_record_dispatch);
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_RECORD_FINISH)
            .write_volatile(recording_finish);
    }

    // ---- vtable_query_4c_read_eight_byte_record (0x0811d21c) -------

    #[test]
    fn record_read_full_chain_dispatches_all_fields_in_protocol_order() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        // 16 bytes: the five byte fields, the skipped padding at 5 and
        // 9, the u16 at 6, the final byte at 8, and room for the
        // recording mock's word reads.
        let mut record = [0xccu8; 16];
        unsafe {
            install_record_mocks();

            let status = vtable_query_4c_read_eight_byte_record(
                fixture.handle_ptr(),
                record.as_mut_ptr(),
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(RECORD_CALLS, 8, "query + six fields + halfword");
            let expected_kinds = [
                MESSAGE_KIND_4,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_1,
                MESSAGE_KIND_2,
                MESSAGE_KIND_1,
            ];
            for (call, expected_kind) in expected_kinds.iter().enumerate() {
                assert_eq!(RECORD_HANDLE[call], fixture.handle_ptr(), "call {call}");
                assert_eq!(RECORD_KIND[call], *expected_kind, "call {call}");
            }
            assert_eq!(
                RECORD_DATA_WORD[0], FORWARDED as u32,
                "the kind-4 out-slot's initial word is the entry r3 spill \
                 (stmdb {{r1, r2, r3, ...}}, sp+8)"
            );
            for field in 0..5 {
                assert_eq!(
                    RECORD_DATA[field + 1],
                    record.as_mut_ptr().add(field) as usize,
                    "kind-1 field {field} reads through record + {field}"
                );
            }
            assert_eq!(
                RECORD_DATA_WORD[6], record.as_mut_ptr() as u32,
                "the kind-2 out-slot IS the record spill slot (mov r2, sp): its \
                 initial word is the spilled record pointer"
            );
            assert_eq!(
                RECORD_DATA[7],
                record.as_mut_ptr().add(8) as usize,
                "the final kind-1 field reads through record + 8"
            );
            assert_eq!(RECORD_EXTRA[0], FORWARDED, "the first dispatch sees entry r3");
            for call in 1..8 {
                assert_eq!(
                    RECORD_EXTRA[call], 0,
                    "later r3 values are method-clobbered and unobservable"
                );
            }
            // The delivered fields landed in the record.
            for field in 0..5 {
                assert_eq!(record[field], RECORD_BYTES[field], "byte field {field}");
            }
            assert_eq!(record[5], 0xcc, "the padding at offset 5 is never touched");
            assert_eq!(
                record.as_ptr().add(6).cast::<u16>().read_unaligned(),
                RECORD_HALFWORD,
                "ldrh [sp]; strh [r4, #6] — the out-slot's low half at record + 6"
            );
            assert_eq!(record[8], RECORD_BYTES[5], "the final byte field");
            assert_eq!(record[9], 0xcc, "the padding at offset 9 is never touched");
            // The finish fired once with the triple's middle slot.
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r5");
            assert_eq!(
                FINISH_BUFFER, SCRATCH,
                "out word 0 is triple[1] — the entry r2 spill (addeq r1, sp, #0x4)"
            );
            assert_eq!(
                FINISH_SIZE, RECORD_PROBE_WORD as usize,
                "out word 1 is triple[2] — the kind-4 method's answer"
            );
            assert_eq!(
                FINISH_UNUSED, 0,
                "r2 is dead across the last dispatch and the thunk discards it"
            );
            assert_eq!(FINISH_FORWARDED, 0, "r3 is likewise dead (method-clobbered)");
        }
    }

    #[test]
    fn record_read_short_circuits_at_every_failing_stage() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            for fail_at in 0..8 {
                install_record_mocks();
                RECORD_RESULTS[fail_at] = READ_ERR;
                let mut record = [0u8; 16];

                let status = vtable_query_4c_read_eight_byte_record(
                    fixture.handle_ptr(),
                    record.as_mut_ptr(),
                    SCRATCH,
                    FORWARDED,
                );

                assert_eq!(
                    status, READ_ERR,
                    "stage {fail_at}: cmp r0, #0; bne — the status returns verbatim"
                );
                assert_eq!(
                    RECORD_CALLS,
                    fail_at + 1,
                    "stage {fail_at}: every later dispatch is skipped"
                );
                assert_eq!(
                    FINISH_CALLS, 0,
                    "stage {fail_at}: the finish bleq never fires"
                );
                let halfword = record.as_ptr().add(6).cast::<u16>().read_unaligned();
                if fail_at >= 6 {
                    assert_eq!(
                        halfword, RECORD_HALFWORD,
                        "stage {fail_at}: strh sits between cmp and bne — the u16 \
                         store at record + 6 runs even on a failing kind-2 dispatch"
                    );
                } else {
                    assert_eq!(
                        halfword, 0,
                        "stage {fail_at}: the kind-2 store has not run yet"
                    );
                }
            }
        }
    }

    #[test]
    fn record_read_finish_result_is_the_return_value() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut record = [0u8; 16];
        unsafe {
            install_record_mocks();
            FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_read_eight_byte_record(
                fixture.handle_ptr(),
                record.as_mut_ptr(),
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(RECORD_CALLS, 8);
            assert_eq!(FINISH_CALLS, 1);
            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the function's return value"
            );
        }
    }

    // ---- recording mocks for the walk-alloc seams -------------------

    const SIZE_ERR: u32 = 0x0bad_0011;
    const WALK_QUERY_ERR: u32 = 0x0bad_0012;
    const ALLOC_CODE: u32 = 0x0bad_0013;
    const SCRATCH: usize = 0x1bad_b002;
    const QUERIED_SIZE: u32 = 0x20;
    const JOURNAL_BARE: u32 = 0x77;
    const FOREIGN_SELECTOR: u32 = 0x99;

    /// Global event order across the three walk-alloc recording mocks
    /// (the STAGE_LOG precedent).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum WalkEvent {
        Query,
        SizeDispatch,
        Alloc,
    }

    static mut WALK_EVENTS: [WalkEvent; 8] = [WalkEvent::Query; 8];
    static mut WALK_EVENT_COUNT: usize = 0;

    unsafe fn record_walk_event(event: WalkEvent) {
        WALK_EVENTS[WALK_EVENT_COUNT] = event;
        WALK_EVENT_COUNT += 1;
    }

    static mut WALK_QUERY_CALLS: usize = 0;
    static mut WALK_QUERY_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut WALK_QUERY_OUT_INITIAL: [u32; 8] = [0; 8];
    static mut WALK_QUERY_UNUSED: [usize; 8] = [0; 8];
    static mut WALK_QUERY_FORWARDED: [usize; 8] = [0; 8];
    static mut WALK_QUERY_WORDS: [u32; 8] = [0; 8];
    static mut WALK_QUERY_RESULTS: [u32; 8] = [MOCK_OK; 8];

    /// The walk-loop query thunk: records the call, then answers the
    /// scripted journal word through the out-slot (the query method's
    /// store).
    unsafe extern "C" fn walk_recording_query(
        handle: *mut *mut u8,
        out: *mut u32,
        unused: usize,
        forwarded: usize,
    ) -> u32 {
        let call = WALK_QUERY_CALLS;
        WALK_QUERY_CALLS += 1;
        record_walk_event(WalkEvent::Query);
        WALK_QUERY_HANDLE[call] = handle;
        // The out-slot's content BEFORE the answer: the body's pair[0].
        WALK_QUERY_OUT_INITIAL[call] = out.read();
        WALK_QUERY_UNUSED[call] = unused;
        WALK_QUERY_FORWARDED[call] = forwarded;
        out.write(WALK_QUERY_WORDS[call]);
        WALK_QUERY_RESULTS[call]
    }

    static mut WALK_SIZE_CALLS: usize = 0;
    static mut WALK_SIZE_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut WALK_SIZE_KIND: [u32; 8] = [0; 8];
    static mut WALK_SIZE_EXTRA: [usize; 8] = [0; 8];
    static mut WALK_SIZE_SIZES: [u32; 8] = [0; 8];
    static mut WALK_SIZE_RESULTS: [u32; 8] = [MOCK_OK; 8];

    /// The bare-branch size query: records the call, then answers the
    /// scripted size through the out-slot (the method's store).
    unsafe extern "C" fn walk_recording_size_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = WALK_SIZE_CALLS;
        WALK_SIZE_CALLS += 1;
        record_walk_event(WalkEvent::SizeDispatch);
        WALK_SIZE_HANDLE[call] = handle;
        WALK_SIZE_KIND[call] = kind;
        WALK_SIZE_EXTRA[call] = extra.read();
        (data as *mut u32).write(WALK_SIZE_SIZES[call]);
        WALK_SIZE_RESULTS[call]
    }

    static mut ALLOC_CALLS: usize = 0;
    static mut ALLOC_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_SIZE: u32 = 0;
    static mut ALLOC_MODE: u32 = 0;
    static mut ALLOC_RESULT: u32 = MOCK_OK;
    static mut WRONG_ALLOC_CALLS: usize = 0;

    /// The vtable slot +0x54 alloc method, recording.
    unsafe extern "C" fn alloc_method(object: *mut u8, size: u32, mode: u32) -> u32 {
        ALLOC_CALLS += 1;
        record_walk_event(WalkEvent::Alloc);
        ALLOC_OBJECT = object;
        ALLOC_SIZE = size;
        ALLOC_MODE = mode;
        ALLOC_RESULT
    }

    /// Decoy for the slots neighbouring +0x54: any call through it
    /// proves the body loaded the wrong offset.
    unsafe extern "C" fn wrong_slot_alloc(_object: *mut u8, _size: u32, _mode: u32) -> u32 {
        WRONG_ALLOC_CALLS += 1;
        0xdead_0000
    }

    /// Resets every walk-alloc recording static WITHOUT touching the
    /// seams (the end-to-end default-seam tests need the wiring kept).
    unsafe fn reset_walk_logs() {
        WALK_EVENT_COUNT = 0;
        WALK_QUERY_CALLS = 0;
        WALK_QUERY_WORDS = [0; 8];
        WALK_QUERY_RESULTS = [MOCK_OK; 8];
        WALK_SIZE_CALLS = 0;
        WALK_SIZE_SIZES = [0; 8];
        WALK_SIZE_RESULTS = [MOCK_OK; 8];
        ALLOC_CALLS = 0;
        ALLOC_OBJECT = core::ptr::null_mut();
        ALLOC_SIZE = 0;
        ALLOC_MODE = 0;
        ALLOC_RESULT = MOCK_OK;
        WRONG_ALLOC_CALLS = 0;
    }

    unsafe fn install_walk_mocks() {
        reset_walk_logs();
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_WALK_QUERY)
            .write_volatile(walk_recording_query);
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_WALK_DISPATCH)
            .write_volatile(walk_recording_size_dispatch);
    }

    // ---- walk-alloc: the bare (tag 0) branch ------------------------

    #[test]
    fn walk_alloc_bare_selector_queries_size_and_allocs_via_slot_54() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        // Decoys at the adjacent non-overlapping host slots: method
        // pointers are 8 bytes wide on the 64-bit host, so 0x4c (the
        // target's preceding slot) spans 0x4c..0x54 and 0x5c is the
        // nearest offset above the 0x54..0x5c pointer.
        chain.install_alloc(VTABLE_SLOT_54 - 8, wrong_slot_alloc);
        chain.install_alloc(VTABLE_SLOT_54 + 8, wrong_slot_alloc);
        chain.link();
        unsafe {
            install_walk_mocks();
            WALK_SIZE_SIZES[0] = QUERIED_SIZE;
            ALLOC_RESULT = ALLOC_CODE;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, ALLOC_CODE, "the blx method's r0 returns verbatim");
            assert_eq!(WALK_QUERY_CALLS, 0, "no journal query on the bare branch");
            assert_eq!(WALK_SIZE_CALLS, 1, "one size query");
            assert_eq!(WALK_SIZE_HANDLE[0], chain.handle_ptr(), "mov r0, r5");
            assert_eq!(WALK_SIZE_KIND[0], MESSAGE_KIND_4, "mov r1, #0x4");
            assert_eq!(
                WALK_SIZE_EXTRA[0], FORWARDED,
                "r3 (arg4) is live into the size query's dispatcher spill"
            );
            assert_eq!(ALLOC_CALLS, 1, "exactly one blx");
            assert_eq!(
                WRONG_ALLOC_CALLS, 0,
                "only vtable slot +0x54 is loaded (ldr r3, [r2, #0x54])"
            );
            assert_eq!(
                ALLOC_OBJECT,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "ldr r0, [r5] — the method receives *handle"
            );
            assert_eq!(
                ALLOC_SIZE,
                QUERIED_SIZE + 4,
                "add r1, r0, #0x4 — the queried size + 4"
            );
            assert_eq!(ALLOC_MODE, 1, "mov r2, #0x1");
            assert_eq!(WALK_EVENT_COUNT, 2);
            assert_eq!(WALK_EVENTS[0], WalkEvent::SizeDispatch);
            assert_eq!(WALK_EVENTS[1], WalkEvent::Alloc);
        }
    }

    #[test]
    fn walk_alloc_bare_size_query_error_skips_the_alloc() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        chain.link();
        unsafe {
            install_walk_mocks();
            WALK_SIZE_RESULTS[0] = SIZE_ERR;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, SIZE_ERR, "cmp r0, #0x0; bne — the status returns verbatim");
            assert_eq!(WALK_SIZE_CALLS, 1);
            assert_eq!(ALLOC_CALLS, 0, "no blx past a failed size query");
            assert_eq!(WALK_EVENT_COUNT, 1);
            assert_eq!(WALK_EVENTS[0], WalkEvent::SizeDispatch);
        }
    }

    #[test]
    fn walk_alloc_bare_status_5_gets_no_special_case() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        chain.link();
        unsafe {
            install_walk_mocks();
            WALK_SIZE_RESULTS[0] = STATUS_UNSUPPORTED;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(
                status, STATUS_UNSUPPORTED,
                "unlike the read siblings, the bare branch has no cmp #0x5 — \
                 5 returns verbatim like any error"
            );
            assert_eq!(ALLOC_CALLS, 0);
        }
    }

    #[test]
    fn walk_alloc_other_tags_return_zero_without_any_message() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            for tag in [COMMIT_TAG, COMMIT_PROBE_TAG, 0x0100_0000] {
                install_walk_mocks();

                let status = vtable_query_4c_walk_alloc(
                    fixture.handle_ptr(),
                    tag | SELECTOR,
                    SCRATCH,
                    FORWARDED,
                );

                assert_eq!(status, 0, "bne 0x0811d524 — mov r0, #0x0");
                assert_eq!(WALK_QUERY_CALLS, 0, "no query for tag {tag:#x}");
                assert_eq!(WALK_SIZE_CALLS, 0, "no size query for tag {tag:#x}");
                assert_eq!(ALLOC_CALLS, 0);
            }
        }
    }

    // ---- walk-alloc: the probe-tag walk loop ------------------------

    #[test]
    fn walk_alloc_probe_walks_recurses_and_stops_at_the_matching_marker() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        chain.link();
        unsafe {
            install_walk_mocks();
            // Journal: a bare word (recursed into -> size query + alloc),
            // then the matching commit+probe marker closing the walk.
            WALK_QUERY_WORDS[0] = JOURNAL_BARE;
            WALK_QUERY_WORDS[1] = COMMIT_PROBE_TAG | SELECTOR;
            WALK_SIZE_SIZES[0] = QUERIED_SIZE;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                PROBE_TAG | SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, 0, "the matching marker closes the walk with 0");
            assert_eq!(WALK_QUERY_CALLS, 2, "one query per journal word");
            assert_eq!(WALK_QUERY_HANDLE[0], chain.handle_ptr(), "mov r0, r5");
            assert_eq!(WALK_QUERY_HANDLE[1], chain.handle_ptr());
            assert_eq!(
                WALK_QUERY_OUT_INITIAL[0],
                SCRATCH as u32,
                "pair[0]'s initial content is the arg3 spill"
            );
            assert_eq!(
                WALK_QUERY_OUT_INITIAL[1], JOURNAL_BARE,
                "the out-slot is not re-initialized between iterations"
            );
            assert_eq!(WALK_QUERY_UNUSED[0], 0, "the thunk discards r2 (mov r2, r1)");
            assert_eq!(
                WALK_QUERY_FORWARDED[0], FORWARDED,
                "r3 (arg4) reaches the FIRST query verbatim"
            );
            assert_eq!(
                WALK_QUERY_FORWARDED[1], 0,
                "r3 is dead across the first query (method-clobbered)"
            );
            assert_eq!(WALK_SIZE_CALLS, 1, "the recursion's bare branch runs once");
            assert_eq!(
                WALK_SIZE_EXTRA[0], 0,
                "the recursion's r3 is dead across the walk query"
            );
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, QUERIED_SIZE + 4);
            assert_eq!(ALLOC_MODE, 1);
            assert_eq!(WALK_EVENT_COUNT, 4);
            assert_eq!(WALK_EVENTS[0], WalkEvent::Query);
            assert_eq!(WALK_EVENTS[1], WalkEvent::SizeDispatch);
            assert_eq!(WALK_EVENTS[2], WalkEvent::Alloc);
            assert_eq!(WALK_EVENTS[3], WalkEvent::Query);
        }
    }

    #[test]
    fn walk_alloc_probe_recurses_into_foreign_commit_probe_markers() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_walk_mocks();
            // A commit+probe marker for a DIFFERENT selector: the
            // cmpeq r1, r4 fails, the walk recurses into it, and the
            // recursion's tag is 0xc0000000 — the return-0 branch.
            WALK_QUERY_WORDS[0] = COMMIT_PROBE_TAG | FOREIGN_SELECTOR;
            WALK_QUERY_WORDS[1] = COMMIT_PROBE_TAG | SELECTOR;

            let status = vtable_query_4c_walk_alloc(
                fixture.handle_ptr(),
                PROBE_TAG | SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, 0);
            assert_eq!(WALK_QUERY_CALLS, 2, "the foreign marker does not close the walk");
            assert_eq!(WALK_SIZE_CALLS, 0, "a foreign marker allocs nothing");
            assert_eq!(ALLOC_CALLS, 0);
            assert_eq!(WALK_EVENT_COUNT, 2);
            assert_eq!(WALK_EVENTS[0], WalkEvent::Query);
            assert_eq!(WALK_EVENTS[1], WalkEvent::Query);
        }
    }

    #[test]
    fn walk_alloc_probe_query_error_returns_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        unsafe {
            install_walk_mocks();
            WALK_QUERY_RESULTS[0] = WALK_QUERY_ERR;

            let status = vtable_query_4c_walk_alloc(
                fixture.handle_ptr(),
                PROBE_TAG | SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, WALK_QUERY_ERR, "cmp r0, #0x0 after the query bl");
            assert_eq!(WALK_QUERY_CALLS, 1, "the error ends the walk");
            assert_eq!(WALK_SIZE_CALLS, 0);
            assert_eq!(ALLOC_CALLS, 0);
        }
    }

    #[test]
    fn walk_alloc_probe_recursion_error_propagates() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        chain.link();
        unsafe {
            install_walk_mocks();
            WALK_QUERY_WORDS[0] = JOURNAL_BARE;
            WALK_SIZE_RESULTS[0] = SIZE_ERR;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                PROBE_TAG | SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(
                status, SIZE_ERR,
                "ldmiane — the recursion's status propagates verbatim"
            );
            assert_eq!(WALK_QUERY_CALLS, 1, "no further queries past the error");
            assert_eq!(WALK_SIZE_CALLS, 1);
            assert_eq!(ALLOC_CALLS, 0, "the size query failed before the blx");
            assert_eq!(WALK_EVENT_COUNT, 2);
            assert_eq!(WALK_EVENTS[0], WalkEvent::Query);
            assert_eq!(WALK_EVENTS[1], WalkEvent::SizeDispatch);
        }
    }

    // ---- walk-alloc: the wired defaults -----------------------------

    #[test]
    fn walk_alloc_default_seams_are_wired_to_the_ported_callees() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        unsafe {
            let dispatch =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_WALK_DISPATCH));
            let query =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_QUERY_4C_WALK_QUERY));
            let expected_dispatch: unsafe extern "C" fn(
                *mut *mut u8,
                u32,
                usize,
                *const usize,
            ) -> u32 = vtable_slot_4c_dispatch;
            let expected_query: unsafe extern "C" fn(
                *mut *mut u8,
                *mut u32,
                usize,
                usize,
            ) -> u32 = crate::util::vtable_query::vtable_query_4c_kind4;
            assert_eq!(
                dispatch as usize, expected_dispatch as usize,
                "the size query defaults to the ported slot +0x4c dispatcher"
            );
            assert_eq!(
                query as usize, expected_query as usize,
                "the walk query defaults to the ported kind-4 query thunk"
            );
        }
    }

    /// End-to-end through the wired-default dispatch seam: the ported
    /// slot +0x4c dispatcher double-dereferences the fake chain and
    /// the slot +0x4c method answers the size, then the body's own
    /// slot +0x54 load performs the alloc.
    static mut WALK_DIRECT_CALLS: usize = 0;
    static mut WALK_DIRECT_KIND: u32 = 0;
    static mut WALK_DIRECT_EXTRA: usize = 0;

    unsafe extern "C" fn walk_direct_method(
        _object: *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        WALK_DIRECT_CALLS += 1;
        WALK_DIRECT_KIND = kind;
        WALK_DIRECT_EXTRA = extra.read();
        (data as *mut u32).write(QUERIED_SIZE);
        MOCK_OK
    }

    #[test]
    fn walk_alloc_default_dispatch_seam_runs_the_ported_dispatcher() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut chain = FakeChain::new();
        chain.install(VTABLE_SLOT_4C, walk_direct_method);
        chain.install_alloc(VTABLE_SLOT_54, alloc_method);
        chain.link();
        unsafe {
            reset_walk_logs();
            WALK_DIRECT_CALLS = 0;

            let status = vtable_query_4c_walk_alloc(
                chain.handle_ptr(),
                SELECTOR,
                SCRATCH,
                FORWARDED,
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(WALK_DIRECT_CALLS, 1, "the size query reached the vtable method");
            assert_eq!(WALK_DIRECT_KIND, MESSAGE_KIND_4);
            assert_eq!(
                WALK_DIRECT_EXTRA, FORWARDED,
                "the ported dispatcher's stmdb sp!, {{r3}} spill exposes arg4"
            );
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, QUERIED_SIZE + 4);
            assert_eq!(ALLOC_MODE, 1);
        }
    }

    // ---- recording mocks for the buffer-size-out read seams ---------

    /// The byte count the probe answers through `size_out` (distinct
    /// from both MESSAGE_KIND_4 and BUFFER_CAPACITY, so a kind/data
    /// mix-up cannot pass silently).
    const BUFFER_SIZE: u32 = 0x24;
    /// The capacity the caller passes in r1 — the original never
    /// reads it (`mov r1, #0x4` kills r1 before any use).
    const BUFFER_CAPACITY: u32 = 0x100;
    /// The marker bytes the read method stores into the buffer.
    const BUFFER_PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    static mut BUFFER_CALLS: usize = 0;
    static mut BUFFER_HANDLE: [*mut *mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut BUFFER_KIND: [u32; 8] = [0; 8];
    static mut BUFFER_DATA: [usize; 8] = [0; 8];
    static mut BUFFER_DATA_WORD: [u32; 8] = [0; 8];
    static mut BUFFER_EXTRA: [usize; 8] = [0; 8];
    static mut BUFFER_RESULTS: [u32; 8] = [MOCK_OK; 8];
    /// The byte count the probe answers through the size pointer.
    static mut BUFFER_ANSWER: u32 = BUFFER_SIZE;

    unsafe extern "C" fn recording_buffer_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        data: usize,
        extra: *const usize,
    ) -> u32 {
        let call = BUFFER_CALLS;
        BUFFER_CALLS += 1;
        BUFFER_HANDLE[call] = handle;
        BUFFER_KIND[call] = kind;
        BUFFER_DATA[call] = data;
        // Call 0's data is the caller's size word; call 1's data is
        // the caller's buffer — the tests back both with real
        // locals, so the word reads are in-bounds.
        BUFFER_DATA_WORD[call] = (data as *const u32).read();
        BUFFER_EXTRA[call] = extra.read();
        if call == 0 {
            // The probe answers the byte count through size_out (a
            // 32-bit store, as the firmware method's `str` would be).
            (data as *mut u32).write(BUFFER_ANSWER);
        } else {
            // The read method delivers the bytes through the caller's
            // buffer pointer.
            (data as *mut u8)
                .copy_from_nonoverlapping(BUFFER_PAYLOAD.as_ptr(), BUFFER_PAYLOAD.len());
        }
        BUFFER_RESULTS[call]
    }

    static mut BUFFER_FINISH_CALLS: usize = 0;
    static mut BUFFER_FINISH_HANDLE: *mut *mut u8 = core::ptr::null_mut();
    static mut BUFFER_FINISH_OUT: *mut u32 = core::ptr::null_mut();
    static mut BUFFER_FINISH_WORD: usize = 0;
    static mut BUFFER_FINISH_UNUSED: usize = 0;
    static mut BUFFER_FINISH_FORWARDED: usize = 0;
    static mut BUFFER_FINISH_RESULT: u32 = MOCK_OK;

    unsafe extern "C" fn recording_buffer_finish(
        handle: *mut *mut u8,
        out: *mut u32,
        unused: usize,
        forwarded: usize,
    ) -> u32 {
        BUFFER_FINISH_CALLS += 1;
        BUFFER_FINISH_HANDLE = handle;
        BUFFER_FINISH_OUT = out;
        // `out` addresses the one-word {size_out} entry spill, whose
        // word is pointer-sized on this 64-bit host.
        BUFFER_FINISH_WORD = (out as *const usize).read();
        BUFFER_FINISH_UNUSED = unused;
        BUFFER_FINISH_FORWARDED = forwarded;
        BUFFER_FINISH_RESULT
    }

    unsafe fn install_buffer_mocks() {
        BUFFER_CALLS = 0;
        BUFFER_RESULTS = [MOCK_OK; 8];
        BUFFER_ANSWER = BUFFER_SIZE;
        BUFFER_FINISH_CALLS = 0;
        BUFFER_FINISH_HANDLE = core::ptr::null_mut();
        BUFFER_FINISH_OUT = core::ptr::null_mut();
        BUFFER_FINISH_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_BUFFER_DISPATCH)
            .write_volatile(recording_buffer_dispatch);
        core::ptr::addr_of_mut!(VTABLE_QUERY_4C_BUFFER_FINISH)
            .write_volatile(recording_buffer_finish);
    }

    // ---- vtable_query_4c_read_buffer_size_out (0x0811d5fc) ----------

    #[test]
    fn buffer_read_probe_unsupported_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();
            BUFFER_RESULTS[0] = UNSUPPORTED_ERR;

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(
                status, UNSUPPORTED_ERR,
                "cmp r0, #0x5; beq — the unsupported status returns verbatim"
            );
            assert_eq!(BUFFER_CALLS, 1, "no read dispatch after a 5");
            assert_eq!(BUFFER_FINISH_CALLS, 0, "no finish call after a 5");
        }
    }

    #[test]
    fn buffer_read_probe_error_bails_before_the_read() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();
            BUFFER_RESULTS[0] = METHOD_ERR;

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(
                status, METHOD_ERR,
                "cmp r0, #0; bne — the probe's hard error returns verbatim"
            );
            assert_eq!(BUFFER_CALLS, 1, "no read dispatch after a probe error");
            assert_eq!(BUFFER_FINISH_CALLS, 0);
        }
    }

    #[test]
    fn buffer_read_probe_args_route_size_out_and_ignore_capacity() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(
                BUFFER_KIND[0], MESSAGE_KIND_4,
                "mov r1, #0x4 — the probe is hardcoded kind 4"
            );
            assert_eq!(BUFFER_HANDLE[0], fixture.handle_ptr(), "mov r5, r0 — r0 passes through");
            assert_eq!(
                BUFFER_DATA[0],
                core::ptr::addr_of_mut!(size_out) as usize,
                "mov r2, r3 — the probe's out-slot IS the caller's size pointer"
            );
            assert_eq!(
                BUFFER_EXTRA[0],
                core::ptr::addr_of_mut!(size_out) as usize,
                "the entry stmdb sp!, {{r3}} spill — the dispatcher's extra \
                 points at a word holding the same size_out pointer"
            );
            assert!(
                BUFFER_KIND[..BUFFER_CALLS]
                    .iter()
                    .all(|&kind| kind != BUFFER_CAPACITY),
                "r1 is dead (`mov r1, #0x4` overwrites it before any use): \
                 the caller's capacity reaches no dispatch"
            );
        }
    }

    #[test]
    fn buffer_read_read_dispatch_routes_the_probed_size_unclamped() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();
            // A probed size LARGER than the caller's capacity: the
            // 0x0811d818 sibling clamps with strhi; this function has
            // no clamp — the read must carry the probed size verbatim.
            BUFFER_ANSWER = 0x180;

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(BUFFER_CALLS, 2, "probe then read");
            assert_eq!(
                BUFFER_KIND[1], 0x180,
                "ldr r1, [r4] — the read's middle argument is the probed \
                 size, NOT the (dead) capacity and NOT clamped to it"
            );
            assert_eq!(BUFFER_HANDLE[1], fixture.handle_ptr(), "mov r0, r5");
            assert_eq!(
                BUFFER_DATA[1],
                buffer.as_mut_ptr() as usize,
                "mov r2, r6 — the read's data is the caller's buffer pointer"
            );
            assert_eq!(
                BUFFER_EXTRA[1], 0,
                "r3 is dead across the probe (method-clobbered); a zero word \
                 stands in for the unobservable extra"
            );
            assert_eq!(
                size_out, 0x180,
                "the probe's store through size_out reaches the caller"
            );
            assert_eq!(
                &buffer[..BUFFER_PAYLOAD.len()],
                &BUFFER_PAYLOAD,
                "the read method's stores through the buffer pointer reach the caller"
            );
        }
    }

    #[test]
    fn buffer_read_read_error_skips_the_finish() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();
            BUFFER_RESULTS[1] = READ_ERR;

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(status, READ_ERR, "the read dispatch's error returns verbatim");
            assert_eq!(BUFFER_CALLS, 2);
            assert_eq!(
                BUFFER_FINISH_CALLS, 0,
                "bleq — the finish fires only on a zero read status"
            );
        }
    }

    #[test]
    fn buffer_read_finish_routing_and_final_return() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();
            BUFFER_FINISH_RESULT = FINISH_CODE;

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(
                status, FINISH_CODE,
                "the finish thunk's error code is the function's return value"
            );
            assert_eq!(BUFFER_FINISH_CALLS, 1);
            assert_eq!(BUFFER_FINISH_HANDLE, fixture.handle_ptr(), "moveq r0, r5");
            assert!(!BUFFER_FINISH_OUT.is_null(), "moveq r1, sp — the entry spill slot");
            assert_eq!(
                BUFFER_FINISH_WORD,
                core::ptr::addr_of_mut!(size_out) as usize,
                "the spill word is the entry r3 — the caller's size_out pointer"
            );
            assert_eq!(
                BUFFER_FINISH_UNUSED, 0,
                "r2 is dead across the read dispatch and the thunk discards \
                 it (mov r2, r1); the port passes 0"
            );
            assert_eq!(
                BUFFER_FINISH_FORWARDED, 0,
                "r3 is likewise dead (method-clobbered across the read \
                 dispatch); the port passes 0"
            );
        }
    }

    #[test]
    fn buffer_read_end_to_end_reports_size_and_delivers_bytes() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut buffer = [0u8; 8];
        let mut size_out: u32 = 0;
        unsafe {
            install_buffer_mocks();

            let status = vtable_query_4c_read_buffer_size_out(
                fixture.handle_ptr(),
                BUFFER_CAPACITY,
                buffer.as_mut_ptr(),
                core::ptr::addr_of_mut!(size_out),
            );

            assert_eq!(status, MOCK_OK);
            assert_eq!(BUFFER_CALLS, 2, "probe then read");
            assert_eq!(BUFFER_KIND[0], MESSAGE_KIND_4, "the probe is always kind 4");
            assert_eq!(BUFFER_KIND[1], BUFFER_SIZE, "the read carries the probed size");
            assert_eq!(size_out, BUFFER_SIZE, "the byte count is reported");
            assert_eq!(&buffer[..BUFFER_PAYLOAD.len()], &BUFFER_PAYLOAD, "the bytes arrive");
            assert_eq!(BUFFER_FINISH_CALLS, 1, "the finish fires on a zero read status");
            assert_eq!(BUFFER_FINISH_HANDLE, fixture.handle_ptr());
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

    // ---- vtable_file_open (0x0811d724): mocks and fixtures -----------

    const OPEN_STATUS_ERR: u32 = 0x0bad_0007;

    static mut REMOVE_CALLS: usize = 0;
    static mut REMOVE_PATH: *const u8 = core::ptr::null();
    static mut REMOVE_ZERO: u32 = 1;

    static mut CTOR_CALLS: usize = 0;
    static mut CTOR_THIS: *mut u8 = core::ptr::null_mut();
    static mut CTOR_PATH: *const u8 = core::ptr::null();
    static mut CTOR_READ_ONLY: u32 = 0xdead;
    static mut CTOR_ZERO: u32 = 0xdead;
    static mut CTOR_FLAGS: u32 = 0xdead;

    static mut OPEN_DISPOSE_CALLS: usize = 0;
    static mut OPEN_DISPOSE_OBJECT: *mut u8 = core::ptr::null_mut();

    /// The block the stub allocator hands out (the ft/system.rs
    /// FILE_ARENA precedent — the real heap core is 32-bit-layout and
    /// cannot run on a 64-bit host, so HEAP_OPS is swapped).
    static mut OPEN_ARENA: [u8; 0x40] = [0; 0x40];

    /// The size the stub allocator observed — pins the 0x34 object size.
    static mut OPEN_ALLOC_SIZE: usize = 0;

    unsafe extern "C" fn stub_open_alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        OPEN_ALLOC_SIZE = size;
        core::ptr::addr_of_mut!(OPEN_ARENA).cast()
    }

    unsafe extern "C" fn stub_open_create(
        _desc: *mut crate::heap::types::HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut crate::heap::types::HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    /// Restores HEAP_OPS and DEFAULT_HEAP on drop, even when a test
    /// panics (the ft/system.rs restore_file_layer precedent).
    struct HeapGuard;
    impl Drop for HeapGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS)
                    .write_volatile(crate::heap::veneers::DEFAULT_HEAP_OPS);
                core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                    .write_volatile(core::ptr::null_mut());
            }
        }
    }

    /// Swaps the stub allocator in and pre-seeds DEFAULT_HEAP so the
    /// lazy init does not run (the ft/system.rs mock_file_layer
    /// precedent).
    unsafe fn install_stub_heap() {
        let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        ops.alloc = stub_open_alloc;
        ops.create = stub_open_create;
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
        core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
            .write_volatile(0x1111_0000 as *mut crate::heap::types::HeapDescriptorDescriptor);
        OPEN_ALLOC_SIZE = 0;
    }

    /// The stand-in store object the recording ctor returns: +0x00 the
    /// vtable pointer, +0x30 the inner-object pointer — large enough
    /// for the host's pointer-sized reads.
    static mut FAKE_STORE: [u8; 0x40] = [0; 0x40];

    /// The stand-in inner object; the ctor mock plants the requested
    /// status at +0x1c.
    static mut FAKE_STORE_INNER: [u8; 0x20] = [0; 0x20];

    unsafe extern "C" fn recording_open_dispose(object: *mut u8) {
        OPEN_DISPOSE_CALLS += 1;
        OPEN_DISPOSE_OBJECT = object;
    }

    /// The stand-in vtable: slot +0x04 is the recording dispose,
    /// written at runtime by the ctor mock (the FakeChain precedent).
    static mut FAKE_STORE_VTABLE: [u8; 0x10] = [0; 0x10];

    unsafe extern "C" fn recording_remove(path: *const u8, zero: u32) -> u32 {
        REMOVE_CALLS += 1;
        REMOVE_PATH = path;
        REMOVE_ZERO = zero;
        0
    }

    /// Builds the stand-in store object with `status` in the inner
    /// object's status word and returns it, recording every argument.
    unsafe extern "C" fn recording_ctor(
        this: *mut u8,
        path: *const u8,
        read_only: u32,
        zero: u32,
        flags: u32,
    ) -> *mut u8 {
        CTOR_CALLS += 1;
        CTOR_THIS = this;
        CTOR_PATH = path;
        CTOR_READ_ONLY = read_only;
        CTOR_ZERO = zero;
        CTOR_FLAGS = flags;
        let object = core::ptr::addr_of_mut!(FAKE_STORE).cast::<u8>();
        let vtable = core::ptr::addr_of_mut!(FAKE_STORE_VTABLE).cast::<u8>();
        vtable
            .add(VTABLE_SLOT_04)
            .cast::<usize>()
            .write(recording_open_dispose as usize);
        object.cast::<usize>().write(vtable as usize);
        object
            .add(STORE_INNER_OFFSET)
            .cast::<usize>()
            .write(core::ptr::addr_of_mut!(FAKE_STORE_INNER) as usize);
        core::ptr::addr_of_mut!(FAKE_STORE_INNER)
            .cast::<u8>()
            .add(STORE_STATUS_OFFSET)
            .cast::<u32>()
            .write(OPEN_STATUS);
        object
    }

    static mut OPEN_STATUS: u32 = MOCK_OK;

    /// Resets the recording state and installs both recording mocks.
    unsafe fn install_recording_open() {
        REMOVE_CALLS = 0;
        REMOVE_PATH = core::ptr::null();
        REMOVE_ZERO = 1;
        CTOR_CALLS = 0;
        CTOR_THIS = core::ptr::null_mut();
        CTOR_PATH = core::ptr::null();
        CTOR_READ_ONLY = 0xdead;
        CTOR_ZERO = 0xdead;
        CTOR_FLAGS = 0xdead;
        OPEN_DISPOSE_CALLS = 0;
        OPEN_DISPOSE_OBJECT = core::ptr::null_mut();
        OPEN_STATUS = MOCK_OK;
        install_stub_heap();
        core::ptr::addr_of_mut!(VTABLE_FILE_OPEN_REMOVE)
            .write_volatile(recording_remove);
        core::ptr::addr_of_mut!(VTABLE_FILE_OPEN_CTOR).write_volatile(recording_ctor);
    }

    /// A stand-in six-byte record, padded so the host's pointer-sized
    /// first-word store is in bounds.
    struct RecordFixture {
        bytes: [u8; 16],
    }

    impl RecordFixture {
        fn new() -> Self {
            RecordFixture { bytes: [0xa5; 16] }
        }
        fn ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
    }

    /// Asserts the record's first word holds `object` with bytes 4 and
    /// 5 overwritten by the trailing mode stores — the exact host image
    /// of the original's `str` + `strb` + `strb` sequence (the byte
    /// stores land inside the pointer-sized word on a 64-bit host; see
    /// the function's deviations).
    unsafe fn assert_record(record: &RecordFixture, object: *mut u8, write_mode: u32) {
        let word = record.bytes.as_ptr().cast::<usize>().read();
        // The exact host image of the original's str + strb + strb
        // sequence: on a 64-bit host the trailing byte stores land
        // inside the pointer-sized first word, so byte 4 is cleared and
        // byte 5 holds the write-mode flag (see the deviations).
        let expected = ((object as usize) & !0xffff_0000_0000usize)
            | (((write_mode != 0) as usize) << 40);
        assert_eq!(word, expected);
        assert_eq!(record.bytes[4], 0, "record.flags cleared on every path");
        assert_eq!(
            record.bytes[5],
            (write_mode != 0) as u8,
            "record.write mirrors write_mode != 0"
        );
    }

    #[test]
    fn file_open_write_mode_calls_the_preopen_remove_with_a_zeroed_r1() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/radio\0";
        unsafe {
            install_recording_open();

            let result = vtable_file_open(record.ptr(), path.as_ptr(), 1);

            assert_eq!(result, MOCK_OK);
            assert_eq!(REMOVE_CALLS, 1, "write mode runs the pre-open remove");
            assert_eq!(REMOVE_PATH, path.as_ptr(), "the remove gets arg2 (r7)");
            assert_eq!(REMOVE_ZERO, 0, "the call site's mov r1, #0x0 is modeled");
        }
    }

    #[test]
    fn file_open_read_mode_skips_the_preopen_remove() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/PlayCounts\0";
        unsafe {
            install_recording_open();

            let result = vtable_file_open(record.ptr(), path.as_ptr(), 0);

            assert_eq!(result, MOCK_OK);
            assert_eq!(REMOVE_CALLS, 0, "read mode takes the beq past the remove");
            assert_eq!(CTOR_CALLS, 1);
        }
    }

    #[test]
    fn file_open_ctor_argument_routing_and_mode_inversion() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/Users\0";
        unsafe {
            install_recording_open();

            vtable_file_open(record.ptr(), path.as_ptr(), 0);
            assert_eq!(OPEN_ALLOC_SIZE, STORE_OBJECT_SIZE, "operator_new(0x34)");
            assert!(!CTOR_THIS.is_null(), "operator_new(0x34) feeds the ctor");
            assert_eq!(CTOR_PATH, path.as_ptr(), "arg2 (r7) routes to the ctor");
            assert_eq!(CTOR_READ_ONLY, 1, "read mode: read_only = (write_mode == 0)");
            assert_eq!(CTOR_ZERO, 0, "the original's r3 immediate");
            assert_eq!(CTOR_FLAGS, STORE_OPEN_FLAGS, "the stacked fifth argument");

            vtable_file_open(record.ptr(), path.as_ptr(), 1);
            assert_eq!(CTOR_READ_ONLY, 0, "write mode inverts the mode bit");
            assert_eq!(CTOR_CALLS, 2);
        }
    }

    #[test]
    fn file_open_success_stores_the_object_and_mode_bytes() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/radio\0";
        unsafe {
            install_recording_open();

            let result = vtable_file_open(record.ptr(), path.as_ptr(), 1);

            assert_eq!(result, MOCK_OK);
            assert_eq!(OPEN_DISPOSE_CALLS, 0, "a zero status keeps the object");
            assert_record(&record, core::ptr::addr_of_mut!(FAKE_STORE).cast::<u8>(), 1);
        }
    }

    #[test]
    fn file_open_failure_disposes_nulls_and_returns_the_status_verbatim() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/PlayCounts\0";
        unsafe {
            install_recording_open();
            OPEN_STATUS = OPEN_STATUS_ERR;

            let result = vtable_file_open(record.ptr(), path.as_ptr(), 0);

            assert_eq!(result, OPEN_STATUS_ERR, "the inner status returns verbatim");
            assert_eq!(OPEN_DISPOSE_CALLS, 1, "a nonzero status disposes the object");
            assert_eq!(
                OPEN_DISPOSE_OBJECT,
                core::ptr::addr_of_mut!(FAKE_STORE).cast::<u8>(),
                "the slot +0x04 method gets the store object"
            );
            assert_record(&record, core::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn file_open_mode_byte_mirrors_write_mode_on_both_paths() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/radio\0";
        unsafe {
            install_recording_open();

            // Success + write mode: byte 5 = 1.
            vtable_file_open(record.ptr(), path.as_ptr(), 1);
            assert_eq!(record.bytes[5], 1);
            // Failure + write mode: the bytes are written after the
            // dispose/NULL, on every path.
            OPEN_STATUS = OPEN_STATUS_ERR;
            vtable_file_open(record.ptr(), path.as_ptr(), 1);
            assert_eq!(record.bytes[5], 1);
            assert_eq!(record.bytes[4], 0);
            // Failure + read mode: byte 5 = 0.
            vtable_file_open(record.ptr(), path.as_ptr(), 0);
            assert_eq!(record.bytes[5], 0);
        }
    }

    #[test]
    fn file_open_default_remove_stub_is_a_noop() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        unsafe {
            // The default is already wired (the guard reinstalls it), but
            // call the stub directly to pin its contract.
            assert_eq!(store_remove_unported(b"any\0".as_ptr(), 0), 0);
            assert_eq!(store_remove_unported(core::ptr::null(), 1), 0);
        }
    }

    #[test]
    fn file_open_default_ctor_stub_fails_the_open_closed() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = RecordFixture::new();
        let path = b"iPod_Control/Device/radio\0";
        unsafe {
            install_stub_heap();
            // No mocks installed: the wired defaults are the stubs. The
            // fail-closed ctor reports a hard failure through the stand-
            // in object, so the ported failure path disposes it through
            // the no-op vtable and NULLs the record.
            let result = vtable_file_open(record.ptr(), path.as_ptr(), 0);

            assert_ne!(result, 0, "the stub fails the open closed");
            assert_record(&record, core::ptr::null_mut(), 0);
            // Write mode reaches the no-op remove stub without harm.
            let result = vtable_file_open(record.ptr(), path.as_ptr(), 1);
            assert_ne!(result, 0);
            assert_eq!(record.bytes[5], 1);
        }
    }

    // ---- vtable_file_record_init (0x0811d8ac) ----------------------

    #[test]
    fn file_record_init_zeroes_the_record_and_returns_the_pointer() {
        let mut record = RecordFixture::new();
        unsafe {
            let result = vtable_file_record_init(record.ptr());

            assert_eq!(result, record.ptr(), "r0 falls through: the argument returns");
            assert_eq!(
                record.bytes.as_ptr().cast::<u32>().read(),
                0,
                "str r1, [r0, #0x0] — record.object = NULL"
            );
            assert_eq!(record.bytes[4], 0, "strb r1, [r0, #0x4] — record.flags = 0");
            assert_eq!(record.bytes[5], 0, "strb r1, [r0, #0x5] — record.write = 0");
            assert_eq!(
                &record.bytes[6..],
                &[0xa5; 10],
                "only the six record bytes are touched"
            );
        }
    }

    #[test]
    fn file_record_init_clears_a_field_inside_a_larger_object() {
        // The object-field call sites (0x081b0268, 0x0811c874,
        // 0x0815e968, 0x082859d8) pass an interior pointer; the
        // surrounding bytes must survive.
        let mut object = [0xa5u8; 24];
        unsafe {
            let record = object.as_mut_ptr().add(8);
            let result = vtable_file_record_init(record);

            assert_eq!(result, record);
            assert_eq!(&object[..8], &[0xa5; 8], "the prefix is untouched");
            assert_eq!(&object[8..14], &[0; 6], "the six record bytes are cleared");
            assert_eq!(&object[14..], &[0xa5; 10], "the tail is untouched");
        }
    }

    // ---- vtable_file_record_dispose (0x0811d8c0) --------------------

    #[test]
    fn file_record_dispose_calls_through_and_returns_the_handle() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install_dispose(VTABLE_SLOT_04, dispose_method);
        chain.install_dispose(VTABLE_SLOT_04 + 8, wrong_slot_dispose);
        chain.link();
        unsafe {
            reset_dispose_log();
            DISPOSE_HANDLE_PTR = chain.handle_ptr() as *const *mut u8;

            let result = vtable_file_record_dispose(chain.handle_ptr());

            assert_eq!(
                result,
                chain.handle_ptr(),
                "mov r0, r4 — the argument returns, not the dispose's 0 status"
            );
            assert_eq!(
                DISPOSE_CALLS, 1,
                "bl 0x0811d7cc — the dispose runs exactly once"
            );
            assert_eq!(
                WRONG_SLOT_CALLS, 0,
                "only vtable slot +0x4 is loaded"
            );
            assert_eq!(
                DISPOSE_OBJECT,
                core::ptr::addr_of_mut!(chain.object) as *mut u8,
                "the dispose received *handle (the record's first word)"
            );
            assert_eq!(
                chain.handle_ptr().read(),
                core::ptr::null_mut(),
                "the dispose NULLed the handle, yet the POINTER still returns"
            );
        }
    }

    #[test]
    fn file_record_dispose_null_handle_is_a_noop_and_still_returns_it() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut handle: *mut u8 = core::ptr::null_mut();
        unsafe {
            reset_dispose_log();
            let handle_ptr = core::ptr::addr_of_mut!(handle);

            let result = vtable_file_record_dispose(handle_ptr);

            assert_eq!(
                result, handle_ptr,
                "mov r0, r4 runs on the NULL path too: the pointer returns"
            );
            assert_eq!(
                DISPOSE_CALLS, 0,
                "the dispose's cmp r0, #0; beq skips the blx on a NULL handle"
            );
            assert_eq!(
                handle,
                core::ptr::null_mut(),
                "the NULL store is skipped as well"
            );
        }
    }

    #[test]
    fn file_record_dispose_discards_the_dispose_status() {
        // vtable_slot_04_dispose always returns 0, and every observed
        // caller consumes the wrapper's return as the RECORD pointer —
        // pin the mov r0, r4 overwrite even when the record lives
        // inside a larger object (the 0x0811c9cc / 0x0815eb58 sites,
        // which do container-of arithmetic on the returned pointer).
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut chain = FakeChain::new();
        chain.install_dispose(VTABLE_SLOT_04, dispose_method);
        chain.link();
        unsafe {
            reset_dispose_log();
            DISPOSE_HANDLE_PTR = chain.handle_ptr() as *const *mut u8;

            let handle_ptr = chain.handle_ptr();
            let result = vtable_file_record_dispose(handle_ptr);

            assert_eq!(
                result, handle_ptr,
                "the returned pointer is bit-identical to the argument"
            );
            assert_ne!(
                result as usize, 0,
                "the dispose's 0 status never reaches the caller"
            );
        }
    }

    // ---- vtable_file_record_construct_kind1 (0x0811d148) -----------

    /// The block the recording kind-1 ctor returns as the registry.
    static mut KIND1_REGISTRY: [u8; 0x28] = [0; 0x28];

    static mut KIND1_CTOR_CALLS: usize = 0;
    static mut KIND1_CTOR_THIS: *mut u8 = core::ptr::null_mut();
    static mut KIND1_GUARD_CALLS: usize = 0;
    static mut KIND1_GUARD_OBJECT: *mut u8 = core::ptr::null_mut();
    /// The record under construction, so the recording mocks can pin
    /// the store/call ordering against it.
    static mut KIND1_RECORD: *const u8 = core::ptr::null();

    unsafe extern "C" fn recording_kind1_ctor(allocation: *mut u8) -> *mut u8 {
        KIND1_CTOR_CALLS += 1;
        KIND1_CTOR_THIS = allocation;
        // Order pins: the tag and the +0x18 NULL store precede the
        // allocation/construct (`strb` / `str` before the `bl`s).
        assert_eq!(
            KIND1_RECORD.read(),
            FILE_RECORD_TAG_KIND1,
            "the tag store precedes the allocation"
        );
        assert_eq!(
            KIND1_RECORD.add(0x18).cast::<u32>().read(),
            0,
            "+0x18 is zeroed before the allocation"
        );
        core::ptr::addr_of_mut!(KIND1_REGISTRY).cast()
    }

    unsafe extern "C" fn recording_kind1_guard(object: *mut u8) {
        KIND1_GUARD_CALLS += 1;
        KIND1_GUARD_OBJECT = object;
        // Order pins: the registry store at +0x04 precedes the guard
        // (`str r0, [r4, #0x4]` before the `bl`), and the trailing
        // field zeroing follows it.
        assert_eq!(
            KIND1_RECORD.add(4).cast::<u32>().read(),
            object as u32,
            "the +0x04 store precedes the guard"
        );
        assert_eq!(
            KIND1_RECORD.add(0x08).cast::<u32>().read(),
            0xa5a5_a5a5,
            "+0x08 is still untouched when the guard runs"
        );
    }

    /// Resets the recording state and installs both recording mocks
    /// plus the stub heap (the `install_recording_open` precedent).
    unsafe fn install_recording_kind1(record: *const u8) {
        KIND1_CTOR_CALLS = 0;
        KIND1_CTOR_THIS = core::ptr::null_mut();
        KIND1_GUARD_CALLS = 0;
        KIND1_GUARD_OBJECT = core::ptr::null_mut();
        KIND1_RECORD = record;
        install_stub_heap();
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_CTOR)
            .write_volatile(recording_kind1_ctor);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_GUARD)
            .write_volatile(recording_kind1_guard);
    }

    #[test]
    fn file_record_kind1_initializes_the_record_and_returns_it() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_kind1(record.as_ptr());

            let result = vtable_file_record_construct_kind1(record.as_mut_ptr());

            assert_eq!(
                result,
                record.as_mut_ptr(),
                "mov r0, r4 — the record pointer returns"
            );
            assert_eq!(record[0], FILE_RECORD_TAG_KIND1, "strb: the kind-1 tag");
            let registry = core::ptr::addr_of_mut!(KIND1_REGISTRY).cast::<u8>();
            assert_eq!(
                record.as_ptr().add(4).cast::<u32>().read(),
                registry as u32,
                "str: the construct result at +0x04 (32-bit on a 64-bit host)"
            );
            assert_eq!(record.as_ptr().add(0x08).cast::<u32>().read(), 0);
            assert_eq!(
                record.as_ptr().add(0x0c).cast::<u32>().read(),
                0xa5a5_a5a5,
                "the +0x0c gap is never written"
            );
            assert_eq!(record.as_ptr().add(0x10).cast::<u32>().read(), 0);
            assert_eq!(
                record.as_ptr().add(0x14).cast::<u16>().read(),
                0,
                "strh: the +0x14 halfword"
            );
            assert_eq!(record.as_ptr().add(0x18).cast::<u32>().read(), 0);
            assert_eq!(
                &record[0x1c..],
                &[0xa5; 4],
                "bytes past the 0x1c record are untouched"
            );
        }
    }

    #[test]
    fn file_record_kind1_allocates_the_registry_and_feeds_it_to_the_ctor() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_kind1(record.as_ptr());

            vtable_file_record_construct_kind1(record.as_mut_ptr());

            assert_eq!(OPEN_ALLOC_SIZE, REGISTRY_OBJECT_SIZE, "operator_new(0x28)");
            assert_eq!(KIND1_CTOR_CALLS, 1, "the registry construct runs once");
            assert_eq!(
                KIND1_CTOR_THIS,
                core::ptr::addr_of_mut!(OPEN_ARENA).cast::<u8>(),
                "the fresh block feeds the construct in r0 — the argument the \
                 reference C drops"
            );
            let registry = core::ptr::addr_of_mut!(KIND1_REGISTRY).cast::<u8>();
            assert_eq!(KIND1_GUARD_CALLS, 1, "the checked-construct guard runs once");
            assert_eq!(
                KIND1_GUARD_OBJECT, registry,
                "the guard checks the construct's result, not the raw allocation"
            );
        }
    }

    #[test]
    fn file_record_kind1_default_guard_is_a_noop() {
        // The non-NULL path is a bare `bx lr`; the NULL path's only
        // effect is the unported diagnostic, so the wired default does
        // nothing on either (the file_open_default_remove_stub_is_a_noop
        // precedent).
        unsafe {
            construct_guard_unported(core::ptr::null_mut());
            construct_guard_unported(0x1c as *mut u8);
        }
    }

    // ---- vtable_file_record_construct_kind2_block (0x0815bdbc) -----

    static mut KIND2_DIAGNOSTIC_CALLS: usize = 0;
    static mut KIND2_DIAGNOSTIC_CODE: u32 = u32::MAX;
    static mut KIND2_DIAGNOSTIC_MESSAGE: *const u8 = core::ptr::null();

    /// The descriptor the kind-2 tests hand the constructor: word 0
    /// the required kind 3, word 1 the block[2] offset, word 2 the
    /// block[3] count.
    static KIND2_DESCRIPTOR: [u32; 3] = [KIND2_BLOCK_DESCRIPTOR_KIND, 0x40, 7];
    const KIND2_EXTRA: u32 = 0x5eed_0002;

    unsafe extern "C" fn recording_kind2_diagnostic(code: u32, message: *const u8) {
        KIND2_DIAGNOSTIC_CALLS += 1;
        KIND2_DIAGNOSTIC_CODE = code;
        KIND2_DIAGNOSTIC_MESSAGE = message;
    }

    unsafe fn install_recording_kind2_diagnostic() {
        KIND2_DIAGNOSTIC_CALLS = 0;
        KIND2_DIAGNOSTIC_CODE = u32::MAX;
        KIND2_DIAGNOSTIC_MESSAGE = core::ptr::null();
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND2_BLOCK_DIAGNOSTIC)
            .write_volatile(recording_kind2_diagnostic);
    }

    #[test]
    fn kind2_block_constructs_five_words_without_a_diagnostic() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut block = [0xa5a5_a5a5u32; 6];
        unsafe {
            install_recording_kind2_diagnostic();

            let result = vtable_file_record_construct_kind2_block(
                block.as_mut_ptr().cast(),
                KIND2_DESCRIPTOR.as_ptr(),
                KIND2_EXTRA,
            );

            assert_eq!(result, block.as_mut_ptr().cast::<u8>(), "mov r0, r4 returns block");
            assert_eq!(KIND2_DIAGNOSTIC_CALLS, 0, "kind 3 does not diagnose");
            assert_eq!(block[0], KIND2_DESCRIPTOR.as_ptr() as u32, "stmia word 0");
            assert_eq!(block[1], KIND2_EXTRA, "stmia word 1");
            assert_eq!(
                block[2],
                (KIND2_DESCRIPTOR.as_ptr() as u32).wrapping_add(KIND2_DESCRIPTOR[1]),
                "str word 2"
            );
            assert_eq!(block[3], KIND2_DESCRIPTOR[2], "str word 3");
            assert_eq!(
                block[4],
                (KIND2_DESCRIPTOR.as_ptr() as u32).wrapping_add(0xc),
                "str word 4"
            );
            assert_eq!(block[5], 0xa5a5_a5a5, "nothing beyond the five-word block changes");
        }
    }

    #[test]
    fn kind2_block_reports_bad_descriptor_and_still_constructs() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let descriptor = [2u32, 0x20, 9];
        let mut block = [0xa5a5_a5a5u32; 6];
        unsafe {
            install_recording_kind2_diagnostic();

            let result = vtable_file_record_construct_kind2_block(
                block.as_mut_ptr().cast(),
                descriptor.as_ptr(),
                KIND2_EXTRA,
            );

            assert_eq!(result, block.as_mut_ptr().cast::<u8>(), "mov r0, r4 returns block");
            assert_eq!(KIND2_DIAGNOSTIC_CALLS, 1, "kind mismatch diagnoses exactly once");
            assert_eq!(KIND2_DIAGNOSTIC_CODE, 0, "movne r0, #0");
            assert_eq!(
                KIND2_DIAGNOSTIC_MESSAGE,
                KIND2_BLOCK_DIAGNOSTIC_MESSAGE as *const u8,
                "ldrne r1, [pc, #0x28] loads the exact literal"
            );
            assert_eq!(block[0], descriptor.as_ptr() as u32, "stmia word 0");
            assert_eq!(block[1], KIND2_EXTRA, "stmia word 1");
            assert_eq!(
                block[2],
                (descriptor.as_ptr() as u32).wrapping_add(descriptor[1]),
                "mismatch falls through to the descriptor-relative word"
            );
            assert_eq!(block[3], descriptor[2], "str word 3");
            assert_eq!(
                block[4],
                (descriptor.as_ptr() as u32).wrapping_add(0xc),
                "str word 4"
            );
            assert_eq!(block[5], 0xa5a5_a5a5, "nothing beyond the five-word block changes");
        }
    }

    // ---- vtable_file_record_teardown (0x0811d008) ------------------

    /// Event tokens for the teardown walk log; data words (key,
    /// registry, free tag) follow their token in the stream.
    const TD_EV_OUTER_BEGIN: u32 = 0x0b00_0001;
    const TD_EV_OUTER_NEXT: u32 = 0x0b00_0002;
    const TD_EV_INNER_BEGIN: u32 = 0x0b00_0003;
    const TD_EV_INNER_NEXT: u32 = 0x0b00_0004;
    const TD_EV_CLEANUP: u32 = 0x0b00_0005;
    const TD_EV_FREE: u32 = 0x0b00_0006;
    const TD_EV_DISPOSE: u32 = 0x0b00_0007;

    /// The tag operator_delete (0x082aad24) frees with.
    const TD_DELETE_TAG: u32 = 2;

    /// The scripted outer keys and their buckets: key 0 -> nodes 0
    /// and 1, key 1 -> node 2.
    const TD_KEYS: [u32; 2] = [0x1111_0001, 0x2222_0002];
    const TD_PAYLOADS: [u32; 3] = [0x1eaf_0001, 0x1eaf_0002, 0x1eaf_0003];

    static mut TD_EVENTS: [u32; 96] = [0; 96];
    static mut TD_EVENT_COUNT: usize = 0;
    static mut TD_FREE_PTRS: [*mut u8; 16] = [core::ptr::null_mut(); 16];
    static mut TD_FREE_TAGS: [usize; 16] = [0; 16];
    static mut TD_FREE_COUNT: usize = 0;

    /// The stand-in registry object and the three fake bucket nodes
    /// (a payload word at +0x04, planted by the installer).
    static mut TD_REGISTRY: [u8; 0x28] = [0; 0x28];
    static mut TD_NODES: [[u8; 0x10]; 3] = [[0; 0x10]; 3];

    /// The outer/inner script cursors: how many keys the outer step
    /// still yields, and the current bucket's pending nodes.
    static mut TD_OUTER_KEY_COUNT: usize = 0;
    static mut TD_OUTER_NEXT_CALLS: usize = 0;
    static mut TD_INNER_PENDING: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut TD_INNER_PENDING_LEN: usize = 0;
    static mut TD_INNER_NEXT_CALLS: usize = 0;

    unsafe fn td_push(event: u32) {
        let count = TD_EVENT_COUNT;
        TD_EVENTS[count] = event;
        TD_EVENT_COUNT = count + 1;
    }

    unsafe fn td_node(index: usize) -> *mut u8 {
        core::ptr::addr_of_mut!(TD_NODES).cast::<u8>().add(index * 0x10)
    }

    unsafe extern "C" fn recording_td_outer_begin(iter: *mut u32, registry: *mut u8) {
        assert!(!iter.is_null(), "the outer iterator scratch is passed in r0");
        td_push(TD_EV_OUTER_BEGIN);
        td_push(registry as u32);
    }

    unsafe extern "C" fn recording_td_outer_next(_iter: *mut u32, key_out: *mut u32) -> u32 {
        td_push(TD_EV_OUTER_NEXT);
        let call = TD_OUTER_NEXT_CALLS;
        TD_OUTER_NEXT_CALLS = call + 1;
        if call < TD_OUTER_KEY_COUNT {
            // FUN_081ddde8's strne: the out-slot is written only on success.
            key_out.write(TD_KEYS[call]);
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn recording_td_inner_begin(
        _iter: *mut u32,
        registry: *mut u8,
        key: u32,
    ) {
        td_push(TD_EV_INNER_BEGIN);
        td_push(key);
        td_push(registry as u32);
        TD_INNER_NEXT_CALLS = 0;
        if key == TD_KEYS[0] {
            TD_INNER_PENDING[0] = td_node(0);
            TD_INNER_PENDING[1] = td_node(1);
            TD_INNER_PENDING_LEN = 2;
        } else if key == TD_KEYS[1] {
            TD_INNER_PENDING[0] = td_node(2);
            TD_INNER_PENDING_LEN = 1;
        } else {
            TD_INNER_PENDING_LEN = 0;
        }
    }

    unsafe extern "C" fn recording_td_inner_next(
        _iter: *mut u32,
        key_out: *mut u32,
        node_out: *mut *mut u8,
    ) -> u32 {
        td_push(TD_EV_INNER_NEXT);
        let call = TD_INNER_NEXT_CALLS;
        TD_INNER_NEXT_CALLS = call + 1;
        if call < TD_INNER_PENDING_LEN {
            key_out.write(0x5eed_0000 + call as u32);
            node_out.write(TD_INNER_PENDING[call]);
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn recording_td_cleanup(state: *mut u32) -> *mut u32 {
        td_push(TD_EV_CLEANUP);
        state
    }

    unsafe extern "C" fn recording_td_dispose(registry: *mut u8) {
        td_push(TD_EV_DISPOSE);
        td_push(registry as u32);
    }

    unsafe extern "C" fn recording_td_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        td_push(TD_EV_FREE);
        td_push(tag as u32);
        let count = TD_FREE_COUNT;
        TD_FREE_PTRS[count] = ptr;
        TD_FREE_TAGS[count] = tag;
        TD_FREE_COUNT = count + 1;
    }

    /// Resets the walk state, plants the node payloads, swaps in the
    /// recording free and installs the six recording seam mocks (the
    /// `install_recording_kind1` precedent).
    unsafe fn install_recording_teardown() {
        TD_EVENT_COUNT = 0;
        TD_FREE_COUNT = 0;
        TD_OUTER_KEY_COUNT = TD_KEYS.len();
        TD_OUTER_NEXT_CALLS = 0;
        TD_INNER_PENDING_LEN = 0;
        TD_INNER_NEXT_CALLS = 0;
        install_stub_heap();
        let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        ops.free = recording_td_free;
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
        for index in 0..3 {
            td_node(index).add(4).cast::<u32>().write(TD_PAYLOADS[index]);
        }
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_BEGIN)
            .write_volatile(recording_td_outer_begin);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_OUTER_NEXT)
            .write_volatile(recording_td_outer_next);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_INNER_BEGIN)
            .write_volatile(recording_td_inner_begin);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_INNER_NEXT)
            .write_volatile(recording_td_inner_next);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_ITER_CLEANUP)
            .write_volatile(recording_td_cleanup);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_TEARDOWN_REGISTRY_DISPOSE)
            .write_volatile(recording_td_dispose);
    }

    /// Builds a 0xa5-filled record with the stand-in registry at +0x04
    /// (32-bit, the constructors' byte-exact precedent) and the kind-1
    /// tag at +0x00.
    unsafe fn td_record(record: &mut [u8; 0x20]) -> *mut u8 {
        let registry = core::ptr::addr_of_mut!(TD_REGISTRY).cast::<u8>();
        record.as_mut_ptr().add(4).cast::<u32>().write(registry as u32);
        record[0] = FILE_RECORD_TAG_KIND1;
        registry
    }

    #[test]
    fn file_record_teardown_empty_registry_runs_straight_to_the_dispose_delete_tail() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_teardown();
            TD_OUTER_KEY_COUNT = 0;
            let registry = td_record(&mut record);
            let registry32 = registry as u32;

            vtable_file_record_teardown(record.as_mut_ptr());

            let events = &TD_EVENTS[..TD_EVENT_COUNT];
            assert_eq!(
                events,
                &[
                    TD_EV_OUTER_BEGIN,
                    registry32,
                    TD_EV_OUTER_NEXT, // -> 0: no keys, no inner iterator at all
                    TD_EV_CLEANUP,    // the outer state object only
                    TD_EV_DISPOSE,
                    registry32,
                    TD_EV_FREE,
                    TD_DELETE_TAG,
                ],
                "begin -> next(0) -> cleanup -> dispose -> operator_delete"
            );
            assert_eq!(TD_FREE_COUNT, 1, "only the registry object is freed");
            assert_eq!(
                TD_FREE_PTRS[0],
                registry32 as *mut u8,
                "operator_delete frees the +0x04 word (32-bit on a 64-bit host)"
            );
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), 0, "+0x04 zeroed");
            assert_eq!(record[0], 0, "the tag byte zeroed");
        }
    }

    #[test]
    fn file_record_teardown_populated_registry_walks_keys_and_frees_nodes_in_order() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_teardown();
            let registry = td_record(&mut record);
            let registry32 = registry as u32;

            vtable_file_record_teardown(record.as_mut_ptr());

            let events = &TD_EVENTS[..TD_EVENT_COUNT];
            assert_eq!(
                events,
                &[
                    TD_EV_OUTER_BEGIN,
                    registry32,
                    TD_EV_OUTER_NEXT, // -> key 0
                    TD_EV_INNER_BEGIN,
                    TD_KEYS[0],
                    registry32,
                    TD_EV_INNER_NEXT, // -> node 0
                    TD_EV_FREE,
                    0x19, // free_wrapper(node0.+0x04, 0x19)
                    TD_EV_FREE,
                    0x19, // free_wrapper(node0, 0x19)
                    TD_EV_INNER_NEXT, // -> node 1
                    TD_EV_FREE,
                    0x19,
                    TD_EV_FREE,
                    0x19,
                    TD_EV_INNER_NEXT, // -> 0: bucket drained
                    TD_EV_CLEANUP,    // the inner state object
                    TD_EV_OUTER_NEXT, // -> key 1
                    TD_EV_INNER_BEGIN,
                    TD_KEYS[1],
                    registry32,
                    TD_EV_INNER_NEXT, // -> node 2
                    TD_EV_FREE,
                    0x19,
                    TD_EV_FREE,
                    0x19,
                    TD_EV_INNER_NEXT, // -> 0
                    TD_EV_CLEANUP,
                    TD_EV_OUTER_NEXT, // -> 0: no more keys
                    TD_EV_CLEANUP,    // the outer state object
                    TD_EV_DISPOSE,
                    registry32,
                    TD_EV_FREE,
                    TD_DELETE_TAG,
                ],
                "the nested walk: per key begin -> [next -> double free] -> cleanup"
            );
            assert_eq!(TD_FREE_COUNT, 7, "six node frees plus the registry delete");
            let expected_ptrs = [
                TD_PAYLOADS[0] as *mut u8, // node0.+0x04 (32-bit payload word)
                td_node(0),
                TD_PAYLOADS[1] as *mut u8,
                td_node(1),
                TD_PAYLOADS[2] as *mut u8,
                td_node(2),
                registry32 as *mut u8,
            ];
            assert_eq!(
                &TD_FREE_PTRS[..7],
                &expected_ptrs,
                "payload first, then the node — the 0x0811d038..0x0811d050 order"
            );
            assert_eq!(
                &TD_FREE_TAGS[..7],
                &[0x19, 0x19, 0x19, 0x19, 0x19, 0x19, TD_DELETE_TAG as usize],
                "mov r1, #0x19 on every node free, tag 2 for operator_delete"
            );
        }
    }

    #[test]
    fn file_record_teardown_null_registry_skips_the_dispose_and_delete() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_teardown();
            TD_OUTER_KEY_COUNT = 0;
            // +0x04 left at the 0xa5 fill? No: the NULL case — write 0.
            record.as_mut_ptr().add(4).cast::<u32>().write(0);
            record[0] = FILE_RECORD_TAG_KIND1;

            vtable_file_record_teardown(record.as_mut_ptr());

            let events = &TD_EVENTS[..TD_EVENT_COUNT];
            assert_eq!(
                events,
                &[
                    TD_EV_OUTER_BEGIN,
                    0, // the NULL registry still feeds the begin (ldr at 0x0811d00c)
                    TD_EV_OUTER_NEXT,
                    TD_EV_CLEANUP,
                ],
                "the iterator prologue runs; cmp r0, #0; beq skips dispose + delete"
            );
            assert_eq!(TD_FREE_COUNT, 0, "no operator_delete on the NULL path");
            assert_eq!(record[0], 0, "the tag byte is still zeroed");
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), 0);
        }
    }

    #[test]
    fn file_record_teardown_zeroes_only_the_registry_word_and_the_tag() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_teardown();
            TD_OUTER_KEY_COUNT = 0;
            td_record(&mut record);

            vtable_file_record_teardown(record.as_mut_ptr());

            assert_eq!(record[0], 0, "strb r0, [r4, #0x0] — tag = 0");
            assert_eq!(
                &record[1..4],
                &[0xa5; 3],
                "bytes +0x01..+0x04 are untouched"
            );
            assert_eq!(
                record.as_ptr().add(4).cast::<u32>().read(),
                0,
                "str r0, [r4, #0x4] — registry = NULL"
            );
            assert_eq!(
                &record[8..],
                &[0xa5; 0x18],
                "bytes past +0x08 are untouched"
            );
        }
    }

    #[test]
    fn file_record_teardown_default_seams_yield_an_empty_traversal() {
        // The wired defaults (reinstalled by the guard) are the
        // documented empty-traversal stubs: no-op begins/cleanups,
        // 0-returning steps, no-op dispose — but operator_delete still
        // frees the registry block.
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_stub_heap();
            let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
            ops.free = recording_td_free;
            core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
            TD_EVENT_COUNT = 0;
            TD_FREE_COUNT = 0;
            let registry = td_record(&mut record);

            vtable_file_record_teardown(record.as_mut_ptr());

            assert_eq!(
                &TD_EVENTS[..TD_EVENT_COUNT],
                &[TD_EV_FREE, TD_DELETE_TAG],
                "no iteration, no dispose — straight to the delete"
            );
            assert_eq!(TD_FREE_COUNT, 1);
            assert_eq!(TD_FREE_PTRS[0], (registry as u32) as *mut u8);
            assert_eq!(record[0], 0);
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), 0);
        }
    }

    // ---- recording mocks for the vtable_file_record_destruct seams ---

    const DT_EV_CONTAINER08: u32 = 0xde08;
    const DT_EV_CONTAINER10: u32 = 0xde10;
    const DT_EV_DISPOSE: u32 = 0xde18;
    const DT_EV_FREE: u32 = 0xdefe;

    static mut DT_EVENTS: [u32; 32] = [0; 32];
    static mut DT_EVENT_COUNT: usize = 0;
    static mut DT_FREE_PTRS: [*mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut DT_FREE_COUNT: usize = 0;

    /// The stand-in kind-1 containers (+0x08 / +0x10), the kind-2 +0x04
    /// block and the kind-2 +0x18 registry.
    static mut DT_CONTAINER08: [u8; 0x18] = [0; 0x18];
    static mut DT_CONTAINER10: [u8; 0x18] = [0; 0x18];
    static mut DT_BLOCK: [u8; 0x14] = [0; 0x14];
    static mut DT_KIND2_REGISTRY: [u8; 0x28] = [0; 0x28];

    /// Sentinel blocks the container-teardown mocks RETURN instead of
    /// their argument — pins that the delete consumes the teardown's
    /// r0 (`bl 0x082aad24` straight after `bl 0x08212a60` /
    /// `bl 0x0821c4ec`), not the raw record field.
    static mut DT_RETURN08: [u8; 8] = [0; 8];
    static mut DT_RETURN10: [u8; 8] = [0; 8];

    unsafe fn dt_push(event: u32) {
        let count = DT_EVENT_COUNT;
        DT_EVENTS[count] = event;
        DT_EVENT_COUNT = count + 1;
    }

    unsafe extern "C" fn recording_dt_container08(container: *mut u8) -> *mut u8 {
        dt_push(DT_EV_CONTAINER08);
        dt_push(container as u32);
        core::ptr::addr_of_mut!(DT_RETURN08).cast()
    }

    unsafe extern "C" fn recording_dt_container10(container: *mut u8) -> *mut u8 {
        dt_push(DT_EV_CONTAINER10);
        dt_push(container as u32);
        core::ptr::addr_of_mut!(DT_RETURN10).cast()
    }

    unsafe extern "C" fn recording_dt_dispose(registry: *mut u8) {
        dt_push(DT_EV_DISPOSE);
        dt_push(registry as u32);
    }

    unsafe extern "C" fn recording_dt_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        dt_push(DT_EV_FREE);
        dt_push(tag as u32);
        let count = DT_FREE_COUNT;
        DT_FREE_PTRS[count] = ptr;
        DT_FREE_COUNT = count + 1;
    }

    /// Resets the recording state, swaps in the recording free and
    /// installs the three recording seam mocks (the
    /// `install_recording_teardown` precedent).
    unsafe fn install_recording_destruct() {
        DT_EVENT_COUNT = 0;
        DT_FREE_COUNT = 0;
        install_stub_heap();
        let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        ops.free = recording_dt_free;
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER08_TEARDOWN)
            .write_volatile(recording_dt_container08);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND1_CONTAINER10_TEARDOWN)
            .write_volatile(recording_dt_container10);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_DESTRUCT_KIND2_DISPOSE)
            .write_volatile(recording_dt_dispose);
    }

    #[test]
    fn file_record_destruct_tag0_is_a_noop_and_returns_the_record() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            record[0] = 0;
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr, "mov r0, r4 — the record returns");
            assert_eq!(DT_EVENT_COUNT, 0, "cmp r0, #0; beq — nothing runs");
            assert_eq!(DT_FREE_COUNT, 0);
            assert_eq!(record[0], 0, "the tag byte is untouched");
            assert_eq!(&record[1..], &[0xa5u8; 0x1f], "the record is untouched");
        }
    }

    #[test]
    fn file_record_destruct_unknown_tag_is_a_noop_and_returns_the_record() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            record[0] = 3;
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr);
            assert_eq!(DT_EVENT_COUNT, 0, "cmp r0, #0x2; bne — nothing runs");
            assert_eq!(DT_FREE_COUNT, 0);
            assert_eq!(record[0], 3, "the unknown tag byte is untouched");
            assert_eq!(&record[1..], &[0xa5u8; 0x1f], "the record is untouched");
        }
    }

    #[test]
    fn file_record_destruct_kind1_null_containers_run_straight_to_the_teardown() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            record[0] = FILE_RECORD_TAG_KIND1;
            record.as_mut_ptr().add(4).cast::<u32>().write(0); // NULL registry
            record.as_mut_ptr().add(8).cast::<u32>().write(0); // NULL +0x08
            record.as_mut_ptr().add(0x10).cast::<u32>().write(0); // NULL +0x10
            record.as_mut_ptr().add(0x18).cast::<u32>().write(0xdead_beef); // unread
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr);
            assert_eq!(
                DT_EVENT_COUNT, 0,
                "both containers NULL: no container teardown, no delete; \
                 the NULL registry makes the teardown's own tail a no-op too"
            );
            assert_eq!(DT_FREE_COUNT, 0);
            // The teardown ran: zeroing the tag and +0x04 is its tail
            // (this function writes nothing back itself).
            assert_eq!(record[0], 0, "vtable_file_record_teardown's strb");
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), 0);
            assert_eq!(record.as_ptr().add(8).cast::<u32>().read(), 0);
            assert_eq!(record.as_ptr().add(0x10).cast::<u32>().read(), 0);
            assert_eq!(
                record.as_ptr().add(0x18).cast::<u32>().read(),
                0xdead_beef,
                "+0x18 is never read on the kind-1 path"
            );
        }
    }

    #[test]
    fn file_record_destruct_kind1_tears_down_and_deletes_both_containers_in_order() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            let container08 = core::ptr::addr_of_mut!(DT_CONTAINER08).cast::<u8>();
            let container10 = core::ptr::addr_of_mut!(DT_CONTAINER10).cast::<u8>();
            let container08_32 = container08 as u32;
            let container10_32 = container10 as u32;
            record[0] = FILE_RECORD_TAG_KIND1;
            record.as_mut_ptr().add(4).cast::<u32>().write(0); // NULL registry
            record.as_mut_ptr().add(8).cast::<u32>().write(container08_32);
            record.as_mut_ptr().add(0x10).cast::<u32>().write(container10_32);
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr);
            let events = &DT_EVENTS[..DT_EVENT_COUNT];
            assert_eq!(
                events,
                &[
                    DT_EV_CONTAINER08,
                    container08_32,
                    DT_EV_FREE,
                    TD_DELETE_TAG,
                    DT_EV_CONTAINER10,
                    container10_32,
                    DT_EV_FREE,
                    TD_DELETE_TAG,
                ],
                "+0x08 first, then +0x10 — each teardown immediately followed \
                 by its operator_delete (0x0811d1d4..0x0811d1f8)"
            );
            assert_eq!(DT_FREE_COUNT, 2);
            assert_eq!(
                DT_FREE_PTRS[0],
                core::ptr::addr_of_mut!(DT_RETURN08).cast::<u8>(),
                "the delete consumes the +0x08 teardown's RETURN, not the field"
            );
            assert_eq!(
                DT_FREE_PTRS[1],
                core::ptr::addr_of_mut!(DT_RETURN10).cast::<u8>(),
                "the delete consumes the +0x10 teardown's RETURN, not the field"
            );
            // The shared teardown ran (its zeroing tail); the container
            // fields themselves are never written back.
            assert_eq!(record[0], 0);
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), 0);
            assert_eq!(record.as_ptr().add(8).cast::<u32>().read(), container08_32);
            assert_eq!(record.as_ptr().add(0x10).cast::<u32>().read(), container10_32);
        }
    }

    #[test]
    fn file_record_destruct_kind2_deletes_the_block_then_disposes_and_deletes_the_registry() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            let block = core::ptr::addr_of_mut!(DT_BLOCK).cast::<u8>();
            let registry = core::ptr::addr_of_mut!(DT_KIND2_REGISTRY).cast::<u8>();
            let block32 = block as u32;
            let registry32 = registry as u32;
            record[0] = FILE_RECORD_TAG_KIND2;
            record.as_mut_ptr().add(4).cast::<u32>().write(block32);
            record.as_mut_ptr().add(0x18).cast::<u32>().write(registry32);
            // +0x08/+0x10 stay at the 0xa5 fill: the kind-2 path never reads them.
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr);
            let events = &DT_EVENTS[..DT_EVENT_COUNT];
            assert_eq!(
                events,
                &[
                    DT_EV_FREE, // operator_delete(+0x04) — NO dispose first
                    TD_DELETE_TAG,
                    DT_EV_DISPOSE,
                    registry32,
                    DT_EV_FREE,
                    TD_DELETE_TAG,
                ],
                "the +0x04 block is deleted bare (blne 0x082aad24); +0x18 is \
                 disposed through 0x0812d300, then deleted (0x0811d1b8..0x0811d1c8)"
            );
            assert_eq!(DT_FREE_COUNT, 2);
            assert_eq!(DT_FREE_PTRS[0], block32 as *mut u8);
            assert_eq!(
                DT_FREE_PTRS[1],
                registry32 as *mut u8,
                "the +0x18 delete frees the guarded word (the \
                 vtable_file_record_teardown convention)"
            );
            // This function writes NOTHING back on the kind-2 path.
            assert_eq!(record[0], FILE_RECORD_TAG_KIND2, "the tag byte stays");
            assert_eq!(record.as_ptr().add(4).cast::<u32>().read(), block32);
            assert_eq!(record.as_ptr().add(0x18).cast::<u32>().read(), registry32);
        }
    }

    #[test]
    fn file_record_destruct_kind2_null_members_is_a_noop() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_destruct();
            record[0] = FILE_RECORD_TAG_KIND2;
            record.as_mut_ptr().add(4).cast::<u32>().write(0); // NULL block
            record.as_mut_ptr().add(0x18).cast::<u32>().write(0); // NULL registry
            let ptr = record.as_mut_ptr();

            let returned = vtable_file_record_destruct(ptr);

            assert_eq!(returned, ptr);
            assert_eq!(
                DT_EVENT_COUNT, 0,
                "blne / beq skip both deletes and the dispose"
            );
            assert_eq!(DT_FREE_COUNT, 0);
            assert_eq!(record[0], FILE_RECORD_TAG_KIND2);
        }
    }

    // ---- vtable_file_record_insert (0x0811d0b8) -----------

    use crate::app::registry::{Registry, RegistryEntry, RegistryVtable};

    const INS_KEY: u32 = 0x1234_5678;
    const INS_INNER_KEY: u32 = 0x9abc_def0;
    const INS_DATA: u32 = 0x0daa_0000;
    const INS_PAYLOAD: u32 = 0x40;

    /// The block the stub allocator hands out for the 8-byte node
    /// (0x10 bytes, so the test can pin the untouched tail).
    static mut INS_NODE_ARENA: [u8; 0x10] = [0xa5; 0x10];
    /// The block it hands out for the miss path's `operator_new(0x28)`.
    static mut INS_REG_ARENA: [u8; 0x28] = [0; 0x28];

    /// The (size, tag) pairs the stub allocator observed, in order.
    static mut INS_ALLOC_LOG: [(usize, usize); 4] = [(0, 0); 4];
    static mut INS_ALLOC_COUNT: usize = 0;

    static mut INS_LOOKUP_CALLS: usize = 0;
    static mut INS_LOOKUP_REGISTRY: *mut u8 = core::ptr::null_mut();
    static mut INS_LOOKUP_KEY: u32 = 0;
    /// The scripted lookup result (NULL = the miss path).
    static mut INS_LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();

    static mut INS_CTOR_CALLS: usize = 0;
    static mut INS_CTOR_THIS: *mut u8 = core::ptr::null_mut();

    static mut INS_GUARD_CALLS: usize = 0;
    static mut INS_GUARD_OBJECT: *mut u8 = core::ptr::null_mut();
    /// The node's first 8 bytes AS THE GUARD SAW THEM — pins the
    /// guard-before-stores ordering (0x0811d0e0 before the `str`s).
    static mut INS_GUARD_NODE_SNAPSHOT: [u8; 8] = [0; 8];

    /// The (registry, key, instance) triples the vtable +0x1c insert
    /// slot observed, in order.
    static mut INS_DISPATCH_LOG: [(usize, u32, usize); 4] = [(0, 0, 0); 4];
    static mut INS_DISPATCH_COUNT: usize = 0;

    /// The recording vtable +0x1c insert slot: captures the container
    /// and the CONTENTS of the stack pair it is handed ({class_id,
    /// instance} — the out-buffer the original builds inside
    /// 0x0810e4ac with `stmia sp, {r1, r2}`).
    unsafe extern "C" fn recording_insert_slot(
        this: *mut Registry,
        entry: *const RegistryEntry,
    ) -> usize {
        let entry = entry.read();
        INS_DISPATCH_LOG[INS_DISPATCH_COUNT] =
            (this as usize, entry.class_id, entry.instance as usize);
        INS_DISPATCH_COUNT += 1;
        0
    }

    unsafe extern "C" fn ins_stub_assign_at(
        _this: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        unreachable!("the insert paths never dispatch +0x24 assign_at");
    }

    unsafe extern "C" fn ins_stub_entry_at(
        _this: *mut Registry,
        _index: i32,
        _out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        unreachable!("the insert paths never dispatch +0x3c entry_at");
    }

    unsafe extern "C" fn ins_stub_index_of(_this: *mut Registry, _key: *const u32) -> i32 {
        unreachable!("the insert paths never dispatch +0x4c index_of");
    }

    unsafe extern "C" fn ins_stub_notify(_this: *mut Registry) -> *mut u8 {
        unreachable!("the insert paths never dispatch the notification slots");
    }

    /// The fake registry vtable both stand-in registries share: only
    /// the +0x1c insert slot is live (the recording mock); every other
    /// slot traps.
    static INS_RECORDING_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: recording_insert_slot,
        unresolved_20: 0,
        assign_at: ins_stub_assign_at,
        unresolved_28: [0; 5],
        entry_at: ins_stub_entry_at,
        unresolved_40: [0; 3],
        index_of: ins_stub_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: ins_stub_notify,
        notify_deferred: ins_stub_notify,
        notify_changed: ins_stub_notify,
    };

    /// The stand-in OUTER registry (what record.+0x04 points at) and
    /// the stand-in BUCKET registry (what the lookup / ctor hands back).
    static mut INS_OUTER_REGISTRY: Registry = Registry {
        vtable: core::ptr::null(),
        container: [0; 7],
        changed: 0,
        notify_enabled: 0,
        reserved: [0; 2],
        observer: core::ptr::null_mut(),
    };
    static mut INS_BUCKET_REGISTRY: Registry = Registry {
        vtable: core::ptr::null(),
        container: [0; 7],
        changed: 0,
        notify_enabled: 0,
        reserved: [0; 2],
        observer: core::ptr::null_mut(),
    };

    unsafe extern "C" fn stub_insert_alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        INS_ALLOC_LOG[INS_ALLOC_COUNT] = (size, _tag);
        INS_ALLOC_COUNT += 1;
        if size == FILE_RECORD_NODE_SIZE {
            core::ptr::addr_of_mut!(INS_NODE_ARENA).cast()
        } else {
            assert_eq!(size, REGISTRY_OBJECT_SIZE, "only the node and the bucket allocate");
            core::ptr::addr_of_mut!(INS_REG_ARENA).cast()
        }
    }

    /// Swaps the recording allocator in and pre-seeds DEFAULT_HEAP (the
    /// install_stub_heap precedent).
    unsafe fn install_insert_heap() {
        let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        ops.alloc = stub_insert_alloc;
        ops.create = stub_open_create;
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
        core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
            .write_volatile(0x2222_0000 as *mut crate::heap::types::HeapDescriptorDescriptor);
        INS_ALLOC_COUNT = 0;
        INS_ALLOC_LOG = [(0, 0); 4];
        INS_NODE_ARENA = [0xa5; 0x10];
    }

    unsafe extern "C" fn recording_insert_lookup(registry: *mut u8, key: u32) -> *mut u8 {
        INS_LOOKUP_CALLS += 1;
        INS_LOOKUP_REGISTRY = registry;
        INS_LOOKUP_KEY = key;
        INS_LOOKUP_RESULT
    }

    unsafe extern "C" fn recording_insert_ctor(allocation: *mut u8) -> *mut u8 {
        INS_CTOR_CALLS += 1;
        INS_CTOR_THIS = allocation;
        core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY).cast()
    }

    unsafe extern "C" fn recording_insert_guard(object: *mut u8) {
        INS_GUARD_CALLS += 1;
        INS_GUARD_OBJECT = object;
        core::ptr::copy_nonoverlapping(object, INS_GUARD_NODE_SNAPSHOT.as_mut_ptr(), 8);
    }

    /// Resets the recorders, installs the lookup/ctor/guard recording
    /// mocks and the recording heap, and points both stand-in
    /// registries at the recording vtable (the install_recording_kind1
    /// precedent). `lookup_result` scripts the hit (a bucket) or the
    /// miss (NULL).
    unsafe fn install_recording_insert(lookup_result: *mut u8) {
        INS_LOOKUP_CALLS = 0;
        INS_LOOKUP_REGISTRY = core::ptr::null_mut();
        INS_LOOKUP_KEY = 0;
        INS_LOOKUP_RESULT = lookup_result;
        INS_CTOR_CALLS = 0;
        INS_CTOR_THIS = core::ptr::null_mut();
        INS_GUARD_CALLS = 0;
        INS_GUARD_OBJECT = core::ptr::null_mut();
        INS_GUARD_NODE_SNAPSHOT = [0; 8];
        INS_DISPATCH_COUNT = 0;
        INS_DISPATCH_LOG = [(0, 0, 0); 4];
        install_insert_heap();
        INS_OUTER_REGISTRY.vtable = &INS_RECORDING_VTABLE;
        INS_BUCKET_REGISTRY.vtable = &INS_RECORDING_VTABLE;
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_INSERT_LOOKUP)
            .write_volatile(recording_insert_lookup);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_CTOR)
            .write_volatile(recording_insert_ctor);
        core::ptr::addr_of_mut!(VTABLE_FILE_RECORD_KIND1_GUARD)
            .write_volatile(recording_insert_guard);
    }

    /// Builds a record whose +0x04 registry field points at the stand-in
    /// outer registry (pointer-sized — the port's host-representation
    /// deviation).
    unsafe fn insert_record(record: &mut [u8; 0x20]) -> *mut u8 {
        record
            .as_mut_ptr()
            .add(4)
            .cast::<*mut u8>()
            .write(core::ptr::addr_of_mut!(INS_OUTER_REGISTRY).cast());
        record.as_mut_ptr()
    }

    #[test]
    fn file_record_insert_hit_path_reuses_the_existing_bucket() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            let bucket = core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY).cast::<u8>();
            install_recording_insert(bucket);
            let record = insert_record(&mut record);

            vtable_file_record_insert(record, INS_KEY, INS_INNER_KEY, INS_DATA, INS_PAYLOAD);

            assert_eq!(INS_LOOKUP_CALLS, 1, "one bucket lookup");
            assert_eq!(
                INS_LOOKUP_REGISTRY,
                core::ptr::addr_of_mut!(INS_OUTER_REGISTRY).cast::<u8>(),
                "the lookup gets record.+0x04"
            );
            assert_eq!(INS_LOOKUP_KEY, INS_KEY, "keyed by arg2");
            assert_eq!(INS_ALLOC_COUNT, 1, "a hit allocates ONLY the node");
            assert_eq!(
                INS_ALLOC_LOG[0],
                (FILE_RECORD_NODE_SIZE, FILE_RECORD_NODE_ALLOC_TAG),
                "malloc_wrapper(8, 0x19)"
            );
            assert_eq!(INS_CTOR_CALLS, 0, "no operator_new(0x28), no construct");
            assert_eq!(INS_DISPATCH_COUNT, 1, "no outer keyed insert on a hit");
            assert_eq!(
                INS_DISPATCH_LOG[0],
                (
                    bucket as usize,
                    INS_INNER_KEY,
                    core::ptr::addr_of_mut!(INS_NODE_ARENA) as usize
                ),
                "the node goes into the looked-up bucket keyed by arg3"
            );
        }
    }

    #[test]
    fn file_record_insert_miss_path_allocates_constructs_and_keyed_inserts_the_bucket() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_insert(core::ptr::null_mut()); // the miss
            let record = insert_record(&mut record);

            vtable_file_record_insert(record, INS_KEY, INS_INNER_KEY, INS_DATA, INS_PAYLOAD);

            assert_eq!(INS_LOOKUP_CALLS, 1);
            assert_eq!(INS_ALLOC_COUNT, 2, "the node, then the 0x28 bucket");
            assert_eq!(
                INS_ALLOC_LOG[0],
                (FILE_RECORD_NODE_SIZE, FILE_RECORD_NODE_ALLOC_TAG),
                "malloc_wrapper(8, 0x19)"
            );
            assert_eq!(
                INS_ALLOC_LOG[1],
                (REGISTRY_OBJECT_SIZE, 2),
                "operator_new(0x28) — the tag-2 veneer"
            );
            assert_eq!(INS_CTOR_CALLS, 1, "class_registry_construct runs once");
            assert_eq!(
                INS_CTOR_THIS,
                core::ptr::addr_of_mut!(INS_REG_ARENA).cast::<u8>(),
                "the fresh block feeds the construct in r0"
            );
            let outer = core::ptr::addr_of_mut!(INS_OUTER_REGISTRY) as usize;
            let bucket = core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY) as usize;
            let node = core::ptr::addr_of_mut!(INS_NODE_ARENA) as usize;
            assert_eq!(INS_DISPATCH_COUNT, 2, "outer bucket insert, then the node insert");
            assert_eq!(
                INS_DISPATCH_LOG[0],
                (outer, INS_KEY, bucket),
                "registry_insert(registry, arg2, bucket) — the new bucket is \
                 keyed into the outer registry first"
            );
            assert_eq!(
                INS_DISPATCH_LOG[1],
                (bucket, INS_INNER_KEY, node),
                "registry_insert(bucket, arg3, node) — the tail"
            );
        }
    }

    #[test]
    fn file_record_insert_stores_arg4_and_arg5_into_the_node() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            let bucket = core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY).cast::<u8>();
            install_recording_insert(bucket);
            let record = insert_record(&mut record);

            vtable_file_record_insert(record, INS_KEY, INS_INNER_KEY, INS_DATA, INS_PAYLOAD);

            let node = core::ptr::addr_of_mut!(INS_NODE_ARENA).cast::<u8>();
            assert_eq!(
                node.cast::<u32>().read(),
                INS_PAYLOAD,
                "str r9, [r4, #0x0] — arg5 at node +0x00"
            );
            assert_eq!(
                node.cast::<u32>().add(1).read(),
                INS_DATA,
                "str r6, [r4, #0x4] — arg4 at node +0x04"
            );
            assert_eq!(
                &INS_NODE_ARENA[8..],
                &[0xa5; 8],
                "bytes past the 8-byte node are untouched"
            );
        }
    }

    #[test]
    fn file_record_insert_dispatches_vtable_slot_1c_with_the_stack_pair() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            install_recording_insert(core::ptr::null_mut()); // the miss: TWO dispatches
            let record = insert_record(&mut record);

            vtable_file_record_insert(record, INS_KEY, INS_INNER_KEY, INS_DATA, INS_PAYLOAD);

            // The recording slot captures the CONTENTS of the {key,
            // value} pair 0x0810e4ac builds on its stack (`stmia sp,
            // {r1, r2}`) and hands to vtable[+0x1c]: first the outer
            // {arg2, bucket}, then the bucket's {arg3, node}.
            assert_eq!(INS_DISPATCH_COUNT, 2);
            let outer = core::ptr::addr_of_mut!(INS_OUTER_REGISTRY) as usize;
            let bucket = core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY) as usize;
            let node = core::ptr::addr_of_mut!(INS_NODE_ARENA) as usize;
            assert_eq!(INS_DISPATCH_LOG[0].0, outer, "the outer registry's vtable");
            assert_eq!(
                (INS_DISPATCH_LOG[0].1, INS_DISPATCH_LOG[0].2),
                (INS_KEY, bucket),
                "the stack pair is {{arg2, new bucket}}"
            );
            assert_eq!(INS_DISPATCH_LOG[1].0, bucket, "the bucket registry's vtable");
            assert_eq!(
                (INS_DISPATCH_LOG[1].1, INS_DISPATCH_LOG[1].2),
                (INS_INNER_KEY, node),
                "the stack pair is {{arg3, node}}"
            );
        }
    }

    #[test]
    fn file_record_insert_runs_the_checked_alloc_guard_on_the_node() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let _heap = HeapGuard;
        let mut record = [0xa5u8; 0x20];
        unsafe {
            let bucket = core::ptr::addr_of_mut!(INS_BUCKET_REGISTRY).cast::<u8>();
            install_recording_insert(bucket);
            let record = insert_record(&mut record);

            vtable_file_record_insert(record, INS_KEY, INS_INNER_KEY, INS_DATA, INS_PAYLOAD);

            assert_eq!(INS_GUARD_CALLS, 1, "the 0x080edb74 guard runs once");
            assert_eq!(
                INS_GUARD_OBJECT,
                core::ptr::addr_of_mut!(INS_NODE_ARENA).cast::<u8>(),
                "the guard checks the fresh node (r0 out of malloc_wrapper)"
            );
            assert_eq!(
                INS_GUARD_NODE_SNAPSHOT, [0xa5; 8],
                "the guard runs BEFORE the node field stores (bl at 0x0811d0e0 \
                 precedes the strs at 0x0811d0e4/0x0811d0e8)"
            );
        }
    }

    // ---- vtable_file_record_lookup (0x0812d160, the
    // VTABLE_FILE_RECORD_INSERT_LOOKUP default) ----

    static mut INS_SCRIPTED_INDEX_OF_RESULT: i32 = -1;
    static mut INS_SCRIPTED_INDEX_OF_KEY: u32 = 0;
    static mut INS_SCRIPTED_INDEX_OF_THIS: *mut Registry = core::ptr::null_mut();
    static mut INS_SCRIPTED_INSTANCE: *mut u8 = core::ptr::null_mut();
    static mut INS_SCRIPTED_ENTRY_AT_CALLS: usize = 0;

    unsafe extern "C" fn scripted_index_of(this: *mut Registry, key: *const u32) -> i32 {
        INS_SCRIPTED_INDEX_OF_THIS = this;
        INS_SCRIPTED_INDEX_OF_KEY = key.read();
        INS_SCRIPTED_INDEX_OF_RESULT
    }

    unsafe extern "C" fn scripted_entry_at(
        _this: *mut Registry,
        _index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        INS_SCRIPTED_ENTRY_AT_CALLS += 1;
        out.write(RegistryEntry {
            class_id: INS_SCRIPTED_INDEX_OF_KEY,
            instance: INS_SCRIPTED_INSTANCE,
        });
        out
    }

    /// The scripted vtable for the lookup tests: +0x4c index_of and
    /// +0x3c entry_at answer, +0x1c insert traps (the lookup never
    /// inserts).
    static INS_SCRIPTED_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: recording_insert_slot,
        unresolved_20: 0,
        assign_at: ins_stub_assign_at,
        unresolved_28: [0; 5],
        entry_at: scripted_entry_at,
        unresolved_40: [0; 3],
        index_of: scripted_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: ins_stub_notify,
        notify_deferred: ins_stub_notify,
        notify_changed: ins_stub_notify,
    };

    static mut INS_LOOKUP_FAKE: Registry = Registry {
        vtable: core::ptr::null(),
        container: [0; 7],
        changed: 0,
        notify_enabled: 0,
        reserved: [0; 2],
        observer: core::ptr::null_mut(),
    };

    #[test]
    fn file_record_lookup_hit_returns_the_slot_value() {
        unsafe {
            let registry = core::ptr::addr_of_mut!(INS_LOOKUP_FAKE);
            (*registry).vtable = &INS_SCRIPTED_VTABLE;

            // Hit: index_of answers, entry_at fills the pair, and the
            // pair's VALUE word returns — the original's
            // `ldrne r0, [sp, #0x0]`: a nonzero search status means
            // the out-slot was written and becomes r0.
            INS_SCRIPTED_INDEX_OF_RESULT = 3;
            INS_SCRIPTED_INSTANCE = 0x5500_0000 as *mut u8;
            INS_SCRIPTED_ENTRY_AT_CALLS = 0;
            let hit = vtable_file_record_lookup(registry.cast(), 0x777);
            assert_eq!(hit, INS_SCRIPTED_INSTANCE);
            assert_eq!(INS_SCRIPTED_ENTRY_AT_CALLS, 1);
        }
    }

    #[test]
    fn file_record_lookup_miss_returns_null() {
        unsafe {
            let registry = core::ptr::addr_of_mut!(INS_LOOKUP_FAKE);
            (*registry).vtable = &INS_SCRIPTED_VTABLE;

            // Miss: index_of answers -1, entry_at never runs (the
            // out-slot is never written — per the asm the slot would
            // still hold the r3 spill, but the miss path never loads
            // it), and r0 stays 0: NULL returns.
            INS_SCRIPTED_INDEX_OF_RESULT = -1;
            INS_SCRIPTED_ENTRY_AT_CALLS = 0;
            let miss = vtable_file_record_lookup(registry.cast(), 0x888);
            assert!(miss.is_null());
            assert_eq!(INS_SCRIPTED_ENTRY_AT_CALLS, 0);
        }
    }

    #[test]
    fn file_record_lookup_routes_registry_and_key_verbatim_to_the_search() {
        unsafe {
            let registry = core::ptr::addr_of_mut!(INS_LOOKUP_FAKE);
            (*registry).vtable = &INS_SCRIPTED_VTABLE;

            // Argument routing: the registry reaches the search's
            // vtable dispatch as `this` verbatim and the key reaches
            // index_of untouched — the original's r0/r1 pass straight
            // through (r2 is dead, overwritten with the out-slot
            // pointer).
            INS_SCRIPTED_INDEX_OF_RESULT = -1;
            INS_SCRIPTED_INDEX_OF_THIS = core::ptr::null_mut();
            let _ = vtable_file_record_lookup(registry.cast(), 0xdead_beef);
            assert_eq!(
                INS_SCRIPTED_INDEX_OF_THIS,
                registry,
                "the registry pointer reaches the search verbatim"
            );
            assert_eq!(INS_SCRIPTED_INDEX_OF_KEY, 0xdead_beef);
        }
    }
}

