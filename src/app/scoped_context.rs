//! The framework's **scoped context token** — a 0x18-byte polymorphic
//! object that call sites build on the stack, hand to a service, and
//! throw away. Three of its members are ported here, all from the
//! 0x0826/0x0827 framework cluster that also holds the string/buffer class
//! (`cxx/string_object.rs`) and the resource-lookup chain
//! (`app/resource_chain.rs`):
//!
//! - [`capture_context_fields`] — `FUN_0826fda0` @ 0x0826fda0.
//! - [`scoped_context_construct`] — `FUN_08270394` @ 0x08270394.
//! - [`scoped_context_destroy`] — `FUN_08270414` @ 0x08270414.
//! - [`scoped_context_owner_flags_any_8062`] — `FUN_082a40c8` @ 0x082a40c8,
//!   a validity-gated predicate over the token owner's flags word.
//! - [`scoped_context_owner_u64_110`] — `FUN_082a368c` @ 0x082a368c, a
//!   validity-gated getter returning the token owner's 64-bit word pair at
//!   +0x110/+0x114.
//! ## What the class is
//!
//! Every constructor in the family plants the same vtable literal,
//! 0x089a5b30, and lays out the same six fields:
//!
//! ```text
//! +0x00  vtable          @ always 0x089a5b30
//! +0x04  owner_valid     @ word; only its low byte is ever read
//! +0x08  owner           @ the object the token speaks for
//! +0x0c  service_context @ derived from the system root, see below
//! +0x10  registry_token  @ derived from the service context
//! +0x14  mode            @ byte
//! ```
//!
//! The family (all binary-scanned over the whole decrypted image):
//!
//! | address | `bl` | what it is |
//! |---|---|---|
//! | 0x08270394 | **109** + 2 `b` | ctor `(this, owner, mode)` — **ported here** |
//! | 0x08270414 | **175** | trivial destructor — **ported here** |
//! | 0x08270418 | 15 | field copy: `dst[+4..+0x14] = src[+4..+0x14]`, vtable untouched |
//! | 0x082703d0 | 7 | ctor that adopts another token's owner through 0x0826fd24 |
//! | 0x08270320 | 2 | a third ctor variant |
//!
//! `0x08270414` really is this class's destructor and not a generic
//! shared no-op: of its 175 call sites, 166 sit within 0x300 bytes of a
//! call to one of the constructors above, or to a function that itself
//! calls one (0x0813b898 is the archetype — it runs 0x08270394 on
//! `this`, then copies a second token in with 0x08270418, and its
//! caller at 0x080feca8 destroys the result through 0x08270414).
//!
//! ## Where the derived fields come from
//!
//! [`capture_context_fields`] computes the two derived words. The
//! constructor calls it after initializing the token:
//!
//! ```text
//! 0826fda0  cmp   r1, #0
//! 0826fda4  str   r1, [r0, #8]          @ owner (again — the ctor already wrote it)
//! 0826fda8  streq r1, [r0, #0xc]
//! 0826fdac  beq   0x826fdcc             @ no owner -> both derived words NULL
//! 0826fdb0  ldr   r1, [pc, #28]         @ &SYSTEM_ROOT (literal 0x089ca674)
//! 0826fdb4  ldr   r1, [r1]
//! 0826fdb8  ldr   r1, [r1, #0x30]       @ service context
//! 0826fdbc  str   r1, [r0, #0xc]
//! 0826fdc0  ldr   r1, [r1, #0xf60]      @ its registry
//! 0826fdc4  cmp   r1, #0
//! 0826fdc8  ldrne r1, [r1, #0x18]
//! 0826fdcc  str   r1, [r0, #0x10]
//! 0826fdd0  bx    lr
//! ```
//!
//! 0x089ca674 is a runtime-initialized RW word with 120 literal-pool
//! references across the image — the framework's system root. The
//! object at root+0x30 is what the "service context" name comes from:
//! its +0xf60 word is the registry that 0x0805e36c interrogates by
//! FourCC (`0x66696c65` = `"file"` at the call site 0x0803bf48, which is
//! also one of this constructor's callers), and +0x18 of that registry
//! is the word cached in the token.
//!
//! The class's own name does not survive in the image: none of the
//! constructors hands a literal to the class-name factory, and the
//! fifteen vtable slots at 0x089a5b30..0x089a5b68 all point into
//! undecoded code. So the port names the class for what it holds rather
//! than inventing a `TC...` name, the `cxx/string_object.rs` precedent.
//!
//! ## Deviations
//!
//! - The object and its vtable are `#[repr(C)]` structs with real Rust
//!   pointers (the `app/resource_chain.rs` precedent), so the field
//!   offsets are the original's on the 32-bit target and stay
//!   self-consistent on the 64-bit host. No literal byte offset appears
//!   in the code.
//! - The vtable is the modeled static [`SCOPED_CONTEXT_VTABLE`], which
//!   carries the fifteen ROM words verbatim; the original's literal
//!   address is [`SCOPED_CONTEXT_VTABLE_ADDRESS`]. Pointer identity with
//!   the ROM table is not preserved, exactly as in `cxx/string_object.rs`.
//! - [`capture_context_fields`] is ported below. The public
//!   [`CAPTURE_CONTEXT_FIELDS`] volatile dispatch slot remains so callers
//!   retain their existing ABI and host tests can replace the callee in
//!   isolation; its default is the real port. The port reads the system
//!   root through [`crate::app::context_scope::APP_ROOT_OBJECT`], the
//!   crate's single static for the RW word @ 0x089ca674
//!   (`app/singletons.rs` deviation: those pages are runtime-initialized
//!   and the image holds stale bytes there). `app/context_scope.rs` walks
//!   the same root for its own capture, so the two share one definition
//!   rather than each modeling the word separately. With a NULL root and
//!   a non-NULL owner the port faults exactly where the original would;
//!   the guard is not added.
//! - [`scoped_context_destroy`] compiles to the same three-instruction
//!   frame as `runtime::cxa_guard::cxa_guard_release`, so the linker
//!   folds the two: `scoped_context_destroy` is emitted as a second
//!   global on `.text.cxa_guard_release`. Behaviorally that is exactly
//!   right — both functions are empty — but it means `objdump -d` prints
//!   only the first label, and `match.py 0x08270414 scoped_context_destroy`
//!   reports the symbol as missing. Diff it through the folded section
//!   (`match.py 0x08270414 cxa_guard_release --size 4`); the emitted code
//!   is `push {fp, lr}; mov fp, sp; pop {fp, pc}`, the crate frame around
//!   the original's bare `bx lr`, identical to `ui/noop_f7f4.rs`.
//! - The destructor's recovered C signature is `void (void)` — the body
//!   is a bare `bx lr` and consumes nothing. The port takes `this`
//!   anyway, because every one of the 175 call sites passes the token in
//!   r0 and the argument documents the calling convention; an unused
//!   AAPCS argument is ABI-identical.

use crate::app::context_scope::app_root_object;
use core::ptr;

/// The original's vtable literal, held in the ctor's own literal-pool
/// word @ 0x082703cc (binary-verified against osos.dec; the sibling
/// ctors' words @ 0x0827038c, 0x082703d0's @ 0x08270410 and 0x08270320's
/// hold the same value).
pub const SCOPED_CONTEXT_VTABLE_ADDRESS: usize = 0x089a_5b30;

/// The class vtable, modeled down to the fifteen words the image
/// serializes at 0x089a5b30..0x089a5b68 (the sixteenth is zero). All
/// fifteen point into undecoded code. Slot +0x08 is the token's
/// validity query: `FUN_0826fd38` calls it as `this->slot8(this)`, and
/// the whole 0x082a4 predicate family (0x082a3fc4, 0x082a40c8 — ported
/// below as [`scoped_context_owner_flags_any_8062`] — 0x082a4574,
/// 0x082a45a4, plus the string getters 0x082a4104/0x082a4188/0x082a420c)
/// gates on it the same way. Anomaly: the slot's serialized word,
/// 0x0820ca2c, lands 0x40 bytes INTO `FUN_0820c9ec` (a 96-byte retry
/// loop @ 0x0820c9ec..0x0820ca4b, Ghidra's own boundary), where the
/// first instruction is a flags-dependent `ble` — not a callable entry.
/// The base-class default is therefore effectively undispatchable and
/// live tokens must carry an overriding derived vtable planted by the
/// filling call (e.g. the callers' vtable+0x170/vtable+0x22c methods).
/// Recorded, not invented.
#[repr(C)]
pub struct ScopedContextVtable {
    /// The fifteen code pointers at 0x089a5b30..0x089a5b68.
    pub slots: [usize; 15],
}

/// The ROM vtable's contents (original @ [`SCOPED_CONTEXT_VTABLE_ADDRESS`]).
pub static SCOPED_CONTEXT_VTABLE: ScopedContextVtable = ScopedContextVtable {
    slots: [
        0x0812_9dec,
        0x0812_9b40,
        0x0820_ca2c,
        0x0812_9d28,
        0x0812_9c20,
        0x083a_0a7c,
        0x0820_bf28,
        0x0820_c2dc,
        0x0820_b88c,
        0x0820_b834,
        0x0820_c468,
        0x0820_c308,
        0x0820_c5ec,
        0x0820_ca98,
        0x083a_0aa0,
    ],
};

/// The stack token itself — 0x18 bytes on the 32-bit target.
#[repr(C)]
pub struct ScopedContext {
    /// +0x00 — the class vtable (original literal 0x089a5b30).
    pub vtable: *const ScopedContextVtable,
    /// +0x04 — cleared by every constructor. Only its low byte is read,
    /// and only by `FUN_0826fd24`, which uses it to decide whether a
    /// *source* token's owner may be adopted.
    pub owner_valid: u32,
    /// +0x08 — the object this token speaks for; NULL is the common case.
    pub owner: *mut u8,
    /// +0x0c — the system root's service context, or NULL when there is
    /// no owner.
    pub service_context: *mut u8,
    /// +0x10 — the service registry's cached word, or NULL.
    pub registry_token: *mut u8,
    /// +0x14 — the caller's mode byte, written last.
    pub mode: u8,
}

/// Pointer-slot index of the service context inside the system root
/// (the original's `ldr r1, [r1, #0x30]`). Expressed as an index rather
/// than a byte offset so it addresses the same slot on the target, where
/// a pointer is 4 bytes, and on the host, where it is 8.
const ROOT_SERVICE_CONTEXT_SLOT: usize = 0x30 / 4;

/// Pointer-slot index of the registry inside the service context
/// (`ldr r1, [r1, #0xf60]`).
const SERVICE_CONTEXT_REGISTRY_SLOT: usize = 0xf60 / 4;

/// Pointer-slot index of the cached word inside the registry
/// (`ldrne r1, [r1, #0x18]`).
const REGISTRY_TOKEN_SLOT: usize = 0x18 / 4;

// Test-only evidence that the owner-null branch reaches neither the
// root-slot accessor nor the unguarded root walk.
#[cfg(test)]
static mut CAPTURE_ROOT_READS: u32 = 0;

/// capture_context_fields — original: `FUN_0826fda0` @ 0x0826fda0
/// (52 bytes of code; the 4-byte system-root literal follows at
/// 0x0826fdd4; **2 `bl` call sites**).
///
/// Unconditionally records `owner` at token +0x08. A NULL owner clears
/// token +0x0c and +0x10 without reading the system-root global. Otherwise
/// it loads the root's +0x30 service context into +0x0c, then caches that
/// context's registry +0xf60 word's +0x18 field at +0x10, or NULL when the
/// registry is NULL. As in ARM, a non-NULL owner requires a valid root and
/// service context; neither is null-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn capture_context_fields(token: *mut ScopedContext, owner: *mut u8) {
    (*token).owner = owner;
    if owner.is_null() {
        (*token).service_context = ptr::null_mut();
        (*token).registry_token = ptr::null_mut();
        return;
    }

    #[cfg(test)]
    unsafe {
        CAPTURE_ROOT_READS += 1;
    }
    let root = app_root_object();
    let service_context = (root as *const *mut u8).add(ROOT_SERVICE_CONTEXT_SLOT).read();
    (*token).service_context = service_context;

    let registry = (service_context as *const *mut u8)
        .add(SERVICE_CONTEXT_REGISTRY_SLOT)
        .read();
    (*token).registry_token = if registry.is_null() {
        ptr::null_mut()
    } else {
        (registry as *const *mut u8).add(REGISTRY_TOKEN_SLOT).read()
    };
}

/// Indirect dispatch for [`capture_context_fields`]. The default is the
/// ported callee; the slot stays replaceable for constructor-test isolation.
pub static mut CAPTURE_CONTEXT_FIELDS: unsafe extern "C" fn(*mut ScopedContext, *mut u8) =
    capture_context_fields;

/// scoped_context_construct — original: `FUN_08270394` @ 0x08270394
/// (60 bytes: 56 code + the 4-byte vtable literal @ 0x082703cc, which
/// Ghidra's 56-byte extent drops; **109 `bl` + 2 `b` call sites**,
/// binary-scanned over the whole decrypted image).
///
/// ```text
/// 08270394  mov   r3, r0
/// 08270398  ldr   r0, [0x082703cc]   @ 0x089a5b30, the class vtable
/// 0827039c  push  {lr}
/// 082703a0  str   r0, [r3]
/// 082703a4  mov   r0, #0
/// 082703a8  stmib r3, {r0, r1}       @ +0x04 = 0, +0x08 = owner
/// 082703ac  str   r0, [r3, #0xc]
/// 082703b0  str   r0, [r3, #0x10]
/// 082703b4  strb  r0, [r3, #0x14]
/// 082703b8  mov   r0, r3
/// 082703bc  bl    0x0826fda0         @ r1 is still the owner
/// 082703c0  mov   r0, r3
/// 082703c4  strb  r2, [r3, #0x14]
/// 082703c8  pop   {pc}
/// ```
///
/// Two orderings are load-bearing and are reproduced: the mode byte is
/// zeroed *before* the capture callee runs and written *after* it, so a
/// callee that reads +0x14 sees zero; and the owner is stored twice,
/// once by the `stmib` and once by the callee, which matters only if the
/// two ever disagree. Returns `this`, which is what the two tail-`b`
/// call sites (0x08159a6c, 0x0816ef78) forward to their own callers.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scoped_context_construct(
    this: *mut ScopedContext,
    owner: *mut u8,
    mode: u8,
) -> *mut ScopedContext {
    (*this).vtable = &SCOPED_CONTEXT_VTABLE;
    (*this).owner_valid = 0;
    (*this).owner = owner;
    (*this).service_context = ptr::null_mut();
    (*this).registry_token = ptr::null_mut();
    (*this).mode = 0;

    // Volatile slot read — the util/inner_state.rs rationale: the slot
    // exists to be swapped at runtime, so the default must not be
    // constant-folded in.
    ptr::read_volatile(ptr::addr_of!(CAPTURE_CONTEXT_FIELDS))(this, owner);

    (*this).mode = mode;
    this
}

/// scoped_context_destroy — original: `FUN_08270414` @ 0x08270414
/// (4 bytes; **175 `bl` call sites**, binary-scanned — no `b` sites).
///
/// The whole body is `bx lr`. The class owns nothing: its two derived
/// words are borrowed views onto the system root, and its owner is not
/// retained, so destruction has nothing to release. The token is left
/// exactly as the constructor wrote it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn scoped_context_destroy(_this: *mut ScopedContext) {}

/// Vtable-slot index of the token validity query (the original's
/// `ldr r1, [r0, #8]`): word 2 of the class vtable.
const VALIDITY_SLOT: usize = 0x08 / 4;

/// Word index of the owner flags word (the original's
/// `ldr r0, [r0, #0xbc]`). Word-indexed so the aligned read addresses
/// the same slot on target and host, the ROOT_SERVICE_CONTEXT_SLOT
/// pattern above.
const OWNER_FLAGS_SLOT: usize = 0xbc / 4;

/// The mask tested against the owner's +0xbc flags word, serialized as
/// the original's only literal-pool word @ 0x082a4100: bits 1, 5, 6 and
/// 15. What the four bits mean does not survive in the image, so the
/// mask keeps its numeric name.
const OWNER_FLAGS_MASK_8062: u32 = 0x8062;

/// ABI of the token vtable's slot-+0x08 validity method.
type ScopedContextValidity = unsafe extern "C" fn(*const ScopedContext) -> u32;

/// scoped_context_owner_flags_any_8062 — original: `FUN_082a40c8` @
/// 0x082a40c8 (60 bytes: 56 code + the 4-byte mask literal @ 0x082a4100
/// that Ghidra's 56-byte extent drops; **42 `bl` call sites**,
/// binary-scanned by decoding every B/BL word in osos.dec — every one an
/// unconditional `bl`, no predicated forms, so no caller NULL-guards the
/// token).
///
/// ```text
/// 082a40c8  push  {r4, lr}
/// 082a40cc  mov   r4, r0
/// 082a40d0  ldr   r0, [r0]         @ token vtable
/// 082a40d4  ldr   r1, [r0, #8]     @ slot +0x08 validity method
/// 082a40d8  mov   r0, r4
/// 082a40dc  blx   r1
/// 082a40e0  cmp   r0, #0
/// 082a40e4  ldrne r0, [r4, #8]     @ owner
/// 082a40e8  ldrne r1, [pc, #16]    @ 0x082a4100 -> 0x00008062
/// 082a40ec  ldrne r0, [r0, #0xbc]  @ owner flags word
/// 082a40f0  tstne r0, r1
/// 082a40f4  moveq r0, #0
/// 082a40f8  movne r0, #1
/// 082a40fc  pop   {r4, pc}
/// ```
///
/// Validity-gated owner-flags predicate over the scoped-context token.
/// It dispatches the token's vtable slot +0x08 (the same virtual
/// `FUN_0826fd38` gates on) and, only when that returns nonzero, reads
/// the owner's flags word at +0xbc and returns 1 when any of the 0x8062
/// bits is set, else 0. When the slot returns 0 the owner is never
/// dereferenced, so a NULL-owner token answers 0 instead of faulting.
/// One of a family of same-shaped predicates over the same owner word —
/// 0x082a3fc4 tests bit 3, 0x082a45a4 tests bit 21, 0x082a4574 tests
/// owner byte +0x8f bit 0 — which callers AND together to decide what
/// an owner supports: the context-menu builder 0x08222eec suppresses an
/// item only when all four answer 0, and the media-player event
/// dispatcher 0x0817c468 compares the predicate across two track
/// tokens. Of the 42 call sites, 39 build their token with
/// scoped_context_construct within the same function (binary-scanned
/// correlation); the rest receive it from their own caller.
///
/// Deviations: the token and its vtable are this module's `#[repr(C)]`
/// models, so the vtable load and slot index are struct field accesses
/// rather than literal byte offsets (the module's standing deviation);
/// the slot word is transmuted to the call ABI at the dispatch point,
/// the ui/element_reference.rs idiom. The owner flags read is an
/// aligned word read — the owner is a 4-aligned framework object and
/// +0xbc is word-aligned. LLVM narrows that read to an `ldrh` because
/// the mask fits in 16 bits and the upper half cannot feed the
/// boolean result; behaviorally identical on plain RAM, noted for the
/// match.py reviewer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_owner_flags_any_8062(
    this: *const ScopedContext,
) -> u32 {
    let validity: ScopedContextValidity =
        core::mem::transmute((*(*this).vtable).slots[VALIDITY_SLOT]);
    if validity(this) == 0 {
        return 0;
    }
    let flags = ((*this).owner as *const u32).add(OWNER_FLAGS_SLOT).read();
    (flags & OWNER_FLAGS_MASK_8062 != 0) as u32
}

/// Word index of the owner's 64-bit pair's low word (the original's
/// `ldrne r0, [r1, #0x110]`); the high word follows at the next index
/// (`ldrne r1, [r1, #0x114]`). Word-indexed so the aligned reads address
/// the same slots on target and host, the OWNER_FLAGS_SLOT pattern above.
const OWNER_U64_110_SLOT: usize = 0x110 / 4;

/// scoped_context_owner_u64_110 — original: `FUN_082a368c` @ 0x082a368c
/// (52 bytes, exact: the next function starts at 0x082a36c0, so there is
/// no trailing literal pool for Ghidra's extent to drop; **33 `bl` call
/// sites, 0 predicated forms**, binary-scanned by decoding every B/BL
/// word in osos.dec — no caller NULL-guards the token).
///
/// ```text
/// 082a368c  push  {r4, lr}
/// 082a3690  mov   r4, r0
/// 082a3694  ldr   r0, [r0]         @ token vtable
/// 082a3698  ldr   r1, [r0, #8]     @ slot +0x08 validity method
/// 082a369c  mov   r0, r4
/// 082a36a0  blx   r1
/// 082a36a4  cmp   r0, #0
/// 082a36a8  ldrne r1, [r4, #8]     @ owner
/// 082a36ac  moveq r0, #0
/// 082a36b0  ldrne r0, [r1, #0x110] @ low word
/// 082a36b4  ldrne r1, [r1, #0x114] @ high word
/// 082a36b8  moveq r1, #0
/// 082a36bc  pop   {r4, pc}
/// ```
///
/// Validity-gated 64-bit owner getter over the scoped-context token, the
/// same shape as [`scoped_context_owner_flags_any_8062`]: dispatch the
/// token's vtable slot +0x08 and, only when it returns nonzero, read the
/// owner's adjacent word pair at +0x110/+0x114 and return it as a u64
/// (r0 = low, r1 = high per AAPCS). An invalid token answers 0 in both
/// halves without touching the owner, so a NULL-owner token returns 0
/// instead of faulting. What the pair means does not survive in the
/// image — callers treat it as an opaque identity (e.g. 0x081688e4's
/// `if (value != 0)` gate) — so the port keeps its offset name, the
/// OWNER_FLAGS_MASK_8062 precedent.
///
/// Ghidra's recovered C returns only the low word (`undefined4`): its
/// decompiler drops the r1 half of the pair, one more case of Ghidra
/// dropping a return register. The raw `ldrne r1, [r1, #0x114]` /
/// `moveq r1, #0` are unambiguous — both halves are live on every exit.
///
/// Deviations: the token and its vtable are this module's `#[repr(C)]`
/// models, so the vtable load and slot index are struct field accesses
/// rather than literal byte offsets (the module's standing deviation);
/// the slot word is transmuted to the call ABI at the dispatch point,
/// the ui/element_reference.rs idiom. The pair is read as two aligned
/// u32 words, not one u64 read: the original needs only 4-byte
/// alignment (two plain `ldr`), and two word reads reproduce that
/// instead of demanding the 8-byte alignment an ldrd would.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_owner_u64_110(this: *const ScopedContext) -> u64 {
    let validity: ScopedContextValidity =
        core::mem::transmute((*(*this).vtable).slots[VALIDITY_SLOT]);
    if validity(this) == 0 {
        return 0;
    }
    let words = (*this).owner as *const u32;
    let low = words.add(OWNER_U64_110_SLOT).read();
    let high = words.add(OWNER_U64_110_SLOT + 1).read();
    (high as u64) << 32 | low as u64
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use std::vec;
    use std::vec::Vec;

    /// Serializes every test that swaps [`CAPTURE_CONTEXT_FIELDS`] or
    /// installs a fixture root. The root lives in `app::context_scope`
    /// and that module's tests write it too, so the lock is the crate-wide
    /// [`APP_ROOT_TEST_LOCK`] rather than a private one.
    use crate::testing::APP_ROOT_TEST_LOCK as SLOT_TEST_LOCK;

    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_OWNER: *mut u8 = ptr::null_mut();
    static mut MOCK_MODE_AT_CALL: u8 = 0xff;
    static mut MOCK_TOKEN: *mut ScopedContext = ptr::null_mut();

    unsafe extern "C" fn recording_capture(token: *mut ScopedContext, owner: *mut u8) {
        MOCK_CALLS += 1;
        MOCK_TOKEN = token;
        MOCK_OWNER = owner;
        MOCK_MODE_AT_CALL = (*token).mode;
    }

    /// Restores the ported capture callee and a NULL root on drop, even on panic.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write_volatile(capture_context_fields);
                ptr::addr_of_mut!(APP_ROOT_OBJECT).write_volatile(ptr::null_mut());
                CAPTURE_ROOT_READS = 0;
            }
        }
    }

    /// A token pre-filled with sentinels, so every field the constructor
    /// is supposed to write is observably overwritten.
    fn poisoned_token() -> ScopedContext {
        ScopedContext {
            vtable: usize::MAX as *const ScopedContextVtable,
            owner_valid: 0xdead_beef,
            owner: usize::MAX as *mut u8,
            service_context: usize::MAX as *mut u8,
            registry_token: usize::MAX as *mut u8,
            mode: 0x5a,
        }
    }

    unsafe fn install_mock() {
        MOCK_CALLS = 0;
        MOCK_TOKEN = ptr::null_mut();
        MOCK_OWNER = usize::MAX as *mut u8;
        MOCK_MODE_AT_CALL = 0xff;
        ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write_volatile(recording_capture);
    }

    #[test]
    fn writes_every_field_and_returns_this() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        let owner = 0x1234_5678usize as *mut u8;
        unsafe { install_mock() };

        let returned = unsafe { scoped_context_construct(&mut token, owner, 0x2a) };

        assert_eq!(returned, &mut token as *mut ScopedContext);
        assert_eq!(token.vtable, &SCOPED_CONTEXT_VTABLE as *const ScopedContextVtable);
        assert_eq!(token.owner_valid, 0);
        assert_eq!(token.owner, owner);
        assert!(token.service_context.is_null());
        assert!(token.registry_token.is_null());
        assert_eq!(token.mode, 0x2a);
    }

    #[test]
    fn calls_the_capture_callee_once_with_the_owner_and_a_zero_mode() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        let owner = 0xabc0_0000usize as *mut u8;
        unsafe { install_mock() };

        unsafe { scoped_context_construct(&mut token, owner, 0xff) };

        // Copy the recorded values out through raw pointers: taking a
        // reference to a `static mut` in `assert_eq!` is the pattern the
        // 2024 edition rejects.
        let (calls, seen_token, seen_owner, mode_at_call) = unsafe {
            (
                ptr::addr_of!(MOCK_CALLS).read(),
                ptr::addr_of!(MOCK_TOKEN).read(),
                ptr::addr_of!(MOCK_OWNER).read(),
                ptr::addr_of!(MOCK_MODE_AT_CALL).read(),
            )
        };
        assert_eq!(calls, 1, "exactly one capture call");
        assert_eq!(seen_token, &mut token as *mut ScopedContext);
        assert_eq!(seen_owner, owner);
        assert_eq!(mode_at_call, 0, "mode is written after the callee");
    }

    #[test]
    fn mode_round_trips_edge_values() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;
        unsafe { install_mock() };
        for mode in [0u8, 1, 0x7f, 0x80, 0xff] {
            let mut token = poisoned_token();
            unsafe { scoped_context_construct(&mut token, ptr::null_mut(), mode) };
            assert_eq!(token.mode, mode);
        }
    }

    /// The registry fixture: a slot array whose [`REGISTRY_TOKEN_SLOT`]
    /// holds the word the token should end up caching.
    fn registry_with_token(token_word: *mut u8) -> Vec<*mut u8> {
        let mut registry = vec![ptr::null_mut(); REGISTRY_TOKEN_SLOT + 1];
        registry[REGISTRY_TOKEN_SLOT] = token_word;
        registry
    }

    #[test]
    fn capture_context_fields_with_null_owner_skips_the_root_walk() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        // A root that would fault if the owner-null path walked it.
        unsafe {
            ptr::addr_of_mut!(APP_ROOT_OBJECT).write_volatile(0x1usize as *mut u8);
            CAPTURE_ROOT_READS = 0;
            capture_context_fields(&mut token, ptr::null_mut());
        }

        assert!(token.owner.is_null());
        assert!(token.service_context.is_null());
        assert!(token.registry_token.is_null());
        assert_eq!(unsafe { ptr::addr_of!(CAPTURE_ROOT_READS).read() }, 0);
    }

    #[test]
    fn capture_context_fields_walks_the_system_root_for_an_owner() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;

        let mut registry = registry_with_token(0x4242_4242usize as *mut u8);
        let mut service_context: Vec<*mut u8> = vec![ptr::null_mut(); SERVICE_CONTEXT_REGISTRY_SLOT + 1];
        service_context[SERVICE_CONTEXT_REGISTRY_SLOT] = registry.as_mut_ptr() as *mut u8;
        let mut root: Vec<*mut u8> = vec![ptr::null_mut(); ROOT_SERVICE_CONTEXT_SLOT + 1];
        root[ROOT_SERVICE_CONTEXT_SLOT] = service_context.as_mut_ptr() as *mut u8;
        unsafe {
            ptr::addr_of_mut!(APP_ROOT_OBJECT).write_volatile(root.as_mut_ptr() as *mut u8);
        }

        let mut token = poisoned_token();
        let owner = 0x0011_2233usize as *mut u8;
        unsafe { CAPTURE_ROOT_READS = 0 };
        unsafe { capture_context_fields(&mut token, owner) };

        assert_eq!(token.owner, owner);
        assert_eq!(token.service_context, service_context.as_mut_ptr() as *mut u8);
        assert_eq!(token.registry_token, 0x4242_4242usize as *mut u8);
        assert_eq!(unsafe { ptr::addr_of!(CAPTURE_ROOT_READS).read() }, 1);
    }

    #[test]
    fn capture_context_fields_yields_a_null_token_when_the_registry_slot_is_null() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;

        let mut service_context: Vec<*mut u8> = vec![ptr::null_mut(); SERVICE_CONTEXT_REGISTRY_SLOT + 1];
        let mut root: Vec<*mut u8> = vec![ptr::null_mut(); ROOT_SERVICE_CONTEXT_SLOT + 1];
        root[ROOT_SERVICE_CONTEXT_SLOT] = service_context.as_mut_ptr() as *mut u8;
        unsafe {
            ptr::addr_of_mut!(APP_ROOT_OBJECT).write_volatile(root.as_mut_ptr() as *mut u8);
        }

        let mut token = poisoned_token();
        unsafe { capture_context_fields(&mut token, 1 as *mut u8) };

        assert_eq!(token.service_context, service_context.as_mut_ptr() as *mut u8);
        assert!(
            token.registry_token.is_null(),
            "a NULL registry must leave the cached word NULL, not fault"
        );
    }

    #[test]
    fn destroy_touches_nothing() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        unsafe { install_mock() };
        unsafe { scoped_context_construct(&mut token, 0x99 as *mut u8, 0x11) };
        let before = (
            token.vtable,
            token.owner_valid,
            token.owner,
            token.service_context,
            token.registry_token,
            token.mode,
        );

        scoped_context_destroy(&mut token);

        assert_eq!(
            (
                token.vtable,
                token.owner_valid,
                token.owner,
                token.service_context,
                token.registry_token,
                token.mode,
            ),
            before
        );
    }

    #[test]
    fn destroy_accepts_a_null_token() {
        // The original never dereferences `this`; neither may the port.
        scoped_context_destroy(ptr::null_mut());
    }

    #[test]
    fn vtable_holds_the_rom_words() {
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[0], 0x0812_9dec);
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[2], 0x0820_ca2c);
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[14], 0x083a_0aa0);
        assert_eq!(SCOPED_CONTEXT_VTABLE_ADDRESS, 0x089a_5b30);
    }

    static mut VALIDITY_CALLS: u32 = 0;
    static mut VALIDITY_TOKEN: *const ScopedContext = ptr::null();
    static mut VALIDITY_RESULT: u32 = 0;

    unsafe extern "C" fn recording_validity(token: *const ScopedContext) -> u32 {
        VALIDITY_CALLS += 1;
        VALIDITY_TOKEN = token;
        VALIDITY_RESULT
    }

    /// Token + owner fixture with a recording slot-+0x08 method. The
    /// owner buffer is one word past the flags word so the read cannot
    /// drift out of bounds. Self-referential: call [`link_fixture`]
    /// after the fixture is at its final address.
    struct PredicateFixture {
        vtable: ScopedContextVtable,
        owner: [u32; OWNER_FLAGS_SLOT + 2],
        token: ScopedContext,
    }

    fn predicate_fixture(flags: u32) -> PredicateFixture {
        let mut slots = [0usize; 15];
        slots[VALIDITY_SLOT] = recording_validity as usize;
        let mut fixture = PredicateFixture {
            vtable: ScopedContextVtable { slots },
            owner: [0; OWNER_FLAGS_SLOT + 2],
            token: ScopedContext {
                vtable: ptr::null(),
                owner_valid: 1,
                owner: ptr::null_mut(),
                service_context: ptr::null_mut(),
                registry_token: ptr::null_mut(),
                mode: 0,
            },
        };
        fixture.owner[OWNER_FLAGS_SLOT] = flags;
        fixture
    }

    fn link_fixture(fixture: &mut PredicateFixture, owner_null: bool) {
        fixture.token.vtable = &fixture.vtable;
        fixture.token.owner = if owner_null {
            ptr::null_mut()
        } else {
            fixture.owner.as_mut_ptr() as *mut u8
        };
    }

    fn reset_validity_recording(result: u32) {
        unsafe {
            VALIDITY_CALLS = 0;
            VALIDITY_TOKEN = ptr::null();
            VALIDITY_RESULT = result;
        }
    }

    #[test]
    fn predicate_short_circuits_when_the_token_is_not_valid() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_validity_recording(0);
        // A NULL owner proves the short-circuit: any read of it faults.
        let mut fixture = predicate_fixture(0xffff_ffff);
        link_fixture(&mut fixture, true);
        let result = unsafe { scoped_context_owner_flags_any_8062(&fixture.token) };
        assert_eq!(result, 0);
        unsafe {
            assert_eq!(VALIDITY_CALLS, 1);
            assert_eq!(VALIDITY_TOKEN as usize, &fixture.token as *const _ as usize);
        }
    }

    #[test]
    fn predicate_is_zero_when_no_mask_bit_is_set() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        for flags in [0u32, !OWNER_FLAGS_MASK_8062, 0x10, 0x8, 0x0020_0000] {
            reset_validity_recording(1);
            let mut fixture = predicate_fixture(flags);
            link_fixture(&mut fixture, false);
            let result = unsafe { scoped_context_owner_flags_any_8062(&fixture.token) };
            assert_eq!(result, 0, "flags {flags:#x} must not trip the 0x8062 mask");
            unsafe {
                assert_eq!(VALIDITY_CALLS, 1);
            }
        }
    }

    #[test]
    fn predicate_is_one_for_each_individual_mask_bit() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // 0x8062 = bits 1, 5, 6, 15 — each alone must answer 1.
        for flags in [0x0002u32, 0x0020, 0x0040, 0x8000] {
            reset_validity_recording(1);
            let mut fixture = predicate_fixture(flags);
            link_fixture(&mut fixture, false);
            let result = unsafe { scoped_context_owner_flags_any_8062(&fixture.token) };
            assert_eq!(result, 1, "single mask bit {flags:#x} must answer 1");
        }
    }

    #[test]
    fn predicate_is_one_with_mask_and_stray_bits_mixed() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_validity_recording(1);
        let mut fixture = predicate_fixture(OWNER_FLAGS_MASK_8062 | 0x0001_0000);
        link_fixture(&mut fixture, false);
        let result = unsafe { scoped_context_owner_flags_any_8062(&fixture.token) };
        assert_eq!(result, 1);
    }

    #[test]
    fn predicate_treats_any_nonzero_validity_as_true() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // The original gates on `cmp r0, #0`, not on a specific value.
        reset_validity_recording(0xffff_ffff);
        let mut fixture = predicate_fixture(0x8000);
        link_fixture(&mut fixture, false);
        let result = unsafe { scoped_context_owner_flags_any_8062(&fixture.token) };
        assert_eq!(result, 1);
    }

    /// Token + owner fixture for the u64 getter: the owner buffer runs
    /// one word past the pair's high word so the reads cannot drift out
    /// of bounds. Self-referential like PredicateFixture: call
    /// [`link_getter_fixture`] after the fixture is at its final address.
    struct GetterFixture {
        vtable: ScopedContextVtable,
        owner: [u32; OWNER_U64_110_SLOT + 2],
        token: ScopedContext,
    }

    fn getter_fixture(low: u32, high: u32) -> GetterFixture {
        let mut slots = [0usize; 15];
        slots[VALIDITY_SLOT] = recording_validity as usize;
        let mut fixture = GetterFixture {
            vtable: ScopedContextVtable { slots },
            owner: [0; OWNER_U64_110_SLOT + 2],
            token: ScopedContext {
                vtable: ptr::null(),
                owner_valid: 1,
                owner: ptr::null_mut(),
                service_context: ptr::null_mut(),
                registry_token: ptr::null_mut(),
                mode: 0,
            },
        };
        fixture.owner[OWNER_U64_110_SLOT] = low;
        fixture.owner[OWNER_U64_110_SLOT + 1] = high;
        fixture
    }

    fn link_getter_fixture(fixture: &mut GetterFixture, owner_null: bool) {
        fixture.token.vtable = &fixture.vtable;
        fixture.token.owner = if owner_null {
            ptr::null_mut()
        } else {
            fixture.owner.as_mut_ptr() as *mut u8
        };
    }

    #[test]
    fn getter_short_circuits_when_the_token_is_not_valid() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_validity_recording(0);
        // A NULL owner proves the short-circuit: any read of it faults.
        let mut fixture = getter_fixture(0xffff_ffff, 0xffff_ffff);
        link_getter_fixture(&mut fixture, true);
        let result = unsafe { scoped_context_owner_u64_110(&fixture.token) };
        assert_eq!(result, 0);
        unsafe {
            assert_eq!(VALIDITY_CALLS, 1);
            assert_eq!(VALIDITY_TOKEN as usize, &fixture.token as *const _ as usize);
        }
    }

    #[test]
    fn getter_assembles_low_and_high_words_in_aapcs_order() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // +0x110 is the low half (r0), +0x114 the high half (r1).
        reset_validity_recording(1);
        let mut fixture = getter_fixture(0x1122_3344, 0x5566_7788);
        link_getter_fixture(&mut fixture, false);
        let result = unsafe { scoped_context_owner_u64_110(&fixture.token) };
        assert_eq!(result, 0x5566_7788_1122_3344);
        unsafe {
            assert_eq!(VALIDITY_CALLS, 1);
        }
    }

    #[test]
    fn getter_reads_each_half_independently() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // Each half alone must land in its own lane: a swapped or
        // duplicated read fails one of these.
        for (low, high, want) in [
            (0xdead_beefu32, 0, 0x0000_0000_dead_beef),
            (0, 0xcafe_babe, 0xcafe_babe_0000_0000),
            (0, 0, 0),
        ] {
            reset_validity_recording(1);
            let mut fixture = getter_fixture(low, high);
            link_getter_fixture(&mut fixture, false);
            let result = unsafe { scoped_context_owner_u64_110(&fixture.token) };
            assert_eq!(result, want, "low {low:#x} high {high:#x}");
        }
    }

    #[test]
    fn getter_treats_any_nonzero_validity_as_true() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // The original gates on `cmp r0, #0`, not on a specific value.
        reset_validity_recording(0xffff_ffff);
        let mut fixture = getter_fixture(7, 9);
        link_getter_fixture(&mut fixture, false);
        let result = unsafe { scoped_context_owner_u64_110(&fixture.token) };
        assert_eq!(result, 0x0000_0009_0000_0007);
    }
}
