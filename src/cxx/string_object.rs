//! The trivial default constructor of an **unidentified** polymorphic
//! two-word class — very likely a retailOS string/buffer class, but the
//! class is not decoded, so this module documents it rather than naming
//! it. It is NOT the copy-on-write `basic_string` of cxx/string.rs:
//! that class is a one-word handle with no vtable, while this one is a
//! two-word object whose first word is a vtable pointer.
//!
//! What identifies the class: four functions in the 0x0827xxxx cluster
//! (next to the NULL-guarded strlen @ 0x082770bc) all plant the same
//! vtable literal, 0x089a6044 (each loads it from its own literal-pool
//! word, binary-verified: 0x08277454, 0x08277480 and 0x082774a4 all
//! hold 0x089a6044):
//!
//! - 0x08277440 — the trivial default ctor (ported here).
//! - 0x08277414 — a second ctor that additionally calls 0x08276620.
//! - 0x08277458 — the deleting destructor (ported here): vtable, then
//!   0x08275d74, then operator delete @ 0x082aad24 (NULL-guarded on
//!   `this`; operator delete is ported as `operator_delete` in
//!   heap/veneers.rs, so it is called directly).
//! - 0x08277484 — the plain destructor (ported here): vtable +
//!   0x08275d74, no delete.
//!
//! The vtable itself is serialized in the image at 0x089a6044: six code
//! pointers (0x0820c2dc, 0x0821183c, 0x082116f8, 0x08213bfc, 0x08213818,
//! 0x0820c5ec) followed by zeros. Ghidra resolves only 0x08213bfc as a
//! function start, so the slots' identities — and with them the class —
//! are undecoded; the second word is a payload pointer that starts NULL
//! and is released by the shared destructor body 0x08275d74 (40 bytes:
//! NULL-guards the payload word at +4, frees it through `free_wrapper`
//! @ 0x080e7970 with caller tag 0x34, then NULLs the word — ported here
//! as `string_object_release_payload`).
//!
//! Ported functions:
//!
//! - `string_default_construct` — original: `FUN_08277440` @ 0x08277440
//!   (20 bytes: 16 code + the 4-byte vtable literal @ 0x08277454;
//!   280 `bl` call sites, binary-scanned). `obj[0] = vtable`,
//!   `obj[1] = NULL`; the original leaves `this` untouched in r0, so the
//!   port returns it.
//! - `string_object_destroy` — original: `FUN_08277484` @ 0x08277484
//!   (32 bytes: 32 code, vtable literal @ 0x082774a4; 899 `bl` call
//!   sites, binary-scanned — one of the hottest functions in the
//!   image). Plants the vtable, runs the payload release @ 0x08275d74,
//!   returns `this`; no operator delete (that is the 0x08277458
//!   sibling's job).
//! - `string_object_release_payload` — original: `FUN_08275d74` @
//!   0x08275d74 (40 bytes; 41 `bl` call sites, binary-scanned). The
//!   shared payload release both destructors run: NULL-guards the
//!   payload word at +4, frees it through `free_wrapper` @ 0x080e7970
//!   with caller tag 0x34, then NULLs the word.
//! - `string_object_delete` — original: `FUN_08277458` @ 0x08277458
//!   (40 bytes: 36 code + the 4-byte vtable literal @ 0x08277480;
//!   0 direct `bl` call sites, binary-scanned — the deleting
//!   destructor is reached through `delete` expressions, not
//!   branches). NULL-guards `this`, plants the vtable, runs the
//!   payload release, then tail-branches to the ported
//!   `operator_delete` @ 0x082aad24 with `this`.
//! - `string_object_c_str` — original: `FUN_082a50b0` @ 0x082a50b0
//!   (16 bytes, **503 `bl` call sites**, binary-scanned — one of the
//!   hottest leaves in the image). The C-string accessor: the payload
//!   word at +4, or a shared empty C string when it is NULL. This
//!   pins the payload down as a heap-allocated NUL-terminated `char`
//!   buffer: sampled call sites feed the result to `strtol` (base
//!   10), character-search and printf-family calls, and the sibling
//!   @ 0x082a50a0 (`ldr r0,[r0,#4]; b 0x08275e20`) runs the count+1
//!   strlen variant over it, while the 0x08279338 neighbor scans the
//!   class's characters for the path separators ':', '/' and '\\'.
//! - `string_object_len_plus1` — original: `FUN_082a50a0` @ 0x082a50a0
//!   (8 bytes; 1 `bl` call site, binary-scanned). The length-plus-one
//!   accessor: a two-instruction thunk (`ldr r0,[r0,#4]; b 0x08275e20`)
//!   that tail-branches to the ported `strlen_safe_plus1` @ 0x08275e20
//!   over the payload word at +4 — the payload's buffer size including
//!   the NUL terminator, or 1 when the payload is NULL (the callee's
//!   own NULL guard; the thunk itself guards nothing). The lone call
//!   site @ 0x081ae498 truncates the result to 16 bits, sizing a copy
//!   buffer. Its 8-byte sibling @ 0x082a50a8 (`ldr r0,[r0,#4]; b
//!   0x0827609c`) runs the 84-byte FUN_0827609c over the payload and
//!   is NOT ported here.
//! - `string_id_record_destroy` — original: `FUN_08258c80` @
//!   0x08258c80 (24 bytes: 20 code + the 4-byte vtable literal @
//!   0x08258c98; 113 `bl` call sites, binary-scanned). The plain
//!   (non-deleting) destructor of a SECOND, derived class built on
//!   this one — see [`StringIdRecord`].
//! - `string_id_record_default_construct` — original: `FUN_08258c58`
//!   @ 0x08258c58 (36 bytes: 28 code + two 4-byte literal-pool words
//!   @ 0x08258c78/0x08258c7c; 49 `bl` call sites, binary-scanned).
//!   The default constructor of the same record class — one `stmia`
//!   plants BOTH vtables — see [`StringIdRecord`].
//! - `string_id_record_construct_from_string_id` — original:
//!   `FUN_08258c08` @ 0x08258c08 (32 bytes: 28 code + the 4-byte
//!   literal-pool word @ 0x08258c28; 7 `bl` call sites,
//!   binary-scanned). The (string, id) constructor of the same record
//!   class — plants the class vtable, chains to the StringObject copy
//!   constructor @ 0x082773e0 on the embedded subobject, stores the id
//!   — see [`StringIdRecord`].
//! - `string_id_record_copy_construct` — original: `FUN_08258c2c` @
//!   0x08258c2c (40 bytes: 36 code + the 4-byte literal-pool word @
//!   0x08258c54; 15 `bl` call sites, binary-scanned). The copy
//!   constructor of the same record class — plants the class vtable,
//!   chains to the StringObject copy constructor @ 0x082773e0 on the
//!   embedded subobject with the source record's subobject, copies the
//!   id — see [`StringIdRecord`].
//! - `string_id_record_assign` — original: `FUN_08258c9c` @
//!   0x08258c9c (40 bytes, all code — no literal-pool word; 12 `bl`
//!   call sites, binary-scanned). The assignment operator of the same
//!   record class — NO vtable store (assignment never replants),
//!   chains to the StringObject assignment operator @ 0x082774a8 on
//!   the embedded subobject with the source record's subobject, copies
//!   the id, returns its own saved `this` — see [`StringIdRecord`].
//! - `string_id_record_equals` — original: `FUN_08258cc4` @
//!   0x08258cc4 (56 bytes, all code — no literal-pool word; 5 `bl`
//!   call sites, binary-scanned). The equality operator of the same
//!   record class — compares the embedded strings (`this`'s RAW
//!   payload word against the source's `string_object_c_str`) through
//!   the UTF-8 comparator @ 0x08276d64, then the id words at +0xc —
//!   see [`StringIdRecord`].
//!
//! # The 0x08258cxx family: a (string, id) record on a StringObject base
//!
//! A six-function cluster at 0x08258c08-0x08258cfc is a 0x10-byte
//! polymorphic class whose +0 word is its own vtable (literal-pool
//! words 0x08258c28/0x08258c54/0x08258c78/0x08258c98 all hold
//! 0x089a76f0, binary-verified) and whose +4/+8 words are an embedded
//! StringObject subobject: the default constructor @ 0x08258c58
//! (`stmia r0, {r1, r2}` with literals 0x089a76f0 and 0x089a6044,
//! binary-verified) plants BOTH vtables, NULLs the payload at +8 and
//! stores -1 at +0xc (ported here). Siblings: a (string, id) constructor @
//! 0x08258c08 (ported here — plants the class vtable, chains to the
//! StringObject copy constructor @ 0x082773e0 on this+4 with the source
//! string argument, stores the id argument at +0xc), a copy constructor @
//! 0x08258c2c (ported here — chains to the same copy constructor @
//! 0x082773e0 on this+4 with the source record's +4 subobject, then
//! copies +0xc), the plain
//! destructor @ 0x08258c80 (ported here), an assignment operator @
//! 0x08258c9c (ported here — chains to the StringObject assignment
//! operator @ 0x082774a8 on this+4 with the source record's +4
//!   subobject, then copies +0xc) and an
//! equality operator @ 0x08258cc4 (ported here — compares the strings
//! through the ported `string_object_c_str` @ 0x082a50b0 and the
//! unported UTF-8 comparator @ 0x08276d64, plus the +0xc words).
//! The class is unidentified; the name is structural (the
//! pair_header.rs precedent). What the sampled call sites establish:
//! records are returned BY VALUE (sret) from virtual slot +0x13c of
//! menu/UI objects and consumed through slot +0x44 (e.g. the
//! 0x081026b4 and 0x0813b9d4 destructor sites), are heap-allocated
//! (`operator_new(0x10)` @ 0x0807f160) and appended to a list at
//! +0x60 of the element_table manager @ 0x08105ffc, and the
//! constructor sites @ 0x0813b828/0x0813b884 build them from a
//! formatted name string plus a database id (0x080528ec reads the
//! record store at r4+0x40). The vtable is serialized in the image at
//! 0x089a76f0: eighteen words (see [`STRING_ID_RECORD_VTABLE`]) —
//! slot 0 is 0x082559ac, a get-descriptive-string function over the
//! id space 0x1f00-0x1f03 (the OpenGL ES VENDOR/RENDERER/VERSION/
//! EXTENSIONS enums, returning "Hans-Martin Will", "Software",
//! "OpenGL ES-CM 1.1" and a pointer-loaded EXTENSIONS string, else
//! storing 0x500 = GL_INVALID_ENUM and returning NULL) — so the class
//! is a GL-flavoured named-object record; the remaining slots are
//! undecoded.
//!
//! Deviations:
//!
//! - The vtable is a ROM address a host cannot reproduce, so it is
//!   modeled as the static [`STRING_OBJECT_VTABLE`] — pointer identity
//!   only, exactly as heap/pool_client.rs models its vtables. The
//!   original address survives as the named constant
//!   [`STRING_OBJECT_VTABLE_ADDRESS`], and the static carries the six
//!   serialized slot addresses verbatim; nothing in this crate
//!   dispatches through them.
//! - `string_object_destroy` reaches the payload release @ 0x08275d74
//!   through the [`STRING_OBJECT_OPS`] dispatch slot (house pattern —
//!   see cxx/string_map.rs `STRING_KEY_MAP_OPS`) so host tests can
//!   install a recording mock; the shipped default is the ported
//!   [`string_object_release_payload`] itself (the same wiring as
//!   heap/tracked.rs's `TRACKED_STATS_OPS.lock`).
//! - `string_object_delete`'s operator delete @ 0x082aad24 IS ported
//!   (heap/veneers.rs `operator_delete`), so it is called directly —
//!   the missing_free_p4 ops-slot rule for unported free contracts
//!   does not apply.
//! - `string_object_c_str`'s shared empty default is a ROM pointer
//!   (the literal-pool word @ 0x082a50c0 holds 0x083e2e3a,
//!   binary-verified — a NUL byte inside the 0x083exxxx stdlib code),
//!   which a host cannot reproduce; the port returns the modeled
//!   static [`STRING_OBJECT_EMPTY_CSTR`], the same simplification
//!   cxx/string.rs makes for its shared empty rep. The original
//!   address survives as [`STRING_OBJECT_EMPTY_CSTR_ADDRESS`].
//! - `string_id_record_destroy` plants the modeled static
//!   [`STRING_ID_RECORD_VTABLE`] for the same ROM-address reason, and
//!   computes its return as the callee's `this+4` minus one word (the
//!   original's `sub r0, r0, #4` on `string_object_destroy`'s return)
//!   rather than returning its own argument — the values are
//!   identical; the subtraction width is `size_of::<usize>()` so the
//!   identity holds on 64-bit hosts too.
//! - `string_id_record_default_construct` plants BOTH modeled statics
//!   ([`STRING_ID_RECORD_VTABLE`] and [`STRING_OBJECT_VTABLE`]) for
//!   the same ROM-address reason — the original's single `stmia` is
//!   two stores here; LLVM may or may not fuse them back.
//! - `string_id_record_construct_from_string_id` chains to the
//!   StringObject copy constructor @ 0x082773e0, which is NOT ported
//!   (its own payload-duplication callee @ 0x08276474 allocates and
//!   dispatches through vtable slot +0xc), so the chain goes through
//!   the [`STRING_OBJECT_COPY_CONSTRUCT`] dispatch slot (the
//!   util/inner_state.rs `INNER_MATERIALIZE_COUNT` pattern). The
//!   default stub is the copy constructor's empty-construction prefix:
//!   plants the StringObject vtable and NULLs the payload — the exact
//!   state the real copy constructor reaches just before its
//!   payload-duplication call — ignoring the source. The real port of
//!   0x082773e0 replaces the stub when it lands. Like
//!   `string_id_record_destroy`, the port derives `this` from the
//!   callee's return minus one word (the original's `sub r0, r0, #4`),
//!   so the dataflow holds on 64-bit hosts too.
//! - `string_id_record_copy_construct` makes the same three deviations
//!   as its (string, id) sibling — the modeled static
//!   [`STRING_ID_RECORD_VTABLE`], the [`STRING_OBJECT_COPY_CONSTRUCT`]
//!   dispatch slot, and `this` derived from the callee's return minus
//!   one word — for the same reasons.
//! - `string_id_record_assign` chains to the StringObject assignment
//!   operator @ 0x082774a8, which is NOT ported (its payload
//!   reassignment helper @ 0x08276474 allocates and dispatches
//!   through vtable slots +0x8/+0xc), so the chain goes through the
//!   [`STRING_OBJECT_ASSIGN`] dispatch slot (the
//!   [`STRING_OBJECT_COPY_CONSTRUCT`] pattern). The default stub is
//!   the real operator's self-assignment-guard prefix — the `cmp r0,
//!   r1` guard whose whole conditional body is the unported helper
//!   call — returning `this` with both objects untouched. Unlike the
//!   constructor siblings, the operator stores no vtable and returns
//!   its own saved `this` (`mov r0, r4`, not the callee's return), so
//!   neither the modeled-vtable nor the return-derivation deviation
//!   applies.
//! - `string_id_record_equals` compares the strings through the ported
//!   [`utf8_strcmp_safe`] comparator @ 0x08276d64. It substitutes the
//!   shared empty C string for either NULL argument, then walks both
//!   strings through [`utf8_next_codepoint`] and compares decoded
//!   codepoints. The source side runs through the ported
//!   [`string_object_c_str`] directly (no deviation).

use crate::heap::veneers::{free_wrapper, operator_delete};
use crate::libc::strlen_safe_plus1::strlen_safe_plus1;

/// Original load address of the class vtable the constructor plants
/// (`ldr r1, [0x08277454]` in every sibling). See the module header for
/// why the port plants a static instead of this address.
pub const STRING_OBJECT_VTABLE_ADDRESS: usize = 0x089a6044;

/// The class vtable, modeled down to its six serialized slots (original
/// @ 0x089a6044; undecoded — see the module header).
#[repr(C)]
pub struct StringObjectVtable {
    /// The six code pointers the image stores at 0x089a6044..0x089a605c.
    pub slots: [usize; 6],
}

/// The vtable instance [`string_default_construct`] plants (original
/// literal: [`STRING_OBJECT_VTABLE_ADDRESS`]). The slots hold their
/// original code addresses as identities only.
pub static STRING_OBJECT_VTABLE: StringObjectVtable = StringObjectVtable {
    slots: [0x0820c2dc, 0x0821183c, 0x082116f8, 0x08213bfc, 0x08213818, 0x0820c5ec],
};

/// The two-word object the constructor initializes.
#[repr(C)]
pub struct StringObject {
    /// +0x00 — the class vtable (original literal 0x089a6044).
    pub vtable: *const StringObjectVtable,
    /// +0x04 — payload pointer, NULL at construction; the destructor
    /// body 0x08275d74 releases it (`free_wrapper` @ 0x080e7970, tag
    /// 0x34) and NULLs the word.
    pub payload: *mut u8,
}

/// string_default_construct — original: `FUN_08277440` @ 0x08277440
/// (20 bytes, 280 `bl` call sites).
///
/// Trivial default constructor: plants the class vtable at `this + 0`
/// and NULLs the payload word at `this + 4`. No allocation, no NULL
/// guard on `this` — the original faults on a NULL `this`, and so does
/// the port. Returns `this` (the original never touches r0 after
/// entry, the ADS constructor return convention).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_default_construct(this: *mut StringObject) -> *mut StringObject {
    (*this).vtable = &STRING_OBJECT_VTABLE;
    (*this).payload = core::ptr::null_mut();
    this
}

/// Indirect dispatch for the payload release @ 0x08275d74 (ported as
/// [`string_object_release_payload`]; see the module header).
#[derive(Clone, Copy)]
pub struct StringObjectOps {
    /// The shared destructor body: NULL-guards `this.payload`, frees it
    /// through `free_wrapper` @ 0x080e7970 with caller tag 0x34, and
    /// NULLs the word.
    pub release_payload: unsafe extern "C" fn(this: *mut StringObject),
}

/// Wired default: the ported release @ 0x08275d74.
pub const DEFAULT_STRING_OBJECT_OPS: StringObjectOps = StringObjectOps {
    release_payload: string_object_release_payload,
};

/// The active payload release. Host tests install recording mocks.
pub static mut STRING_OBJECT_OPS: StringObjectOps = DEFAULT_STRING_OBJECT_OPS;

/// Reads the release_payload slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn release_payload_op() -> unsafe extern "C" fn(*mut StringObject) {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_OPS.release_payload))
}

/// Caller tag the original passes to `free_wrapper` (`mov r1, #0x34` @
/// 0x08275d88). Telemetry only (see `BlockHeader::link_or_tag`).
pub const TAG_STRING_OBJECT_PAYLOAD: usize = 0x34;

/// string_object_release_payload — original: `FUN_08275d74` @ 0x08275d74
/// (40 bytes, 41 `bl` call sites).
///
/// The shared payload release of the two-word string/buffer class, run
/// by both destructor siblings (0x08277458 and the ported 0x08277484):
/// NULL-guards the payload word at `this + 4` (a NULL payload returns
/// untouched — the original's `ldmiaeq` early-out), frees it through
/// `free_wrapper` @ 0x080e7970 with caller tag 0x34, then NULLs the
/// word. No NULL guard on `this` — the original faults on a NULL
/// `this`, and so does the port. The original returns void with r0
/// clobbered by the free path, and so does the port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_release_payload(this: *mut StringObject) {
    let payload = (*this).payload;
    if payload.is_null() {
        return;
    }
    free_wrapper(payload, TAG_STRING_OBJECT_PAYLOAD);
    (*this).payload = core::ptr::null_mut();
}

/// string_object_destroy — original: `FUN_08277484` @ 0x08277484
/// (32 bytes, 899 `bl` call sites).
///
/// The plain (non-deleting) destructor: plants the class vtable at
/// `this + 0`, then runs the shared payload release @ 0x08275d74 on
/// `this` and returns `this`. Unlike the deleting-destructor sibling @
/// 0x08277458 there is no operator delete — the caller owns the
/// storage. No NULL guard on `this` — the original faults on a NULL
/// `this`, and so does the port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_destroy(this: *mut StringObject) -> *mut StringObject {
    (*this).vtable = &STRING_OBJECT_VTABLE;
    release_payload_op()(this);
    this
}

/// string_object_delete — original: `FUN_08277458` @ 0x08277458
/// (40 bytes: 36 code + the 4-byte vtable literal @ 0x08277480; 0
/// direct `bl` call sites, binary-scanned).
///
/// The deleting destructor, sibling of [`string_object_destroy`] @
/// 0x08277484: NULL-guards `this` (the original's `movs r4, r0` /
/// `ldmiaeq sp!, {r4, pc}` — a NULL `this` returns untouched), plants
/// the class vtable at `this + 0`, runs the shared payload release @
/// 0x08275d74 on `this`, then tail-branches to operator delete @
/// 0x082aad24 with `this`. Unlike the destroy sibling there IS a NULL
/// guard on `this`. The delete primitive is ported
/// ([`operator_delete`], the NULL-guarded tag-2 `free_wrapper`), so it
/// is called directly rather than through an ops slot. The port
/// returns void: the original tail-branches into the delete without
/// rewriting r0, so the caller sees whatever the free path leaves
/// there, never a usable `this`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_delete(this: *mut StringObject) {
    if this.is_null() {
        return;
    }
    (*this).vtable = &STRING_OBJECT_VTABLE;
    release_payload_op()(this);
    operator_delete(this as *mut u8);
}

/// Original load address of the shared empty C string
/// [`string_object_c_str`] falls back to: the literal-pool word @
/// 0x082a50c0 holds 0x083e2e3a (binary-verified against osos.dec), and
/// the byte at 0x083e2e3a is 0x00 — a NUL inside the vector-growth
/// code of the 0x083exxxx stdlib cluster, so the default reads as "".
pub const STRING_OBJECT_EMPTY_CSTR_ADDRESS: usize = 0x083e2e3a;

/// The shared empty C string, modeled (the original's default points
/// into ROM code — see [`STRING_OBJECT_EMPTY_CSTR_ADDRESS`] — which a
/// host cannot reproduce). Never written: every payload write goes
/// through the word at `this + 4`, never through this pointer.
static STRING_OBJECT_EMPTY_CSTR: u8 = 0;

/// string_object_c_str — original: `FUN_082a50b0` @ 0x082a50b0
/// (16 bytes, **503 `bl` call sites**, binary-scanned — one of the
/// hottest leaves in the image; a 4-byte tail-branch thunk @
/// 0x082a704c, `b 0x082a50b0`, also reaches it and is not ported
/// here).
///
/// The C-string accessor of the two-word string class: returns the
/// payload pointer at `this + 4`, or the shared empty C string when
/// the payload is NULL — `ldr r0, [r0, #4]; cmp r0, #0; ldreq r0,
/// [0x082a50c0]; bx lr`. The result is never NULL; sampled call sites
/// treat it as a read-only `const char *` (strtol with base 10,
/// character-search and printf-family calls). No NULL guard on `this`
/// — the original faults on a NULL `this`, and so does the port.
///
/// Deviation: the original's default is a ROM pointer (see
/// [`STRING_OBJECT_EMPTY_CSTR_ADDRESS`]); the port returns the modeled
/// static [`STRING_OBJECT_EMPTY_CSTR`] instead.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_c_str(this: *const StringObject) -> *const u8 {
    let payload = (*this).payload as *const u8;
    if payload.is_null() {
        return &STRING_OBJECT_EMPTY_CSTR;
    }
    payload
}

/// string_object_len_plus1 — original: `FUN_082a50a0` @ 0x082a50a0
/// (8 bytes, 1 `bl` call site, binary-scanned).
///
/// The length-plus-one accessor of the two-word string class: a
/// two-instruction thunk — `ldr r0, [r0, #4]; b 0x08275e20` — that
/// loads the payload word at `this + 4` and tail-branches to the
/// ported [`strlen_safe_plus1`] @ 0x08275e20 over it. Returns the
/// payload's buffer size including the NUL terminator, or 1 when the
/// payload is NULL (the thunk guards nothing; the callee's own NULL
/// guard yields 1 — unlike [`string_object_c_str`], which substitutes
/// a shared empty C string before any strlen runs). No NULL guard on
/// `this` — the original faults on a NULL `this`, and so does the
/// port. The lone call site @ 0x081ae498 truncates the result to 16
/// bits (`mov r6, r0, lsl #0x10; mov r6, r6, lsr #0x10`), sizing a
/// copy buffer. The callee is ported, so it is called directly.
///
/// Deviation: the callee address is read through a volatile pointer
/// (the same anti-const-fold trick as [`release_payload_op`]) purely
/// to stop LLVM from inlining [`strlen_safe_plus1`] and dissolving
/// the thunk; codegen stays a load plus a tail branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_len_plus1(this: *const StringObject) -> usize {
    let len_plus1: unsafe extern "C" fn(*const u8) -> usize =
        core::ptr::read_volatile(&(strlen_safe_plus1 as unsafe extern "C" fn(*const u8) -> usize));
    len_plus1((*this).payload as *const u8)
}

/// Original load address of the 0x08258cxx-class vtable
/// [`string_id_record_destroy`] plants (its literal-pool word @
/// 0x08258c98 holds 0x089a76f0, binary-verified against osos.dec; the
/// three constructor siblings load the same value from 0x08258c28,
/// 0x08258c54 and 0x08258c78). See the module header for why the port
/// plants a static instead of this address.
pub const STRING_ID_RECORD_VTABLE_ADDRESS: usize = 0x089a76f0;

/// The 0x08258cxx-class vtable, modeled down to its eighteen
/// serialized words (original @ 0x089a76f0; the class is unidentified
/// — see the module header).
#[repr(C)]
pub struct StringIdRecordVtable {
    /// The eighteen words the image stores at 0x089a76f0..0x089a7738,
    /// binary-verified: slot 0 is the id-to-string query 0x082559ac,
    /// slot 1 is NULL, the rest are undecoded code pointers (followed
    /// by a zero tail at 0x089a7738).
    pub slots: [usize; 18],
}

/// The vtable instance [`string_id_record_destroy`] plants (original
/// literal: [`STRING_ID_RECORD_VTABLE_ADDRESS`]). The slots hold their
/// original code addresses as identities only; nothing in this crate
/// dispatches through them.
pub static STRING_ID_RECORD_VTABLE: StringIdRecordVtable = StringIdRecordVtable {
    slots: [
        0x082559ac, 0x00000000, 0x08129dec, 0x08129b40, 0x0821f04c, 0x08129d28,
        0x0820ed90, 0x083a4368, 0x0820e610, 0x0820f084, 0x08255b5c, 0x08255b44,
        0x0821f220, 0x0821f200, 0x0820f074, 0x0821f384, 0x0821f1f8, 0x0820f250,
    ],
};

/// The 0x10-byte object the 0x08258cxx cluster operates on: its own
/// vtable at +0, an embedded StringObject subobject at +4 (the
/// StringObject vtable at +4, the payload at +8 — the default constructor @
/// 0x08258c58 stores both vtables in one `stmia`), and an integer id
/// at +0xc (-1 by default). `repr(C)` gives this exact layout on
/// 32-bit ARM; on 64-bit hosts the fields pad wider, which only the
/// tests see.
#[repr(C)]
pub struct StringIdRecord {
    /// +0x00 — the class vtable (original literal 0x089a76f0).
    pub vtable: *const StringIdRecordVtable,
    /// +0x04 — the embedded StringObject subobject (base or member —
    /// indistinguishable from the code; it keeps its OWN vtable, so
    /// it is not the primary base).
    pub string: StringObject,
    /// +0x0c — the integer id; the default constructor @ 0x08258c58
    /// stores -1 (`mvn r1, #0x0`), the (string, id) constructor @
    /// 0x08258c08 and the copy constructor @ 0x08258c2c store/copy
    /// it, the assignment operator @ 0x08258c9c copies it, and the
    /// equality operator @ 0x08258cc4 compares it.
    pub id: i32,
}

/// string_id_record_destroy — original: `FUN_08258c80` @ 0x08258c80
/// (24 bytes: 20 code + the 4-byte vtable literal @ 0x08258c98;
/// 113 `bl` call sites, binary-scanned).
///
/// The plain (non-deleting) destructor of the 0x10-byte (string, id)
/// record class: plants the class vtable at `this + 0` (`str r1,
/// [r0], #0x4` — the post-index add also forms the `this + 4`
/// argument), then destroys the embedded StringObject subobject at
/// `this + 4` through the ported [`string_object_destroy`] @
/// 0x08277484 (which re-plants the StringObject vtable at +4 and
/// releases the payload at +8), and returns `this`. The original
/// derives the return from the callee: `string_object_destroy`
/// returns its `this + 4` argument in r0 and the destructor subtracts
/// one word (`sub r0, r0, #4`). No operator delete (the caller owns
/// the storage — sampled sites destroy stack temporaries), no NULL
/// guard on `this` — the original faults on a NULL `this`, and so
/// does the port. The callee is ported, so it is called directly, not
/// through an ops slot.
///
/// Deviation: the return is computed as the callee's return minus
/// `size_of::<usize>()` (one vtable word) so the original's dataflow
/// — and its value — holds on 64-bit hosts too.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_destroy(
    this: *mut StringIdRecord,
) -> *mut StringIdRecord {
    (*this).vtable = &STRING_ID_RECORD_VTABLE;
    let base = string_object_destroy(&mut (*this).string);
    (base as *mut u8).sub(core::mem::size_of::<usize>()) as *mut StringIdRecord
}

/// string_id_record_default_construct — original: `FUN_08258c58` @
/// 0x08258c58 (36 bytes: 28 code + two 4-byte literal-pool words @
/// 0x08258c78/0x08258c7c, both binary-verified against osos.dec;
/// 49 `bl` call sites, binary-scanned).
///
/// The default constructor of the 0x10-byte (string, id) record
/// class: one `stmia r0, {r1, r2}` plants BOTH vtables — the class
/// vtable at `this + 0` (pool word @ 0x08258c78 holds 0x089a76f0)
/// and the embedded StringObject's vtable at `this + 4` (pool word @
/// 0x08258c7c holds 0x089a6044) — then stores -1 at `this + 0xc`
/// (`mvn r1, #0x0`, the default id) and NULL at `this + 8` (the
/// embedded payload). The original stores the id BEFORE the payload
/// (`str r1,[r0,#0xc]` precedes `str r2,[r0,#0x8]`); the port
/// reproduces that order. No allocation, no call into the
/// StringObject default ctor (the `stmia` inlines it), no NULL guard
/// on `this` — the original faults on a NULL `this`, and so does the
/// port. Returns `this`: the original never touches r0 after entry,
/// the ADS constructor return convention (same as
/// [`string_default_construct`]).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_default_construct(
    this: *mut StringIdRecord,
) -> *mut StringIdRecord {
    (*this).vtable = &STRING_ID_RECORD_VTABLE;
    (*this).string.vtable = &STRING_OBJECT_VTABLE;
    (*this).id = -1;
    (*this).string.payload = core::ptr::null_mut();
    this
}

/// Default [`STRING_OBJECT_COPY_CONSTRUCT`] stub: the empty-construction
/// prefix of the unported StringObject copy constructor @ 0x082773e0 —
/// plants the StringObject vtable at `this + 0` (the original's
/// `ldr r0, [0x08277410]; str r0, [r4, #0x0]`, literal 0x089a6044
/// binary-verified) and NULLs the payload word at `this + 4` (the
/// original's `movne r0, #0x0; strne r0, [r4, #0x4]`) — the exact state
/// the real copy constructor reaches just before its payload-duplication
/// call @ 0x08276474 — ignoring `source`. Exact for constructing an
/// empty string; the real port of 0x082773e0 replaces this stub when it
/// lands (see the module header).
unsafe extern "C" fn string_object_copy_construct_stub(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    let _ = source;
    (*this).vtable = &STRING_OBJECT_VTABLE;
    (*this).payload = core::ptr::null_mut();
    this
}

/// Indirect dispatch for the unported StringObject copy constructor @
/// 0x082773e0 (the util/inner_state.rs `INNER_MATERIALIZE_COUNT`
/// pattern). Chained to by [`string_id_record_construct_from_string_id`]
/// and by the ported copy constructor sibling
/// [`string_id_record_copy_construct`]. Host tests install a recording
/// mock; the real port of 0x082773e0 replaces the default stub when it
/// lands.
pub static mut STRING_OBJECT_COPY_CONSTRUCT: unsafe extern "C" fn(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject = string_object_copy_construct_stub;

/// Reads the copy-construct slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away; the [`release_payload_op`] rationale).
#[inline(always)]
pub(crate) unsafe fn copy_construct_op() -> unsafe extern "C" fn(
    *mut StringObject,
    *const StringObject,
) -> *mut StringObject {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_COPY_CONSTRUCT))
}

/// string_id_record_construct_from_string_id — original: `FUN_08258c08`
/// @ 0x08258c08 (32 bytes: 28 code + the 4-byte literal-pool word @
/// 0x08258c28 = 0x089a76f0, binary-verified against osos.dec; 7 `bl`
/// call sites, binary-scanned: 0x0813b828, 0x0813b884, 0x0813bd64,
/// 0x0813bde0, 0x0813c3fc, 0x0813c478, 0x0813c9c8 — the name-plus-
/// database-id record construction sites; see the module header).
///
/// The (string, id) constructor of the 0x10-byte (string, id) record
/// class: plants the class vtable at `this + 0` (`ldr r2, [0x08258c28];
/// str r2, [r0], #0x4` — the post-index add also forms the `this + 4`
/// argument, the embedded StringObject subobject), then chains to the
/// StringObject copy constructor @ 0x082773e0 on `this + 4` with
/// `source` still in r1 (verified against osos.asm: the scouting note's
/// "chains to the StringObject copy ctor on this+4" is exact), derives
/// `this` back from the callee's return (`sub r0, r0, #4` — the callee
/// returns its argument), stores the `id` argument at `this + 0xc`, and
/// returns `this`. No NULL guard on `this` or `source` — the original
/// faults on either, and so does the port.
///
/// Deviations (see the module header): the class vtable is the modeled
/// static [`STRING_ID_RECORD_VTABLE`]; the unported copy constructor @
/// 0x082773e0 dispatches through [`STRING_OBJECT_COPY_CONSTRUCT`]; the
/// return/id store derive `this` from the callee's return minus
/// `size_of::<usize>()` (one vtable word) so the original's dataflow —
/// and its values — hold on 64-bit hosts too.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_construct_from_string_id(
    this: *mut StringIdRecord,
    source: *const StringObject,
    id: i32,
) -> *mut StringIdRecord {
    (*this).vtable = &STRING_ID_RECORD_VTABLE;
    let base = copy_construct_op()(&mut (*this).string, source);
    let record = (base as *mut u8).sub(core::mem::size_of::<usize>()) as *mut StringIdRecord;
    (*record).id = id;
    record
}

/// string_id_record_copy_construct — original: `FUN_08258c2c` @
/// 0x08258c2c (40 bytes: 36 code + the 4-byte literal-pool word @
/// 0x08258c54 = 0x089a76f0, binary-verified against osos.dec; 15 `bl`
/// call sites, binary-scanned).
///
/// The copy constructor of the 0x10-byte (string, id) record class:
/// saves `source` in r4 (`mov r4, r1`), plants the class vtable at
/// `this + 0` (`ldr r1, [0x08258c54]; str r1, [r0], #0x4` — the
/// post-index add also forms the `this + 4` argument, the embedded
/// StringObject subobject), chains to the StringObject copy
/// constructor @ 0x082773e0 on `this + 4` with the SOURCE RECORD's
/// embedded subobject (`add r1, r4, #0x4` — `source + 4`, not the
/// source record itself), loads the source id word (`ldr r1,
/// [r4, #0xc]`), derives `this` back from the callee's return
/// (`sub r0, r0, #0x4` — the callee returns its argument), stores the
/// id at `this + 0xc`, and returns `this`. No allocation of its own,
/// no NULL guard on `this` or `source` — the original faults on
/// either, and so does the port.
///
/// Deviations (the same three as the (string, id) sibling — see the
/// module header): the class vtable is the modeled static
/// [`STRING_ID_RECORD_VTABLE`]; the unported copy constructor @
/// 0x082773e0 dispatches through [`STRING_OBJECT_COPY_CONSTRUCT`]; the
/// return/id store derive `this` from the callee's return minus
/// `size_of::<usize>()` (one vtable word) so the original's dataflow —
/// and its values — hold on 64-bit hosts too.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_copy_construct(
    this: *mut StringIdRecord,
    source: *const StringIdRecord,
) -> *mut StringIdRecord {
    (*this).vtable = &STRING_ID_RECORD_VTABLE;
    let base = copy_construct_op()(&mut (*this).string, &(*source).string);
    let record = (base as *mut u8).sub(core::mem::size_of::<usize>()) as *mut StringIdRecord;
    (*record).id = (*source).id;
    record
}

/// Default [`STRING_OBJECT_ASSIGN`] stub: the self-assignment-guard
/// prefix of the unported StringObject assignment operator @
/// 0x082774a8 — the original is `cmp r0, r1` with its whole body
/// conditional (`ldrne r1, [r1, #0x4]; movne r0, r4; blne
/// 0x08276474`): when `this` and `source` differ it reassigns the
/// payload from the source's payload word through 0x08276474 (the
/// same vtable-dispatching duplication helper the copy constructor
/// chains to), and when they are equal it does nothing at all. The
/// stub reproduces the guard and the `mov r0, r4` return, and skips
/// only the unported helper call — both objects stay untouched.
/// Exact for self-assignment; the real port of 0x082774a8 replaces
/// this stub when it lands (see the module header).
unsafe extern "C" fn string_object_assign_stub(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    if this != source as *mut StringObject {
        // The real operator would reassign `this`'s payload from
        // `source`'s payload word through 0x08276474 — unported.
    }
    this
}

/// Indirect dispatch for the unported StringObject assignment
/// operator @ 0x082774a8 (the [`STRING_OBJECT_COPY_CONSTRUCT`]
/// pattern). Chained to by the ported record assignment operator
/// [`string_id_record_assign`]. Host tests install a recording mock;
/// the real port of 0x082774a8 replaces the default stub when it
/// lands.
pub static mut STRING_OBJECT_ASSIGN: unsafe extern "C" fn(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject = string_object_assign_stub;

/// Reads the assign slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default
/// away; the [`release_payload_op`] rationale).
#[inline(always)]
pub(crate) unsafe fn assign_op() -> unsafe extern "C" fn(
    *mut StringObject,
    *const StringObject,
) -> *mut StringObject {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_ASSIGN))
}

/// string_id_record_assign — original: `FUN_08258c9c` @ 0x08258c9c
/// (40 bytes, all code — no literal-pool word; 12 `bl` call sites,
/// binary-scanned: five consecutive @ 0x08177d7c-0x08177dac, five
/// consecutive @ 0x0817a3dc-0x0817a40c, 0x0822a164, 0x0822a2a8).
///
/// The assignment operator of the 0x10-byte (string, id) record
/// class: saves `source` in r5 and `this` in r4 (`mov r5, r1; mov
/// r4, r0`), chains to the StringObject assignment operator @
/// 0x082774a8 on the embedded subobject (`add r0, r0, #0x4` — `this
/// + 4`) with the SOURCE RECORD's embedded subobject (`add r1, r1,
/// #0x4` — `source + 4`, not the source record itself), copies the
/// id word (`ldr r0, [r5, #0xc]; str r0, [r4, #0xc]`), and returns
/// its own saved `this` (`mov r0, r4`) — NOT the callee's return,
/// unlike the constructor siblings' `sub r0, r0, #0x4` derivation.
/// Unlike the constructors there is NO vtable store: assignment
/// never replants. There is also no self-assignment guard at this
/// level — the guard lives inside the StringObject operator (its
/// `cmp r0, r1` on the subobjects catches record self-assignment,
/// and the id self-copy is harmless). No allocation of its own, no
/// NULL guard on `this` or `source` — the original faults on either,
/// and so does the port.
///
/// Deviations (see the module header): the unported StringObject
/// assignment operator @ 0x082774a8 dispatches through
/// [`STRING_OBJECT_ASSIGN`], whose default stub is the real
/// operator's self-assignment-guard prefix. Neither of the
/// constructor siblings' other two deviations applies: there is no
/// vtable to model (none is stored) and no return to derive (the
/// original returns its own argument, exact on every host).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_assign(
    this: *mut StringIdRecord,
    source: *const StringIdRecord,
) -> *mut StringIdRecord {
    assign_op()(&mut (*this).string, &(*source).string);
    (*this).id = (*source).id;
    this
}

/// Decodes the codepoint at `*cursor` and advances the cursor — original:
/// `FUN_08276214` @ 0x08276214 (112 bytes, all code).
///
/// The retail decoder returns ASCII unchanged after consuming one byte. A
/// `0b110xxxxx` lead consumes two bytes and a `0b1110xxxx` lead consumes
/// three, assembling their payload bits without validating continuation
/// bytes, overlong encodings, or surrogate values. Every other high-bit lead
/// — including a four-byte UTF-8 lead — consumes exactly three bytes and
/// returns zero, which its string-comparison caller treats as a terminator.
/// The original faults for an invalid `cursor` or unreadable sequence, and
/// this direct raw-pointer port has the same preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_next_codepoint(cursor: *mut *const u8) -> u32 {
    let sequence = *cursor;
    *cursor = sequence.add(1);

    let lead = *sequence as u32;
    if lead & 0x80 == 0 {
        return lead;
    }

    *cursor = sequence.add(2);
    let second_byte = *sequence.add(1) as u32;
    if lead & 0xe0 == 0xc0 {
        return second_byte & 0x3f | (lead & 0x1f) << 6;
    }

    *cursor = sequence.add(3);
    if lead & 0xf0 == 0xe0 {
        return (lead & 0x0f) << 12
            | (second_byte & 0x3f) << 6
            | (*sequence.add(2) as u32 & 0x3f);
    }

    0
}

/// utf8_strcmp_safe — original: `FUN_08276d64` @ 0x08276d64 (56 bytes,
/// all code; source: `ipod-decomp/decomp/c/026/08276d64_FUN_08276d64.c`).
///
/// Substitutes the firmware's shared empty C string for either NULL argument,
/// then decodes both cursors with [`utf8_next_codepoint`]. Returns the first
/// unequal decoded codepoints' difference, or zero once both decoders return
/// the same zero codepoint. Consequently an invalid or four-byte lead ends
/// comparison because the retail decoder consumes three bytes and returns
/// zero for it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_strcmp_safe(a: *const u8, b: *const u8) -> i32 {
    let empty = core::ptr::addr_of!(STRING_OBJECT_EMPTY_CSTR);
    let mut a_cursor = if a.is_null() { empty } else { a };
    let mut b_cursor = if b.is_null() { empty } else { b };

    loop {
        let codepoint_a = utf8_next_codepoint(&mut a_cursor);
        let codepoint_b = utf8_next_codepoint(&mut b_cursor);
        if codepoint_a != codepoint_b {
            return codepoint_a as i32 - codepoint_b as i32;
        }
        if codepoint_a == 0 {
            return 0;
        }
    }
}

/// string_id_record_equals — original: `FUN_08258cc4` @ 0x08258cc4
/// (56 bytes, all code — no literal-pool word; 5 `bl` call sites,
/// binary-scanned: five consecutive @ 0x081978ec-0x0819793c, comparing
/// the records at +0x18/+0x28/+0x38/+0x48/+0x58 of two larger
/// structures, each result consumed as a bool by `cmp r0, #0x0`).
///
/// The equality operator of the 0x10-byte (string, id) record class:
/// `mov r4, r0; mov r5, r1` saves `this`/`source`, `add r0, r1, #0x4;
/// bl 0x082a50b0` runs the ported [`string_object_c_str`] over the
/// SOURCE RECORD's embedded subobject (never NULL — a NULL source
/// payload yields the shared empty string), `mov r1, r0; ldr r0,
/// [r4, #0x8]; bl 0x08276d64` compares `this`'s RAW payload word
/// (NULL passed through untouched — the substitution guard lives
/// inside the comparator, an asymmetry with the source side) against
/// the source's C string through the UTF-8 comparator @ 0x08276d64,
/// and only when that returns 0 (`cmp r0, #0x0` with the rest
/// conditional) are the id words compared (`ldreq r0, [r4, #0xc];
/// ldreq r1, [r5, #0xc]; cmpeq r0, r1`), yielding 1 on equality, 0
/// otherwise (`moveq r0, #0x1; movne r0, #0x0`). No allocation, no
/// vtable store, no NULL guard on `this` or `source` — the original
/// faults on either, and so does the port.
///
/// The ported [`utf8_strcmp_safe`] is called directly. The return is the C++
/// `bool` widened to `i32` (the original's `movne r0, #0x0` / `moveq r0,
/// #0x1` writes the whole register — exact).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_record_equals(
    this: *const StringIdRecord,
    source: *const StringIdRecord,
) -> i32 {
    let source_cstr = string_object_c_str(&(*source).string);
    let cmp = utf8_strcmp_safe((*this).string.payload as *const u8, source_cstr);
    if cmp == 0 && (*this).id == (*source).id {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    #[test]
    fn plants_the_vtable_and_a_null_payload() {
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            assert_eq!(string_default_construct(this), this);
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(object.payload.is_null());
        }
    }

    #[test]
    fn the_static_vtable_carries_the_six_serialized_slots() {
        assert_eq!(STRING_OBJECT_VTABLE_ADDRESS, 0x089a6044);
        assert_eq!(
            STRING_OBJECT_VTABLE.slots,
            [0x0820c2dc, 0x0821183c, 0x082116f8, 0x08213bfc, 0x08213818, 0x0820c5ec]
        );
    }

    /// Serializes the destroy tests — the ops table and the recorder
    /// are shared globals.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Objects handed to the recording release, in call order, paired
    /// with the vtable pointer observed at entry.
    static mut RELEASE_CALLS: Vec<(usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_release(this: *mut StringObject) {
        (*core::ptr::addr_of_mut!(RELEASE_CALLS))
            .push((this as usize, (*this).vtable as usize));
    }

    /// Installs the recording release; restores the default ops on
    /// drop.
    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = OPS_LOCK.lock().unwrap();
        unsafe {
            (*core::ptr::addr_of_mut!(RELEASE_CALLS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS),
                StringObjectOps {
                    release_payload: recording_release,
                },
            );
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(STRING_OBJECT_OPS),
                    DEFAULT_STRING_OBJECT_OPS,
                );
            }
        }
    }

    fn release_calls() -> Vec<(usize, usize)> {
        unsafe { (*core::ptr::addr_of!(RELEASE_CALLS)).clone() }
    }

    #[test]
    fn destroy_plants_the_vtable_then_releases_and_returns_this() {
        let _bench = bench();
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            assert_eq!(string_object_destroy(this), this);
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let calls = release_calls();
        assert_eq!(calls.len(), 1, "exactly one payload release");
        assert_eq!(calls[0].0, this as usize, "release receives `this`");
        assert_eq!(
            calls[0].1,
            &STRING_OBJECT_VTABLE as *const _ as usize,
            "the vtable store precedes the release call (str before bl)"
        );
    }

    #[test]
    fn destroy_forwards_the_payload_untouched() {
        let _bench = bench();
        let mut payload_storage = [0u8; 8];
        let payload = payload_storage.as_mut_ptr();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        unsafe {
            string_object_destroy(&mut object);
        }
        assert_eq!(object.payload, payload, "destroy itself never touches the payload word");
    }

    #[test]
    fn release_payload_with_null_payload_frees_nothing() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            string_object_release_payload(&mut object);
        }
        assert!(object.payload.is_null());
        assert_eq!(
            crate::heap::veneers::tests::free_log().0,
            0,
            "a NULL payload is the original's ldmiaeq early-out"
        );
    }

    #[test]
    fn release_payload_frees_tag_0x34_then_nulls_the_word() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        let mut payload_storage = [0u8; 8];
        let payload = payload_storage.as_mut_ptr();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        unsafe {
            string_object_release_payload(&mut object);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(calls, 1, "exactly one heap free");
        assert_eq!(freed, payload, "the payload word is what gets freed");
        assert_eq!(tag, 0x34, "the original's mov r1, #0x34");
        assert_eq!(tag, TAG_STRING_OBJECT_PAYLOAD);
        assert!(
            object.payload.is_null(),
            "the word is NULLed after the free (mov r0,#0; str r0,[r4,#4])"
        );
    }

    #[test]
    fn wired_default_ops_is_the_ported_release() {
        assert_eq!(
            DEFAULT_STRING_OBJECT_OPS.release_payload as usize,
            string_object_release_payload as usize
        );
    }

    #[test]
    fn destroy_with_the_default_ops_releases_the_payload() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        let mut payload_storage = [0u8; 8];
        let payload = payload_storage.as_mut_ptr();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            assert_eq!(string_object_destroy(this), this);
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(calls, 1);
        assert_eq!(freed, payload);
        assert_eq!(tag, 0x34);
        assert!(object.payload.is_null(), "destroy releases and NULLs");
    }

    #[test]
    fn delete_with_null_this_touches_nothing() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _bench = bench();
        unsafe {
            string_object_delete(core::ptr::null_mut());
        }
        assert!(
            release_calls().is_empty(),
            "the original's movs/ldmiaeq early-out skips the release"
        );
        assert_eq!(
            crate::heap::veneers::tests::free_log().0,
            0,
            "and never reaches operator delete"
        );
    }

    #[test]
    fn delete_releases_payload_then_operator_deletes_this() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _bench = bench();
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            string_object_delete(this);
        }
        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        let calls = release_calls();
        assert_eq!(calls.len(), 1, "exactly one payload release");
        assert_eq!(calls[0].0, this as usize, "release receives `this`");
        assert_eq!(
            calls[0].1,
            &STRING_OBJECT_VTABLE as *const _ as usize,
            "the vtable store precedes the release call (str before bl)"
        );
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(
            calls, 1,
            "the recording release frees nothing, so the one free is the delete"
        );
        assert_eq!(freed, this as *mut u8, "operator delete receives `this`");
        assert_eq!(tag, 2, "operator_delete @ 0x082aad24's tag-2 free");
    }

    #[test]
    fn delete_with_default_ops_frees_payload_then_this() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        let mut payload_storage = [0u8; 8];
        let payload = payload_storage.as_mut_ptr();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            string_object_delete(this);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(calls, 2, "the payload free, then the delete of `this`");
        assert_eq!(freed, this as *mut u8, "the LAST free is the delete");
        assert_eq!(tag, 2, "operator delete's tag-2, after the payload's 0x34");
        assert!(object.payload.is_null(), "the release NULLed the word first");
        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
    }

    #[test]
    fn c_str_returns_the_payload_word_untouched() {
        let mut payload_storage = *b"nowplaying\0";
        let payload = payload_storage.as_mut_ptr();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        unsafe {
            assert_eq!(
                string_object_c_str(&object),
                payload as *const u8,
                "a non-NULL payload is returned verbatim (ldr r0,[r0,#4]; bx lr)"
            );
            assert_eq!(object.payload, payload, "the accessor never writes");
        }
    }

    #[test]
    fn c_str_with_null_payload_returns_the_shared_empty() {
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            let s = string_object_c_str(&object);
            assert!(!s.is_null(), "the accessor never returns NULL");
            assert_eq!(*s, 0, "the shared default reads as \"\"");
            assert_eq!(
                s, &STRING_OBJECT_EMPTY_CSTR as *const u8,
                "the default is the modeled static, not a fresh buffer"
            );
        }
    }

    #[test]
    fn c_str_shared_empty_is_a_singleton() {
        let a = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let b = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            assert_eq!(
                string_object_c_str(&a),
                string_object_c_str(&b),
                "every NULL-payload object shares the one empty C string"
            );
        }
    }

    #[test]
    fn empty_cstr_address_is_binary_verified() {
        assert_eq!(STRING_OBJECT_EMPTY_CSTR_ADDRESS, 0x083e2e3a);
    }

    #[test]
    fn len_plus1_counts_the_payload_including_the_nul() {
        let mut payload_storage = *b"nowplaying\0";
        let payload = payload_storage.as_mut_ptr();
        let object = StringObject {
            vtable: core::ptr::null(),
            payload,
        };
        unsafe {
            assert_eq!(
                string_object_len_plus1(&object),
                11,
                "strlen(payload) + 1, the buffer size including the NUL"
            );
            assert_eq!(object.payload, payload, "the accessor never writes");
        }
    }

    #[test]
    fn len_plus1_with_null_payload_returns_one() {
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            assert_eq!(
                string_object_len_plus1(&object),
                1,
                "the thunk guards nothing; strlen_safe_plus1's own NULL guard yields 1"
            );
        }
    }

    /// Every length 0..64 at every start alignment 0..3 through the
    /// object, checked against the ported strlen_safe_plus1 directly.
    #[test]
    fn len_plus1_matches_strlen_safe_plus1_all_lengths_and_alignments() {
        for align in 0..4usize {
            let mut buf: Vec<u8> = std::vec![0u8; align + 64 + 1];
            for len in 0..64usize {
                for i in 0..len {
                    buf[align + i] = (i as u8 % 251) + 1; // non-NUL payload
                }
                buf[align + len] = 0;
                let p = unsafe { buf.as_mut_ptr().add(align) };
                let object = StringObject {
                    vtable: core::ptr::null(),
                    payload: p,
                };
                unsafe {
                    assert_eq!(
                        string_object_len_plus1(&object),
                        strlen_safe_plus1(p),
                        "align={align} len={len}"
                    );
                    assert_eq!(string_object_len_plus1(&object), len + 1);
                }
            }
        }
    }

    #[test]
    fn the_record_static_vtable_carries_the_eighteen_serialized_slots() {
        assert_eq!(STRING_ID_RECORD_VTABLE_ADDRESS, 0x089a76f0);
        assert_eq!(
            STRING_ID_RECORD_VTABLE.slots,
            [
                0x082559ac, 0x00000000, 0x08129dec, 0x08129b40, 0x0821f04c, 0x08129d28,
                0x0820ed90, 0x083a4368, 0x0820e610, 0x0820f084, 0x08255b5c, 0x08255b44,
                0x0821f220, 0x0821f200, 0x0820f074, 0x0821f384, 0x0821f1f8, 0x0820f250,
            ]
        );
    }

    #[test]
    fn record_destroy_plants_derived_vtable_destroys_embedded_string_and_returns_this() {
        let _bench = bench();
        let mut record = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 42,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(
                record.string.vtable, &STRING_OBJECT_VTABLE as *const _,
                "the callee re-plants the StringObject vtable at +4"
            );
        }
        let calls = release_calls();
        assert_eq!(calls.len(), 1, "exactly one payload release");
        assert_eq!(
            calls[0].0,
            core::ptr::addr_of!(record.string) as usize,
            "the release receives the embedded subobject (this + 4 on target)"
        );
        assert_eq!(
            calls[0].1,
            &STRING_OBJECT_VTABLE as *const _ as usize,
            "the derived vtable store at +0 precedes the call, and the \
             StringObject vtable store at +4 happens inside it (str before bl)"
        );
    }

    #[test]
    fn record_destroy_derives_the_return_from_the_callee() {
        let _bench = bench();
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            // The original: r0 = string_object_destroy(this + 4); r0 -= 4.
            // The port subtracts one vtable word from the callee's return,
            // which lands back on `this` whatever the host's field padding.
            let expected = (core::ptr::addr_of_mut!(record.string) as *mut u8)
                .sub(core::mem::size_of::<usize>()) as *mut StringIdRecord;
            assert_eq!(string_id_record_destroy(this), expected);
            assert_eq!(expected, this, "and that is `this` on every host");
        }
    }

    #[test]
    fn record_destroy_with_default_ops_releases_the_embedded_payload() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        let mut payload_storage = [0u8; 8];
        let payload = payload_storage.as_mut_ptr();
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload,
            },
            id: 7,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(calls, 1);
        assert_eq!(freed, payload, "the embedded payload word is what gets freed");
        assert_eq!(tag, 0x34, "the StringObject payload release's tag");
        assert!(record.string.payload.is_null(), "the release NULLed the word");
        assert_eq!(record.id, 7, "the destructor never touches the id word");
    }

    #[test]
    fn record_default_construct_plants_both_vtables_null_payload_minus1_id() {
        let mut record = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 42,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_default_construct(this), this);
            assert_eq!(
                record.vtable,
                &STRING_ID_RECORD_VTABLE as *const _,
                "the stmia's first register: the class vtable at +0"
            );
            assert_eq!(
                record.string.vtable,
                &STRING_OBJECT_VTABLE as *const _,
                "the stmia's second register: the StringObject vtable at +4"
            );
            assert_eq!(record.id, -1, "mvn r1, #0x0 -> id word at +0xc");
            assert!(
                record.string.payload.is_null(),
                "mov r2, #0x0 -> the embedded payload word at +8"
            );
        }
    }

    #[test]
    fn record_default_construct_needs_no_heap_and_calls_nothing() {
        // The stmia inlines the StringObject default ctor: no call
        // into string_default_construct, no allocation — a recording
        // release installed on the ops slot must observe nothing, and
        // the payload word is NULLed in place, never freed.
        let _bench = bench();
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 7,
        };
        unsafe {
            string_id_record_default_construct(&mut record);
        }
        assert!(release_calls().is_empty(), "the ctor runs no destructor body");
        assert!(record.string.payload.is_null());
    }

    #[test]
    fn record_default_construct_then_destroy_roundtrips_a_fresh_record() {
        let _bench = bench();
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_default_construct(this), this);
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let calls = release_calls();
        assert_eq!(
            calls.len(),
            1,
            "destroying the fresh record runs exactly one (NULL-payload) release"
        );
        assert_eq!(calls[0].0, core::ptr::addr_of!(record.string) as usize);
        assert_eq!(record.id, -1, "destroy never rewrites the ctor's id");
    }

    // ---- string_id_record_construct_from_string_id --------------------

    /// Serializes the tests that swap `STRING_OBJECT_COPY_CONSTRUCT`
    /// (the `OPS_LOCK` precedent; a separate slot, a separate lock).
    static COPY_SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// Copy-construct dispatches observed by the recording mock:
    /// (subobject, source, class vtable word at subobject-1 read at
    /// entry), in call order.
    static mut COPY_CALLS: Vec<(usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_copy_construct(
        this: *mut StringObject,
        source: *const StringObject,
    ) -> *mut StringObject {
        // The word one pointer-width before the subobject is the
        // record's +0 class vtable: reading it here proves the outer
        // ctor's store precedes this dispatch (str before bl).
        let class_vtable = (this as *const usize).sub(1).read();
        (*core::ptr::addr_of_mut!(COPY_CALLS)).push((
            this as usize,
            source as usize,
            class_vtable,
        ));
        // The real copy constructor returns its `this` argument; the
        // port derives the record pointer from that return, so the mock
        // must too. It also leaves the subobject in the empty-string
        // state, so the record stays valid for a following destroy.
        (*this).vtable = &STRING_OBJECT_VTABLE;
        (*this).payload = core::ptr::null_mut();
        this
    }

    /// Restores the default stub on drop, even when a test panics.
    struct CopySlotGuard;
    impl Drop for CopySlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_COPY_CONSTRUCT)
                    .write_volatile(string_object_copy_construct_stub);
            }
        }
    }

    /// Installs the recording copy constructor; restores the stub on
    /// drop.
    fn copy_bench() -> (MutexGuard<'static, ()>, CopySlotGuard) {
        let lock = COPY_SLOT_LOCK.lock().unwrap();
        unsafe {
            (*core::ptr::addr_of_mut!(COPY_CALLS)).clear();
            core::ptr::addr_of_mut!(STRING_OBJECT_COPY_CONSTRUCT)
                .write_volatile(recording_copy_construct);
        }
        (lock, CopySlotGuard)
    }

    fn copy_calls() -> Vec<(usize, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(COPY_CALLS)).clone() }
    }

    #[test]
    fn record_from_string_id_plants_vtable_dispatches_stores_id_returns_this() {
        let _bench = copy_bench();
        let mut source = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let mut record = StringIdRecord {
            vtable: 0x0bad_f00d as *const StringIdRecordVtable,
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(
                string_id_record_construct_from_string_id(this, &source, 42),
                this
            );
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.id, 42, "str r4, [r0, #0xc]");
        }
        let calls = copy_calls();
        assert_eq!(calls.len(), 1, "exactly one copy-construct dispatch");
        assert_eq!(
            calls[0].0,
            core::ptr::addr_of!(record.string) as usize,
            "the chain receives the embedded subobject (this + 4 on target)"
        );
        assert_eq!(
            calls[0].1,
            core::ptr::addr_of_mut!(source) as usize,
            "the source argument is forwarded untouched (r1 survives)"
        );
        assert_eq!(
            calls[0].2,
            &STRING_ID_RECORD_VTABLE as *const _ as usize,
            "the class vtable store at +0 precedes the chain (str before bl)"
        );
    }

    #[test]
    fn record_from_string_id_derives_this_from_the_callee_return() {
        let _bench = copy_bench();
        let mut source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            // The original: r0 = copy_ctor(this + 4, source); r0 -= 4.
            // The port subtracts one vtable word from the callee's
            // return, which lands back on `this` whatever the host's
            // field padding.
            let expected = (core::ptr::addr_of_mut!(record.string) as *mut u8)
                .sub(core::mem::size_of::<usize>())
                as *mut StringIdRecord;
            assert_eq!(
                string_id_record_construct_from_string_id(this, &source, 7),
                expected
            );
            assert_eq!(expected, this, "and that is `this` on every host");
        }
    }

    #[test]
    fn record_from_string_id_stores_edge_ids_verbatim() {
        let _bench = copy_bench();
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        for id in [-1i32, i32::MIN, i32::MAX, 0, 0x1f03] {
            let mut record = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                id: 0x5555_5555,
            };
            unsafe {
                string_id_record_construct_from_string_id(&mut record, &source, id);
            }
            assert_eq!(record.id, id, "the id word at +0xc is stored verbatim");
        }
    }

    #[test]
    fn record_from_string_id_default_stub_constructs_an_empty_string() {
        // The default slot (no mock): the stub plants the StringObject
        // vtable and NULLs the payload, ignoring the source — the real
        // copy constructor's empty-construction prefix.
        let _lock = COPY_SLOT_LOCK.lock().unwrap();
        let mut source = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let source_before = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(source)
                    as *const [u8; core::mem::size_of::<StringObject>()],
            )
        };
        let mut record = StringIdRecord {
            vtable: 0x0bad_f00d as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0x1111_1111 as *const StringObjectVtable,
                payload: 0x2222_2222 as *mut u8,
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(
                string_id_record_construct_from_string_id(this, &source, 0x1f00),
                this
            );
        }
        assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
        assert_eq!(
            record.string.vtable, &STRING_OBJECT_VTABLE as *const _,
            "the stub plants the StringObject vtable at +4"
        );
        assert!(
            record.string.payload.is_null(),
            "the stub NULLs the embedded payload at +8"
        );
        assert_eq!(record.id, 0x1f00);
        let source_after = unsafe {
            core::ptr::read(core::ptr::addr_of!(source) as *const [u8; core::mem::size_of::<StringObject>()])
        };
        assert_eq!(source_after, source_before, "the stub never touches the source");
    }

    #[test]
    fn record_from_string_id_then_destroy_roundtrips() {
        // Construct through the default stub, destroy through the
        // recording release — the same round trip the default-ctor
        // roundtrip test runs, now over the (string, id) path.
        let _bench = bench();
        let _copy_lock = COPY_SLOT_LOCK.lock().unwrap();
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(
                string_id_record_construct_from_string_id(this, &source, 0x1f03),
                this
            );
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let calls = release_calls();
        assert_eq!(
            calls.len(),
            1,
            "destroying the constructed record runs exactly one (NULL-payload) release"
        );
        assert_eq!(calls[0].0, core::ptr::addr_of!(record.string) as usize);
        assert_eq!(record.id, 0x1f03, "destroy never rewrites the ctor's id");
    }

    // ---- string_id_record_copy_construct -----------------------------

    #[test]
    fn record_copy_construct_plants_vtable_dispatches_copies_id_returns_this() {
        let _bench = copy_bench();
        let mut source = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 0x1f01,
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_copy_construct(this, &source), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.id, 0x1f01, "ldr r1,[r4,#0xc]; str r1,[r0,#0xc]");
        }
        let calls = copy_calls();
        assert_eq!(calls.len(), 1, "exactly one copy-construct dispatch");
        assert_eq!(
            calls[0].0,
            core::ptr::addr_of!(record.string) as usize,
            "the chain receives the embedded subobject (this + 4 on target)"
        );
        assert_eq!(
            calls[0].1,
            core::ptr::addr_of!(source.string) as usize,
            "the source's embedded subobject is forwarded (add r1, r4, #0x4), \
             not the source record itself"
        );
        assert_eq!(
            calls[0].2,
            &STRING_ID_RECORD_VTABLE as *const _ as usize,
            "the class vtable store at +0 precedes the chain (str before bl)"
        );
    }

    #[test]
    fn record_copy_construct_derives_this_from_the_callee_return() {
        let _bench = copy_bench();
        let source = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 7,
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            // The original: r0 = copy_ctor(this + 4, source + 4); r0 -= 4.
            // The port subtracts one vtable word from the callee's
            // return, which lands back on `this` whatever the host's
            // field padding.
            let expected = (core::ptr::addr_of_mut!(record.string) as *mut u8)
                .sub(core::mem::size_of::<usize>())
                as *mut StringIdRecord;
            assert_eq!(string_id_record_copy_construct(this, &source), expected);
            assert_eq!(expected, this, "and that is `this` on every host");
        }
    }

    #[test]
    fn record_copy_construct_copies_edge_ids_verbatim() {
        let _bench = copy_bench();
        for id in [-1i32, i32::MIN, i32::MAX, 0, 0x1f03] {
            let source = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                id,
            };
            let mut record = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                id: 0x5555_5555,
            };
            unsafe {
                string_id_record_copy_construct(&mut record, &source);
            }
            assert_eq!(record.id, id, "the id word at +0xc is copied verbatim");
        }
    }

    #[test]
    fn record_copy_construct_default_stub_constructs_an_empty_string() {
        // The default slot (no mock): the stub plants the StringObject
        // vtable and NULLs the payload, ignoring the source's subobject
        // — the real copy constructor's empty-construction prefix. The
        // id copy is the outer ctor's own work and happens regardless.
        let _lock = COPY_SLOT_LOCK.lock().unwrap();
        let mut source = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 0x1f02,
        };
        let source_before = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(source)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: 0x1111_1111 as *const StringObjectVtable,
                payload: 0x2222_2222 as *mut u8,
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_copy_construct(this, &source), this);
        }
        assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
        assert_eq!(
            record.string.vtable, &STRING_OBJECT_VTABLE as *const _,
            "the stub plants the StringObject vtable at +4"
        );
        assert!(
            record.string.payload.is_null(),
            "the stub NULLs the embedded payload at +8"
        );
        assert_eq!(record.id, 0x1f02, "the outer ctor copies the id itself");
        let source_after = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(source)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        assert_eq!(source_after, source_before, "the copy never writes the source");
    }

    #[test]
    fn record_copy_construct_then_destroy_roundtrips() {
        // Copy-construct through the default stub, destroy through the
        // recording release — the same round trip the (string, id)
        // sibling runs, now over the copy path.
        let _bench = bench();
        let _copy_lock = COPY_SLOT_LOCK.lock().unwrap();
        let source = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0x1f00,
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_copy_construct(this, &source), this);
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let calls = release_calls();
        assert_eq!(
            calls.len(),
            1,
            "destroying the copied record runs exactly one (NULL-payload) release"
        );
        assert_eq!(calls[0].0, core::ptr::addr_of!(record.string) as usize);
        assert_eq!(record.id, 0x1f00, "destroy never rewrites the copied id");
    }

    // ---- string_id_record_assign -----------------------------------

    /// Serializes the tests that swap `STRING_OBJECT_ASSIGN` (the
    /// `COPY_SLOT_LOCK` precedent; a separate slot, a separate lock).
    static ASSIGN_SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// Assign dispatches observed by the recording mock: (subobject,
    /// source subobject, class vtable word at subobject-1 read at
    /// entry), in call order.
    static mut ASSIGN_CALLS: Vec<(usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_assign(
        this: *mut StringObject,
        source: *const StringObject,
    ) -> *mut StringObject {
        // The word one pointer-width before the subobject is the
        // record's +0 class vtable: the assignment operator stores NO
        // vtable, so the recorder must observe the caller's sentinel
        // here (the exact inverse of the constructor mock's check).
        let class_vtable = (this as *const usize).sub(1).read();
        (*core::ptr::addr_of_mut!(ASSIGN_CALLS)).push((
            this as usize,
            source as usize,
            class_vtable,
        ));
        // The real operator returns its `this` argument (mov r0, r4).
        this
    }

    /// Restores the default stub on drop, even when a test panics.
    struct AssignSlotGuard;
    impl Drop for AssignSlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN)
                    .write_volatile(string_object_assign_stub);
            }
        }
    }

    /// Installs the recording assign; restores the stub on drop.
    fn assign_bench() -> (MutexGuard<'static, ()>, AssignSlotGuard) {
        let lock = ASSIGN_SLOT_LOCK.lock().unwrap();
        unsafe {
            (*core::ptr::addr_of_mut!(ASSIGN_CALLS)).clear();
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN).write_volatile(recording_assign);
        }
        (lock, AssignSlotGuard)
    }

    fn assign_calls() -> Vec<(usize, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(ASSIGN_CALLS)).clone() }
    }

    #[test]
    fn record_assign_dispatches_copies_id_returns_this_and_stores_no_vtable() {
        let _bench = assign_bench();
        let mut source = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 0x1f01,
        };
        let mut record = StringIdRecord {
            vtable: 0x5555_5555 as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0x1111_1111 as *const StringObjectVtable,
                payload: 0x2222_2222 as *mut u8,
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_assign(this, &source), this);
            assert_eq!(record.id, 0x1f01, "ldr r0,[r5,#0xc]; str r0,[r4,#0xc]");
            assert_eq!(
                record.vtable, 0x5555_5555 as *const StringIdRecordVtable,
                "assignment never replants the class vtable (no str [r4,#0x0])"
            );
        }
        let calls = assign_calls();
        assert_eq!(calls.len(), 1, "exactly one assign dispatch");
        assert_eq!(
            calls[0].0,
            core::ptr::addr_of!(record.string) as usize,
            "the chain receives the embedded subobject (add r0, r0, #0x4)"
        );
        assert_eq!(
            calls[0].1,
            core::ptr::addr_of!(source.string) as usize,
            "the SOURCE's embedded subobject is forwarded (add r1, r1, #0x4), \
             not the source record itself"
        );
        assert_eq!(
            calls[0].2, 0x5555_5555usize,
            "no vtable store precedes the chain: the +0 word is still the sentinel"
        );
    }

    #[test]
    fn record_assign_returns_its_own_this_not_the_callee_return() {
        // The original ends `mov r0, r4` — the saved `this` — so the
        // callee's return value is discarded entirely. A mock that
        // returns a bogus pointer proves the port does the same (the
        // constructor siblings instead DERIVE this from the return).
        unsafe extern "C" fn bogus_assign(
            _this: *mut StringObject,
            _source: *const StringObject,
        ) -> *mut StringObject {
            0x1usize as *mut StringObject
        }
        let _lock = ASSIGN_SLOT_LOCK.lock().unwrap();
        let _guard = AssignSlotGuard;
        unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN).write_volatile(bogus_assign);
        }
        let source = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 7,
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(
                string_id_record_assign(this, &source),
                this,
                "mov r0, r4: the saved `this`, not the callee's r0"
            );
        }
    }

    #[test]
    fn record_assign_copies_edge_ids_verbatim() {
        let _bench = assign_bench();
        for id in [-1i32, i32::MIN, i32::MAX, 0, 0x1f03] {
            let source = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                id,
            };
            let mut record = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                id: 0x5555_5555,
            };
            unsafe {
                string_id_record_assign(&mut record, &source);
            }
            assert_eq!(record.id, id, "the id word at +0xc is copied verbatim");
        }
    }

    #[test]
    fn record_assign_default_stub_leaves_both_objects_untouched_except_id() {
        // The default slot (no mock): the stub is the real operator's
        // self-assignment-guard prefix — guard, no payload work — so
        // the payload/vtable words on both sides are untouched and the
        // id copy is the outer operator's own work.
        let _lock = ASSIGN_SLOT_LOCK.lock().unwrap();
        let mut source = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: 0x0bad_f00d as *mut u8,
            },
            id: 0x1f02,
        };
        let source_before = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(source)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        let mut record = StringIdRecord {
            vtable: 0x5555_5555 as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0x1111_1111 as *const StringObjectVtable,
                payload: 0x2222_2222 as *mut u8,
            },
            id: -1,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_assign(this, &source), this);
        }
        assert_eq!(record.id, 0x1f02, "the outer operator copies the id itself");
        assert_eq!(
            record.vtable, 0x5555_5555 as *const StringIdRecordVtable,
            "the stub stores no vtable"
        );
        assert_eq!(
            record.string.vtable, 0x1111_1111 as *const StringObjectVtable,
            "the stub never touches the destination subobject"
        );
        assert_eq!(record.string.payload, 0x2222_2222 as *mut u8);
        let source_after = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(source)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        assert_eq!(source_after, source_before, "the assignment never writes the source");
    }

    #[test]
    fn record_assign_self_assignment_through_default_stub_is_a_noop() {
        // Record self-assignment: the subobject pointers compare equal
        // inside the StringObject operator (its cmp r0, r1), which the
        // stub reproduces — and the id self-copy is value-preserving.
        let _lock = ASSIGN_SLOT_LOCK.lock().unwrap();
        let mut record = StringIdRecord {
            vtable: 0x5555_5555 as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0x1111_1111 as *const StringObjectVtable,
                payload: 0x2222_2222 as *mut u8,
            },
            id: 0x1f03,
        };
        let before = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(record)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_assign(this, this), this);
        }
        let after = unsafe {
            core::ptr::read(
                core::ptr::addr_of!(record)
                    as *const [u8; core::mem::size_of::<StringIdRecord>()],
            )
        };
        assert_eq!(after, before, "self-assignment changes nothing");
    }

    #[test]
    fn record_assign_then_destroy_roundtrips() {
        // Default-construct a record, assign over it through the
        // default stub, destroy through the recording release — the
        // same round trip the constructor siblings run, now over the
        // assignment path.
        let _bench = bench();
        let _assign_lock = ASSIGN_SLOT_LOCK.lock().unwrap();
        let source = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0x1f00,
        };
        let mut record = StringIdRecord {
            vtable: core::ptr::null(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            id: 0,
        };
        let this: *mut StringIdRecord = &mut record;
        unsafe {
            assert_eq!(string_id_record_default_construct(this), this);
            assert_eq!(string_id_record_assign(this, &source), this);
            assert_eq!(record.id, 0x1f00);
            assert_eq!(string_id_record_destroy(this), this);
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        let calls = release_calls();
        assert_eq!(
            calls.len(),
            1,
            "destroying the assigned record runs exactly one (NULL-payload) release"
        );
        assert_eq!(calls[0].0, core::ptr::addr_of!(record.string) as usize);
        assert_eq!(record.id, 0x1f00, "destroy never rewrites the assigned id");
    }

    // ---- string_id_record_equals -----------------------------------


    /// A record with a garbage vtable, a garbage StringObject vtable,
    /// the given payload and id.
    fn test_record(payload: *mut u8, id: i32) -> StringIdRecord {
        StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload,
            },
            id,
        }
    }

    #[test]
    fn record_equals_compares_payload_strings_and_ids() {
        let mut this_storage = *b"artist\0";
        let mut source_storage = *b"artist\0";
        let mut other_storage = *b"album\0";
        let this_rec = test_record(this_storage.as_mut_ptr(), 7);
        let same_rec = test_record(source_storage.as_mut_ptr(), 7);
        let different_id = test_record(source_storage.as_mut_ptr(), 8);
        let different_string = test_record(other_storage.as_mut_ptr(), 7);
        unsafe {
            assert_eq!(string_id_record_equals(&this_rec, &same_rec), 1);
            assert_eq!(string_id_record_equals(&this_rec, &different_id), 0);
            assert_eq!(string_id_record_equals(&this_rec, &different_string), 0);
        }
    }

    #[test]
    fn record_equals_treats_null_payload_as_empty() {
        let a = test_record(core::ptr::null_mut(), -1);
        let b = test_record(core::ptr::null_mut(), -1);
        let different_id = test_record(core::ptr::null_mut(), 0);
        unsafe {
            assert_eq!(string_id_record_equals(&a, &b), 1);
            assert_eq!(string_id_record_equals(&a, &different_id), 0);
        }
    }

    fn decode_next(bytes: &[u8]) -> (u32, usize) {
        let start = bytes.as_ptr();
        let mut cursor = start;
        let codepoint = unsafe { utf8_next_codepoint(&mut cursor) };
        let consumed = unsafe { cursor.offset_from(start) as usize };
        (codepoint, consumed)
    }

    #[test]
    fn utf8_next_codepoint_consumes_one_ascii_byte_including_nul() {
        assert_eq!(decode_next(&[0x00]), (0, 1));
        assert_eq!(decode_next(&[0x7f]), (0x7f, 1));
    }

    #[test]
    fn utf8_next_codepoint_decodes_two_bytes_without_continuation_validation() {
        assert_eq!(decode_next(&[0xc2, 0xa2]), (0x00a2, 2));
        assert_eq!(
            decode_next(&[0xc2, 0xff]),
            (0x00bf, 2),
            "the decoder masks a malformed second byte instead of rejecting it"
        );
    }

    #[test]
    fn utf8_next_codepoint_decodes_three_bytes_without_continuation_validation() {
        assert_eq!(decode_next(&[0xe2, 0x82, 0xac]), (0x20ac, 3));
        assert_eq!(
            decode_next(&[0xef, 0xff, 0x80]),
            (0xffc0, 3),
            "both continuation bytes are merely payload-masked"
        );
    }

    #[test]
    fn utf8_next_codepoint_invalid_and_four_byte_leads_consume_three_and_return_zero() {
        for sequence in [
            [0x80, 0xaa, 0xbb, 0xcc],
            [0xbf, 0xaa, 0xbb, 0xcc],
            [0xf0, 0x9f, 0x92, 0xa9],
            [0xf7, 0xaa, 0xbb, 0xcc],
            [0xff, 0xaa, 0xbb, 0xcc],
        ] {
            assert_eq!(
                decode_next(&sequence),
                (0, 3),
                "lead byte {:#04x}",
                sequence[0]
            );
        }
    }

    // ---- utf8_strcmp_safe -------------------------------------------

    fn compare(a: &[u8], b: &[u8]) -> i32 {
        unsafe { utf8_strcmp_safe(a.as_ptr(), b.as_ptr()) }
    }

    #[test]
    fn utf8_strcmp_safe_compares_ascii_prefixes_and_raw_first_difference() {
        assert_eq!(compare(b"abc\0", b"abc\0"), 0);
        assert_eq!(compare(b"abc\0", b"abd\0"), -1);
        assert_eq!(compare(b"abd\0", b"abc\0"), 1);
        assert_eq!(compare(b"ab\0", b"abc\0"), -99, "NUL - 'c'");
        assert_eq!(compare(b"abc\0", b"ab\0"), 99, "'c' - NUL");
    }

    #[test]
    fn utf8_strcmp_safe_compares_decoded_multibyte_codepoints() {
        assert_eq!(
            compare(&[0xc3, 0xa0, 0], &[0xc2, 0xbf, 0]),
            33,
            "U+00E0 - U+00BF, not the lead-byte difference"
        );
        assert_eq!(
            compare(&[0xe2, 0x82, 0xac, 0], &[0xe2, 0x82, 0xad, 0]),
            -1,
            "U+20AC - U+20AD"
        );
    }

    #[test]
    fn utf8_strcmp_safe_substitutes_the_shared_empty_for_null() {
        unsafe {
            assert_eq!(utf8_strcmp_safe(core::ptr::null(), core::ptr::null()), 0);
            assert_eq!(utf8_strcmp_safe(core::ptr::null(), b"\0".as_ptr()), 0);
            assert_eq!(utf8_strcmp_safe(core::ptr::null(), b"a\0".as_ptr()), -97);
            assert_eq!(utf8_strcmp_safe(b"a\0".as_ptr(), core::ptr::null()), 97);
        }
    }

    #[test]
    fn utf8_strcmp_safe_uses_decoder_results_for_malformed_and_four_byte_leads() {
        assert_eq!(
            compare(&[0xc2, 0xff, 0], &[0xc2, 0xbf, 0]),
            0,
            "the decoder payload-masks malformed continuation bytes"
        );
        assert_eq!(
            compare(&[0xf0, 0x9f, 0x92, 0xa9, b'x', 0], b"\0"),
            0,
            "a four-byte lead decodes as the comparator's terminator"
        );
    }
}
