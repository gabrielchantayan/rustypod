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
//! - `string_object_assign_cstr` — original: `FUN_0827639c` @
//!   0x0827639c (100 bytes).
//!   Assigns a nonempty caller-owned C string by asking virtual slot
//!   +0x8 for exactly `strlen(source) + 1` bytes with flag zero, then
//!   copying the source (including its NUL) into the returned storage.
//!   A NULL or empty source instead tail-dispatches virtual slot +0xc;
//!   an allocation failure returns without copying or falling back.
//! - `string_object_assign_utf16` — original: `FUN_082765a8` @
//!   0x082765a8 (120 bytes, all code; 48 `bl` call sites — 47
//!   unconditional, 1 predicated — binary-scanned). The UTF-16 sibling
//!   of `string_object_assign_payload`: transcodes a bounded UTF-16
//!   range into the payload. It sizes the storage with the ported
//!   bounded counter `utf16_utf8_byte_len_bounded_plus1` @ 0x08276338,
//!   asks virtual slot +0x8 for exactly that many bytes with flag zero,
//!   runs the (unported) transcoder @ 0x0827675c into the result and
//!   writes the terminator itself at `byte_len - 1`. Its guard tests the
//!   COUNT, not the first code unit: only a NULL pointer or a
//!   non-positive count tail-dispatches virtual slot +0xc.
//! - `string_object_construct_from_cstr` — original: `FUN_08277304` @
//!   0x08277304 (44 bytes: 40 code + the 4-byte vtable literal @
//!   0x0827732c; 143 `bl` call sites, binary-scanned). The converting
//!   constructor `StringObject(const char *)`: plants the vtable, NULLs
//!   the payload word so the shared assignment path sees no prior
//!   payload to release, then chains to `string_object_assign_cstr` @
//!   0x0827639c with the caller's C string; returns `this`.
//! - `string_object_copy_construct` — original: `FUN_082773e0` @
//!   0x082773e0 (52 bytes: 48 code + the 4-byte vtable literal @
//!   0x08277410; 212 `bl` call sites, binary-scanned). The copy
//!   constructor: plants the vtable unconditionally, and only when
//!   `this != source` (an ADDRESS test) NULLs the payload word and
//!   duplicates the source's payload through
//!   `string_object_assign_payload` @ 0x08276474; returns `this`. It is
//!   the wired default of the [`STRING_OBJECT_COPY_CONSTRUCT`] slot.
//! - `retail_vsnprintf` — original: `FUN_08074ba0` @ 0x08074ba0
//!   (60 bytes, all code). A second bounded `vsnprintf` veneer: for a
//!   nonzero size it passes the string sink descriptor, a mutable output
//!   cursor, `size - 1`, format, and va_list to conversion core
//!   0x08077c94; then writes one NUL at the core's final cursor and
//!   returns the core's count. A zero size returns zero without calling
//!   the core or touching the buffer.
//! - `string_object_format` — original: `FUN_082769d4` @ 0x082769d4
//!   (68 bytes, all code; 117 `bl` call sites, binary-scanned). The
//!   class's printf-style assignment, `int format(const char *fmt,
//!   ...)`: formats into a 512-byte stack scratch buffer through the
//!   bounded formatter @ 0x08074ba0, hands the buffer to
//!   `string_object_assign_payload` @ 0x08276474, and returns the
//!   formatter's character count.
//! - `string_object_insert_cstr` — original: `FUN_08276a18` @
//!   0x08276a18 (68 bytes, all code; 61 `bl` call sites,
//!   binary-scanned). The guard wrapper of the class's insert
//!   operation, `void insert(int index, const char *source)`: a NULL
//!   or empty source and a negative index are silent no-ops, otherwise
//!   the source's byte length is measured through
//!   `strlen_safe_plus1` @ 0x08275e20 and the call tail-branches to
//!   the (unported) insert core @ 0x08275f48, which resolves the UTF-8
//!   character index to a byte position and splices the source in.
//! - `utf8_codepoint_count_safe` — original: `FUN_082770e0` @
//!   0x082770e0 (48 bytes, all code; 102 `bl` call sites,
//!   binary-scanned). The UTF-8 counterpart of the NULL-guarded
//!   `strlen_safe` @ 0x082770bc it sits immediately after: it counts
//!   *codepoints* by walking the string through
//!   `utf8_next_codepoint` @ 0x08276214 until that decoder reports
//!   zero. NULL returns 0 without decoding.
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
//! - `string_object_destroy_veneer` — original: `thunk_FUN_082792fc` @
//!   0x082792fc (4 bytes: the single word `b 0x08277484`; **98** `bl`
//!   call sites, binary-scanned). The long-branch veneer through which
//!   the far callers reach `string_object_destroy`.
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
//! - `string_object_utf8_strcmp_safe` — original: `FUN_082a5368` @
//!   0x082a5368 (8 bytes; 39 `bl` call sites, binary-scanned, zero
//!   predicated). A two-instruction thunk (`ldr r0,[r0,#4]; b
//!   0x08276d64`) that tail-branches to the ported
//!   [`utf8_strcmp_safe`] over the payload word at +4 with the second
//!   argument passed through in r1 — the class's compare-against-C-
//!   string, consumed by keyword-dispatch chains as an equality test.
//! - `string_object_is_empty` — original: `FUN_082a5370` @ 0x082a5370
//!   (28 bytes, all code — no literal-pool word; 55 `bl` call sites,
//!   binary-scanned). The emptiness predicate of the same string
//!   class: true when the payload word at +4 is NULL or points at a
//!   NUL byte. Byte-identical-alias scan: the exact 7-word pattern
//!   occurs ONCE in osos.dec — this function has no twins.
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
//!   serialized slot addresses verbatim. [`string_object_assign_cstr`]
//!   models its two virtual calls with the explicit injectable
//!   [`STRING_OBJECT_ASSIGN_CSTR_OPS`] boundary instead of treating
//!   those ROM addresses as host-callable pointers.
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
//!   StringObject copy constructor @ 0x082773e0 through the
//!   [`STRING_OBJECT_COPY_CONSTRUCT`] dispatch slot (the
//!   util/inner_state.rs `INNER_MATERIALIZE_COUNT` pattern) so host
//!   tests can observe the dispatch; the wired default is the ported
//!   [`string_object_copy_construct`] itself. Like
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
//! - `string_object_insert_cstr` tail-branches to the insert core @
//!   0x08275f48, which is NOT ported, so the branch dispatches through
//!   the [`STRING_OBJECT_INSERT_CORE`] slot (the
//!   [`RETAIL_VSNPRINTF_ENGINE`] pattern). The default no-op
//!   reproduces only the core's own early-return paths — the ones the
//!   wrapper's guards make unreachable — so the port is NOT
//!   hook-ready until the core is ported and wired in.

use core::mem::MaybeUninit;

use crate::heap::veneers::{free_wrapper, operator_delete};
use crate::libc::strcpy::strcpy;
use crate::libc::strlen_safe::strlen_safe;
use crate::libc::strlen_safe_plus1::strlen_safe_plus1;
use crate::printf::printf_api::VaList;

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

/// Explicit host-model boundary for the `StringObject` virtual calls in
/// [`string_object_assign_cstr`]. On retailOS these are the object's vtable
/// slots +0x8 and +0xc respectively; the modeled host vtable retains ROM
/// addresses only, so it cannot be invoked as native host function pointers.
///
/// `allocate_payload` owns whatever replacement/free protocol the concrete
/// object needs. The assignment routine neither frees the caller-owned source
/// nor writes `this.payload` directly: after a non-NULL result it only copies
/// source bytes into the returned storage. `clear_payload` is the exact
/// NULL/empty fallback dispatch and likewise owns its payload cleanup.
#[derive(Clone, Copy)]
pub struct StringObjectAssignCstrOps {
    /// Original vtable slot +0x8: obtain storage for a replacement payload.
    pub allocate_payload: unsafe extern "C" fn(
        this: *mut StringObject,
        requested_size: usize,
        flags: u32,
    ) -> *mut u8,
    /// Original vtable slot +0xc: clear/release the current payload.
    pub clear_payload: unsafe extern "C" fn(this: *mut StringObject),
}

/// Default boundary before the two virtual callees are ported. Returning NULL
/// takes the original caller's allocation-failure exit; the no-op clear is
/// intentionally not a substitute for the unported +0xc virtual method.
unsafe extern "C" fn missing_assign_cstr_allocation(
    _this: *mut StringObject,
    _requested_size: usize,
    _flags: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn missing_assign_cstr_clear(_this: *mut StringObject) {}

/// Wired defaults for [`STRING_OBJECT_ASSIGN_CSTR_OPS`].
pub const DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS: StringObjectAssignCstrOps =
    StringObjectAssignCstrOps {
        allocate_payload: missing_assign_cstr_allocation,
        clear_payload: missing_assign_cstr_clear,
    };

/// Active model of vtable slots +0x8/+0xc for
/// [`string_object_assign_cstr`]. Tests replace these boundaries to observe
/// the exact dispatch protocol; a later port of either virtual callee replaces
/// its corresponding default without changing this caller.
pub static mut STRING_OBJECT_ASSIGN_CSTR_OPS: StringObjectAssignCstrOps =
    DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS;

#[inline(always)]
unsafe fn assign_cstr_allocate_op() -> unsafe extern "C" fn(
    *mut StringObject,
    usize,
    u32,
) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        STRING_OBJECT_ASSIGN_CSTR_OPS.allocate_payload
    ))
}

#[inline(always)]
unsafe fn assign_cstr_clear_op() -> unsafe extern "C" fn(*mut StringObject) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        STRING_OBJECT_ASSIGN_CSTR_OPS.clear_payload
    ))
}

/// string_object_assign_cstr — original: `FUN_0827639c` @ 0x0827639c
/// (100 bytes).
///
/// Source: `ipod-decomp/decomp/c/026/0827639c_FUN_0827639c.c`.
///
/// Assigns the caller-owned, NUL-terminated `source` to this polymorphic
/// string object. It makes its branch decision from precisely the source
/// pointer and first byte: NULL and `source[0] == 0` invoke vtable slot +0xc
/// with only `this`; nonempty source requests `strlen_safe(source) + 1` bytes
/// through vtable slot +0x8 with a zero flag. A NULL allocation result is an
/// immediate failure return: it neither copies source nor invokes the +0xc
/// fallback. Otherwise `strcpy` copies through the NUL into the returned
/// storage. The source remains caller-owned; replacement/free ownership of
/// this object's prior payload belongs solely to the virtual boundaries.
///
/// The virtual callees are intentionally not ported here. They are modeled by
/// [`STRING_OBJECT_ASSIGN_CSTR_OPS`], an injectable faithful boundary for
/// slots +0x8/+0xc because [`STRING_OBJECT_VTABLE`] stores ROM identities,
/// not callable host pointers. No NULL guard exists for `this`, matching the
/// original's dereference to load its vtable before either virtual call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_assign_cstr(this: *mut StringObject, source: *const u8) {
    if source.is_null() || source.read() == 0 {
        assign_cstr_clear_op()(this);
        return;
    }

    let requested_size = strlen_safe(source).wrapping_add(1);
    let destination = assign_cstr_allocate_op()(this, requested_size, 0);
    if destination.is_null() {
        return;
    }
    strcpy(destination, source);
}

/// string_object_assign_payload — original: `FUN_08276474` @ 0x08276474
/// (100 bytes).
///
/// Source: `ipod-decomp/decomp/c/026/08276474_FUN_08276474.c`.
///
/// Assigns the caller-supplied C-string payload used by the StringObject copy
/// assignment operator. NULL and an empty payload dispatch only vtable slot
/// +0xc with `this`. Otherwise it calls the inclusive-length helper
/// [`strlen_safe_plus1`] @ 0x08275e20, requests exactly that many bytes from
/// vtable slot +0x8 as `(this, requested_size, 0)`, and copies the source
/// including its NUL terminator into the returned storage. A NULL allocation
/// result returns immediately without copying or falling back to +0xc.
///
/// The allocation virtual call owns replacing/freeing this object's prior
/// payload; this helper neither frees nor stores the payload word itself.
/// The two virtual callees remain modeled by
/// [`STRING_OBJECT_ASSIGN_CSTR_OPS`], because the modeled vtable contains ROM
/// identities rather than host-callable pointers. As in the original, `this`
/// is not NULL-guarded before virtual dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_assign_payload(
    this: *mut StringObject,
    payload: *const u8,
) {
    if payload.is_null() || payload.read() == 0 {
        assign_cstr_clear_op()(this);
        return;
    }

    let requested_size = strlen_safe_plus1(payload);
    let destination = assign_cstr_allocate_op()(this, requested_size, 0);
    if destination.is_null() {
        return;
    }
    strcpy(destination, payload);
}

/// The unported UTF-16 -> UTF-8 transcoder @ 0x0827675c, the writing half
/// of [`string_object_assign_utf16`] (124 bytes: 0x0827675c..0x082767d8,
/// where the next function's `push {r3, r4, lr}` begins; 5 `bl` call
/// sites, binary-scanned).
///
/// It converts at most `max_code_units` UTF-16 units into `destination`
/// with the same 0x80/0x800 thresholds the sizing helper
/// [`utf16_utf8_byte_len_bounded_plus1`] @ 0x08276338 counts by (and the
/// same absence of surrogate pairing), stops early on a UTF-16 NUL after
/// storing that NUL as a single zero byte, appends no terminator of its
/// own, and returns the number of code units consumed.
pub type Utf16ToUtf8Fn = unsafe extern "C" fn(
    destination: *mut u8,
    utf16: *const u16,
    max_code_units: i32,
) -> i32;

/// Placeholder for the unported transcoder. It writes nothing and reports
/// zero code units, so the storage [`string_object_assign_utf16`] obtained
/// keeps whatever the allocation left in it apart from the terminator the
/// assignment itself writes.
unsafe extern "C" fn utf16_to_utf8_stub(
    _destination: *mut u8,
    _utf16: *const u16,
    _max_code_units: i32,
) -> i32 {
    0
}

/// Active model of the transcoder @ 0x0827675c. A later port of that
/// function replaces this default without changing its caller.
pub static mut STRING_OBJECT_UTF16_TRANSCODE: Utf16ToUtf8Fn = utf16_to_utf8_stub;

#[inline(always)]
unsafe fn utf16_transcode_op() -> Utf16ToUtf8Fn {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_UTF16_TRANSCODE))
}

/// string_object_assign_utf16 — original: `FUN_082765a8` @ 0x082765a8
/// (120 bytes, all code — no literal-pool word; the next function's
/// `push {r3, r4, r5, lr}` starts at 0x08276620). **48 `bl` call sites**
/// (47 unconditional, 1 predicated) and 0 tail `b`, binary-scanned by
/// decoding every ARM `B`/`BL` word in `work/firmware/osos.dec` for every
/// condition code.
///
/// The UTF-16 sibling of [`string_object_assign_payload`] @ 0x08276474:
/// `void assign(const unsigned short *utf16, int max_code_units)`. It
/// transcodes a bounded UTF-16 range into this object's payload.
///
/// ```text
/// subs  r5, r1, #0        ; utf16
/// cmpne r6, #0            ; only when utf16 != NULL
/// ldrle r1, [vtable, #12] ; utf16 == NULL || max_code_units <= 0
/// bxle  r1                ;   -> tail-dispatch slot +0xc with `this`
/// bl    0x08276338        ; utf16_utf8_byte_len_bounded_plus1(utf16, n)
/// blx   [vtable, #8]      ; allocate(this, byte_len, 0)
/// movs  r4, r0
/// popeq {..., pc}         ; NULL allocation: no copy, no +0xc fallback
/// bl    0x0827675c        ; transcode(destination, utf16, n)
/// add   r1, r4, r7
/// strb  r0, [r1, #-1]     ; destination[byte_len - 1] = 0
/// ```
///
/// Three details separate it from the C-string siblings. The guard tests
/// the **count**, not `source[0]`: a NULL pointer or a non-positive
/// `max_code_units` (the `LE` is signed) is the only path to virtual slot
/// +0xc, so a range whose first code unit is a UTF-16 NUL still allocates
/// — one byte, holding just the terminator. The size handed to slot +0x8
/// is the exact UTF-8 byte length the bounded counter @ 0x08276338
/// reports, terminator included, so the allocation and the transcoder
/// agree on the encoding thresholds by construction. And the NUL is
/// written by *this* function at `destination[byte_len - 1]`, from the
/// sizing helper's count rather than from the transcoder's return value,
/// which is discarded.
///
/// The two virtual callees remain modeled by
/// [`STRING_OBJECT_ASSIGN_CSTR_OPS`] (slots +0x8/+0xc) and the transcoder
/// by [`STRING_OBJECT_UTF16_TRANSCODE`], because [`STRING_OBJECT_VTABLE`]
/// stores ROM identities rather than host-callable pointers and
/// 0x0827675c is not yet ported. As in the original, `this` is not
/// NULL-guarded before virtual dispatch, and the source range stays
/// caller-owned — the allocation virtual call owns replacing and freeing
/// any prior payload.
///
/// The byte length is kept `i32` and the terminator addressed with a
/// signed `offset`, preserving the original's 32-bit signed arithmetic:
/// the counter documents that its sum wraps, and a wrapped count would
/// index backwards from `destination` on the target exactly as it does
/// here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_assign_utf16(
    this: *mut StringObject,
    utf16: *const u16,
    max_code_units: i32,
) {
    if utf16.is_null() || max_code_units <= 0 {
        assign_cstr_clear_op()(this);
        return;
    }

    let requested_size = utf16_utf8_byte_len_bounded_plus1(utf16, max_code_units);
    let destination = assign_cstr_allocate_op()(this, requested_size as usize, 0);
    if destination.is_null() {
        return;
    }
    utf16_transcode_op()(destination, utf16, max_code_units);
    destination.offset(requested_size as isize - 1).write(0);
}

/// Size of the stack scratch buffer [`string_object_format`] formats into
/// (`sub sp, sp, #516` reserves 512 bytes at `sp + 4` plus a 4-byte
/// alignment pad, and `mov r1, #512` is the length handed to vsnprintf).
pub const STRING_OBJECT_FORMAT_BUFFER_LEN: usize = 512;

/// Firmware sink descriptor passed to the conversion core by
/// [`retail_vsnprintf`] (the literal-pool word at 0x08074bdc).
pub const RETAIL_VSNPRINTF_SINK_ADDRESS: usize = 0x0807ca58;

/// The unported conversion core @ 0x08077c94 used by [`retail_vsnprintf`].
///
/// It receives the sink descriptor, an in/out cursor, the maximum number of
/// non-NUL bytes, format, and the va_list. It owns conversion and bounded
/// emission; this module only ports the veneer around it.
pub type RetailVsnprintfEngineFn = unsafe extern "C" fn(
    sink: usize,
    cursor: *mut *mut u8,
    maximum: usize,
    format: *const u8,
    args: VaList,
) -> i32;

/// Placeholder for the unported conversion core. It emits nothing, leaving
/// the cursor intact; [`retail_vsnprintf`] therefore supplies the empty
/// C string its original veneer guarantees.
unsafe extern "C" fn retail_vsnprintf_engine_stub(
    _sink: usize,
    _cursor: *mut *mut u8,
    _maximum: usize,
    _format: *const u8,
    _args: VaList,
) -> i32 {
    0
}

/// Active conversion core for [`retail_vsnprintf`]. Host tests replace this
/// seam because the 0x08077c94 conversion engine has not been ported.
pub static mut RETAIL_VSNPRINTF_ENGINE: RetailVsnprintfEngineFn = retail_vsnprintf_engine_stub;

/// retail_vsnprintf — original: `FUN_08074ba0` @ 0x08074ba0 (60 bytes).
///
/// The firmware's second `vsnprintf` implementation, named
/// `retail_vsnprintf` here to distinguish it from the separately ported
/// standard-library veneer at 0x08032f94. For a nonzero `size`, create a
/// local output cursor at `buf`, call conversion core 0x08077c94 with its
/// serialized string sink descriptor and `size - 1` byte budget, then put a
/// NUL at the cursor the core leaves behind. Return the core's result
/// unchanged. With `size == 0`, return zero before invoking the core or
/// accessing `buf`.
///
/// Register usage: r0 = buf, r1 = size, r2 = format, r3 = ap. The explicit
/// [`VaList`] is ABI-exact: this is C's `vsnprintf`, not a variadic veneer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_vsnprintf(
    buf: *mut u8,
    size: usize,
    format: *const u8,
    args: VaList,
) -> i32 {
    if size == 0 {
        return 0;
    }

    let mut cursor = buf;
    let count = core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_VSNPRINTF_ENGINE))(
        RETAIL_VSNPRINTF_SINK_ADDRESS,
        &mut cursor,
        size - 1,
        format,
        args,
    );
    cursor.write(0);
    count
}

/// string_object_format — original: `FUN_082769d4` @ 0x082769d4
/// (68 bytes, all code — no literal-pool word; 117 `bl` call sites,
/// binary-scanned).
///
/// `int StringObject::format(const char *format, ...)`: the class's
/// printf-style assignment. Decoded from the raw ARM at 0x082769d4:
///
/// ```text
/// push {r0, r1, r2, r3}   ; ADS variadic spill: this, format, arg, arg
/// push {r4, r5, lr}
/// sub  sp, sp, #516       ; 512-byte scratch at sp+4, 4-byte pad at sp+0
/// mov  r5, r0             ; r5 = this
/// ldr  r2, [sp, #532]     ; r2 = the spilled `format`
/// add  r0, sp, #4         ; r0 = scratch
/// add  r3, sp, #536       ; r3 = &spilled arg 2 — the va_list
/// mov  r1, #512
/// bl   0x08074ba0         ; vsnprintf(scratch, 512, format, va)
/// mov  r4, r0             ; keep the formatted length
/// mov  r0, r5
/// add  r1, sp, #4
/// bl   0x08276474         ; string_object_assign_payload(this, scratch)
/// mov  r0, r4
/// add  sp, sp, #516
/// pop  {r4, r5}
/// ldr  pc, [sp], #20      ; return, dropping the variadic spill
/// ```
///
/// Format the caller's arguments into a 512-byte stack buffer, hand that
/// buffer to [`string_object_assign_payload`] (which sizes and requests
/// replacement storage through vtable slot +0x8, or dispatches slot +0xc
/// when the formatted text came out empty), and return the formatter's
/// character count — *not* `this`, and not the stored length. The scratch
/// buffer is caller-owned stack: the object always receives a copy.
///
/// Call sites confirm the shape, e.g. @ 0x08176a4c the format literal is
/// `"%s, %s"` with two string arguments, and @ 0x0816ff3c it is `"%d"`.
/// There is no NULL guard on `this` — the original dereferences it inside
/// the assignment for the vtable, and so does the port.
///
/// Deviations:
/// - The variadic `...` becomes an explicit [`VaList`] (house convention,
///   see `printf/printf_api.rs`): stable Rust cannot define C-variadic
///   functions, and `args` IS the pointer the original's spill builds.
/// - The veneer @ 0x08074ba0 is ported directly as [`retail_vsnprintf`].
///   Its conversion core @ 0x08077c94 remains an explicit
///   [`RETAIL_VSNPRINTF_ENGINE`] seam; the default emits no text, rather than
///   borrowing the distinct 0x08032f94 printf engine.
/// - The scratch buffer is [`core::mem::MaybeUninit`], matching the
///   original's unwritten stack frame; the formatter's NUL termination is
///   what makes it readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_format(
    this: *mut StringObject,
    format: *const u8,
    args: VaList,
) -> i32 {
    let mut scratch = MaybeUninit::<[u8; STRING_OBJECT_FORMAT_BUFFER_LEN]>::uninit();
    let scratch = scratch.as_mut_ptr() as *mut u8;

    let length = retail_vsnprintf(scratch, STRING_OBJECT_FORMAT_BUFFER_LEN, format, args);
    string_object_assign_payload(this, scratch);
    length
}

/// The unported insert core @ 0x08275f48 that
/// [`string_object_insert_cstr`] tail-branches to. It re-checks the
/// wrapper's guards (NULL/empty source, negative index — all already
/// excluded by the wrapper), grows the payload through vtable slot +0x8
/// to `(old_len + source_len + 1 + 0x1f) & !0x1f` bytes, resolves the
/// UTF-8 character `index` to a byte pointer (0x082a50c4), shifts the
/// tail with memmove, copies the source in with memcpy, and writes the
/// final NUL. `source_len` is the source's byte length WITHOUT its NUL.
pub type StringObjectInsertCoreFn = unsafe extern "C" fn(
    this: *mut StringObject,
    index: i32,
    source: *const u8,
    source_len: usize,
);

/// Placeholder for the unported insert core @ 0x08275f48. A no-op is
/// exactly the core's own early-return paths — the only ones reachable
/// past the wrapper's guards (nonempty source, nonnegative index) — and
/// is intentionally not a substitute for the core's grow/shift/copy
/// body: this port is NOT hook-ready until 0x08275f48 is ported and
/// wired in as the default.
unsafe extern "C" fn missing_insert_core(
    _this: *mut StringObject,
    _index: i32,
    _source: *const u8,
    _source_len: usize,
) {
}

/// Active insert core for [`string_object_insert_cstr`] (the
/// [`RETAIL_VSNPRINTF_ENGINE`] pattern). Host tests install a recording
/// mock; a later port of 0x08275f48 replaces the default without
/// changing this caller.
pub static mut STRING_OBJECT_INSERT_CORE: StringObjectInsertCoreFn = missing_insert_core;

/// string_object_insert_cstr — original: `FUN_08276a18` @ 0x08276a18
/// (68 bytes, all code — no literal-pool word; 61 `bl` call sites,
/// binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/026/08276a18_FUN_08276a18.c` (Ghidra
/// inlines the tail-branch target 0x08275f48 into the body; the raw
/// ARM below is the whole 68-byte function).
///
/// The guard wrapper of the class's insert operation,
/// `void StringObject::insert(int index, const char *source)`.
/// Decoded from the raw ARM at 0x08276a18:
///
/// ```text
/// push {r4, r5, r6, lr}
/// movs r4, r2            ; r4 = source, flags from the pointer itself
/// mov  r6, r0            ; r6 = this
/// ldrbne r0, [r4]        ; source != NULL: r0 = source[0]
/// mov  r5, r1            ; r5 = index
/// cmpne r0, #0           ; source != NULL: test the first byte
/// popeq {r4, r5, r6, pc} ; return when source == NULL or source[0] == 0
/// cmp  r5, #0
/// poplt {r4, r5, r6, pc} ; return when index < 0
/// mov  r0, r4
/// bl   0x08275e20        ; strlen_safe_plus1(source)
/// sub  r3, r0, #1        ; source_len = strlen(source)
/// mov  r0, r6
/// mov  r2, r4
/// mov  r1, r5
/// pop  {r4, r5, r6, lr}
/// b    0x08275f48        ; insert_core(this, index, source, source_len)
/// ```
///
/// A NULL or empty (`source[0] == 0`) source and a negative `index` are
/// silent no-ops. Otherwise the source's byte length (without the NUL)
/// is measured through the ported [`strlen_safe_plus1`] @ 0x08275e20
/// and the call tail-branches to the insert core @ 0x08275f48 with
/// `(this, index, source, source_len)`. `index` is a UTF-8 CHARACTER
/// position, not a byte offset — the core resolves it by walking
/// codepoints (0x082a50c4 over `utf8_next_codepoint` @ 0x08276214) —
/// while `source_len` is a plain byte count. Sampled call sites pass
/// `mvn r1, #0x80000000` (0x7fffffff, INT_MAX) as the append-at-end
/// idiom (0x08053a34, 0x08074258).
///
/// Deviation: the insert core @ 0x08275f48 is NOT ported, so the tail
/// branch dispatches through the [`STRING_OBJECT_INSERT_CORE`] slot
/// (the [`RETAIL_VSNPRINTF_ENGINE`] pattern) whose default is a no-op
/// reproducing the core's own early-return paths — see
/// [`missing_insert_core`]. There is no NULL guard on `this`, matching
/// the original (it only ever reaches the core's vtable dereference).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_insert_cstr(
    this: *mut StringObject,
    index: i32,
    source: *const u8,
) {
    if source.is_null() || source.read() == 0 {
        return;
    }
    if index < 0 {
        return;
    }
    // Read through a volatile fn pointer so the length keeps its `bl
    // 0x08275e20` shape instead of being inlined (the
    // string_object_len_plus1 convention).
    let len_plus1: unsafe extern "C" fn(*const u8) -> usize =
        core::ptr::read_volatile(&(strlen_safe_plus1 as unsafe extern "C" fn(*const u8) -> usize));
    let source_len = len_plus1(source) - 1;
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_INSERT_CORE))(
        this, index, source, source_len,
    );
}

/// string_object_assign — original: `FUN_082774a8` @ 0x082774a8
/// (32 bytes, 217 `bl` call sites — the most-called function of the class).
///
/// The class's copy-assignment operator, `StringObject &operator=(const
/// StringObject &source)`. Decoded from the raw ARM at 0x082774a8:
///
/// ```text
/// push {r4, lr}
/// cmp  r0, r1          ; self-assignment test, on ADDRESS not content
/// mov  r4, r0          ; save `this` across the call
/// ldrne r1, [r1, #4]   ; r1 = source->payload
/// movne r0, r4
/// blne 0x08276474      ; string_object_assign_payload(this, source->payload)
/// mov  r0, r4          ; return `this` on every path
/// pop  {r4, pc}
/// ```
///
/// Two details of the original are load-bearing and reproduced exactly.
/// First, the self-assignment guard compares the two object *addresses*, so
/// `x = x` is a complete no-op — not even a redundant copy of the payload
/// through the allocator — while assigning from a distinct object that
/// happens to share a payload pointer still runs the full path. Second,
/// `this` is returned unconditionally (`mov r0, r4` sits after the
/// conditional call), giving the C++ chaining convention even when the guard
/// skipped the work.
///
/// The SOURCE's payload word is forwarded to the ported
/// [`string_object_assign_payload`] @ 0x08276474, which owns replacing and
/// releasing this object's prior payload through vtable slots +0x8/+0xc.
/// This operator itself never reads or writes `this.payload`.
///
/// Neither operand is NULL-guarded: the original faults on the `ldrne` for a
/// NULL `source`, and dereferencing one here faults the same way. A NULL
/// `this` reaches the callee exactly as it does in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_assign(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    if this as *const StringObject != source {
        string_object_assign_payload(this, (*source).payload);
    }
    this
}

/// string_object_construct_from_cstr — original: `FUN_08277304` @
/// 0x08277304 (44 bytes: 40 code + the 4-byte vtable literal @
/// 0x0827732c = 0x089a6044, binary-verified against osos.dec; 143 `bl`
/// call sites, binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/026/08277304_FUN_08277304.c` (Ghidra
/// drops the second argument: r1 is never written between entry and the
/// `bl`, so the caller's C string flows straight through).
///
/// The class's converting constructor, `StringObject(const char
/// *source)`. Decoded from the raw ARM at 0x08277304:
///
/// ```text
/// push {r4, lr}
/// mov  r4, r0          ; save `this` across the call
/// ldr  r0, [0x0827732c] ; 0x089a6044, the class vtable
/// str  r0, [r4]
/// mov  r0, #0
/// str  r0, [r4, #4]    ; payload = NULL — raw storage, nothing to free
/// mov  r0, r4
/// bl   0x0827639c      ; string_object_assign_cstr(this, source)
/// mov  r0, r4          ; return `this`
/// pop  {r4, pc}
/// ```
///
/// It is exactly the default constructor @ 0x08277440 followed by the
/// ported [`string_object_assign_cstr`] @ 0x0827639c: NULLing the
/// payload word first is what makes the shared assignment path safe on
/// uninitialized storage — the +0x8 allocation slot sees no prior
/// payload to release. `source` is caller-owned and passed through
/// untouched; an empty or NULL `source` leaves the object in the
/// freshly-constructed state through the +0xc clear slot, and an
/// allocation failure leaves the payload NULL. `this` is returned
/// unconditionally (the ADS constructor convention) and is not
/// NULL-guarded — the original faults on the vtable store, and so does
/// the port.
///
/// Deviation: the vtable is the modeled static [`STRING_OBJECT_VTABLE`]
/// rather than the ROM address (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_construct_from_cstr(
    this: *mut StringObject,
    source: *const u8,
) -> *mut StringObject {
    (*this).vtable = &STRING_OBJECT_VTABLE;
    (*this).payload = core::ptr::null_mut();
    string_object_assign_cstr(this, source);
    this
}

/// string_object_copy_construct — original: `FUN_082773e0` @ 0x082773e0
/// (52 bytes: 48 code + the 4-byte vtable literal @ 0x08277410 =
/// 0x089a6044, binary-verified against osos.dec; 212 `bl` call sites,
/// binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/026/082773e0_FUN_082773e0.c`.
///
/// The class's copy constructor, `StringObject(const StringObject
/// &source)`. Decoded from the raw ARM at 0x082773e0:
///
/// ```text
/// push  {r4, lr}
/// mov   r4, r0
/// ldr   r0, [0x08277410] ; 0x089a6044, the class vtable
/// cmp   r4, r1           ; self-construction test, on ADDRESS not content
/// str   r0, [r4]         ; UNCONDITIONAL — the vtable is planted either way
/// movne r0, #0
/// strne r0, [r4, #4]     ; payload = NULL — raw storage, nothing to free
/// ldrne r1, [r1, #4]     ; r1 = source->payload
/// movne r0, r4
/// blne  0x08276474       ; string_object_assign_payload(this, source->payload)
/// mov   r0, r4           ; return `this` on every path
/// pop   {r4, pc}
/// ```
///
/// Two details of the original are load-bearing and reproduced exactly.
/// First, the vtable store sits *outside* the guard while the payload
/// NULLing sits inside it, so constructing an object from itself plants
/// the vtable and leaves the existing payload word alone instead of
/// leaking it — the same address-not-content guard
/// [`string_object_assign`] uses, but here it also decides whether the
/// storage is treated as raw. Second, `this` is returned on every path
/// (`mov r0, r4` follows the conditional call).
///
/// The duplication itself is the ported [`string_object_assign_payload`]
/// @ 0x08276474 over the SOURCE's payload word: it sizes the copy with
/// [`strlen_safe_plus1`], asks vtable slot +0x8 for the storage and
/// copies through the NUL, or dispatches slot +0xc when the source
/// payload is NULL or empty. A failed allocation leaves this object's
/// payload NULL — the empty-string state the constructor already
/// established. Neither operand is NULL-guarded: the original faults on
/// the vtable store for a NULL `this` and on the `ldrne` for a NULL
/// `source`, and so does the port.
///
/// Deviation: the vtable is the modeled static [`STRING_OBJECT_VTABLE`]
/// rather than the ROM address (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_copy_construct(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    (*this).vtable = &STRING_OBJECT_VTABLE;
    if this as *const StringObject != source {
        (*this).payload = core::ptr::null_mut();
        string_object_assign_payload(this, (*source).payload);
    }
    this
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

/// string_object_destroy_veneer — original: `thunk_FUN_082792fc` @
/// 0x082792fc (4 bytes; **98** `bl` call sites).
///
/// One word — `b 0x08277484` (0xeafff860) — the long-branch veneer
/// through which the 0x0827xxxx-and-above callers reach
/// [`string_object_destroy`]. Genuinely 4 bytes, not the 8 of the
/// `ldr pc, [pc, #-4]` + target-word form: this is a direct `B`, and
/// the following word (0x08279300, `push {r4, lr}`) is the entry of an
/// unrelated function. It sits in a veneer block — the word before it,
/// 0x082792f8, is `b 0x082aad24` (operator delete).
///
/// 98 `bl` call sites and 0 `b`, binary-scanned by decoding every ARM
/// `B`/`BL` word in `work/firmware/osos.dec` and resolving its target.
///
/// Kept as its own `#[inline(never)]` symbol rather than an alias so a
/// hook at 0x082792fc lands on a real forwarding branch; the callee is
/// called directly, which lowers to a plain tail branch plus the
/// target's mandatory non-leaf frame pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_destroy_veneer(
    this: *mut StringObject,
) -> *mut StringObject {
    string_object_destroy(this)
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

/// string_object_utf8_strcmp_safe — original: `FUN_082a5368` @
/// 0x082a5368 (8 bytes, all code — the next function starts at
/// 0x082a5370; **39 `bl` call sites**, binary-scanned, zero of them
/// predicated).
///
/// Source: `ipod-decomp/decomp/c/029/082a5368_FUN_082a5368.c` (the
/// callee inlined — matches the raw ARM once the tail branch is
/// followed).
///
/// The compare-against-C-string accessor of the two-word string
/// class, `int StringObject::utf8_strcmp(const char *other)`: a
/// two-instruction thunk — `ldr r0, [r0, #4]; b 0x08276d64` — that
/// loads the payload word at `this + 4` and tail-branches to the
/// ported [`utf8_strcmp_safe`] @ 0x08276d64 with the caller's second
/// argument passed through untouched in r1. Returns the first
/// unequal decoded codepoints' difference, 0 on equality; a NULL
/// payload reads as the shared empty string (the thunk guards
/// nothing — the substitution guard lives inside the callee, exactly
/// the asymmetry [`string_id_record_equals`] documents). No NULL
/// guard on `this` — the original faults on a NULL `this`, and so
/// does the port.
///
/// It opens the class's accessor cluster at 0x082a5368-0x082a5398
/// ([`string_object_is_empty`] @ 0x082a5370, the raw payload
/// accessor `ldr r0,[r0,#4]; bx lr` @ 0x082a538c, and a payload ->
/// [`utf8_codepoint_count_safe`] chain @ 0x082a5394). Call sites pin
/// the use: twenty consecutive sites @ 0x0809f7b4-0x0809fa60 compare
/// a stack-built StringObject (constructed from a u16 string through
/// FUN_082765a8) against a series of literal keywords ("Acoustic",
/// ... @ 0x0809faa4 on), each result consumed by `cmp r0,#0; bne` —
/// a genre-name -> ID dispatch chain (0x64 on the first match); a
/// second nineteen-site cluster @ 0x0813ba04-0x0813cb88 runs the
/// same shape, plus singletons @ 0x0809fb8c, 0x08118b84, 0x08118be0
/// and 0x081192d4. The callee is ported, so it is called directly.
///
/// Deviation: the callee address is read through a volatile pointer
/// (the same anti-const-fold trick as [`string_object_len_plus1`])
/// purely to stop LLVM from inlining [`utf8_strcmp_safe`] and
/// dissolving the thunk; codegen stays a load plus a tail branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_utf8_strcmp_safe(
    this: *const StringObject,
    other: *const u8,
) -> i32 {
    let compare: unsafe extern "C" fn(*const u8, *const u8) -> i32 =
        core::ptr::read_volatile(
            &(utf8_strcmp_safe as unsafe extern "C" fn(*const u8, *const u8) -> i32),
        );
    compare((*this).payload as *const u8, other)
}

/// string_object_is_empty — original: `FUN_082a5370` @ 0x082a5370
/// (28 bytes, all code — the next function starts at 0x082a538c; 55
/// `bl` call sites, binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/029/082a5370_FUN_082a5370.c` (matches
/// the raw ARM exactly).
///
/// The emptiness predicate of the two-word string class,
/// `bool StringObject::is_empty()`. Decoded from the raw ARM at
/// 0x082a5370:
///
/// ```text
/// ldr    r0, [r0, #4]   ; r0 = this->payload
/// cmp    r0, #0
/// ldrbne r0, [r0]       ; non-NULL payload: r0 = payload[0]
/// cmpne  r0, #0
/// moveq  r0, #1         ; NULL payload or empty string -> 1
/// movne  r0, #0         ; nonempty -> 0
/// bx     lr
/// ```
///
/// Returns true exactly when the payload word at `this + 4` is NULL
/// (the default-constructed/cleared state) or points at a NUL byte —
/// i.e. the object holds no characters. A NULL payload never
/// dereferences (the `ldrbne`/`cmpne` are predicated on the pointer
/// test), matching [`string_object_c_str`]'s treatment of NULL as the
/// empty string. No NULL guard on `this` — the original faults on a
/// NULL `this`, and so does the port.
///
/// It sits in the class's accessor cluster at 0x082a5368-0x082a5398
/// (the ported [`string_object_utf8_strcmp_safe`] chain @ 0x082a5368,
/// the raw payload accessor `ldr r0,[r0,#4]; bx lr` @ 0x082a538c, and
/// a payload ->
/// [`utf8_codepoint_count_safe`] chain @ 0x082a5394). Call sites pin
/// the class: at 0x0807a528/0x0807a53c the receiver is the object
/// [`string_object_assign_cstr`] @ 0x0827639c just wrote, and at
/// 0x0810034c/0x08100354 the same receiver flows to
/// [`string_object_c_str`] @ 0x082a50b0.
///
/// Alias scan: the exact 7-word instruction pattern occurs exactly
/// once in osos.dec (0x082a5370 itself) — unlike
/// `handle_deref_or_null` and `container_is_empty`, this body has NO
/// byte-identical twins.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_is_empty(this: *const StringObject) -> bool {
    let payload = (*this).payload as *const u8;
    payload.is_null() || payload.read() == 0
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

/// Indirect dispatch for the StringObject copy constructor @ 0x082773e0
/// (the util/inner_state.rs `INNER_MATERIALIZE_COUNT` pattern). Chained
/// to by [`string_id_record_construct_from_string_id`] and by the copy
/// constructor sibling [`string_id_record_copy_construct`]. The wired
/// default is the ported [`string_object_copy_construct`] itself (it
/// replaced the empty-construction stub when the port landed); the slot
/// stays so host tests can install recording mocks — the
/// [`STRING_OBJECT_OPS`] wiring.
pub static mut STRING_OBJECT_COPY_CONSTRUCT: unsafe extern "C" fn(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject = string_object_copy_construct;

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
/// static [`STRING_ID_RECORD_VTABLE`]; the copy constructor @
/// 0x082773e0 dispatches through [`STRING_OBJECT_COPY_CONSTRUCT`]
/// (wired to the ported [`string_object_copy_construct`]); the
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
/// [`STRING_ID_RECORD_VTABLE`]; the copy constructor @
/// 0x082773e0 dispatches through [`STRING_OBJECT_COPY_CONSTRUCT`]
/// (wired to the ported [`string_object_copy_construct`]); the
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

/// Encodes a codepoint into the retail UTF-8-like byte form — original:
/// `FUN_0825c870` @ 0x0825c870 (140 bytes, all code; source:
/// `ipod-decomp/decomp/c/025/0825c870_FUN_0825c870.c`).
///
/// The raw ARM first uses an **unsigned** `<= 0x7f` comparison for the
/// one-byte form, then signed `blt` comparisons for the remaining
/// thresholds: `0x800`, `0x10000`, and `0x110000`. Thus normal values encode
/// as one through four bytes, including surrogate values, while values with
/// bit 31 set take the signed-less-than two-byte path. Values from
/// `0x110000` through `0x7fffffff` store only a NUL at `destination[0]`.
///
/// The four-byte path has two material retail defects: it reuses the
/// three-byte form's `codepoint >> 6` continuation at byte 1 (rather than
/// bits 12..17), and stores bytes 0, 1, and 3 plus the NUL at byte 4, but
/// **does not write byte 2**. This port retains those effects rather than
/// repairing it into standard UTF-8. The
/// destination must point to at least five writable bytes; NULL or unreadable
/// memory faults just as it does in the firmware. Returns void (the original
/// only restores `pc`; r0 is not a result).
///
/// Deviations: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_encode_codepoint(destination: *mut u8, codepoint: u32) {
    if codepoint <= 0x7f {
        destination.write(codepoint as u8);
        destination.add(1).write(0);
        return;
    }

    let final_continuation = (codepoint as u8 & 0x3f) | 0x80;
    if (codepoint as i32) < 0x800 {
        destination.write(((codepoint as i32 >> 6) as u8) | 0xc0);
        destination.add(1).write(final_continuation);
        destination.add(2).write(0);
        return;
    }

    let second_continuation = ((codepoint >> 6) as u8 & 0x3f) | 0x80;
    if (codepoint as i32) < 0x10000 {
        destination.write(((codepoint as i32 >> 12) as u8) | 0xe0);
        destination.add(1).write(second_continuation);
        destination.add(2).write(final_continuation);
        destination.add(3).write(0);
        return;
    }

    if (codepoint as i32) < 0x110000 {
        destination.write(((codepoint as i32 >> 18) as u8) | 0xf0);
        destination.add(1).write(second_continuation);
        destination.add(3).write(final_continuation);
        destination.add(4).write(0);
    } else {
        destination.write(0);
    }
}


/// utf8_codepoint_count_safe — original: `FUN_082770e0` @ 0x082770e0
/// (48 bytes, all code — no literal-pool word; 102 `bl` call sites,
/// binary-scanned).
///
/// The UTF-8 counterpart of [`strlen_safe`] @ 0x082770bc, which sits
/// immediately before it in the image: where that one counts *bytes*,
/// this one counts *codepoints*. Decoded from the raw ARM at 0x082770e0:
///
/// ```text
/// push {r0, r4, lr}    ; spill `text` — [sp] IS the cursor
/// ldr  r0, [sp]
/// mov  r4, #0          ; count
/// cmp  r0, #0
/// beq  done            ; NULL -> 0, without decoding
/// loop:
/// mov  r0, sp          ; &cursor
/// bl   0x08276214      ; utf8_next_codepoint(&cursor)
/// cmp  r0, #0
/// addne r4, r4, #1
/// bne  loop
/// done:
/// mov  r0, r4
/// pop  {r3, r4, pc}
/// ```
///
/// The spilled argument word doubles as the cursor cell the decoder
/// advances, so the walk needs no other state. Termination is whatever
/// [`utf8_next_codepoint`] calls a zero codepoint: the NUL byte, but also
/// any four-byte or otherwise malformed lead — those consume three bytes
/// and stop the count, exactly as they end a comparison in
/// [`utf8_strcmp_safe`]. Codepoints are counted, not validated: an empty
/// string and a NULL pointer both return 0.
///
/// Deviations: none. The NULL guard runs once before the loop, as in the
/// original; a non-NULL but unreadable string faults in both.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_codepoint_count_safe(text: *const u8) -> usize {
    let mut cursor = text;
    if cursor.is_null() {
        return 0;
    }

    let mut count = 0usize;
    while utf8_next_codepoint(&mut cursor) != 0 {
        count += 1;
    }
    count
}

/// Decodes the codepoint ending immediately before `*cursor` and moves the
/// cursor backward — original: `FUN_08276288` @ 0x08276288 (116 bytes, all
/// code; source: `ipod-decomp/decomp/c/026/08276288_FUN_08276288.c`).
///
/// The retail reverse decoder first consumes the final byte. ASCII returns
/// unchanged. For a high-bit byte, it consumes the preceding byte and accepts
/// a two-byte form only when that byte has a `0b110xxxxx` prefix. Otherwise it
/// consumes a third byte and accepts a three-byte form only when that byte has
/// a `0b1110xxxx` prefix. As with the forward decoder, continuation bytes,
/// overlong encodings, and surrogate values are not validated; any other
/// three-byte lookbehind returns zero after consuming all three bytes. This
/// deliberately also means a malformed final lead byte can consume bytes
/// before it and return zero. The original faults for an invalid cursor or
/// unreadable lookbehind, and this raw-pointer port has the same preconditions.
///
/// Deviation: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_prev_codepoint(cursor: *mut *const u8) -> u32 {
    let sequence_end = *cursor;
    *cursor = sequence_end.sub(1);
    let final_byte = *sequence_end.sub(1);
    if final_byte & 0x80 == 0 {
        return final_byte as u32;
    }

    *cursor = sequence_end.sub(2);
    let preceding_byte = *sequence_end.sub(2);
    if preceding_byte & 0xe0 == 0xc0 {
        return (final_byte & 0x3f) as u32 | ((preceding_byte & 0x1f) as u32) << 6;
    }

    *cursor = sequence_end.sub(3);
    let leading_byte = *sequence_end.sub(3);
    if leading_byte & 0xf0 == 0xe0 {
        return ((leading_byte & 0x0f) as u32) << 12
            | ((preceding_byte & 0x3f) as u32) << 6
            | (final_byte & 0x3f) as u32;
    }

    0
}

/// utf16_utf8_byte_len_plus1 — original: `FUN_082762fc` @ 0x082762fc
/// (60 bytes, all code; source:
/// `ipod-decomp/decomp/c/026/082762fc_FUN_082762fc.c`).
///
/// Counts the UTF-8 byte length implied by NUL-terminated UTF-16 code units,
/// then includes the output's NUL terminator. A NULL input is an empty string
/// and returns 1. Each nonzero code unit below 0x80, below 0x800, or otherwise
/// contributes one, two, or three bytes respectively. The retail loop does
/// not recognize surrogate pairs: each surrogate is independently counted as
/// a three-byte unit. Its signed 32-bit accumulator wraps, rather than
/// trapping, on an overlong input.
#[inline(always)]
fn utf8_byte_len_add(total: i32, byte_count: i32) -> i32 {
    total.wrapping_add(byte_count)
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf16_utf8_byte_len_plus1(utf16: *const u16) -> i32 {
    let mut utf8_byte_len = 0;
    let mut code_unit_ptr = utf16;

    if !code_unit_ptr.is_null() {
        loop {
            let code_unit = *code_unit_ptr;
            if code_unit == 0 {
                break;
            }
            code_unit_ptr = code_unit_ptr.add(1);

            let encoded_bytes = if code_unit < 0x80 {
                1
            } else if code_unit < 0x800 {
                2
            } else {
                3
            };
            utf8_byte_len = utf8_byte_len_add(utf8_byte_len, encoded_bytes);
        }
    }

    utf8_byte_len_add(utf8_byte_len, 1)
}

/// utf16_utf8_byte_len_bounded_plus1 — original: `FUN_08276338` @
/// 0x08276338 (72 bytes, all code; source:
/// `ipod-decomp/decomp/c/026/08276338_FUN_08276338.c`).
///
/// Counts the UTF-8 byte length implied by at most `max_code_units` UTF-16
/// code units and includes the output's NUL terminator. A NULL input is an
/// empty string and returns 1. The retail loop reads only while the signed
/// bound is positive; it stops earlier at a UTF-16 NUL. Each nonzero code
/// unit below 0x80, below 0x800, or otherwise contributes one, two, or three
/// bytes respectively. It neither combines nor validates surrogate pairs.
/// The pointer advances and the remaining bound decrements only after a
/// nonzero code unit is counted, so a terminating NUL leaves the bound
/// untouched. Its signed 32-bit accumulator, including the final NUL byte,
/// wraps on overflow.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf16_utf8_byte_len_bounded_plus1(
    utf16: *const u16,
    mut max_code_units: i32,
) -> i32 {
    let mut utf8_byte_len = 0;
    let mut code_unit_ptr = utf16;

    if !code_unit_ptr.is_null() {
        while max_code_units > 0 {
            let code_unit = *code_unit_ptr;
            if code_unit == 0 {
                break;
            }

            let encoded_bytes = if code_unit < 0x80 {
                1
            } else if code_unit < 0x800 {
                2
            } else {
                3
            };
            utf8_byte_len = utf8_byte_len_add(utf8_byte_len, encoded_bytes);
            code_unit_ptr = code_unit_ptr.add(1);
            max_code_units -= 1;
        }
    }

    utf8_byte_len_add(utf8_byte_len, 1)
}

/// utf8_codepoint_byte_width — original: `FUN_08276380` @ 0x08276380
/// (28 bytes, all code; source:
/// `ipod-decomp/decomp/c/026/08276380_FUN_08276380.c`).
///
/// Classifies the number of UTF-8 bytes needed for an unsigned codepoint:
/// values through 0x7f need one byte, values from 0x80 through 0x7ff need
/// two, and every value from 0x800 through `u32::MAX` needs three. The
/// original compares unsigned values (`0x7f < codepoint`, then
/// `codepoint < 0x800`); this `u32` signature preserves those boundary
/// semantics exactly. It does not validate Unicode scalar values, so
/// surrogates and out-of-range codepoints take the three-byte branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn utf8_codepoint_byte_width(codepoint: u32) -> u32 {
    if 0x7f < codepoint {
        if codepoint < 0x800 {
            2
        } else {
            3
        }
    } else {
        1
    }
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
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes all host tests that replace [`STRING_OBJECT_OPS`].
    ///
    /// The dispatch slot is process-global, so sibling C++ module tests use
    /// this lock alongside this module's own destruction tests.
    pub(crate) static STRING_OBJECT_OPS_TEST_LOCK: Mutex<()> = Mutex::new(());


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

    /// Serializes the modeled +0x8/+0xc virtual slots and their recorders.
    static ASSIGN_CSTR_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ASSIGN_CSTR_ALLOCATE_CALLS: Vec<(usize, usize, u32)> = Vec::new();
    static mut ASSIGN_CSTR_CLEAR_CALLS: Vec<usize> = Vec::new();
    static mut ASSIGN_CSTR_ALLOCATE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_assign_cstr_allocate(
        this: *mut StringObject,
        requested_size: usize,
        flags: u32,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ASSIGN_CSTR_ALLOCATE_CALLS)).push((
            this as usize,
            requested_size,
            flags,
        ));
        core::ptr::read_volatile(core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_RESULT))
    }

    unsafe extern "C" fn recording_assign_cstr_clear(this: *mut StringObject) {
        (*core::ptr::addr_of_mut!(ASSIGN_CSTR_CLEAR_CALLS)).push(this as usize);
    }

    /// `(sink, cursor, maximum, format, args)` received by conversion core
    /// 0x08077c94 through `retail_vsnprintf`.
    static mut FORMAT_ENGINE_CALLS: Vec<(usize, usize, usize, usize, usize)> = Vec::new();
    /// Canned conversion output. The recorder models the core's bounded write
    /// protocol; the veneer under test appends the terminator itself.
    static mut FORMAT_ENGINE_OUTPUT: &[u8] = b"\0";
    static mut FORMAT_ENGINE_RESULT: i32 = 0;

    unsafe extern "C" fn recording_format_engine(
        sink: usize,
        cursor: *mut *mut u8,
        maximum: usize,
        format: *const u8,
        args: VaList,
    ) -> i32 {
        let initial_cursor = *cursor;
        (*core::ptr::addr_of_mut!(FORMAT_ENGINE_CALLS)).push((
            sink,
            initial_cursor as usize,
            maximum,
            format as usize,
            args as usize,
        ));
        let output = core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_ENGINE_OUTPUT));
        let text_len = output.len() - 1;
        let written = if text_len < maximum { text_len } else { maximum };
        core::ptr::copy_nonoverlapping(output.as_ptr(), initial_cursor, written);
        *cursor = initial_cursor.add(written);
        core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_ENGINE_RESULT))
    }

    /// Arms conversion-core output for the next formatter invocation. Only
    /// valid while the bench guard — which owns the lock and installs the
    /// recorder — is alive.
    fn arm_format_output(output: &'static [u8], result: i32) {
        assert_eq!(output.last(), Some(&0), "canned output must be NUL-terminated");
        unsafe {
            core::ptr::addr_of_mut!(FORMAT_ENGINE_OUTPUT).write(output);
            core::ptr::addr_of_mut!(FORMAT_ENGINE_RESULT).write(result);
        }
    }

    /// `(destination, utf16, max_code_units)` received by the transcoder
    /// 0x0827675c through `string_object_assign_utf16`.
    static mut UTF16_TRANSCODE_CALLS: Vec<(usize, usize, i32)> = Vec::new();

    /// Models the transcoder's writing half well enough to prove the
    /// terminator lands where the sizing helper says: the same 0x80/0x800
    /// thresholds, no surrogate pairing, early stop on a UTF-16 NUL (which
    /// it stores as one zero byte), and no terminator of its own.
    unsafe extern "C" fn recording_utf16_transcode(
        destination: *mut u8,
        utf16: *const u16,
        max_code_units: i32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(UTF16_TRANSCODE_CALLS)).push((
            destination as usize,
            utf16 as usize,
            max_code_units,
        ));

        let mut out = destination;
        let mut consumed = 0;
        for index in 0..max_code_units.max(0) {
            let code_unit = *utf16.offset(index as isize);
            if code_unit < 0x80 {
                out.write(code_unit as u8);
                out = out.add(1);
                if code_unit == 0 {
                    return consumed;
                }
            } else if code_unit < 0x800 {
                out.write(0xc0 | (code_unit >> 6) as u8);
                out.add(1).write(0x80 | (code_unit & 0x3f) as u8);
                out = out.add(2);
            } else {
                out.write(0xe0 | (code_unit >> 12) as u8);
                out.add(1).write(0x80 | ((code_unit >> 6) & 0x3f) as u8);
                out.add(2).write(0x80 | (code_unit & 0x3f) as u8);
                out = out.add(3);
            }
            consumed += 1;
        }
        consumed
    }

    /// Restores the unported virtual-method boundary even when a test panics.
    struct AssignCstrOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for AssignCstrOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                    .write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
                core::ptr::addr_of_mut!(RETAIL_VSNPRINTF_ENGINE)
                    .write_volatile(retail_vsnprintf_engine_stub);
                core::ptr::addr_of_mut!(STRING_OBJECT_UTF16_TRANSCODE)
                    .write_volatile(utf16_to_utf8_stub);
            }
        }
    }

    fn assign_cstr_bench(allocation_result: *mut u8) -> AssignCstrOpsGuard {
        let lock = ASSIGN_CSTR_OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(ASSIGN_CSTR_ALLOCATE_CALLS)).clear();
            (*core::ptr::addr_of_mut!(ASSIGN_CSTR_CLEAR_CALLS)).clear();
            (*core::ptr::addr_of_mut!(FORMAT_ENGINE_CALLS)).clear();
            (*core::ptr::addr_of_mut!(UTF16_TRANSCODE_CALLS)).clear();
            core::ptr::addr_of_mut!(STRING_OBJECT_UTF16_TRANSCODE)
                .write_volatile(recording_utf16_transcode);
            core::ptr::addr_of_mut!(ASSIGN_CSTR_ALLOCATE_RESULT).write(allocation_result);
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps {
                    allocate_payload: recording_assign_cstr_allocate,
                    clear_payload: recording_assign_cstr_clear,
                },
            );
            core::ptr::addr_of_mut!(RETAIL_VSNPRINTF_ENGINE).write_volatile(recording_format_engine);
        }
        arm_format_output(b"\0", 0);
        AssignCstrOpsGuard { _lock: lock }
    }

    #[test]
    fn assign_cstr_allocates_strlen_plus_nul_then_copies_without_transferring_source() {
        let mut destination = [0xa5u8; 16];
        let source = *b"album\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_assign_cstr(this, source.as_ptr()) };

        let allocations =
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() };
        assert_eq!(allocations, std::vec![(this as usize, 6, 0)]);
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "nonempty input never reaches vtable slot +0xc"
        );
        assert_eq!(&destination[..6], &source, "the copy includes the NUL");
        assert_eq!(source, *b"album\0", "source remains caller-owned");
        assert_eq!(
            object.payload, 0xcafe_f00d as *mut u8,
            "only the +0x8 virtual callee owns replacement/free bookkeeping"
        );
    }

    #[test]
    fn assign_cstr_allocation_failure_skips_copy_and_fallback() {
        let source = *b"full\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x1111_1111 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());

        unsafe { string_object_assign_cstr(this, source.as_ptr()) };

        let allocations =
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() };
        assert_eq!(allocations, std::vec![(this as usize, 5, 0)]);
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "a NULL +0x8 result returns directly instead of falling back to +0xc"
        );
        assert_eq!(object.payload, 0x1111_1111 as *mut u8);
    }

    #[test]
    fn assign_cstr_null_and_empty_dispatch_only_the_clear_slot() {
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x2222_2222 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let empty = [0u8; 1];
        let _bench = assign_cstr_bench(0x3333_3333 as *mut u8);

        unsafe {
            string_object_assign_cstr(this, core::ptr::null());
            string_object_assign_cstr(this, empty.as_ptr());
        }

        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "NULL and first-byte-NUL skip strlen and vtable slot +0x8"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize, this as usize],
            "both branch forms dispatch vtable slot +0xc with only this"
        );
        assert_eq!(object.payload, 0x2222_2222 as *mut u8);
    }

    #[test]
    fn assign_payload_uses_inclusive_length_and_leaves_bookkeeping_to_allocation() {
        let mut destination = [0xa5u8; 16];
        let payload = *b"album\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_assign_payload(this, payload.as_ptr()) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 6, 0)],
            "0x08275e20 supplies strlen plus the NUL"
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "nonempty payload never reaches vtable slot +0xc"
        );
        assert_eq!(&destination[..6], &payload, "the copy includes the NUL");
        assert_eq!(payload, *b"album\0", "source payload remains caller-owned");
        assert_eq!(
            object.payload, 0xcafe_f00d as *mut u8,
            "replacement/free bookkeeping belongs to the +0x8 virtual call"
        );
    }

    #[test]
    fn assign_payload_allocation_failure_skips_copy_and_clear_fallback() {
        let payload = *b"full\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x1111_1111 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());

        unsafe { string_object_assign_payload(this, payload.as_ptr()) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 5, 0)]
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "a NULL +0x8 result returns instead of dispatching +0xc"
        );
        assert_eq!(object.payload, 0x1111_1111 as *mut u8);
    }

    #[test]
    fn assign_payload_null_and_empty_dispatch_only_vtable_slot_0xc() {
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x2222_2222 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let empty = [0u8; 1];
        let _bench = assign_cstr_bench(0x3333_3333 as *mut u8);

        unsafe {
            string_object_assign_payload(this, core::ptr::null());
            string_object_assign_payload(this, empty.as_ptr());
        }

        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "NULL and first-byte-NUL skip 0x08275e20 and vtable slot +0x8"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize, this as usize]
        );
        assert_eq!(object.payload, 0x2222_2222 as *mut u8);
    }

    // ---- string_object_assign_utf16 ---------------------------------

    fn utf16_transcode_calls() -> Vec<(usize, usize, i32)> {
        unsafe { (*core::ptr::addr_of!(UTF16_TRANSCODE_CALLS)).clone() }
    }

    /// A fresh object for the UTF-16 assignment tests; the payload word is a
    /// recognizable non-NULL so the tests can assert the port never writes it
    /// (the +0x8 virtual call owns that word).
    fn utf16_test_object() -> StringObject {
        StringObject {
            vtable: core::ptr::null(),
            payload: 0x2222_2222 as *mut u8,
        }
    }

    #[test]
    fn assign_utf16_sizes_with_the_bounded_counter_then_terminates_the_transcode() {
        // 1 + 2 + 3 encoded bytes, plus the terminator this function writes.
        let code_units: [u16; 3] = [0x41, 0xa9, 0x20ac];
        let mut destination = [0xa5u8; 16];
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_assign_utf16(this, code_units.as_ptr(), 3) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 7, 0)],
            "slot +0x8 receives exactly the bounded counter's inclusive length"
        );
        assert_eq!(
            utf16_transcode_calls(),
            std::vec![(destination.as_ptr() as usize, code_units.as_ptr() as usize, 3)],
            "0x0827675c gets the allocation, the source and the UNCLAMPED count"
        );
        assert_eq!(&destination[..7], b"A\xc2\xa9\xe2\x82\xac\0");
        assert_eq!(&destination[7..], &[0xa5u8; 9], "nothing past byte_len - 1");
        assert!(unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() });
        assert_eq!(object.payload, 0x2222_2222 as *mut u8, "the port never stores it");
    }

    /// The bound, not the source's own terminator, is what the guard reads —
    /// but the counter still stops at an embedded UTF-16 NUL, so a count
    /// larger than the string sizes only the units before it.
    #[test]
    fn assign_utf16_honors_the_bound_and_stops_at_an_embedded_nul() {
        let code_units: [u16; 4] = [0x41, 0x42, 0, 0x43];
        let mut destination = [0xa5u8; 16];
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_assign_utf16(this, code_units.as_ptr(), 4) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 3, 0)],
            "'A' + 'B' + the terminator; the counter never reaches 'C'"
        );
        assert_eq!(&destination[..3], b"AB\0");
    }

    /// The decisive difference from the C-string siblings: a first code unit
    /// of zero is NOT the empty-source case. It still allocates — one byte,
    /// holding only the terminator this function writes.
    #[test]
    fn assign_utf16_guards_on_the_count_not_the_first_code_unit() {
        let code_units: [u16; 2] = [0, 0x41];
        let mut destination = [0xa5u8; 4];
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_assign_utf16(this, code_units.as_ptr(), 2) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 1, 0)],
            "a leading UTF-16 NUL still takes the allocating path"
        );
        assert!(unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() });
        assert_eq!(destination[0], 0);
        assert_eq!(&destination[1..], &[0xa5u8; 3]);
    }

    /// NULL, and every non-positive count including the signed-negative ones
    /// the original's `LE` covers, dispatch only virtual slot +0xc.
    #[test]
    fn assign_utf16_null_and_nonpositive_counts_dispatch_only_vtable_slot_0xc() {
        let code_units: [u16; 1] = [0x41];
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(0x3333_3333 as *mut u8);

        unsafe {
            string_object_assign_utf16(this, core::ptr::null(), 4);
            string_object_assign_utf16(this, code_units.as_ptr(), 0);
            string_object_assign_utf16(this, code_units.as_ptr(), -1);
            string_object_assign_utf16(this, code_units.as_ptr(), i32::MIN);
        }

        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "the guarded paths skip 0x08276338 and vtable slot +0x8"
        );
        assert!(utf16_transcode_calls().is_empty());
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize; 4]
        );
        assert_eq!(object.payload, 0x2222_2222 as *mut u8);
    }

    /// A NULL allocation is an immediate return: no transcode, no terminator
    /// store through the NULL, and no fallback to slot +0xc.
    #[test]
    fn assign_utf16_allocation_failure_skips_transcode_and_clear_fallback() {
        let code_units: [u16; 2] = [0x41, 0x42];
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());

        unsafe { string_object_assign_utf16(this, code_units.as_ptr(), 2) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 3, 0)]
        );
        assert!(utf16_transcode_calls().is_empty());
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "allocation failure does not fall back to slot +0xc"
        );
    }

    /// Self-reference: assigning from storage the allocation itself hands back
    /// is the aliasing case the original does nothing to prevent. The
    /// terminator still lands at `byte_len - 1` of the returned block.
    #[test]
    fn assign_utf16_terminates_at_byte_len_even_when_source_aliases_destination() {
        let mut scratch = [0u8; 16];
        let code_units = scratch.as_mut_ptr() as *mut u16;
        unsafe {
            code_units.write(0x41);
            code_units.add(1).write(0x42);
        }
        let mut object = utf16_test_object();
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(scratch.as_mut_ptr());

        unsafe { string_object_assign_utf16(this, code_units, 2) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 3, 0)]
        );
        assert_eq!(&scratch[..3], b"AB\0");
    }

    // ---- string_object_format ---------------------------------------

    /// A distinguishable stand-in for the va_list the original's spill builds.
    const FORMAT_ARGS: VaList = 0x4444_4444 as VaList;

    #[test]
    fn retail_vsnprintf_forwards_engine_arguments_truncates_and_terminates() {
        let mut buf = [0xa5u8; 4];
        let format = b"%s\0";
        let _bench = assign_cstr_bench(core::ptr::null_mut());
        arm_format_output(b"album\0", 5);

        let count = unsafe { retail_vsnprintf(buf.as_mut_ptr(), buf.len(), format.as_ptr(), FORMAT_ARGS) };

        assert_eq!(count, 5, "the conversion core's would-be count survives truncation");
        assert_eq!(&buf, b"alb\0", "the veneer writes the NUL at the final bounded cursor");
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(FORMAT_ENGINE_CALLS)).clone() },
            std::vec![(
                RETAIL_VSNPRINTF_SINK_ADDRESS,
                buf.as_mut_ptr() as usize,
                3,
                format.as_ptr() as usize,
                FORMAT_ARGS as usize,
            )],
            "the ARM shuffle is sink, cursor, size - 1, format, va_list"
        );
    }

    #[test]
    fn retail_vsnprintf_zero_size_skips_engine_and_buffer() {
        let mut buf = [0xa5u8; 2];
        let _bench = assign_cstr_bench(core::ptr::null_mut());
        arm_format_output(b"x\0", 1);

        assert_eq!(
            unsafe { retail_vsnprintf(buf.as_mut_ptr(), 0, b"%s\0".as_ptr(), FORMAT_ARGS) },
            0
        );
        assert_eq!(buf, [0xa5; 2], "size zero takes the early return before any store");
        assert!(
            unsafe { (*core::ptr::addr_of!(FORMAT_ENGINE_CALLS)).is_empty() },
            "size zero must not call 0x08077c94"
        );
    }

    #[test]
    fn format_bounds_the_scratch_then_assigns_it_and_returns_the_length() {
        let mut destination = [0xa5u8; 16];
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x2222_2222 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let format = b"%s, %s\0";
        let _bench = assign_cstr_bench(destination.as_mut_ptr());
        arm_format_output(b"artist, album\0", 13);

        let length = unsafe { string_object_format(this, format.as_ptr(), FORMAT_ARGS) };

        assert_eq!(length, 13, "the formatter's count is returned, not `this`");
        let formatter = unsafe { (*core::ptr::addr_of!(FORMAT_ENGINE_CALLS)).clone() };
        assert_eq!(formatter.len(), 1);
        let (sink, scratch, maximum, seen_format, seen_args) = formatter[0];
        assert_eq!(sink, RETAIL_VSNPRINTF_SINK_ADDRESS);
        assert_eq!(maximum, STRING_OBJECT_FORMAT_BUFFER_LEN - 1);
        assert_eq!(seen_format, format.as_ptr() as usize, "format passed verbatim");
        assert_eq!(seen_args, FORMAT_ARGS as usize, "va_list passed verbatim");

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 14, 0)],
            "the scratch text sizes the allocation (strlen + NUL)"
        );
        assert!(unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() });
        assert_eq!(&destination[..14], b"artist, album\0");
        assert_eq!(
            object.payload, 0x2222_2222 as *mut u8,
            "the payload word belongs to the allocation slot, untouched here"
        );
        assert_ne!(scratch, destination.as_mut_ptr() as usize, "the scratch is a copy source");
    }

    #[test]
    fn format_empty_output_dispatches_the_clear_slot_only() {
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(0x3333_3333 as *mut u8);
        arm_format_output(b"\0", 0);

        let length = unsafe { string_object_format(this, b"\0".as_ptr(), FORMAT_ARGS) };

        assert_eq!(length, 0);
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "an empty scratch never reaches vtable slot +0x8"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize]
        );
        assert!(object.payload.is_null(), "a NULL prior payload is never read");
    }

    #[test]
    fn format_allocation_failure_still_returns_the_formatted_length() {
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x2222_2222 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());
        arm_format_output(b"track\0", 5);

        let length = unsafe { string_object_format(this, b"%s\0".as_ptr(), FORMAT_ARGS) };

        assert_eq!(length, 5, "the count survives a failed assignment");
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 6, 0)]
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "allocation failure does not fall back to vtable slot +0xc"
        );
    }

    #[test]
    fn format_returns_the_formatter_result_verbatim_including_overflow() {
        let mut destination = [0xa5u8; 8];
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());
        // The original returns the conversion core's count untouched: a
        // would-be length past the 512-byte scratch is reported as such.
        arm_format_output(b"ab\0", 900);

        assert_eq!(
            unsafe { string_object_format(this, b"%s\0".as_ptr(), FORMAT_ARGS) },
            900
        );
        assert_eq!(&destination[..3], b"ab\0", "only the truncated text is assigned");
    }

    /// Serializes the insert-core seam and its recorder.
    static INSERT_CORE_LOCK: Mutex<()> = Mutex::new(());
    /// `(this, index, source, source_len)` received by the insert core
    /// @ 0x08275f48 through the [`STRING_OBJECT_INSERT_CORE`] slot.
    static mut INSERT_CORE_CALLS: Vec<(usize, i32, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_insert_core(
        this: *mut StringObject,
        index: i32,
        source: *const u8,
        source_len: usize,
    ) {
        (*core::ptr::addr_of_mut!(INSERT_CORE_CALLS)).push((
            this as usize,
            index,
            source as usize,
            source_len,
        ));
    }

    /// Restores the unported insert-core boundary even when a test panics.
    struct InsertCoreGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for InsertCoreGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_INSERT_CORE)
                    .write_volatile(missing_insert_core);
            }
        }
    }

    fn insert_core_bench() -> InsertCoreGuard {
        let lock = INSERT_CORE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(INSERT_CORE_CALLS)).clear();
            core::ptr::addr_of_mut!(STRING_OBJECT_INSERT_CORE)
                .write_volatile(recording_insert_core);
        }
        InsertCoreGuard { _lock: lock }
    }

    #[test]
    fn insert_cstr_null_and_empty_source_are_silent_no_ops() {
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x3333_3333 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = insert_core_bench();

        unsafe {
            string_object_insert_cstr(this, 0, core::ptr::null());
            string_object_insert_cstr(this, 4, b"\0".as_ptr());
        }

        assert!(
            unsafe { (*core::ptr::addr_of!(INSERT_CORE_CALLS)).is_empty() },
            "a NULL or empty source returns before measuring or dispatching"
        );
        assert_eq!(object.payload, 0x3333_3333 as *mut u8);
    }

    #[test]
    fn insert_cstr_negative_index_is_a_silent_no_op() {
        let source = *b"album\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x4444_4444 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = insert_core_bench();

        unsafe {
            string_object_insert_cstr(this, -1, source.as_ptr());
            string_object_insert_cstr(this, i32::MIN, source.as_ptr());
        }

        assert!(
            unsafe { (*core::ptr::addr_of!(INSERT_CORE_CALLS)).is_empty() },
            "a negative index returns before measuring or dispatching"
        );
        assert_eq!(object.payload, 0x4444_4444 as *mut u8);
    }

    #[test]
    fn insert_cstr_dispatches_the_core_with_byte_length_and_verbatim_arguments() {
        // "héllo": six bytes but five codepoints — source_len must be the
        // BYTE length (strlen_safe_plus1 minus the NUL), which is what the
        // core's memmove/memcpy splice consumes; the character index is the
        // core's own codepoint-walk business.
        let source = *b"h\xc3\xa9llo\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x5555_5555 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = insert_core_bench();

        unsafe { string_object_insert_cstr(this, 7, source.as_ptr()) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(INSERT_CORE_CALLS)).clone() },
            std::vec![(this as usize, 7, source.as_ptr() as usize, 6)],
            "(this, index, source, strlen(source)) tail-branch arguments"
        );
    }

    #[test]
    fn insert_cstr_index_zero_and_int_max_reach_the_core() {
        let source = *b"x\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = insert_core_bench();

        unsafe {
            string_object_insert_cstr(this, 0, source.as_ptr());
            // The sampled call sites' append-at-end idiom (mvn r1,
            // #0x80000000 = 0x7fffffff): not negative, so it dispatches.
            string_object_insert_cstr(this, i32::MAX, source.as_ptr());
        }

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(INSERT_CORE_CALLS)).clone() },
            std::vec![
                (this as usize, 0, source.as_ptr() as usize, 1),
                (this as usize, i32::MAX, source.as_ptr() as usize, 1),
            ],
            "only a NEGATIVE index is rejected"
        );
    }

    #[test]
    fn insert_cstr_default_core_leaves_the_object_untouched() {
        // No bench: the wired default is missing_insert_core, a no-op
        // reproducing the unported core's own early-return paths. The
        // payload assertion holds even if a sibling test's recorder is
        // installed concurrently — the recorder never writes the object.
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0x6666_6666 as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);

        unsafe { string_object_insert_cstr(this, 0, b"x\0".as_ptr()) };

        assert_eq!(object.payload, 0x6666_6666 as *mut u8);
    }

    #[test]
    fn assign_forwards_the_source_payload_and_returns_this() {
        let mut destination = [0xa5u8; 16];
        let mut source_storage = *b"artist\0";
        let mut target = StringObject {
            vtable: core::ptr::null(),
            payload: 0xdead_beef as *mut u8,
        };
        let mut source = StringObject {
            vtable: core::ptr::null(),
            payload: source_storage.as_mut_ptr(),
        };
        let this = core::ptr::addr_of_mut!(target);
        let from = core::ptr::addr_of!(source);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        let returned = unsafe { string_object_assign(this, from) };

        assert_eq!(returned, this, "the operator returns `this` for chaining");
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 7, 0)],
            "the SOURCE's payload reached 0x08276474 (strlen \"artist\" + NUL)"
        );
        assert_eq!(&destination[..7], b"artist\0", "copied including the NUL");
        assert_eq!(
            source.payload,
            source_storage.as_mut_ptr(),
            "the source object is left untouched"
        );
        assert_eq!(
            target.payload, 0xdead_beef as *mut u8,
            "this operator never writes the payload word itself (+0x8 owns it)"
        );
    }

    #[test]
    fn assign_to_self_is_a_complete_no_op_but_still_returns_this() {
        let mut storage = *b"nowplaying\0";
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: storage.as_mut_ptr(),
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(0x4444_4444 as *mut u8);

        let returned = unsafe { string_object_assign(this, this as *const StringObject) };

        assert_eq!(returned, this);
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "`cmp r0, r1` skips the call entirely — not even a re-copy"
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "self-assignment must not release the payload it is keeping"
        );
        assert_eq!(object.payload, storage.as_mut_ptr(), "payload survives x = x");
    }

    #[test]
    fn assign_guards_on_address_not_on_a_shared_payload_pointer() {
        // Two DISTINCT objects that happen to share one payload pointer: the
        // original compares addresses (`cmp r0, r1`), so this runs the full
        // path even though the payload word is identical.
        let mut destination = [0xa5u8; 16];
        let mut shared = *b"ok\0";
        let mut target = StringObject {
            vtable: core::ptr::null(),
            payload: shared.as_mut_ptr(),
        };
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: shared.as_mut_ptr(),
        };
        let this = core::ptr::addr_of_mut!(target);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        let returned = unsafe { string_object_assign(this, core::ptr::addr_of!(source)) };

        assert_eq!(returned, this);
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, 3, 0)],
            "distinct addresses assign even with an identical payload word"
        );
        assert_eq!(&destination[..3], b"ok\0");
    }

    #[test]
    fn assign_from_a_null_payload_source_dispatches_only_the_clear_slot() {
        let mut target = StringObject {
            vtable: core::ptr::null(),
            payload: 0x5555_5555 as *mut u8,
        };
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let this = core::ptr::addr_of_mut!(target);
        let _bench = assign_cstr_bench(0x6666_6666 as *mut u8);

        let returned = unsafe { string_object_assign(this, core::ptr::addr_of!(source)) };

        assert_eq!(returned, this);
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "a NULL source payload never allocates"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize],
            "it reaches vtable slot +0xc through the ported assign_payload"
        );
    }


    // ---- string_object_construct_from_cstr ----------------------------

    #[test]
    fn construct_from_cstr_nulls_garbage_storage_then_assigns_the_source() {
        let mut destination = [0xa5u8; 16];
        let source = *b"track\0";
        // Raw storage: both words hold garbage, as they do at a real
        // construction site.
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        let returned =
            unsafe { string_object_construct_from_cstr(this, source.as_ptr()) };

        assert_eq!(returned, this, "the ADS constructor return convention");
        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(
            object.payload.is_null(),
            "the ctor NULLs the garbage payload word; only the +0x8 slot \
             ever writes it, and the mock does not"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, source.len(), 0u32)],
            "it chains to assign_cstr, which asks +0x8 for strlen + 1"
        );
        assert_eq!(&destination[..source.len()], &source[..]);
        assert_eq!(&source, b"track\0", "the source stays caller-owned");
    }

    #[test]
    fn construct_from_cstr_with_null_or_empty_source_leaves_a_fresh_object() {
        for source in [core::ptr::null(), b"\0".as_ptr()] {
            let mut object = StringObject {
                vtable: 0xdead_beef as *const StringObjectVtable,
                payload: 0xcafe_f00d as *mut u8,
            };
            let this = core::ptr::addr_of_mut!(object);
            let _bench = assign_cstr_bench(0x6666_6666 as *mut u8);

            assert_eq!(
                unsafe { string_object_construct_from_cstr(this, source) },
                this
            );

            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(object.payload.is_null());
            assert!(
                unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
                "an empty source never allocates"
            );
            assert_eq!(
                unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
                std::vec![this as usize],
                "it reaches vtable slot +0xc through the ported assign_cstr"
            );
        }
    }

    #[test]
    fn construct_from_cstr_allocation_failure_still_leaves_an_empty_object() {
        let source = *b"track\0";
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());

        assert_eq!(
            unsafe { string_object_construct_from_cstr(this, source.as_ptr()) },
            this
        );

        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(
            object.payload.is_null(),
            "a failed allocation leaves the freshly-constructed empty state"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).len() },
            1
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "failure never falls back to the +0xc slot"
        );
    }

    // ---- string_object_copy_construct ---------------------------------

    #[test]
    fn copy_construct_duplicates_the_source_payload_and_returns_this() {
        let mut destination = [0xa5u8; 16];
        let payload = *b"artist\0";
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: payload.as_ptr() as *mut u8,
        };
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        let returned =
            unsafe { string_object_copy_construct(this, core::ptr::addr_of!(source)) };

        assert_eq!(returned, this);
        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(object.payload.is_null(), "the ctor NULLs the garbage word");
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, payload.len(), 0u32)],
            "the SOURCE's payload sizes the +0x8 request, inclusive of the NUL"
        );
        assert_eq!(&destination[..payload.len()], &payload[..]);
        assert_eq!(
            source.payload,
            payload.as_ptr() as *mut u8,
            "the source object is never modified"
        );
    }

    #[test]
    fn copy_construct_from_self_plants_the_vtable_and_keeps_the_payload() {
        let payload = *b"artist\0";
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: payload.as_ptr() as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(0x6666_6666 as *mut u8);

        let returned = unsafe { string_object_copy_construct(this, this) };

        assert_eq!(returned, this);
        assert_eq!(
            object.vtable,
            &STRING_OBJECT_VTABLE as *const _,
            "the vtable store sits OUTSIDE the guard"
        );
        assert_eq!(
            object.payload,
            payload.as_ptr() as *mut u8,
            "the payload NULLing sits INSIDE the guard: self-construction \
             keeps the existing payload instead of dropping it"
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() }
                && unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "self-construction dispatches nothing at all"
        );
    }

    #[test]
    fn copy_construct_guards_on_address_not_on_a_shared_payload_pointer() {
        let mut destination = [0xa5u8; 16];
        let payload = *b"artist\0";
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: payload.as_ptr() as *mut u8,
        };
        // Distinct object, same payload pointer: the address guard does
        // not fire, so the full duplication path runs.
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: payload.as_ptr() as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(destination.as_mut_ptr());

        unsafe { string_object_copy_construct(this, core::ptr::addr_of!(source)) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(this as usize, payload.len(), 0u32)]
        );
        assert_eq!(&destination[..payload.len()], &payload[..]);
    }

    #[test]
    fn copy_construct_from_a_null_payload_source_dispatches_only_the_clear_slot() {
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(0x6666_6666 as *mut u8);

        assert_eq!(
            unsafe { string_object_copy_construct(this, core::ptr::addr_of!(source)) },
            this
        );

        assert!(object.payload.is_null());
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).is_empty() },
            "a NULL source payload never allocates"
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).clone() },
            std::vec![this as usize]
        );
    }

    #[test]
    fn copy_construct_allocation_failure_leaves_an_empty_object() {
        let payload = *b"artist\0";
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: payload.as_ptr() as *mut u8,
        };
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);
        let _bench = assign_cstr_bench(core::ptr::null_mut());

        unsafe { string_object_copy_construct(this, core::ptr::addr_of!(source)) };

        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(
            object.payload.is_null(),
            "a failed allocation leaves the empty-string state"
        );
        assert!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_CLEAR_CALLS)).is_empty() },
            "failure never falls back to the +0xc slot"
        );
    }

    #[test]
    fn wired_default_copy_construct_slot_is_the_ported_constructor() {
        // Serialize against the tests that swap the slot.
        let _lock = COPY_SLOT_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let installed = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_COPY_CONSTRUCT))
        };
        assert_eq!(
            installed as usize,
            string_object_copy_construct as usize,
            "the port replaced the empty-construction stub"
        );
    }

    /// The destroy tests share [`STRING_OBJECT_OPS_TEST_LOCK`] with sibling
    /// C++ module tests because the ops table and recorder are global.

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
        let lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
    fn the_destroy_veneer_reaches_destroy_and_is_a_distinct_symbol() {
        let _bench = bench();
        let mut object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: 0xcafe_f00d as *mut u8,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            assert_eq!(string_object_destroy_veneer(this), this);
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        assert_eq!(release_calls().len(), 1, "the veneer forwards exactly once");
        // The image has two entry points; an alias would make a hook at
        // 0x082792fc meaningless.
        assert_ne!(
            string_object_destroy_veneer as usize,
            string_object_destroy as usize
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
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
    fn utf8_strcmp_safe_thunk_compares_the_payload_against_the_cstr() {
        let mut payload_storage = *b"Acoustic\0";
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: payload_storage.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"Acoustic\0".as_ptr()),
                0,
                "the genre-dispatch shape: equal strings compare 0"
            );
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"Acoustid\0".as_ptr()),
                'c' as i32 - 'd' as i32,
                "the first unequal codepoints' difference"
            );
            assert_eq!(object.payload, payload_storage.as_mut_ptr());
        }
        assert_eq!(
            payload_storage, *b"Acoustic\0",
            "the comparator never writes"
        );
    }

    #[test]
    fn utf8_strcmp_safe_thunk_passes_a_null_payload_through_untouched() {
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            // The thunk guards nothing; the callee's own NULL
            // substitution makes a NULL payload read as "".
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"\0".as_ptr()),
                0
            );
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"a\0".as_ptr()),
                -(b'a' as i32)
            );
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, core::ptr::null()),
                0,
                "NULL vs NULL: both sides substitute the shared empty"
            );
        }
    }

    #[test]
    fn utf8_strcmp_safe_thunk_compares_decoded_multibyte_codepoints() {
        // U+00E9 (é) = 0xc3 0xa9 vs U+00E8 (è) = 0xc3 0xa8: the
        // difference is the decoded codepoints', not the raw bytes'.
        let mut payload_storage = *b"caf\xc3\xa9\0";
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: payload_storage.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"caf\xc3\xa8\0".as_ptr()),
                1,
                "0xe9 - 0xe8, decoded"
            );
            assert_eq!(
                string_object_utf8_strcmp_safe(&object, b"caf\xc3\xa9\0".as_ptr()),
                0
            );
        }
    }

    /// Short strings over ASCII plus multibyte leads through the
    /// object, checked against the ported utf8_strcmp_safe directly.
    #[test]
    fn utf8_strcmp_safe_thunk_matches_the_callee_on_a_sweep() {
        let cases: [&[u8]; 8] = [
            b"\0",
            b"a\0",
            b"ab\0",
            b"b\0",
            b"\xc3\xa9\0",
            b"\xc3\xa8x\0",
            b"abc\0",
            b"abd\0",
        ];
        for a in cases {
            for b in cases {
                let mut storage = [0u8; 8];
                storage[..a.len()].copy_from_slice(a);
                let object = StringObject {
                    vtable: core::ptr::null(),
                    payload: storage.as_mut_ptr(),
                };
                unsafe {
                    assert_eq!(
                        string_object_utf8_strcmp_safe(&object, b.as_ptr()),
                        utf8_strcmp_safe(a.as_ptr(), b.as_ptr()),
                        "a={a:?} b={b:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn is_empty_is_true_for_a_null_payload() {
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        unsafe {
            assert!(string_object_is_empty(&object));
        }
    }

    #[test]
    fn is_empty_is_true_for_a_payload_pointing_at_nul() {
        let storage = *b"\0trail";
        let object = StringObject {
            vtable: core::ptr::null(),
            payload: storage.as_ptr() as *mut u8,
        };
        unsafe {
            assert!(string_object_is_empty(&object));
        }
    }

    #[test]
    fn is_empty_is_false_for_a_nonempty_payload_and_reads_one_byte_only() {
        // A multi-byte payload: only the first byte decides, and the
        // object itself is untouched.
        let storage = *b"x\0";
        let object = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: storage.as_ptr() as *mut u8,
        };
        unsafe {
            assert!(!string_object_is_empty(&object));
            assert_eq!(object.vtable, 0xdead_beef as *const StringObjectVtable);
        }
        assert_eq!(storage, *b"x\0");
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
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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

    /// Restores the wired default (the ported copy constructor) on
    /// drop, even when a test panics.
    struct CopySlotGuard;
    impl Drop for CopySlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_COPY_CONSTRUCT)
                    .write_volatile(string_object_copy_construct);
            }
        }
    }

    /// Installs the recording copy constructor; restores the wired
    /// default on drop.
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
    fn record_from_string_id_wired_default_duplicates_the_source_string() {
        // The default slot (no mock) is the ported copy constructor: it
        // plants the StringObject vtable at +4, NULLs the payload at +8
        // and duplicates the source's payload through the +0x8 slot.
        let _lock = COPY_SLOT_LOCK.lock().unwrap();
        let mut destination = [0xa5u8; 16];
        let payload = *b"album\0";
        let mut source = StringObject {
            vtable: 0xdead_beef as *const StringObjectVtable,
            payload: payload.as_ptr() as *mut u8,
        };
        let _bench = assign_cstr_bench(destination.as_mut_ptr());
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
            "the copy constructor plants the StringObject vtable at +4"
        );
        assert!(
            record.string.payload.is_null(),
            "it NULLs the embedded payload at +8; only the +0x8 slot writes it"
        );
        assert_eq!(record.id, 0x1f00);
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(
                core::ptr::addr_of!(record.string) as usize,
                payload.len(),
                0u32
            )],
            "the duplication runs on the embedded subobject at +4"
        );
        assert_eq!(&destination[..payload.len()], &payload[..]);
        let source_after = unsafe {
            core::ptr::read(core::ptr::addr_of!(source) as *const [u8; core::mem::size_of::<StringObject>()])
        };
        assert_eq!(source_after, source_before, "the copy never touches the source");
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
    fn record_copy_construct_wired_default_duplicates_the_source_string() {
        // The default slot (no mock) is the ported copy constructor,
        // running on the source RECORD's embedded subobject at +4. The
        // id copy is the outer ctor's own work.
        let _lock = COPY_SLOT_LOCK.lock().unwrap();
        let mut destination = [0xa5u8; 16];
        let payload = *b"album\0";
        let mut source = StringIdRecord {
            vtable: 0xdead_beef as *const StringIdRecordVtable,
            string: StringObject {
                vtable: 0xcafe_f00d as *const StringObjectVtable,
                payload: payload.as_ptr() as *mut u8,
            },
            id: 0x1f02,
        };
        let _bench = assign_cstr_bench(destination.as_mut_ptr());
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
            "the copy constructor plants the StringObject vtable at +4"
        );
        assert!(
            record.string.payload.is_null(),
            "it NULLs the embedded payload at +8; only the +0x8 slot writes it"
        );
        assert_eq!(record.id, 0x1f02, "the outer ctor copies the id itself");
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(ASSIGN_CSTR_ALLOCATE_CALLS)).clone() },
            std::vec![(
                core::ptr::addr_of!(record.string) as usize,
                payload.len(),
                0u32
            )],
            "the duplication runs subobject-to-subobject"
        );
        assert_eq!(&destination[..payload.len()], &payload[..]);
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

    fn decode_prev(bytes: &[u8]) -> (u32, usize) {
        let end = unsafe { bytes.as_ptr().add(bytes.len()) };
        let mut cursor = end;
        let codepoint = unsafe { utf8_prev_codepoint(&mut cursor) };
        let consumed = unsafe { end.offset_from(cursor) as usize };
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

    #[test]
    fn utf8_prev_codepoint_consumes_one_ascii_byte_including_nul() {
        assert_eq!(decode_prev(&[0x00]), (0, 1));
        assert_eq!(decode_prev(&[0x7f]), (0x7f, 1));
    }

    #[test]
    fn utf8_prev_codepoint_decodes_two_bytes_without_continuation_validation() {
        assert_eq!(decode_prev(&[0xc2, 0xa2]), (0x00a2, 2));
        assert_eq!(
            decode_prev(&[0xc2, 0xff]),
            (0x00bf, 2),
            "the decoder masks a malformed final byte instead of rejecting it"
        );
    }

    #[test]
    fn utf8_prev_codepoint_decodes_three_bytes_without_continuation_validation() {
        assert_eq!(decode_prev(&[0xe2, 0x82, 0xac]), (0x20ac, 3));
        assert_eq!(
            decode_prev(&[0xe2, 0xff, 0x80]),
            (0x2fc0, 3),
            "both bytes after the 3-byte lead are merely payload-masked"
        );
    }

    #[test]
    fn utf8_prev_codepoint_malformed_and_four_byte_tails_consume_three_and_return_zero() {
        assert_eq!(
            decode_prev(&[0xaa, 0xbb, 0x80]),
            (0, 3),
            "no 0b1110xxxx byte appears in the three-byte lookbehind"
        );
        assert_eq!(
            decode_prev(&[0x80, b'a', 0xc2]),
            (0, 3),
            "a malformed final lead also consumes the three-byte lookbehind"
        );
        assert_eq!(
            decode_prev(&[0xf0, 0x9f, 0x92, 0xa9]),
            (0, 3),
            "the final continuation of a four-byte encoding is not decoded"
        );
    }

    // ---- utf16_utf8_byte_len_plus1 ----------------------------------

    fn utf16_encoded_len(code_units: &[u16]) -> i32 {
        unsafe { utf16_utf8_byte_len_plus1(code_units.as_ptr()) }
    }

    #[test]
    fn utf16_utf8_byte_len_plus1_null_and_terminator_are_one() {
        assert_eq!(unsafe { utf16_utf8_byte_len_plus1(core::ptr::null()) }, 1);
        assert_eq!(utf16_encoded_len(&[0]), 1);
    }

    #[test]
    fn utf16_utf8_byte_len_plus1_uses_the_exact_encoding_boundaries() {
        assert_eq!(
            utf16_encoded_len(&[0x7f, 0x80, 0x7ff, 0x800, 0]),
            9,
            "1 + 2 + 2 + 3 bytes, then the output terminator"
        );
    }

    #[test]
    fn utf16_utf8_byte_len_plus1_counts_surrogate_code_units_independently() {
        assert_eq!(
            utf16_encoded_len(&[0xd83d, 0xdca9, 0]),
            7,
            "the original counts a surrogate pair as two three-byte units plus NUL"
        );
    }

    #[test]
    fn utf16_utf8_byte_len_plus1_wraps_the_signed_accumulator() {
        assert_eq!(utf8_byte_len_add(i32::MAX, 1), i32::MIN);
        assert_eq!(utf8_byte_len_add(i32::MAX, 3), i32::MIN + 2);
        assert_eq!(utf8_byte_len_add(-1, 1), 0, "the terminal NUL also wraps");
    }

    // ---- utf16_utf8_byte_len_bounded_plus1 --------------------------

    fn bounded_utf16_encoded_len(code_units: &[u16], max_code_units: i32) -> i32 {
        unsafe { utf16_utf8_byte_len_bounded_plus1(code_units.as_ptr(), max_code_units) }
    }

    #[test]
    fn utf16_utf8_byte_len_bounded_plus1_null_and_nonpositive_bounds_are_one() {
        assert_eq!(
            unsafe { utf16_utf8_byte_len_bounded_plus1(core::ptr::null(), 4) },
            1
        );

        let unreadable = core::ptr::NonNull::<u16>::dangling().as_ptr();
        assert_eq!(unsafe { utf16_utf8_byte_len_bounded_plus1(unreadable, 0) }, 1);
        assert_eq!(unsafe { utf16_utf8_byte_len_bounded_plus1(unreadable, -1) }, 1);
    }

    #[test]
    fn utf16_utf8_byte_len_bounded_plus1_honors_bound_and_encoding_thresholds() {
        let code_units = [0x7f, 0x80, 0x7ff, 0x800];
        assert_eq!(
            bounded_utf16_encoded_len(&code_units, 4),
            9,
            "1 + 2 + 2 + 3 bytes, then the output terminator"
        );
        assert_eq!(
            bounded_utf16_encoded_len(&code_units, 3),
            6,
            "the positive bound excludes the fourth code unit"
        );
    }

    #[test]
    fn utf16_utf8_byte_len_bounded_plus1_stops_at_utf16_nul_before_bound() {
        assert_eq!(
            bounded_utf16_encoded_len(&[0x800, 0, 0x7f], 3),
            4,
            "the terminator is not counted as UTF-8 data and ends the loop"
        );
    }

    // ---- utf8_codepoint_byte_width ----------------------------------

    #[test]
    fn utf8_codepoint_byte_width_uses_unsigned_utf8_boundaries() {
        for (codepoint, expected) in [
            (0u32, 1),
            (0x7f, 1),
            (0x80, 2),
            (0x7ff, 2),
            (0x800, 3),
            (u32::MAX, 3),
        ] {
            assert_eq!(
                utf8_codepoint_byte_width(codepoint),
                expected,
                "codepoint {codepoint:#x}"
            );
        }
    }


    // ---- utf8_codepoint_count_safe ----------------------------------

    fn codepoints(text: &[u8]) -> usize {
        unsafe { utf8_codepoint_count_safe(text.as_ptr()) }
    }

    #[test]
    fn utf8_codepoint_count_safe_returns_zero_for_null_and_empty() {
        assert_eq!(unsafe { utf8_codepoint_count_safe(core::ptr::null()) }, 0);
        assert_eq!(codepoints(b"\0"), 0);
    }

    #[test]
    fn utf8_codepoint_count_safe_counts_ascii_bytes_like_strlen_safe() {
        for text in [&b"a\0"[..], b"abc\0", b"playlist name\0"] {
            assert_eq!(
                codepoints(text),
                unsafe { strlen_safe(text.as_ptr()) },
                "pure ASCII agrees with the byte strlen @ 0x082770bc"
            );
        }
    }

    #[test]
    fn utf8_codepoint_count_safe_counts_multibyte_sequences_as_one_each() {
        // "é€a" — a two-byte, a three-byte and an ASCII codepoint (6 bytes).
        let text = [0xc3, 0xa9, 0xe2, 0x82, 0xac, b'a', 0];
        assert_eq!(codepoints(&text), 3);
        assert_eq!(unsafe { strlen_safe(text.as_ptr()) }, 6, "six bytes, three codepoints");
    }

    #[test]
    fn utf8_codepoint_count_safe_stops_where_the_decoder_reports_zero() {
        // A four-byte lead decodes as the decoder's terminator: the count
        // stops there even though bytes follow.
        assert_eq!(codepoints(&[b'a', 0xf0, 0x9f, 0x92, 0xa9, b'b', 0]), 1);
        // A lone continuation byte is equally malformed and equally final.
        assert_eq!(codepoints(&[b'a', b'b', 0x80, 0x80, 0x80, b'c', 0]), 2);
    }

    #[test]
    fn utf8_codepoint_count_safe_does_not_validate_continuation_bytes() {
        // The decoder masks payload bits without checking them, so a
        // malformed but well-shaped two-byte sequence still counts as one.
        assert_eq!(codepoints(&[0xc3, 0xff, b'x', 0]), 2);
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

    fn encode_codepoint(codepoint: u32) -> [u8; 5] {
        let mut output = [0xa5; 5];
        unsafe { utf8_encode_codepoint(output.as_mut_ptr(), codepoint) };
        output
    }

    #[test]
    fn utf8_encode_codepoint_stores_all_normal_length_terminators() {
        assert_eq!(encode_codepoint(0), [0, 0, 0xa5, 0xa5, 0xa5]);
        assert_eq!(encode_codepoint(0x7f), [0x7f, 0, 0xa5, 0xa5, 0xa5]);

        assert_eq!(encode_codepoint(0x80), [0xc2, 0x80, 0, 0xa5, 0xa5]);
        assert_eq!(encode_codepoint(0x7ff), [0xdf, 0xbf, 0, 0xa5, 0xa5]);

        assert_eq!(encode_codepoint(0x800), [0xe0, 0xa0, 0x80, 0, 0xa5]);
        assert_eq!(encode_codepoint(0xffff), [0xef, 0xbf, 0xbf, 0, 0xa5]);
    }

    #[test]
    fn utf8_encode_codepoint_retains_the_retail_four_byte_hole() {
        assert_eq!(
            encode_codepoint(0x10000),
            [0xf0, 0x80, 0xa5, 0x80, 0],
            "the raw ARM has no strb to destination + 2"
        );
        assert_eq!(
            encode_codepoint(0x10ffff),
            [0xf4, 0xbf, 0xa5, 0xbf, 0],
            "the maximum accepted value follows the same partial-store path"
        );
    }

    #[test]
    fn utf8_encode_codepoint_accepts_surrogates_and_rejects_the_unsigned_range() {
        assert_eq!(encode_codepoint(0xd7ff), [0xed, 0x9f, 0xbf, 0, 0xa5]);
        assert_eq!(encode_codepoint(0xd800), [0xed, 0xa0, 0x80, 0, 0xa5]);
        assert_eq!(encode_codepoint(0xdfff), [0xed, 0xbf, 0xbf, 0, 0xa5]);

        assert_eq!(encode_codepoint(0x110000), [0, 0xa5, 0xa5, 0xa5, 0xa5]);
        assert_eq!(
            encode_codepoint(0x7fff_ffff),
            [0, 0xa5, 0xa5, 0xa5, 0xa5],
            "rejection writes only the first NUL"
        );
    }

    #[test]
    fn utf8_encode_codepoint_uses_signed_thresholds_after_ascii() {
        assert_eq!(
            encode_codepoint(0x8000_0000),
            [0xc0, 0x80, 0, 0xa5, 0xa5],
            "a negative signed u32 reaches the two-byte path"
        );
        assert_eq!(encode_codepoint(u32::MAX), [0xff, 0xbf, 0, 0xa5, 0xa5]);
    }
}
