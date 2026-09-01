//! The path class's constructors over caller-supplied two-word string
//! object storage: base-construct from a C string or StringObject and
//! re-plant the derived vtable word, or default-construct an empty path
//! object directly.
//!
//! Ports:
//! - [`path_object_construct`] — original: `FUN_08279284` @ 0x08279284
//!   (20 bytes; **24 `bl` call sites**, grep on `decomp/osos.asm`).
//! - [`path_object_construct_from_string_object`] — original:
//!   `FUN_0827929c` @ 0x0827929c (20 bytes of code plus its 4-byte
//!   vtable literal @ 0x082792b0, so 24 bytes of true extent; **25 plain
//!   `bl` call sites, 0 `b`, 0 predicated**, binary-scanned).
//! - [`path_object_copy_construct`] — original: `FUN_082792b4` @
//!   0x082792b4 (20 bytes of code plus the 4-byte vtable literal @
//!   0x082792c8, so 24 bytes of true extent; **28 `bl` call sites: 27
//!   plain plus ONE predicated `blne` @ 0x083de170, 0 `b`**, binary-
//!   scanned by decoding every B/BL word in `work/firmware/osos.dec`;
//!   zero data-word references, so never virtually dispatched).
//! - [`path_object_default_construct`] — original: `FUN_082792cc` @
//!   0x082792cc (20 bytes: five ARM instructions plus the 4-byte vtable
//!   literal @ 0x082792e0, so 24 bytes of true extent; **42 `bl`, 0 `b`,
//!   0 predicated call sites**, binary-scanned by decoding every B/BL
//!   word in `work/firmware/osos.dec`).
//!
//! ## What it is
//!
//! An ADS C++ converting constructor, `PathObject(const char *path)`
//! over caller-supplied raw storage — the C++ source shape is
//!
//! ```text
//! PathObject::PathObject(const char *path) : StringObject(path) {
//!     this->vtable = &PathObject_vtable;   // 0x089a60d8
//! }
//! ```
//!
//! Decoded from the raw ARM at 0x08279284:
//!
//! ```text
//! 08279284  stmdb sp!, {r4, lr}
//! 08279288  bl    0x08277304        @ string_object_construct_from_cstr
//! 0827928c  ldr   r1, [0x8279298]   @ 0x089a60d8: path-class vtable
//! 08279290  str   r1, [r0, #0x0]    @ over the base StringObject vtable
//! 08279294  ldmia sp!, {r4, pc}     @ return the base ctor's result
//! ```
//!
//! Both arguments flow into the base constructor untouched — no
//! register is written between entry and the `bl`, so r0 (the raw
//! storage) and r1 (the caller's C string) arrive verbatim, the same
//! invisible-forwarding shape the base port documents for its own
//! decomp. The base constructor @ 0x08277304 (ported as
//! [`string_object_construct_from_cstr`]) plants the base
//! StringObject vtable at +0x00, NULLs the +0x04 payload word and
//! assigns the C string; the veneer then overwrites +0x00 with the
//! literal-pool word @ 0x08279298 = **0x089a60d8** (binary-verified
//! against osos.dec), the vtable of the StringObject-derived path
//! class, and returns the base constructor's result straight from r0 —
//! the ADS constructor convention.
//!
//! The pushed r4 is never written: pure non-leaf frame etiquette, so
//! the port saves no register.
//!
//! ## Call-site census
//!
//! 24 `bl` sites: 0x0806859c / 0x080685bc / 0x080685dc (the
//! `FUN_08068504` database-path trio: Photo Database, ArtworkDB,
//! iTunesDB), 0x08084d38 (the remove wrapper's guard), 0x080890c4,
//! 0x08089168, 0x080891f0, 0x08090bd4, 0x0809b688, 0x080a8ec0,
//! 0x080f4ab8 (the [`crate::app::path_exists`] wrapper), 0x080f4b2c /
//! 0x080f4b3c (the `FUN_080f4b1c` pair — Ghidra shows no r1 write for
//! the first, a stale-register construction of an empty path),
//! 0x08100980, 0x08117914, 0x0811af80, 0x0811c5bc, 0x08136570,
//! 0x081a29b0, 0x081a2c54, 0x081afdfc, 0x081b0018, 0x081bc670 and
//! 0x081bda2c. Every site passes raw two-word storage in r0 and a path
//! C string in r1; most destroy the object through the ported
//! `string_object_destroy_veneer` @ 0x082792fc on scope exit.
//!
//! ## Faithful details
//!
//! - The return is the base constructor's RESULT, not a recomputed
//!   `this` — r0 flows from the `bl` into the epilogue untouched.
//!   Observable only if a constructor ever returns anything but its
//!   own storage; reproduced exactly by returning the base result.
//! - The vtable overwrite is UNCONDITIONAL and runs after the assign:
//!   an empty/NULL source or a failed payload allocation still leaves
//!   the derived path-class vtable at +0x00 over a NULL payload.
//! - Neither argument is NULL-guarded: the original faults inside the
//!   base constructor's vtable store for a NULL `this`, and so does
//!   the port.
//!
//! ## Deviations
//!
//! - The base constructor is ported and called DIRECTLY (the
//!   transition_addon.rs ported-callees-called-directly precedent);
//!   on host its assign-cstr allocation boundary fails closed, so a
//!   constructed path object carries the derived vtable over a NULL
//!   payload.
//! - The planted vtable is the ROM identity constant
//!   [`PATH_OBJECT_VTABLE_ADDRESS`] (the `StringObjectVtable`
//!   ROM-identity precedent; nothing ported dispatches through it).
//! - With this port the [`crate::app::path_exists`]
//!   `PATH_OBJECT_CTOR` seam's wired default switched from its
//!   faithful local default to this symbol (the
//!   `path_probe_via_facade` rewiring precedent), so this symbol IS
//!   hook-ready.
//!
//! ## The default constructor
//!
//! `path_object_default_construct` — original: `FUN_082792cc` @
//! 0x082792cc — is the same class's DEFAULT constructor,
//! `PathObject()`, decoded from the raw ARM:
//!
//! ```text
//! 082792cc  mov  r1, #0
//! 082792d0  str  r1, [r0, #4]     @ this->payload = NULL
//! 082792d4  ldr  r1, [0x82792e0]  @ 0x089a60d8: path-class vtable
//! 082792d8  str  r1, [r0, #0x0]   @ this->vtable = it
//! 082792dc  bx   lr               @ return this (r0 untouched)
//! 082792e0  .word 0x089a60d8      @ literal pool; the next function
//!                                   starts at 0x082792e4
//! ```
//!
//! Unlike the converting veneer this is a LEAF: it does not chain the
//! base StringObject default constructor @ 0x08277440 (same shape —
//! vtable at +0x00, NULL payload at +0x04, `bx lr` — but with the BASE
//! vtable 0x089a6044). The base's vtable store would be dead one
//! instruction later, so the compiler folded base+derived into the two
//! stores above, with the payload NULL written FIRST (the base
//! constructor's own order is vtable-then-payload; here it is
//! payload-then-vtable — unobservable to any caller, reproduced in the
//! port's store order).
//!
//! Call-site census: **42 `bl`, 0 `b`, 0 predicated** sites and ZERO
//! data-word references (a full-image word scan finds no 0x082792cc
//! outside the literal-free code stream — the address appears in no
//! vtable, so the constructor is never dispatched virtually). Sampled
//! sites default-construct stack-resident path-object guards in pairs
//! — 0x0805aa08/0x0805aa10 (`add r0, sp, #12` / `add r0, sp, #4`, both
//! destroyed through the ported `string_object_destroy_veneer` @
//! 0x082792fc on the error path) and 0x082736ec/0x082736f4
//! (`add r0, sp, #16` / `add r0, sp, #8`). Every caller passes raw
//! two-word storage; `this` is never NULL-guarded, exactly like the
//! base default constructor.
//!
//! Faithful details:
//!
//! - Both words are written UNCONDITIONALLY: constructing over an
//!   already-populated object discards its vtable AND its payload
//!   pointer (the original leaks the old payload — no release — and so
//!   does the port).
//! - The return is `this` by register passthrough: r0 is never
//!   written, so the ADS constructor convention hands the caller its
//!   own storage pointer back.
//!
//! ## The copy constructor
//!
//! `path_object_copy_construct` — original: `FUN_082792b4` @
//! 0x082792b4 — is the same class's COPY constructor, `PathObject(const
//! StringObject &source)` over caller-supplied raw storage, sitting
//! between the converting and default siblings in the image. Decoded
//! from the raw ARM:
//!
//! ```text
//! 082792b4  stmdb sp!, {r4, lr}
//! 082792b8  bl    0x082773e0        @ string_object_copy_construct
//! 082792bc  ldr   r1, [0x82792c8]   @ 0x089a60d8: path-class vtable
//! 082792c0  str   r1, [r0, #0x0]    @ over the base StringObject vtable
//! 082792c4  ldmia sp!, {r4, pc}     @ return the base ctor's result
//! 082792c8  .word 0x089a60d8        @ literal pool; the next function
//!                                     (path_object_default_construct)
//!                                     starts at 0x082792cc
//! ```
//!
//! The exact shape of the converting veneer above with the base COPY
//! constructor @ 0x082773e0 (ported as
//! [`string_object_copy_construct`]) in the `bl` slot: both arguments
//! flow in untouched, the base plants its vtable, duplicates the
//! source's payload word (its address-not-content self-construction
//! guard included), and the veneer then overwrites +0x00 with the
//! derived identity and returns the base's r0 verbatim.
//!
//! Call-site census: **28 `bl`, 0 `b`, 0 data-word references**. 27
//! plain sites: 0x0812bbb4 / 0x0812bbe0, 0x081a2ae0, the 0x081bc9d8 -
//! 0x081bde78 cluster of thirteen, 0x081ef788 / 0x081ef9a4,
//! 0x0826c970, 0x08278418, 0x08278eb8 (inside
//! `silver_controller_transition_addon_construct`, building the
//! embedded string member at this+0x0c) and the 0x082a55f4 -
//! 0x082a563c cluster of four. The ONE predicated site is a `blne` @
//! 0x083de170 under `cmp r0, #0`: that caller NULL-guards the storage
//! pointer itself, so the veneer — like its siblings — carries no NULL
//! guard of its own and faults inside the base constructor for a NULL
//! `this`.

use crate::cxx::string_object::{
    string_object_construct_from_cstr, string_object_copy_construct,
    StringObject, StringObjectVtable,
};

/// Original load address of the StringObject-derived path class's
/// vtable — the literal-pool word @ 0x08279298 the veneer plants over
/// the base StringObject vtable at +0x00 (binary-verified against
/// osos.dec). Kept as an identity constant: no ported code dispatches
/// through it.
pub const PATH_OBJECT_VTABLE_ADDRESS: usize = 0x089a_60d8;

/// path_object_construct — original: `FUN_08279284` @ 0x08279284 (20
/// bytes; **24 `bl` call sites**, grep on `decomp/osos.asm`).
///
/// Base-constructs the two-word [`StringObject`] at `this` from the
/// caller-owned C string `path`, overwrites the +0x00 vtable word with
/// the derived path-class vtable identity
/// [`PATH_OBJECT_VTABLE_ADDRESS`], and returns the base constructor's
/// result verbatim. See the module header for the stock instruction
/// sequence, the call-site census, and the faithful-details list.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_construct(
    this: *mut StringObject,
    path: *const u8,
) -> *mut StringObject {
    let this = string_object_construct_from_cstr(this, path);
    (*this).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    this
}

/// path_object_construct_from_string_object — original: `FUN_0827929c`
/// @ 0x0827929c (20 bytes of code plus the 4-byte vtable literal @
/// 0x082792b0 = 0x089a60d8, so 24 bytes of true extent; the next
/// function, [`path_object_copy_construct`], starts at 0x082792b4.
/// **25 plain `bl` call sites, 0 `b`, 0 predicated calls, and zero
/// data-word references**, binary-scanned by decoding every B/BL word in
/// `work/firmware/osos.dec`; it is never virtually dispatched).
///
/// Constructs the StringObject-derived path class at `this` from the
/// already-constructed base [`StringObject`] `source`: it forwards both
/// registers unchanged to [`string_object_copy_construct`], overwrites
/// the returned object's +0x00 base vtable with the derived
/// [`PATH_OBJECT_VTABLE_ADDRESS`] identity, then returns the base
/// constructor's result verbatim. The 25 callers construct from
/// StringObjects—for example, 0x080474d4 takes the StringObject result of
/// `string_owner_embedded_init` in r1—rather than a C string; the
/// byte-identical [`path_object_copy_construct`] sibling has the narrower
/// PathObject-source type at its C++ boundary.
///
/// The derived-vtable overwrite is unconditional after the base copy:
/// null-payload sources, failed payload duplication, and `this == source`
/// still receive the derived identity. Neither pointer is NULL-guarded,
/// matching the base constructor's faults; unlike the copy sibling no
/// caller is predicated, so all 25 callers rely on valid storage.
///
/// Deliberate deviations: calls the ported base constructor directly, and
/// uses the ROM vtable identity constant instead of a host-callable vtable.
/// A distinct link section prevents LLVM from folding this export into its
/// byte-identical copy-constructor sibling.
///
/// # Safety
///
/// `this` must point to writable two-word raw storage; `source` must point
/// to a readable [`StringObject`], unless it is exactly `this`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[link_section = ".text.path_object_construct_from_string_object"]
pub unsafe extern "C" fn path_object_construct_from_string_object(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    let this = string_object_copy_construct(this, source);
    (*this).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    this
}

/// path_object_copy_construct — original: `FUN_082792b4` @ 0x082792b4
/// (20 bytes of code + the 4-byte vtable literal @ 0x082792c8 =
/// 0x089a60d8, so 24 bytes of true extent; the next function,
/// [`path_object_default_construct`], starts at 0x082792cc. **28 `bl`
/// call sites — 27 plain plus ONE predicated `blne` @ 0x083de170, 0
/// `b`, zero data-word references**, binary-scanned against
/// `work/firmware/osos.dec`, so never virtually dispatched).
///
/// The path class's copy constructor: copy-constructs the two-word
/// [`StringObject`] at `this` from `source` through the ported base
/// [`string_object_copy_construct`] (vtable + payload duplication with
/// its address-not-content self guard), then overwrites the +0x00
/// vtable word with the derived path-class identity
/// [`PATH_OBJECT_VTABLE_ADDRESS`] and returns the base constructor's
/// result verbatim. See the module header for the stock instruction
/// sequence and the call-site census.
///
/// Faithful details, shared with the converting sibling:
///
/// - The return is the base constructor's RESULT, not a recomputed
///   `this` — r0 flows from the `bl` into the epilogue untouched.
/// - The vtable overwrite is UNCONDITIONAL and runs after the copy:
///   a NULL-payload source, a failed payload allocation, and the
///   self-construction guard path all still leave the derived
///   path-class vtable at +0x00.
/// - Neither argument is NULL-guarded: the original faults inside the
///   base constructor's vtable store for a NULL `this` and on the
///   payload load for a NULL `source`, and so does the port. The one
///   predicated call site (`blne` @ 0x083de170) shows callers do
///   their own guarding.
///
/// Deviation: the base constructor is ported and called DIRECTLY (the
/// transition_addon.rs ported-callees-called-directly precedent); the
/// planted vtable is the ROM identity constant
/// [`PATH_OBJECT_VTABLE_ADDRESS`], not a host-callable pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_copy_construct(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    let this = string_object_copy_construct(this, source);
    (*this).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    this
}

/// path_object_default_construct — original: `FUN_082792cc` @
/// 0x082792cc (20 bytes of code + the 4-byte vtable literal @
/// 0x082792e0; **42 `bl`, 0 `b`, 0 predicated call sites**,
/// binary-scanned against `work/firmware/osos.dec`; zero data-word
/// references, so never virtually dispatched).
///
/// Default-constructs the two-word [`StringObject`] at `this` as an
/// EMPTY path object: NULLs the +0x04 payload word, then plants the
/// derived path-class vtable identity [`PATH_OBJECT_VTABLE_ADDRESS`]
/// at +0x00 (the original's store order), returning `this` by r0
/// passthrough. A leaf — unlike [`path_object_construct`] it does not
/// chain the base constructor; the folded stores are the whole body.
/// Neither word survives: both are written unconditionally.
///
/// # Safety
///
/// `this` must address at least two writable words of raw storage.
/// The original NULL-`this` faults on the payload store; so does the
/// port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_default_construct(
    this: *mut StringObject,
) -> *mut StringObject {
    (*this).payload = core::ptr::null_mut();
    (*this).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use std::vec::Vec;

    static PATH: &[u8] = b"iPod_Control/Device/radio_test\0";

    /// A garbage pre-fill any real construction must overwrite: the
    /// base constructor defines both words, so nothing of this may
    /// survive.
    const GARBAGE_VTABLE: *const StringObjectVtable =
        0xdead_beefusize as *const StringObjectVtable;
    const GARBAGE_PAYLOAD: *mut u8 = 0x5a5a_5a5ausize as *mut u8;

    fn garbage_storage() -> StringObject {
        StringObject {
            vtable: GARBAGE_VTABLE,
            payload: GARBAGE_PAYLOAD,
        }
    }

    /// The independent reference model of the original's two steps:
    /// base construction semantics (modeled base vtable + NULL payload
    /// + the assign), then the unconditional derived-identity store
    /// over +0x00, returning the base result. It runs the same ported
    /// base constructor the veneer does — the base's own behavior is
    /// pinned by cxx/string_object's tests; what this model pins is
    /// the COMPOSITION (base first, overwrite second, result
    /// verbatim).
    unsafe fn reference_model(
        this: *mut StringObject,
        path: *const u8,
    ) -> *mut StringObject {
        let result = string_object_construct_from_cstr(this, path);
        (*result).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
        result
    }

    #[test]
    fn returns_the_base_ctors_result_verbatim() {
        let mut storages: Vec<StringObject> =
            (0..4).map(|_| garbage_storage()).collect();
        for storage in storages.iter_mut() {
            let this = storage as *mut StringObject;
            unsafe {
                let result = path_object_construct(this, PATH.as_ptr());
                assert_eq!(
                    result, this,
                    "r0 flows from the bl into the epilogue untouched: this verbatim"
                );
            }
        }
    }

    #[test]
    fn plants_the_derived_vtable_over_the_base() {
        let mut storage = garbage_storage();
        unsafe {
            path_object_construct(&mut storage, PATH.as_ptr());
            assert_eq!(
                storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS,
                "the +0x00 word is the literal-pool identity 0x089a60d8"
            );
            assert_ne!(
                storage.vtable,
                &STRING_OBJECT_VTABLE as *const _,
                "the overwrite replaced the modeled base vtable the ctor planted"
            );
        }
    }

    #[test]
    fn base_construction_defines_both_words_from_garbage() {
        for path in [b"\0".as_ptr(), PATH.as_ptr()] {
            let mut storage = garbage_storage();
            unsafe {
                path_object_construct(&mut storage, path);
                assert_ne!(
                    storage.vtable, GARBAGE_VTABLE,
                    "the base constructor ran: the garbage vtable is gone"
                );
                assert_ne!(
                    storage.payload, GARBAGE_PAYLOAD,
                    "the base constructor ran: the garbage payload is gone"
                );
            }
        }
    }

    #[test]
    fn empty_and_null_sources_still_carry_the_derived_vtable() {
        // The +0xc clear boundary is a no-op for empty/NULL sources, so
        // these paths are immune to the assign-ops state: the payload
        // the base constructor NULLed stays NULL, and the unconditional
        // overwrite still plants the derived identity.
        for path in [b"\0".as_ptr(), core::ptr::null()] {
            let mut storage = garbage_storage();
            unsafe {
                let result = path_object_construct(&mut storage, path);
                assert_eq!(result, &mut storage as *mut _);
                assert_eq!(
                    storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS,
                    "the overwrite is unconditional — no assign outcome skips it"
                );
                assert!(
                    storage.payload.is_null(),
                    "empty/NULL sources leave the freshly-NULLed payload alone"
                );
            }
        }
    }

    #[test]
    fn fail_closed_assign_leaves_a_null_payload_for_nonempty_sources() {
        // The wired default of the assign-cstr allocation boundary
        // returns NULL (the path_exists.rs
        // default_ctor_builds_the_derived_path_object precedent): the
        // constructed path object is vtable-only.
        let mut storage = garbage_storage();
        unsafe {
            path_object_construct(&mut storage, PATH.as_ptr());
            assert_eq!(storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert!(
                storage.payload.is_null(),
                "the default allocation boundary fails closed, so no payload"
            );
        }
    }

    #[test]
    fn matches_the_reference_model_across_sources() {
        let sources: [&[u8]; 4] = [
            b"\0",
            b"a\0",
            b"iPod_Control/iTunes/iTunesDB\0",
            b"/very/long/path/component/that/keeps/going/and/going/on\0",
        ];
        for source in sources {
            let mut ported = garbage_storage();
            let mut model = garbage_storage();
            unsafe {
                let ported_result =
                    path_object_construct(&mut ported, source.as_ptr());
                let model_result =
                    reference_model(&mut model, source.as_ptr());
                assert_eq!(
                    ported_result,
                    &mut ported as *mut _,
                    "ported returns this"
                );
                assert_eq!(
                    model_result,
                    &mut model as *mut _,
                    "model returns this"
                );
                assert_eq!(
                    ported.vtable as usize, model.vtable as usize,
                    "vtable word matches the reference composition"
                );
                assert_eq!(
                    ported.payload, model.payload,
                    "payload word matches the reference composition"
                );
            }
        }
    }

    // --- path_object_default_construct @ 0x082792cc ---

    /// The independent byte-level reference of the original's two
    /// stores: payload NULL first, derived vtable identity second,
    /// this returned — over raw 8-byte storage, nothing else touched.
    unsafe fn default_construct_reference(this: *mut StringObject) -> *mut StringObject {
        (*this).payload = core::ptr::null_mut();
        (*this).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
        this
    }

    #[test]
    fn default_construct_returns_this_verbatim() {
        let mut storages: Vec<StringObject> =
            (0..4).map(|_| garbage_storage()).collect();
        for storage in storages.iter_mut() {
            let this = storage as *mut StringObject;
            unsafe {
                assert_eq!(
                    path_object_default_construct(this),
                    this,
                    "r0 is never written: the caller's storage pointer passes through"
                );
            }
        }
    }

    #[test]
    fn default_construct_defines_both_words_from_garbage() {
        let mut storage = garbage_storage();
        unsafe {
            path_object_default_construct(&mut storage);
            assert_eq!(
                storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS,
                "+0x00 is the literal-pool identity 0x089a60d8, not the modeled base vtable"
            );
            assert_ne!(
                storage.vtable,
                &STRING_OBJECT_VTABLE as *const _,
                "no base-constructor vtable ever lands: the leaf folds it away"
            );
            assert!(
                storage.payload.is_null(),
                "+0x04 is NULLed — the empty path object's payload"
            );
        }
    }

    #[test]
    fn default_construct_over_an_existing_object_discards_both_words() {
        // Both stores are unconditional: reconstructing over a live
        // object overwrites its vtable AND its payload pointer (the
        // original leaks the old payload; the port reproduces the
        // overwrite, the leak is the caller's bug either way).
        let fake_payload = 0x0bad_f00dusize as *mut u8;
        let mut storage = StringObject {
            vtable: PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable,
            payload: fake_payload,
        };
        unsafe {
            path_object_default_construct(&mut storage);
            assert_eq!(storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert!(
                storage.payload.is_null(),
                "the prior payload pointer is discarded, not released"
            );
        }
    }

    #[test]
    fn default_construct_matches_the_byte_reference() {
        let mut ported = garbage_storage();
        let mut model = garbage_storage();
        unsafe {
            assert_eq!(
                path_object_default_construct(&mut ported),
                &mut ported as *mut _,
                "ported returns its own storage"
            );
            assert_eq!(
                default_construct_reference(&mut model),
                &mut model as *mut _,
                "reference returns its own storage"
            );
            assert_eq!(ported.vtable as usize, model.vtable as usize);
            assert_eq!(ported.payload, model.payload);
        }
    }

    // --- path_object_copy_construct @ 0x082792b4 ---

    static SOURCE_PAYLOAD: &[u8] = b"iPod_Control/Music/F00/track.m4a\0";

    fn source_object(payload: *mut u8) -> StringObject {
        StringObject {
            // The base copy constructor reads only the source's +0x04
            // payload word; its vtable is never consulted.
            vtable: core::ptr::null(),
            payload,
        }
    }

    /// The independent reference model of the original's two steps:
    /// base copy-construction semantics, then the unconditional
    /// derived-identity store over +0x00, returning the base result.
    /// It runs the same ported base constructor the veneer does — the
    /// base's own behavior is pinned by cxx/string_object's tests;
    /// what this model pins is the COMPOSITION.
    unsafe fn copy_construct_reference(
        this: *mut StringObject,
        source: *const StringObject,
    ) -> *mut StringObject {
        let result = string_object_copy_construct(this, source);
        (*result).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
        result
    }

    // --- path_object_construct_from_string_object @ 0x0827929c ---

    #[test]
    fn construct_from_string_object_matches_copy_composition_across_sources() {
        let payloads = [
            core::ptr::null_mut(),
            b"\0".as_ptr() as *mut u8,
            b"a\0".as_ptr() as *mut u8,
            SOURCE_PAYLOAD.as_ptr() as *mut u8,
        ];
        for payload in payloads {
            let source = source_object(payload);
            let mut ported = garbage_storage();
            let mut model = garbage_storage();
            unsafe {
                assert_eq!(
                    path_object_construct_from_string_object(&mut ported, &source),
                    &mut ported as *mut _,
                    "the base copy result flows through r0 unchanged"
                );
                assert_eq!(
                    copy_construct_reference(&mut model, &source),
                    &mut model as *mut _,
                    "the independent composition returns its storage"
                );
                assert_eq!(ported.vtable as usize, model.vtable as usize);
                assert_eq!(ported.payload, model.payload);
                assert_eq!(
                    source.payload, payload,
                    "constructing a path never modifies its StringObject source"
                );
            }
        }
    }

    #[test]
    fn construct_from_string_object_self_preserves_payload() {
        let mut storage = garbage_storage();
        let this = core::ptr::addr_of_mut!(storage);
        unsafe {
            assert_eq!(path_object_construct_from_string_object(this, this), this);
            assert_eq!(storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert_eq!(
                storage.payload, GARBAGE_PAYLOAD,
                "the base copy constructor's address guard skips the payload clear"
            );
        }
    }

    #[test]
    fn copy_construct_returns_the_base_ctors_result_verbatim() {
        let source = source_object(core::ptr::null_mut());
        let mut storages: Vec<StringObject> =
            (0..4).map(|_| garbage_storage()).collect();
        for storage in storages.iter_mut() {
            let this = storage as *mut StringObject;
            unsafe {
                assert_eq!(
                    path_object_copy_construct(this, &source),
                    this,
                    "r0 flows from the bl into the epilogue untouched"
                );
            }
        }
    }

    #[test]
    fn copy_construct_plants_the_derived_vtable_over_the_base() {
        let source = source_object(SOURCE_PAYLOAD.as_ptr() as *mut u8);
        let mut storage = garbage_storage();
        unsafe {
            path_object_copy_construct(&mut storage, &source);
            assert_eq!(
                storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS,
                "the +0x00 word is the literal-pool identity 0x089a60d8"
            );
            assert_ne!(
                storage.vtable,
                &STRING_OBJECT_VTABLE as *const _,
                "the overwrite replaced the modeled base vtable the copy ctor planted"
            );
        }
    }

    #[test]
    fn copy_construct_from_a_null_payload_source_stays_empty() {
        let source = source_object(core::ptr::null_mut());
        let mut storage = garbage_storage();
        unsafe {
            assert_eq!(
                path_object_copy_construct(&mut storage, &source),
                &mut storage as *mut _
            );
            assert_eq!(storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert!(
                storage.payload.is_null(),
                "the base copy ctor NULLs the garbage word; the clear boundary leaves it"
            );
            assert!(
                source.payload.is_null(),
                "the source object is never modified"
            );
        }
    }

    #[test]
    fn copy_construct_fail_closed_assign_leaves_a_null_payload() {
        // The wired default of the assign allocation boundary returns
        // NULL (the fail-closed precedent of the converting sibling's
        // tests): a nonempty source payload still yields a vtable-only
        // path object. strlen_safe_plus1 DOES read the source payload
        // before the allocation fails, so it must be real memory.
        let source = source_object(SOURCE_PAYLOAD.as_ptr() as *mut u8);
        let mut storage = garbage_storage();
        unsafe {
            path_object_copy_construct(&mut storage, &source);
            assert_eq!(storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert!(
                storage.payload.is_null(),
                "a failed allocation leaves the freshly-NULLed payload alone"
            );
            assert_eq!(
                source.payload,
                SOURCE_PAYLOAD.as_ptr() as *mut u8,
                "the source object is never modified"
            );
        }
    }

    #[test]
    fn copy_construct_from_self_keeps_the_payload() {
        // The base copy ctor's address-not-content guard: for
        // `this == source` it plants its vtable but leaves the payload
        // word alone, and the veneer then overwrites the vtable with
        // the derived identity. The garbage payload is never
        // dereferenced — a missing guard would fault on it.
        let mut storage = garbage_storage();
        let this = core::ptr::addr_of_mut!(storage);
        unsafe {
            assert_eq!(path_object_copy_construct(this, this), this);
            assert_eq!(
                storage.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS,
                "the unconditional overwrite still runs on the self path"
            );
            assert_eq!(
                storage.payload, GARBAGE_PAYLOAD,
                "self-construction keeps the existing payload word"
            );
        }
    }

    #[test]
    fn copy_construct_matches_the_reference_model_across_sources() {
        let sources = [
            core::ptr::null_mut(),
            b"\0".as_ptr() as *mut u8,
            b"a\0".as_ptr() as *mut u8,
            SOURCE_PAYLOAD.as_ptr() as *mut u8,
        ];
        for payload in sources {
            let source = source_object(payload);
            let mut ported = garbage_storage();
            let mut model = garbage_storage();
            unsafe {
                assert_eq!(
                    path_object_copy_construct(&mut ported, &source),
                    &mut ported as *mut _,
                    "ported returns this"
                );
                assert_eq!(
                    copy_construct_reference(&mut model, &source),
                    &mut model as *mut _,
                    "model returns this"
                );
                assert_eq!(
                    ported.vtable as usize, model.vtable as usize,
                    "vtable word matches the reference composition"
                );
                assert_eq!(
                    ported.payload, model.payload,
                    "payload word matches the reference composition"
                );
            }
        }
    }
}
