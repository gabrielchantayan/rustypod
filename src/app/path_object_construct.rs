//! The path class's converting-constructor veneer: base-construct a
//! two-word string object from a C string, then re-plant the vtable
//! word with the StringObject-derived path class's vtable.
//!
//! Port:
//! - [`path_object_construct`] — original: `FUN_08279284` @ 0x08279284
//!   (20 bytes; **24 `bl` call sites**, grep on `decomp/osos.asm`).
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

use crate::cxx::string_object::{
    string_object_construct_from_cstr, StringObject, StringObjectVtable,
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
}
