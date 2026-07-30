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

use crate::heap::veneers::{free_wrapper, operator_delete};

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
}
