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
//! - 0x08277458 — the deleting destructor: vtable, then 0x08275d74,
//!   then operator delete @ 0x082aad24 (NULL-guarded on `this`).
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
//! @ 0x080e7970 with caller tag 0x34, then NULLs the word).
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
//! - The payload release @ 0x08275d74 is not ported, so
//!   `string_object_destroy` reaches it through the
//!   [`STRING_OBJECT_OPS`] dispatch slot (house pattern — see
//!   cxx/string_map.rs `STRING_KEY_MAP_OPS`). The shipped default is a
//!   no-op that leaks the payload, the `missing_free_p4` house rule for
//!   unported destructors: the real callee frees through the heap with
//!   caller tag 0x34, and guessing that wrong corrupts. Host tests
//!   install a recording mock.

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

/// Indirect dispatch for the unported payload release @ 0x08275d74
/// (see the module header).
#[derive(Clone, Copy)]
pub struct StringObjectOps {
    /// The shared destructor body: NULL-guards `this.payload`, frees it
    /// through `free_wrapper` @ 0x080e7970 with caller tag 0x34, and
    /// NULLs the word.
    pub release_payload: unsafe extern "C" fn(this: *mut StringObject),
}

/// Fail-closed default: performs no release — the payload is leaked,
/// not freed (the `missing_free_p4` house rule for unported
/// destructors; see the module header). Deliberately not a passthrough
/// to `free_wrapper`: the tag-0x34 free contract belongs to the
/// unported 0x08275d74, and guessing wrong corrupts the heap.
unsafe extern "C" fn missing_release_payload(_this: *mut StringObject) {}

/// Wired default (documented leak until 0x08275d74 is ported).
pub const DEFAULT_STRING_OBJECT_OPS: StringObjectOps = StringObjectOps {
    release_payload: missing_release_payload,
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
    fn default_release_is_a_noop_leak() {
        let _lock = OPS_LOCK.lock().unwrap();
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: 0xcafe_f00d as *mut u8,
        };
        let this: *mut StringObject = &mut object;
        unsafe {
            assert_eq!(string_object_destroy(this), this);
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(
                object.payload, 0xcafe_f00d as *mut u8,
                "the stub frees nothing and NULLs nothing (documented leak)"
            );
        }
    }
}
