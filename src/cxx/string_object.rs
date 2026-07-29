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
//! - 0x08277440 — **this port**, the trivial default ctor.
//! - 0x08277414 — a second ctor that additionally calls 0x08276620.
//! - 0x08277458 — the deleting destructor: vtable, then 0x08275d74,
//!   then operator delete @ 0x082aad24 (NULL-guarded on `this`).
//! - 0x08277484 — the plain destructor (990 `bl` call sites): vtable +
//!   0x08275d74, no delete.
//!
//! The vtable itself is serialized in the image at 0x089a6044: six code
//! pointers (0x0820c2dc, 0x0821183c, 0x082116f8, 0x08213bfc, 0x08213818,
//! 0x0820c5ec) followed by zeros. Ghidra resolves only 0x08213bfc as a
//! function start, so the slots' identities — and with them the class —
//! are undecoded; the second word is a payload pointer that starts NULL
//! and is presumably released by the shared destructor body 0x08275d74.
//!
//! Ported functions:
//!
//! - `string_default_construct` — original: `FUN_08277440` @ 0x08277440
//!   (20 bytes: 16 code + the 4-byte vtable literal @ 0x08277454;
//!   280 `bl` call sites, binary-scanned). `obj[0] = vtable`,
//!   `obj[1] = NULL`; the original leaves `this` untouched in r0, so the
//!   port returns it.
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
    /// body 0x08275d74 presumably releases it.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
