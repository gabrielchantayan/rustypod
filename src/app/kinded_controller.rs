//! `kinded_controller_construct` — original: `FUN_08260a50` @
//! 0x08260a50, the constructor of the mid-hierarchy Silver-framework
//! controller class that 24 leaf classes in the 0x0822xxxx-0x0823xxxx
//! block derive from, each tagging itself with a distinct small-integer
//! *kind* byte.
//!
//! # Extent, from the raw bytes
//!
//! Decoded with `arm-none-eabi-objdump` over `work/firmware/osos.dec`
//! at load base 0x08000000, not taken from Ghidra:
//!
//! ```text
//! 08260a50  push {r3, r4, r5, r6, r7, r8, r9, lr}
//!   ...
//! 08260ac8  pop  {r3, r4, r5, r6, r7, r8, r9, pc}
//! 08260acc  .word 0x00000000     @ literal: the empty name
//! 08260ad0  .word 0x089a35e4     @ literal: this class's vtable
//! 08260ad4  cmp  r0, #0          @ the deleting-dtor wrapper starts here
//! ```
//!
//! Ghidra's 124 bytes are the code only; the function owns BOTH trailing
//! literal-pool words (reached by `add r2, pc, #76` @ 0x08260a78 and
//! `ldr r0, [pc, #56]` @ 0x08260a90), so the true extent is **132
//! bytes**, 0x08260a50..0x08260ad4. The sibling at 0x08260ad4 is the
//! class's NULL-guarded deleting-dtor wrapper (`bl 0x08260aec`, tail
//! `b operator_delete`); the plain dtor @ 0x08260aec re-plants the SAME
//! vtable literal 0x089a35e4, destroys the StringObject at +0xbc
//! (`bl 0x08277484` = string_object_destroy) and tail-branches to the
//! base class's dtor @ 0x0821a31c — which is what pins the vtable and
//! the member layout down as this class's own.
//!
//! # Call sites
//!
//! **23 `bl` sites, all unconditional** — verified by decoding every
//! ARM B/BL word in osos.dec: no `b` sites, no predicated forms, and
//! 0 occurrences of 0x08260a50 as a data word, so it is never reached
//! through a vtable (a statically bound constructor, exactly like the
//! ported grand-base `silver_controller_construct` @ 0x08134db4).
//! Every site is a leaf-class constructor in 0x08223158..0x0823b424
//! chaining in with its own kind immediate in r2 (0, 1, 3..11, 13..18,
//! 20..23 observed), a 0/1 flag in r3 and zero stack arguments.
//!
//! # Class hierarchy
//!
//! ```text
//! 0x0810e2e4  framework base (unported; name string at +0x28)
//! 0x08134db4  silver_controller_construct   (ported, app/silver_controller)
//! 0x0821a180  body-bearing controller       (unported; seam here) —
//!             vtable 0x08993c90, refcounted UI-proxy body at +0xb4,
//!             word +0xb8 = -1, flag bytes +0xb0/+0xb1/+0xb2
//! 0x08260a50  THIS CLASS — vtable 0x089a35e4, StringObject at +0xbc,
//!             bytes +0xc4..+0xc9, word +0xcc
//! 24 leaves   each plant their own vtable plus a SECONDARY vtable on
//!             the embedded interface sub-object at +0xd0 (planted by
//!             the 12-byte helper @ 0x0821599c, literal 0x08993258) and
//!             set further members (+0xd4 byte, a TickAccumulator, ...)
//! ```
//!
//! # Algorithm
//!
//! 1. `body = *body_slot` (`ldr r1, [r1]` @ 0x08260a5c) — the caller's
//!    handle slot is only READ, never written.
//! 2. `refcounted_body_acquire(&local, body)` @ 0x0839cd5c (seam — the
//!    acquire counterpart of the ported `refcounted_body_release` @
//!    0x0839cd98: store body into the slot; when non-NULL, bump its
//!    refcount at +4 under the optional mutex at +8). The local slot is
//!    the pushed-r3 scratch word, so it holds the incoming r3 until the
//!    acquire's first store overwrites it; the port keeps an initialized
//!    local instead (the garbage is never read in either version).
//! 3. `object = construct_base(this, &local, EMPTY_NAME)` @ 0x0821a180
//!    (seam). The third argument is `&literal@0x08260acc`, a word whose
//!    value is 0 — the base threads it straight into
//!    `silver_controller_construct` as the name C string, so the class
//!    is nameless (""). Every later store and the return value use the
//!    base constructor's RETURN (`mov r4, r0` @ 0x08260a84), not the
//!    incoming `this`.
//! 4. `refcounted_body_release(&local)` (ported, called directly) —
//!    drops the construction reference; the base ctor holds its own
//!    acquire at object+0xb4.
//! 5. Plant [`VTABLE_ADDRESS`] at object+0x00.
//! 6. Default-construct the StringObject at +0xbc (ported
//!    `string_default_construct` @ 0x08277440, called directly).
//! 7. Store the derived tail: byte +0xc4 = 0, +0xc5 = 0, +0xc6 = 1,
//!    +0xc7 = `kind`, +0xc8 = `flag`, +0xc9 = `extra_byte`, word +0xcc
//!    = `extra_word` — the two stack arguments arrive via
//!    `ldrd r8, [sp, #32]` past the eight saved registers.
//! 8. Return `object` (the epilogue's `sub r0, r0, #188` after the
//!    string ctor recovers the object from the member pointer; Ghidra's
//!    `void` return is wrong).
//!
//! What `kind`, `flag`, `extra_byte` and `extra_word` MEAN is not
//! recovered: nothing in the ctor or dtor reads them, and no symbolic
//! name survives. The kind byte is a per-leaf-class tag by observation
//! of the 23 call sites.
//!
//! # Deviations
//!
//! - The vtable is stored as the `u32` ROM address [`VTABLE_ADDRESS`]
//!   and the port claims nothing about its contents: the decrypted
//!   osos.dec holds a jump table of the app/image_format switch at
//!   0x089a35e4 (its first words decode as `b 0x08105da0` & co. — code
//!   addresses inside 0x08105xxx, not a function-entry list), exactly
//!   the stale-RW-page caveat `app/silver_controller` records for
//!   0x08984570 and `app/registry` records for 0x08989718. The runtime
//!   vtable lives in a loaded page the file does not carry.
//! - The name argument is a crate static of four NUL bytes where the
//!   original passes the address of its own zero literal-pool word;
//!   both point at an empty C string, which is all the base reads.
//! - The two unported callees ride the [`KINDED_CONTROLLER_OPS`]
//!   `read_volatile` seam (house pattern): firmware transmutes of the
//!   retail addresses on target (hook-ready), a faithful model of the
//!   60-byte acquire and a return-`this` base stub on host. The ported
//!   `refcounted_body_release` and `string_default_construct` are
//!   called directly.
//! - On a 64-bit host the ported `string_default_construct` writes two
//!   HOST-width pointers at +0xbc, so its payload store covers
//!   +0xc4..+0xcc and is in turn overwritten by the flag-byte stores
//!   that follow it in BOTH the original and the port — the
//!   `ui/string_view` precedent. Final state is identical on the
//!   target and deterministic on the host; only the intermediate
//!   +0xc4..+0xcb bytes differ (host payload high halves vs target
//!   NULL).
//! - Object pointers and the +0xcc word are 32-bit target values
//!   written with aligned `u32` stores, so host fixtures must sit
//!   below 4 GiB (`crate::testing::try_map_u32_slab`).

use crate::cxx::handle::{refcounted_body_release, RefcountedBody};
use crate::cxx::string_object::string_default_construct;
#[cfg(not(target_os = "none"))]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock};

/// The vtable this constructor installs at +0x00 — the literal pool
/// word @ 0x08260ad0, binary-verified against `osos.dec` and
/// cross-checked against the class dtor @ 0x08260aec, which re-plants
/// the same literal. See the module header: the file's bytes AT
/// 0x089a35e4 are a stale page (an image_format jump table), so this
/// is a loaded-image address only.
pub const VTABLE_ADDRESS: u32 = 0x089a_35e4;

/// Byte offset of the embedded StringObject (`add r0, r4, #188` @
/// 0x08260a9c), destroyed by the class dtor @ 0x08260aec.
pub const STRING_OFFSET: usize = 0xbc;

/// Byte offset of the derived tail's first flag byte, always stored 0.
pub const FLAG_C4_OFFSET: usize = 0xc4;
/// Byte offset of the second always-zero flag byte.
pub const FLAG_C5_OFFSET: usize = 0xc5;
/// Byte offset of the always-one flag byte.
pub const FLAG_C6_OFFSET: usize = 0xc6;
/// Byte offset of the per-leaf-class kind tag (the r2 argument).
pub const KIND_OFFSET: usize = 0xc7;
/// Byte offset of the 0/1 flag (the r3 argument).
pub const FLAG_OFFSET: usize = 0xc8;
/// Byte offset of the fifth argument (first stack argument).
pub const EXTRA_BYTE_OFFSET: usize = 0xc9;
/// Byte offset of the sixth argument's word (second stack argument).
pub const EXTRA_WORD_OFFSET: usize = 0xcc;

/// The empty name handed to the base constructor — the original passes
/// `&literal@0x08260acc`, whose value is 0 (see the module header).
static EMPTY_NAME: [u8; 4] = [0; 4];

/// Writes one word of the opaque target layout. Object pointers are
/// 32-bit on the device, so host fixtures backing them must sit below
/// 4 GiB (`crate::testing::try_map_u32_slab`).
#[inline(always)]
unsafe fn write_word(at: *mut u8, value: u32) {
    unsafe { at.cast::<u32>().write(value) }
}

/// The two callees of [`kinded_controller_construct`] that have no port
/// yet.
#[derive(Clone, Copy)]
pub struct KindedControllerOps {
    /// Original 0x0839cd5c (60 bytes, extent binary-verified: the ported
    /// release @ 0x0839cd98 starts immediately after): the acquire half
    /// of the refcounted-body pair. `*slot = body`, then when `body` is
    /// non-NULL bump its refcount at +4 under the optional mutex at +8
    /// (each mutex load NULL-checked separately), `blne` mutex_lock
    /// 0x0807f5c4 / mutex_unlock 0x0807f6a0.
    pub body_acquire: unsafe extern "C" fn(
        slot: *mut *mut RefcountedBody,
        body: *mut RefcountedBody,
    ),
    /// Original 0x0821a180: the direct base constructor. Chains
    /// `silver_controller_construct` @ 0x08134db4 (ported) with
    /// `(this, name)`, plants vtable 0x08993c90, clears the flag bytes
    /// +0xb0..+0xb2, acquires `*body_slot` into the body handle at +0xb4
    /// (creating the shared 0x48-byte UI-proxy state when the handle
    /// arrives empty), stores -1 at +0xb8 and dispatches vtable slot
    /// +0xb4 with `(this, 0x6f, 2)`. Returns the object.
    pub construct_base: unsafe extern "C" fn(
        this: *mut u8,
        body_slot: *mut *mut RefcountedBody,
        name: *const u8,
    ) -> *mut u8,
}

/// Target default: the retail acquire @ 0x0839cd5c.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_body_acquire(
    slot: *mut *mut RefcountedBody,
    body: *mut RefcountedBody,
) {
    let acquire: unsafe extern "C" fn(*mut *mut RefcountedBody, *mut RefcountedBody) =
        core::mem::transmute(0x0839_cd5cusize);
    acquire(slot, body)
}

/// Host model of the 0x0839cd5c acquire — faithful, not inert: every
/// callee on its path is either data-driven or ported (the
/// kernel/sync_mutex lock pair), so the model reproduces it exactly,
/// including the two separately NULL-checked mutex loads and the
/// unconditional slot store.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn model_body_acquire(
    slot: *mut *mut RefcountedBody,
    body: *mut RefcountedBody,
) {
    unsafe {
        slot.write(body);
        if body.is_null() {
            return;
        }
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_lock(mutex);
        }
        (*body).refcount += 1;
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }
}

/// Target default: the retail base constructor @ 0x0821a180.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_base(
    this: *mut u8,
    body_slot: *mut *mut RefcountedBody,
    name: *const u8,
) -> *mut u8 {
    let construct: unsafe extern "C" fn(
        *mut u8,
        *mut *mut RefcountedBody,
        *const u8,
    ) -> *mut u8 = core::mem::transmute(0x0821_a180usize);
    construct(this, body_slot, name)
}

/// Host default before 0x0821a180 is ported: the original returns the
/// object it constructed, and the shared-state creation it performs is
/// not something a stub can stand in for (the
/// `missing_construct_base` precedent in app/silver_controller).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_base(
    this: *mut u8,
    _body_slot: *mut *mut RefcountedBody,
    _name: *const u8,
) -> *mut u8 {
    this
}

/// Active model of the constructor's unported callees. Host tests
/// install recording mocks; real ports of 0x0839cd5c / 0x0821a180
/// replace the defaults when they land.
#[cfg(target_os = "none")]
pub static mut KINDED_CONTROLLER_OPS: KindedControllerOps = KindedControllerOps {
    body_acquire: firmware_body_acquire,
    construct_base: firmware_construct_base,
};

/// Active model of the constructor's unported callees — host defaults
/// (see above).
#[cfg(not(target_os = "none"))]
pub static mut KINDED_CONTROLLER_OPS: KindedControllerOps = KindedControllerOps {
    body_acquire: model_body_acquire,
    construct_base: missing_construct_base,
};

#[inline(always)]
unsafe fn ops() -> KindedControllerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KINDED_CONTROLLER_OPS)) }
}

/// kinded_controller_construct — original: `FUN_08260a50` @ 0x08260a50
/// (132 bytes: 124 of code plus two literal-pool words; **23 `bl` call
/// sites**, all unconditional, binary-scanned over osos.dec).
///
/// Constructs the mid-hierarchy kind-tagged controller: safely adopts
/// the caller's refcounted body through a local acquire/release pair
/// around the base constructor, plants this class's vtable,
/// default-constructs the StringObject at +0xbc and stores the flag
/// bytes +0xc4..+0xc9 and the argument word at +0xcc. Returns the base
/// constructor's return value, as ADS constructors do.
///
/// No NULL guard on `this` or `body_slot` — the original has none.
///
/// # Safety
///
/// `this` must satisfy the installed [`KindedControllerOps`]
/// `construct_base` and point at a writable object of at least
/// `EXTRA_WORD_OFFSET + 4` bytes; `body_slot` must be a readable,
/// aligned handle slot. The object must be 8-byte-alignment-compatible
/// with `string_default_construct` at +0xbc on the host (see the
/// module header's host-widening deviation).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kinded_controller_construct(
    this: *mut u8,
    body_slot: *mut *mut RefcountedBody,
    kind: u8,
    flag: u8,
    extra_byte: u8,
    extra_word: u32,
) -> *mut u8 {
    unsafe {
        let ops = ops();
        // The original's local slot is the pushed-r3 scratch word; the
        // acquire overwrites it before any read on every path.
        let mut local: *mut RefcountedBody = core::ptr::null_mut();
        (ops.body_acquire)(&mut local, body_slot.read());
        let object = (ops.construct_base)(this, &mut local, EMPTY_NAME.as_ptr());
        refcounted_body_release(&mut local);
        write_word(object, VTABLE_ADDRESS);
        string_default_construct(object.add(STRING_OFFSET).cast());
        object.add(FLAG_C4_OFFSET).write(0);
        object.add(FLAG_C5_OFFSET).write(0);
        object.add(FLAG_C6_OFFSET).write(1);
        object.add(KIND_OFFSET).write(kind);
        object.add(FLAG_OFFSET).write(flag);
        object.add(EXTRA_BYTE_OFFSET).write(extra_byte);
        write_word(object.add(EXTRA_WORD_OFFSET), extra_word);
        object
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    /// Object plus a RefcountedBody plus a caller slot, all below 4 GiB.
    const FIXTURE_LEN: usize = 0x1000;
    /// The object sits at slab+4, not slab: the ported
    /// `string_default_construct` writes two host-width pointers at
    /// object+0xbc and dereferences them, so object+0xbc must be
    /// 8-aligned on a 64-bit host (the ui/string_view VIEW_OFFSET
    /// precedent). Every field this constructor writes is byte- or
    /// u32-addressed, so the +4 shift costs nothing else.
    const OBJECT_OFFSET: usize = 0x004;
    /// A second object the base mock can return instead of `this`, to
    /// prove every store follows the base's return value.
    const ALT_OBJECT_OFFSET: usize = 0x204;
    const BODY_OFFSET: usize = 0x400;
    const CALLER_SLOT_OFFSET: usize = 0x440;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::KINDED_CONTROLLER, FIXTURE_LEN).map(|p| p as usize)
    });

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    fn seam_lock() -> MutexGuard<'static, ()> {
        SEAM_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// One observed seam call, in order.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Call {
        Acquire(*mut RefcountedBody),
        Base(*mut u8, *mut RefcountedBody),
    }

    static mut CALLS: Vec<Call> = Vec::new();
    /// What the base mock returns; defaults to its `this`.
    static mut BASE_RETURN: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_acquire(
        slot: *mut *mut RefcountedBody,
        body: *mut RefcountedBody,
    ) {
        unsafe {
            (*ptr::addr_of_mut!(CALLS)).push(Call::Acquire(body));
            // Behave like the real acquire: the base must see the body
            // in the slot, and the refcount bumps around the base call.
            model_body_acquire(slot, body);
        }
    }

    unsafe extern "C" fn recording_base(
        this: *mut u8,
        body_slot: *mut *mut RefcountedBody,
        name: *const u8,
    ) -> *mut u8 {
        unsafe {
            // Ordering evidence: the acquire ran first.
            assert_eq!((*ptr::addr_of!(CALLS)).len(), 1);
            // The empty-name deviation: four NUL bytes.
            assert_eq!((0..4).map(|i| name.add(i).read()).collect::<Vec<_>>(), [0; 4]);
            (*ptr::addr_of_mut!(CALLS)).push(Call::Base(this, body_slot.read()));
            let alternate = ptr::addr_of!(BASE_RETURN).read();
            if alternate.is_null() { this } else { alternate }
        }
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(KINDED_CONTROLLER_OPS).write_volatile(KindedControllerOps {
                    body_acquire: model_body_acquire,
                    construct_base: missing_construct_base,
                });
                (*ptr::addr_of_mut!(CALLS)).clear();
                ptr::addr_of_mut!(BASE_RETURN).write(ptr::null_mut());
            }
        }
    }

    /// Poisons the slab, installs the recording boundary and returns
    /// `(object, body, caller_slot)`.
    fn bench() -> Option<(OpsGuard, *mut u8, *mut RefcountedBody, *mut *mut RefcountedBody)> {
        let lock = seam_lock();
        let slab = SLAB.as_ref().copied()? as *mut u8;
        unsafe {
            ptr::write_bytes(slab, 0xa5, FIXTURE_LEN);
            (*ptr::addr_of_mut!(CALLS)).clear();
            ptr::addr_of_mut!(BASE_RETURN).write(ptr::null_mut());
            ptr::addr_of_mut!(KINDED_CONTROLLER_OPS).write_volatile(KindedControllerOps {
                body_acquire: recording_acquire,
                construct_base: recording_base,
            });
            let object = slab.add(OBJECT_OFFSET);
            let body = slab.add(BODY_OFFSET).cast::<RefcountedBody>();
            let caller_slot = slab.add(CALLER_SLOT_OFFSET).cast::<*mut RefcountedBody>();
            Some((OpsGuard { _lock: lock }, object, body, caller_slot))
        }
    }

    /// Host-state read of a target u32 field.
    unsafe fn word(at: *mut u8) -> u32 {
        unsafe { at.cast::<u32>().read() }
    }

    #[test]
    fn stores_follow_the_base_return_and_arguments_land_verbatim() {
        let Some((_guard, object, body, caller_slot)) = bench() else {
            assert!(note_missing_u32_fixture("kinded_controller"));
            return;
        };
        unsafe {
            (*body).opaque0 = 0;
            (*body).refcount = 7;
            (*body).mutex = ptr::null_mut();
            caller_slot.write(body);

            let result = kinded_controller_construct(object, caller_slot, 0x17, 1, 0xab, 0xdead_beef);

            assert_eq!(result, object, "the base returned `this`, so it comes back");
            assert_eq!(word(object), VTABLE_ADDRESS, "vtable planted at +0x00");
            // The StringObject: vtable is the ported ctor's static; the
            // host-width payload store at +0xc4..+0xcc is overwritten by
            // the flag bytes that follow it in BOTH original and port.
            assert_eq!(
                *(object.add(STRING_OFFSET).cast::<usize>()),
                &STRING_OBJECT_VTABLE as *const _ as usize,
            );
            assert_eq!(object.add(FLAG_C4_OFFSET).read(), 0);
            assert_eq!(object.add(FLAG_C5_OFFSET).read(), 0);
            assert_eq!(object.add(FLAG_C6_OFFSET).read(), 1);
            assert_eq!(object.add(KIND_OFFSET).read(), 0x17);
            assert_eq!(object.add(FLAG_OFFSET).read(), 1);
            assert_eq!(object.add(EXTRA_BYTE_OFFSET).read(), 0xab);
            assert_eq!(word(object.add(EXTRA_WORD_OFFSET)), 0xdead_beef);
            // Call order and content: acquire(body) then base(this, body).
            assert_eq!(
                *ptr::addr_of!(CALLS),
                Vec::from([Call::Acquire(body), Call::Base(object, body)]),
            );
            // Net refcount: acquire +1, release -1 — back to the entry
            // value, and the caller's slot is never written.
            assert_eq!((*body).refcount, 7);
            assert_eq!(caller_slot.read(), body);
        }
    }

    #[test]
    fn stores_and_return_follow_a_redirected_base_return() {
        let Some((_guard, object, body, caller_slot)) = bench() else {
            assert!(note_missing_u32_fixture("kinded_controller"));
            return;
        };
        unsafe {
            let slab = SLAB.as_ref().copied().unwrap() as *mut u8;
            let alternate = slab.add(ALT_OBJECT_OFFSET);
            ptr::addr_of_mut!(BASE_RETURN).write(alternate);
            (*body).opaque0 = 0;
            (*body).refcount = 3;
            (*body).mutex = ptr::null_mut();
            caller_slot.write(body);

            let result = kinded_controller_construct(object, caller_slot, 9, 0, 0x5a, 42);

            // `mov r4, r0` after the base call: everything lands on the
            // base's return, not on the incoming `this`.
            assert_eq!(result, alternate);
            assert_eq!(word(alternate), VTABLE_ADDRESS);
            assert_eq!(alternate.add(KIND_OFFSET).read(), 9);
            assert_eq!(alternate.add(FLAG_OFFSET).read(), 0);
            assert_eq!(alternate.add(EXTRA_BYTE_OFFSET).read(), 0x5a);
            assert_eq!(word(alternate.add(EXTRA_WORD_OFFSET)), 42);
            assert_eq!(word(object), 0xa5a5_a5a5, "incoming `this` is untouched");
        }
    }

    #[test]
    fn null_body_passes_through_acquire_and_release_untouched() {
        let Some((_guard, object, body, caller_slot)) = bench() else {
            assert!(note_missing_u32_fixture("kinded_controller"));
            return;
        };
        unsafe {
            let _ = body;
            caller_slot.write(ptr::null_mut());

            let result = kinded_controller_construct(object, caller_slot, 4, 1, 0, 0);

            assert_eq!(result, object);
            assert_eq!(
                *ptr::addr_of!(CALLS),
                Vec::from([Call::Acquire(ptr::null_mut()), Call::Base(object, ptr::null_mut())]),
            );
            // The release's NULL-body early-out leaves the caller slot
            // alone; the object is still fully initialized.
            assert_eq!(caller_slot.read(), ptr::null_mut());
            assert_eq!(word(object), VTABLE_ADDRESS);
            assert_eq!(object.add(FLAG_C6_OFFSET).read(), 1);
            assert_eq!(object.add(KIND_OFFSET).read(), 4);
            assert_eq!(object.add(FLAG_OFFSET).read(), 1);
        }
    }

    #[test]
    fn host_defaults_keep_the_refcount_neutral_and_initialize() {
        let Some((_guard, object, body, caller_slot)) = bench() else {
            assert!(note_missing_u32_fixture("kinded_controller"));
            return;
        };
        unsafe {
            // Restore the wired host defaults over the recording mocks.
            ptr::addr_of_mut!(KINDED_CONTROLLER_OPS).write_volatile(KindedControllerOps {
                body_acquire: model_body_acquire,
                construct_base: missing_construct_base,
            });
            (*body).opaque0 = 0;
            (*body).refcount = 2;
            (*body).mutex = ptr::null_mut();
            caller_slot.write(body);

            let result = kinded_controller_construct(object, caller_slot, 0x0d, 0, 0x11, 0x2222_3333);

            // The base stub never acquires the body into the object, so
            // the local acquire/release pair must cancel out exactly.
            assert_eq!(result, object);
            assert_eq!((*body).refcount, 2);
            assert_eq!(caller_slot.read(), body);
            assert_eq!(word(object), VTABLE_ADDRESS);
            assert_eq!(object.add(KIND_OFFSET).read(), 0x0d);
            assert_eq!(word(object.add(EXTRA_WORD_OFFSET)), 0x2222_3333);
        }
    }

    #[test]
    fn zero_arguments_store_the_constant_tail() {
        let Some((_guard, object, body, caller_slot)) = bench() else {
            assert!(note_missing_u32_fixture("kinded_controller"));
            return;
        };
        unsafe {
            (*body).opaque0 = 0;
            (*body).refcount = 1;
            (*body).mutex = ptr::null_mut();
            caller_slot.write(body);

            kinded_controller_construct(object, caller_slot, 0, 0, 0, 0);

            assert_eq!(object.add(KIND_OFFSET).read(), 0);
            assert_eq!(object.add(FLAG_OFFSET).read(), 0);
            assert_eq!(object.add(EXTRA_BYTE_OFFSET).read(), 0);
            assert_eq!(word(object.add(EXTRA_WORD_OFFSET)), 0);
            // The constants are not argument-driven: still 0, 0, 1.
            assert_eq!(object.add(FLAG_C4_OFFSET).read(), 0);
            assert_eq!(object.add(FLAG_C5_OFFSET).read(), 0);
            assert_eq!(object.add(FLAG_C6_OFFSET).read(), 1);
        }
    }
}
