//! The NULL-guarded two-level handle accessor the C++ layer instantiates
//! once per wrapped type — 22 byte-identical 16-byte copies in osos.
//!
//! Every copy is exactly these four words:
//!
//! ```text
//! ldr   r0, [r0]      ; cell = *slot
//! cmp   r0, #0
//! ldrne r0, [r0]      ; cell ? *cell : NULL
//! bx    lr
//! ```
//!
//! i.e. `T *get() const { return cell_ ? *cell_ : nullptr; }` on a class
//! whose sole (offset-0) member is a `T **`. The compiler emitted one
//! out-of-line copy per template instantiation instead of sharing them,
//! so the image carries 22 functions that differ only in address. This
//! module is the single port; `names.yaml` records the alias map, and a
//! hook may point every one of the 22 addresses at this symbol.
//!
//! Binary-scanned `bl` call sites (no `b` sites anywhere), 725 in total:
//!
//! | address    | calls | address    | calls | address    | calls |
//! |------------|-------|------------|-------|------------|-------|
//! | 0x083d604c | 253   | 0x083d606c | 69    | 0x083d6190 | 69    |
//! | 0x083d61d0 | 66    | 0x083d64f4 | 97    | 0x083d60bc | 25    |
//! | 0x083d64c4 | 18    | 0x083d64e4 | 18    | 0x083d602c | 17    |
//! | 0x083d61a0 | 16    | 0x083d6180 | 13    | 0x083d64d4 | 9     |
//! | 0x083d607c | 9     | 0x083d603c | 8     | 0x083d609c | 8     |
//! | 0x083d60ac | 7     | 0x083d61b0 | 7     | 0x083d60cc | 5     |
//! | 0x083d608c | 4     | 0x083d605c | 3     | 0x083d61c0 | 2     |
//! | 0x08262b1c | 2     |            |       |            |       |
//!
//! 0x08262b1c is the one copy outside the C++ block (it sits in the
//! application layer); it is the same four words and aliases here too.
//!
//! The 0x083d604c copy is the canonical one (most call sites) and the
//! address this port cites. Note the NULL test is on the *inner* pointer,
//! not on `slot`: a NULL `slot` faults in the original, and does here.
//!
//! Also here: [`refcounted_ptr_construct`], the birth counterpart
//! @ 0x0839ed38 that wraps an implementation pointer in a fresh
//! [`RefcountedBody`] (refcount 1, optional mutex) and installs it in a
//! handle slot; [`refcounted_ptr_assign`], the mutex-guarded shared-body
//! assign that backs the C++ layer's refcounted handles (it sits outside
//! the 0x083c0000-0x083dffff block, at 0x0839eda0, so it is not one of
//! the byte-identical families above), and [`refcounted_body_release`],
//! its refcount-drop teardown @ 0x0839cd98. [`refcounted_ptr_release`]
//! is the thin destroy-and-return-this wrapper @ 0x0816cd44, and
//! [`refcounted_body_release_owned`] is the sibling teardown @ 0x0839d2c0
//! whose final drop also disposes and tag-2-deletes the implementation
//! [`refcounted_body_release_dtor`] is the third sibling teardown
//! @ 0x0839cbc0, byte-identical to the canonical release except its final
//! drop dispatches vtable slot 1 (+4) instead of slot 7 (+0x1c).
//! [`refcounted_body_release_slot1_copy`] @ 0x0839d038 is another separately
//! linked copy of that slot-1 teardown. [`refcounted_body_release_dtor_variant`]
//! @ 0x0839d3ac is a further copy, byte-identical modulo direct-call
//! displacements. [`refcounted_body_release_owned_variant`] @ 0x0839cf4c is an
//! owning sibling whose implementation disposer remains an unported direct call.
//! [`refcounted_body_acquire`] @ 0x0839cd5c and
//! [`refcounted_body_attach`] @ 0x0839d370 are separately linked
//! store-and-bump copies used by refcounted-handle constructors and
//! copy-assignment operators respectively.
//! [`refcounted_body_release_retain_count`] @ 0x0839d498 is a final-drop
//! sibling that passes its just-zeroed count to a direct disposer before
//! freeing the body. [`refcounted_ptr_assign_owned`] @ 0x0839f1b0 combines
//! the owning release with that attach; [`refcounted_ptr_copy_assign`] @
//! 0x0839f28c is the C++ copy-assignment operator itself: slot-pointer-guarded
//! slot-1 release followed by attach, returning `dst`.

#[cfg(not(target_os = "none"))]
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::{operator_delete, operator_new};
use crate::kernel::sync_mutex::{mutex_create, mutex_delete, mutex_lock, mutex_unlock, Mutex};

/// handle_deref_or_null — original: `FUN_083d604c` @ 0x083d604c
/// (16 bytes; 253 `bl` call sites at that address, 725 across all 22
/// byte-identical copies — see the module header for the alias map).
///
/// Loads the handle cell out of `slot` and dereferences it, yielding
/// NULL when the cell is NULL.
///
/// # Safety
/// `slot` must be readable; the cell it holds must be readable when
/// non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_deref_or_null(slot: *const *const *mut u8) -> *mut u8 {
    let cell = slot.read();
    if cell.is_null() {
        return core::ptr::null_mut();
    }
    cell.read()
}

/// handle_deref_field12 — original: `FUN_083d5ea0` @ 0x083d5ea0
/// (20 bytes; 11 `bl` call sites — the only copy of this offset in the
/// image).
///
/// [`handle_deref_or_null`] with the second load at +0xc instead of +0:
/// `cell = *slot; return cell ? cell[3] : NULL`. What the fourth word
/// of the cell holds is not identified.
///
/// The field is addressed by WORD INDEX (3), like the +0 field of the
/// primary port is word 0 — byte-exact +0xc on the 32-bit target,
/// disjoint from the cell's other words on a 64-bit host.
///
/// # Safety
/// `slot` must be readable; the cell it holds must have at least four
/// readable words when non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_deref_field12(slot: *const *const *mut u8) -> *mut u8 {
    let cell = slot.read();
    if cell.is_null() {
        return core::ptr::null_mut();
    }
    cell.add(3).read()
}

/// handle_elem_ptr — original: `FUN_083d60dc` @ 0x083d60dc (20 bytes;
/// 3 `bl` call sites, all unconditional and all inside
/// `plane_cursor_init` @ 0x0839bae0 — verified by decoding every branch
/// word in osos.dec: no `b` sites, no predicated forms, no data-word
/// references). One byte-identical copy exists, `FUN_083d60f0` @
/// 0x083d60f0 (3 more `bl` sites, all inside the byte-similar sibling
/// cursor init @ 0x0839bb58); hook both addresses to this symbol.
///
/// The indexed member of the [`handle_deref_or_null`] family:
///
/// ```text
/// ldr   r0, [r0]            ; cell = *slot
/// cmp   r0, #0
/// ldrne r0, [r0]            ; base = cell ? *cell : NULL
/// add   r0, r0, r1, lsl #2  ; base + index (4-byte elements)
/// bx    lr
/// ```
///
/// i.e. a pointer to word `index` of the u32 array whose base is the
/// cell's first word. NOTE: like the rest of the family the NULL test
/// is on the INNER pointer (a NULL `slot` faults), and the element add
/// is UNCONDITIONAL — a NULL cell does not yield NULL but
/// `index * 4` as a bare address. The elements are typed u32 because
/// the `lsl #2` fixes a 4-byte element size; what a word holds is the
/// caller's business (the video colorspace converter treats them as
/// packed pixel words).
///
/// # Safety
/// `slot` must be readable; the cell it holds must be readable when
/// non-NULL. The returned pointer is never dereferenced here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_elem_ptr(slot: *const *const *const u32, index: u32) -> *mut u32 {
    let cell = slot.read();
    let base = if cell.is_null() {
        core::ptr::null()
    } else {
        cell.read()
    };
    base.wrapping_add(index as usize).cast_mut()
}

/// Shared body of the C++ layer's refcounted handles — the object a
/// `*mut RefcountedBody` slot points at. On the ARM target its three words
/// are the implementation pointer (+0), signed reference count (+4), and
/// optional [`Mutex`] pointer (+8). Host fixtures widen each target pointer
/// word to `usize`, keeping pointers intact and the fields disjoint.
#[repr(C)]
pub struct RefcountedBody {
    /// Target +0: implementation pointer. Its first word is the vtable
    /// pointer used by [`refcounted_body_release`] at the final drop.
    pub opaque0: usize,
    /// Target +4: intrusive reference count, changed under the mutex.
    pub refcount: i32,
    /// Target +8: optional mutex guarding the refcount (NULL = unguarded).
    pub mutex: *mut Mutex,
}

/// refcounted_ptr_construct — original: `FUN_0839ed38` @ 0x0839ed38
/// (104 bytes; 30 `bl` call sites, all unconditional — verified by
/// decoding every branch word in osos.dec: no `b` sites, no predicated
/// forms, and the address appears in no data word, so it is never
/// virtually dispatched).
///
/// The birth counterpart of [`refcounted_body_release`]: NULLs the
/// handle slot first, then, when `implementation` is non-NULL, allocates
/// a 12-byte [`RefcountedBody`] with tag-2 `operator_new` (0x082aadd4),
/// fills it as `{ implementation, refcount = 1, mutex = NULL }` and, only
/// when `want_mutex` is nonzero, allocates an 8-byte [`Mutex`] the same
/// way, zeroes both its words, installs it at body+8, and initializes
/// its semaphore cell with `mutex_create` (0x080744a4, ported in
/// kernel/sync_mutex.rs). The finished body is stored into the slot last
/// and the slot is returned — the ADS construct-and-return-this idiom,
/// mirroring [`refcounted_ptr_assign`]. A NULL `implementation` leaves
/// the slot NULL with no allocation at all.
///
/// The allocation sizes are the original's immediates (12 and 8 — the
/// 32-bit target sizes of [`RefcountedBody`] and [`Mutex`]); on a
/// 64-bit host the structs are wider, so host fixtures must back the
/// mock allocations with oversized arenas.
///
/// Codegen deviation: LLVM inlines the ported `mutex_create` (ROM_KERNEL
/// dispatch included) instead of emitting the original's `bl`, so the
/// ARM body is larger but keeps the same alloc/init/store sequence.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot; it is not NULL-checked,
/// as in the original. `implementation` becomes the body's opaque word
/// verbatim and is only ever compared against NULL here. Allocation
/// failure behavior is whatever the active heap provides — the original
/// does not check either `operator_new` result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_construct(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}
/// refcounted_handle_construct — original: `FUN_0839ebc4` @ 0x0839ebc4
/// (104 bytes; 13 direct `bl` call sites, all unconditional — verified by
/// decoding every ARM B/BL word in osos.dec: no `b` sites, no predicated
/// forms, and no image data-word references).
///
/// A separately linked C++ template instantiation of
/// [`refcounted_ptr_construct`]. It clears `slot`, then, when
/// `implementation` is non-NULL, allocates a tag-2 12-byte
/// [`RefcountedBody`] and initializes it as `{ implementation, 1, NULL }`.
/// A nonzero `want_mutex` allocates and zeroes a tag-2 8-byte [`Mutex`],
/// installs it in the body, and calls [`mutex_create`] before publishing the
/// body to `slot`. It returns `slot`; a NULL implementation performs no
/// allocations. Raw bytes establish the exact extent: the next separately
/// linked function begins at 0x0839ec2c.
///
/// Deliberate codegen deviation: LLVM may inline the ported [`mutex_create`]
/// rather than retaining the ARM `bl`. The dedicated target section keeps
/// this separately hookable template copy from being folded into its
/// byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot. `implementation` is opaque;
/// allocation failures are unchecked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_handle_construct")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_handle_construct(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}

/// refcounted_handle_construct_variant — original: `FUN_0839eca0` @
/// 0x0839eca0 (104 bytes; 13 direct `bl` call sites, all unconditional —
/// verified by decoding every ARM B/BL word in osos.dec: no `b` sites, no
/// predicated forms, and no image data-word references).
///
/// A separately linked C++ template instantiation of
/// [`refcounted_ptr_construct`]. It clears `slot`, then, when
/// `implementation` is non-NULL, allocates a tag-2 12-byte
/// [`RefcountedBody`] and initializes it as `{ implementation, 1, NULL }`.
/// A nonzero `want_mutex` allocates and zeroes a tag-2 8-byte [`Mutex`],
/// installs it in the body, and calls [`mutex_create`] before publishing the
/// body to `slot`. It returns `slot`; a NULL implementation performs no
/// allocations.
///
/// Deliberate codegen deviation: LLVM may inline the ported [`mutex_create`]
/// rather than retaining the ARM `bl`. The dedicated target section keeps
/// this separately hookable template copy from being folded into its
/// byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot. `implementation` is opaque;
/// allocation failures are unchecked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_handle_construct_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_handle_construct_variant(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}

/// refcounted_ptr_construct_variant — original: `FUN_0839f148` @
/// 0x0839f148 (104 bytes; 29 `bl` call sites, all unconditional —
/// verified by decoding every branch word in osos.dec: no `b` sites, no
/// predicated forms, and no data-word references).
///
/// A separately linked C++ template instantiation of
/// [`refcounted_ptr_construct`]. It clears `slot`, then when
/// `implementation` is non-NULL creates a tag-2 12-byte
/// [`RefcountedBody`] containing `{ implementation, 1, NULL }`. A nonzero
/// `want_mutex` adds a tag-2 8-byte zeroed [`Mutex`], stores it in the body,
/// and calls [`mutex_create`] before storing the completed body into `slot`.
/// It returns `slot`. The raw body ends exactly at 0x0839f1b0, where the next
/// separately linked function starts.
///
/// Deliberate codegen deviation: like the canonical port, LLVM may inline
/// [`mutex_create`] instead of retaining its original `bl`. A dedicated
/// target section prevents LLVM from folding this hookable template instance
/// into its byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot. `implementation` is opaque;
/// allocation failures are unchecked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_ptr_construct_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_construct_variant(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}

/// refcounted_ptr_construct_secondary_variant — original: `FUN_0839f1e0` @
/// 0x0839f1e0 (104 bytes; 10 direct `bl` call sites, all unconditional:
/// 0x0810ce24, 0x0810d040, 0x0814aeb8, 0x0814b29c, 0x081cc6e0,
/// 0x081cc784, 0x081f0c6c, 0x081f0dac, 0x081fcb88, and 0x081fcbb8).
/// Decoding every ARM B/BL word in osos.dec found no tail `b`, no predicated
/// calls, and no image word equal to the address, so it is not virtually
/// dispatched. Raw instructions establish the exact extent: the separately
/// linked sibling begins at 0x0839f248.
///
/// A separately linked C++ template instantiation of
/// [`refcounted_ptr_construct`]. It clears `slot`, then when
/// `implementation` is non-NULL creates a tag-2 12-byte [`RefcountedBody`]
/// containing `{ implementation, 1, NULL }`. A nonzero `want_mutex` adds a
/// tag-2 8-byte zeroed [`Mutex`], stores it in the body, and calls
/// [`mutex_create`] before publishing the completed body into `slot`.
/// Returns `slot`; a NULL implementation performs no allocations.
///
/// Deliberate codegen deviation: LLVM may inline the ported
/// [`mutex_create`] instead of retaining its original `bl`. A dedicated
/// target section prevents this hookable template instance from being folded
/// into its byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot. `implementation` is opaque;
/// allocation failures are unchecked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_ptr_construct_secondary_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_construct_secondary_variant(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}

/// refcounted_ptr_construct_tertiary_variant — original: `FUN_0839f2bc` @
/// 0x0839f2bc (104 bytes; 9 direct `bl` call sites, all unconditional:
/// 0x08113eb8, 0x08113edc, 0x0811710c, 0x0811711c, 0x081172b0,
/// 0x081172d4, 0x08211488, 0x082117d0, and 0x08211d7c). Decoding every ARM
/// B/BL word in osos.dec found no tail `b`, no predicated calls, and no image
/// word equal to this address, so it is never virtually dispatched. Raw
/// instructions establish the exact extent: the separately linked
/// [`refcounted_ptr_copy_assign`] begins at 0x0839f324.
///
/// A separately linked C++ template instantiation of
/// [`refcounted_ptr_construct`]. It clears `slot`, then when
/// `implementation` is non-NULL creates a tag-2 12-byte [`RefcountedBody`]
/// containing `{ implementation, 1, NULL }`. A nonzero `want_mutex` adds a
/// tag-2 8-byte zeroed [`Mutex`], stores it in the body, and calls
/// [`mutex_create`] before publishing the completed body into `slot`.
/// Returns `slot`; a NULL implementation performs no allocations.
///
/// Deliberate codegen deviation: LLVM may inline the ported
/// [`mutex_create`] instead of retaining its original `bl`. A dedicated
/// target section prevents this hookable template instance from being folded
/// into its byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot. `implementation` is opaque;
/// allocation failures are unchecked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_ptr_construct_tertiary_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_construct_tertiary_variant(
    slot: *mut *mut RefcountedBody,
    implementation: usize,
    want_mutex: u32,
) -> *mut *mut RefcountedBody {
    slot.write(core::ptr::null_mut());
    if implementation != 0 {
        let body = operator_new(12).cast::<RefcountedBody>();
        (*body).opaque0 = implementation;
        (*body).refcount = 1;
        (*body).mutex = core::ptr::null_mut();
        if want_mutex != 0 {
            let mutex = operator_new(8).cast::<Mutex>();
            (*mutex).sem_cell = core::ptr::null_mut();
            (*mutex).unused = 0;
            (*body).mutex = mutex;
            mutex_create(mutex);
        }
        slot.write(body);
    }
    slot
}






/// refcounted_ptr_assign — original: `FUN_0839eda0` @ 0x0839eda0
/// (68 bytes; 78 `bl` call sites).
///
/// The copy-assign of a refcounted handle slot: `obj = *src;
/// *dst = obj`, and when `obj` is non-NULL its refcount (+4) is bumped
/// by one under the mutex at +8. The mutex field is loaded twice —
/// before the lock and again before the unlock — and each load is
/// NULL-checked separately, so a NULL mutex means an unguarded bump.
/// Returns `dst`.
///
/// The lock pair is `kernel::sync_mutex::mutex_lock` /
/// `mutex_unlock` (originals @ 0x0807f5c4 / 0x0807f6a0, now ported);
/// an earlier scouting note deferred this function until those landed.
///
/// Codegen deviation: LLVM inlines the ported lock/unlock (guards and
/// ROM_KERNEL dispatch included) instead of emitting the original's
/// `bl` pair, so the ARM body is larger but structurally the same —
/// both mutex-field loads are NULL-checked, the bump sits between
/// them, and `dst` is returned untouched.
///
/// # Safety
/// `dst` and `src` must be valid, aligned pointer slots; when the
/// loaded body pointer is non-NULL it must point at a readable/writable
/// [`RefcountedBody`]. As in the original, the slot pointers themselves
/// are not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_assign(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    let obj = src.read();
    dst.write(obj);
    if !obj.is_null() {
        let mutex = (*obj).mutex;
        if !mutex.is_null() {
            mutex_lock(mutex);
        }
        // Original: `add r0, r0, #1` — a plain wrapping increment.
        (*obj).refcount = (*obj).refcount.wrapping_add(1);
        // Re-loaded, as in the original: a racing release could in
        // principle have torn the object down under us.
        let mutex = (*obj).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }
    dst
}
///
/// refcounted_ptr_copy_construct — original: `FUN_0839ef3c` @ `0x0839ef3c`
/// (24 bytes). Raw decoding establishes the exact extent: the next separately
/// linked function begins at `0x0839ef54`. Decoding every ARM `B`/`BL` word
/// in `osos.dec` finds 10 direct `bl` callers: nine unconditional
/// (`0x08132d28`, `0x08132ef4`, `0x08133290`, `0x0813332c`, `0x081333d0`,
/// `0x081334b4`, `0x08133510`, `0x08133584`, and `0x081336c8`) plus one
/// `blne` at `0x083dc2fc`; there are no tail `b` transfers and no image
/// data-word references, so it is not virtually dispatched. The sole
/// predicated caller guards its own destination slot.
///
/// C++ copy-constructor for a refcounted handle: loads `*src`, installs that
/// body in `dst`, and adds one to its signed refcount under its optional
/// mutex. It returns `dst`; neither slot pointer is NULL-checked.
///
/// Deliberate deviation: stock calls the separately linked attach helper
/// `FUN_0839cf10`. Its decoded body is byte-identical in behavior to the
/// already ported [`refcounted_body_attach`] @ `0x0839d370` (store, optional
/// mutex lock, wrapping increment, fresh optional mutex unlock), so this
/// port calls that canonical implementation. The dedicated target section
/// keeps this small separately hookable constructor from folding with a
/// byte-identical Rust sibling.
///
/// # Safety
///
/// `dst` and `src` must be valid, aligned pointer slots. When `*src` is
/// non-NULL, it must point at a writable [`RefcountedBody`] whose optional
/// mutex satisfies [`refcounted_body_attach`]'s preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_ptr_copy_construct")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_copy_construct(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    refcounted_body_attach(dst, src.read());
    dst
}

///
/// refcounted_ptr_assign_owned — original: `FUN_0839f1b0` @ 0x0839f1b0
/// (48 bytes; 13 `bl` call sites, all unconditional — verified by decoding
/// every ARM B/BL word in osos.dec: no `b` sites, no predicated forms, and
/// no data-word references). The next separately linked function starts at
/// 0x0839f1e0.
///
/// The owning copy-assignment operator for a refcounted handle slot:
///
/// ```text
/// if (dst != src) {
///     refcounted_body_release_owned(dst);
///     refcounted_body_attach(dst, *src);
/// }
/// return dst;
/// ```
///
/// The guard compares slot pointers, not bodies. Its source load follows the
/// release, exactly as the ARM's `ldr r1,[r4]` does, so a source slot that
/// aliases storage altered by the release is observed after that alteration.
/// Unlike [`refcounted_ptr_copy_assign`], the discarded body is released by
/// the owning variant, which disposes and frees its implementation on the
/// final reference. The original calls separately linked copies of the
/// release and attach helpers at 0x0839d2c0 and 0x0839d284; this port uses
/// their already-ported equivalent helpers. LLVM may emit different helper
/// displacements, but retains the release/load/attach sequence.
///
/// # Safety
/// `dst` and `src` must be valid, aligned pointer slots. Their non-NULL
/// bodies must satisfy the safety requirements of
/// [`refcounted_body_release_owned`] and [`refcounted_body_attach`]. As in
/// the original, neither slot pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_assign_owned(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    if dst != src.cast_mut() {
        refcounted_body_release_owned(dst);
        refcounted_body_attach(dst, src.read());
    }
    dst
}


/// refcounted_body_acquire — original: `FUN_0839cd5c` @ 0x0839cd5c
/// (60 bytes; **10 `bl` call sites**, all unconditional, plus 2
/// unconditional tail `b` sites at 0x08131fbc and 0x08218e08). Decoding
/// every ARM B/BL word in osos.dec found no predicated sites and no image
/// word equals this address, so it is never virtually dispatched. Ghidra's
/// extent is exact: [`refcounted_body_release`] starts immediately after at
/// 0x0839cd98.
///
/// Stores `body` into `dst` unconditionally, then when `body` is non-NULL
/// increments its signed refcount at +4 with ARM's wrapping `add`. The
/// optional mutex at +8 is loaded and NULL-checked separately before each
/// lock and unlock; a NULL mutex therefore leaves the increment unguarded.
/// This is a separately linked copy of [`refcounted_body_attach`] with the
/// same algorithm. It has its own target text section so LLVM cannot fold
/// away the hookable firmware entry.
///
/// Deliberate deviation: the Rust port calls the already ported mutex
/// helpers directly; LLVM may inline them rather than retaining the ARM
/// `blne`/tail-`bne` pair, but the store/guard/increment/guard order is
/// unchanged.
///
/// # Safety
///
/// `dst` must be a valid, aligned pointer slot; when `body` is non-NULL it
/// must point at a readable/writable [`RefcountedBody`]. Neither pointer is
/// NULL-checked by the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_body_acquire")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_acquire(
    dst: *mut *mut RefcountedBody,
    body: *mut RefcountedBody,
) {
    dst.write(body);
    if body.is_null() {
        return;
    }
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }
    (*body).refcount = (*body).refcount.wrapping_add(1);
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_unlock(mutex);
    }
}

/// refcounted_body_attach — original: `FUN_0839d370` @ 0x0839d370
/// (60 bytes; 6 `bl` call sites — 3 unconditional (0x081f0dbc,
/// 0x081fcc30, and 0x0839f2b0 inside [`refcounted_ptr_copy_assign`])
/// plus 3 `blne` (0x083e8a60, 0x083e8c28, 0x083e9538) whose callers
/// predicate on the DESTINATION SLOT pointer (`movs r0, r5; ldrne
/// r1, [r4]; blne`), NULL-checking the slot themselves. Verified by
/// decoding every ARM B/BL word in osos.dec: no `b` sites and no
/// data-word references, so it is never virtually dispatched. Ghidra's
/// 60-byte extent is exact: [`refcounted_body_release_dtor_variant`]
/// starts immediately after at 0x0839d3ac.
///
/// The shared-body attach half of the copy-assignment operators:
/// `*dst = body`, unconditionally (`str r1, [r0]` precedes the
/// conditional `popeq`), then when `body` is non-NULL its refcount (+4)
/// is bumped by one under the optional mutex at +8 (mutex_lock @
/// 0x0807f5c4 / mutex_unlock @ 0x0807f6a0, both ported in
/// kernel/sync_mutex.rs). The mutex field is loaded twice — once for
/// the lock and again for the unlock — each load NULL-checked
/// separately, so a NULL mutex means an unguarded bump. This is exactly
/// [`refcounted_ptr_assign`] with the `obj = *src` load hoisted out:
/// that load is this function's second argument.
///
/// The original's return value is unreliable and unused: r0 survives as
/// `dst` only on the NULL-body `popeq`; the bump path tail-branches
/// into mutex_unlock (returning ITS value) or pops with r0 = mutex.
/// This port therefore returns nothing.
///
/// Codegen deviation: LLVM inlines the ported lock/unlock (guards and
/// ROM_KERNEL dispatch included) instead of emitting the original's
/// `blne`/tail-`bne` pair, so the ARM body is larger but keeps the
/// store/guard/bump/guard structure — match.py structural confirms.
///
/// # Safety
/// `dst` must be a valid, aligned pointer slot; when `body` is non-NULL
/// it must point at a readable/writable [`RefcountedBody`]. As in the
/// original, the slot pointer itself is not NULL-checked (predicated
/// callers do that), and the store happens even for a NULL body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_attach(
    dst: *mut *mut RefcountedBody,
    body: *mut RefcountedBody,
) {
    // `str r1, [r0]` executes before the `movs`-flagged conditional
    // pop: the store is unconditional, the bump is not.
    dst.write(body);
    if body.is_null() {
        return;
    }
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }
    // Original: `add r0, r0, #1` — a plain wrapping increment.
    (*body).refcount = (*body).refcount.wrapping_add(1);
    // Re-loaded, as in the original: a racing release could in
    // principle have torn the object down under us.
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_unlock(mutex);
    }
}

/// refcounted_ptr_copy_assign — original: `FUN_0839f28c` @ 0x0839f28c
/// (48 bytes; 14 `bl` call sites, all unconditional — verified by
/// decoding every ARM B/BL word in osos.dec: no `b` sites, no
/// predicated forms, and the address appears in no data word, so it is
/// never virtually dispatched. Ghidra's 48-byte extent is exact: a
/// separately linked sibling begins immediately after at 0x0839f2bc).
///
/// The C++ copy-assignment operator of a refcounted handle slot:
///
/// ```text
/// if (dst != src) {
///     refcounted_body_release_dtor_variant(dst);   // drop old body
///     refcounted_body_attach(dst, *src);           // share new body
/// }
/// return dst;
/// ```
///
/// The guard compares the SLOT POINTERS, not the bodies — two distinct
/// slots holding the same body with refcount 1 will destroy the body in
/// the release and then attach the dangling pointer, bumping the freed
/// body's refcount back to 1. That aliasing hazard is reproduced
/// faithfully (a host test pins it). `*src` is loaded AFTER the
/// release, exactly as the ARM does (`ldr r1, [r4]` follows the
/// release `bl`), so a `src` slot aliasing storage the release
/// invalidates behaves identically to the original. Returns `dst`
/// unconditionally, including on the self-assign early-out.
///
/// Both callees are ported: the slot-1 teardown
/// [`refcounted_body_release_dtor_variant`] @ 0x0839d3ac, and
/// [`refcounted_body_attach`] @ 0x0839d370 ported alongside this
/// function. A byte-similar sibling copy-assign @ 0x0839f324 (6 `bl`
/// sites) pairs two different helpers (release 0x0839d498, attach
/// 0x0839d45c, both unported) and remains unported.
///
/// Codegen deviation: LLVM emits the two calls as `bl`s to the ported
/// symbols (both are `#[inline(never)]` exports), matching the
/// original's structure exactly; inside them the ported mutex helpers
/// inline, as documented on each callee.
///
/// # Safety
/// `dst` and `src` must be valid, aligned pointer slots; their non-NULL
/// bodies (and those bodies' mutexes, implementations, and vtables with
/// a live virtual destructor at word index 1) must be valid for the
/// release and attach operations encoded by the original. As in the
/// original, the slot pointers themselves are not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_copy_assign(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    if dst != src.cast_mut() {
        refcounted_body_release_dtor_variant(dst);
        refcounted_body_attach(dst, src.read());
    }
    dst
}

/// refcounted_handle_copy_assign — original: `FUN_0839ec70` @ 0x0839ec70
/// (48 bytes; 11 `bl` call sites, all unconditional — verified by decoding
/// every ARM B/BL word in osos.dec: no `b` sites, no predicated forms, and no
/// image word references, so it is never virtually dispatched. The next
/// separately linked function starts at 0x0839eca0).
///
/// Copy-assigns a refcounted handle slot. Distinct slot addresses first release
/// `*dst` through the slot-1 destructor at 0x0839cbc0, then load `*src` and
/// attach it, which stores it in `dst` and increases its signed refcount under
/// its optional mutex. The source load deliberately follows the release, and
/// the function returns `dst` even for self-assignment.
///
/// The ARM body calls the separately linked attach helper at 0x0839cb84. That
/// 60-byte helper is byte-identical to [`refcounted_body_attach`] at
/// 0x0839d370 modulo direct-branch displacements, so this port calls the
/// already ported canonical helper. A dedicated target section preserves this
/// separately hookable export; LLVM may otherwise fold it with a sibling.
///
/// # Safety
/// `dst` and `src` must be valid, aligned pointer slots; their non-NULL bodies
/// and associated mutexes, implementations, and vtables must meet the safety
/// requirements of [`refcounted_body_release_dtor`] and
/// [`refcounted_body_attach`]. The original does not NULL-check either slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_handle_copy_assign")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_handle_copy_assign(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    if dst != src.cast_mut() {
        refcounted_body_release_dtor(dst);
        refcounted_body_attach(dst, src.read());
    }
    dst
}

/// refcounted_body_release — original: `FUN_0839cd98` @ 0x0839cd98
/// (144 bytes; called by the refcounted-handle release wrappers).
///
/// Drops the shared body's signed refcount under its optional mutex. A
/// non-final drop simply unlocks and NULLs the caller's slot. On the final
/// transition, it invokes the implementation's virtual destructor at vtable
/// slot 7 (+0x1c), unlocks, deletes the mutex (including its semaphore
/// cell), then tag-2-deletes the mutex object and body. The final slot store
/// happens on every non-NULL-body path. The target's plain `subs` wraps on
/// underflow, so only a result of exactly zero is final.
///
/// The target body layout is documented on [`RefcountedBody`]. `opaque0`
/// must be a valid implementation pointer when nonzero; its first word must
/// be a valid vtable containing a virtual destructor at word index 7.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. Its non-NULL body, mutex,
/// implementation, vtable, and virtual destructor must all be live and
/// valid for the operations encoded by the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            let vtable = (implementation as *const usize).read() as *const usize;
            let destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(7).read());
            destructor(implementation);
        }

        // The original re-reads the slot after the destructor before
        // releasing and destroying the body it still names.
        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_unlock(mutex);
                mutex_delete(mutex);
                // Reload after mutex_delete, exactly as the ARM does before
                // the tag-2 delete, then clear the field after that delete.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        // This helper call is reached with a fresh load from the slot in the
        // ARM body; the mutex helper performs its own NULL guards.
        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_unlock(mutex);
            }
        }
    }

    slot.write(core::ptr::null_mut());
}

/// Implementation disposal behind [`refcounted_body_release_owned`]:
/// original `FUN_0827948c` @ 0x0827948c (44 bytes, unported). The raw
/// body is `push {r4,lr}; mov r4,r0; ldr r0,[r0]; cmp r0,#0; ldrne r1,[r0];
/// ldrne r1,[r1,#4]; blxne r1; add r0,r4,#4; bl 0x08277484; sub r0,r0,#4;
/// pop {r4,pc}` — i.e. when the implementation's first word (a callback
/// interface pointer) is non-NULL it calls virtual slot 1 (+4) on that
/// interface, then runs the ported plain destructor
/// [`string_object_destroy`] on the two-word StringObject member at byte
/// offset +4 and returns `this` (the destructor returns its argument;
/// the `sub` undoes the `add`). On the firmware target this is a direct
/// call to the still-unported ROM address; host builds model it
/// faithfully — every callee on the chain is either data-driven (the
/// interface vtable) or ported ([`string_object_destroy`]).
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispose_implementation(implementation: *mut u8) -> *mut u8 {
    let dispose: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(0x0827_948cusize);
    dispose(implementation)
}

/// Host model of the 0x0827948c disposal — see the target twin above.
/// The StringObject member sits one pointer word into the implementation
/// (target byte offset +4; host fixtures widen it like every other
/// pointer field, so the member never overlaps the callback word).
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispose_implementation(implementation: *mut u8) -> *mut u8 {
    let callback = (implementation as *const *mut u8).read();
    if !callback.is_null() {
        let vtable = (callback as *const *const usize).read();
        let release: unsafe extern "C" fn(*mut u8) =
            core::mem::transmute(vtable.add(1).read());
        release(callback);
    }
    let string = implementation.add(core::mem::size_of::<usize>()) as *mut StringObject;
    string_object_destroy(string);
    implementation
}

/// refcounted_body_release_owned — original: `FUN_0839d2c0` @ 0x0839d2c0
/// (144 bytes — Ghidra's 136-byte extent drops the trailing
/// `str r6,[r4]` / `pop {r4,r5,r6,pc}`; the body runs to 0x0839d350,
/// where the separately linked 16-byte mutex-lock helper starts
/// (0x0839d350 locks, 0x0839d360 unlocks; each loads body+8, NULL-checks
/// it and tail-branches to mutex_lock 0x0807f5c4 / mutex_unlock
/// 0x0807f6a0). 28 `bl` call sites, all unconditional — verified by
/// decoding every ARM B/BL word in osos.dec: no `b` sites, no predicated
/// forms, and the address appears in no data word, so it is never
/// virtually dispatched).
///
/// A sibling template instantiation of [`refcounted_body_release`] @
/// 0x0839cd98 over the same [`RefcountedBody`] layout (+0 implementation,
/// +4 i32 refcount, +8 Mutex*); the two bodies are byte-identical except
/// for the final drop's implementation disposal. Where the sibling
/// invokes vtable slot 7 (+0x1c) on the implementation and never frees
/// it, this instantiation OWNS its implementation: when the NULL-guarded
/// word at body+0 is non-NULL it runs the disposal @ 0x0827948c (see
/// [`dispose_implementation`]) and tag-2-deletes the implementation
/// block through `operator_delete` (0x082aad24, ported) with the
/// disposal's return value. Everything else matches the sibling: NULL
/// body early-out (the slot is left untouched), refcount decremented
/// under the optional mutex with a plain wrapping `subs` (zero
/// underflows to -1 and takes the shared path), non-final drop unlocks
/// and NULLs the slot, final drop unlocks through a FRESH slot load,
/// then — gated on a second fresh slot load being non-NULL — destroys
/// the mutex (mutex_delete 0x0807f650, ported), tag-2-deletes the
/// reloaded mutex word, clears the mutex field, tag-2-deletes the body,
/// and NULLs the slot on every path that reached the decrement.
///
/// Codegen deviation: LLVM inlines the ported mutex lock/unlock/delete
/// (ROM_KERNEL dispatch included) where the original `bl`s the two
/// 16-byte helpers and 0x0807f650; match.py shows the same
/// guard/decrement/dispose/delete structure inside a larger body.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its
/// mutex, its implementation, the implementation's callback interface
/// and that interface's vtable must all be live and valid for the
/// operations encoded by the original. As in the original, the slot
/// pointer itself is not NULL-checked, and the lock/unlock helpers
/// guard only the mutex word — never the body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_owned(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    // Lock helper @ 0x0839d350, entered with the body's first load.
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    // Fresh slot load; the ARM carries it in r0 across the `bne`.
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            // The disposal returns `this`, and that return feeds the
            // tag-2 delete directly (the ARM never reloads r0).
            let implementation = dispose_implementation(implementation);
            operator_delete(implementation);
        }

        // Unlock helper @ 0x0839d360 on its own fresh slot load; like
        // the lock helper it guards only the mutex word.
        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                // Reloaded between the delete and the tag-2 free, exactly
                // as the ARM does, then cleared after that free.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// ABI of the direct implementation disposer at 0x0816f5c0.
type RefcountedImplementationDisposer = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Calls the still-unported implementation disposer directly on device.
///
/// The complete 124-byte body at 0x0816f5c0 frees several implementation
/// fields and returns its input. It is deliberately not assigned a class
/// identity here.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_refcounted_implementation_dispose(implementation: *mut u8) -> *mut u8 {
    let disposer: RefcountedImplementationDisposer = core::mem::transmute(0x0816_f5c0usize);
    disposer(implementation)
}

/// Host default for the unported 0x0816f5c0 implementation disposer.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refcounted_implementation_dispose(implementation: *mut u8) -> *mut u8 {
    implementation
}

/// Host-only test injection for the raw 0x0816f5c0 direct call.
#[cfg(not(target_os = "none"))]
static mut REFCOUNTED_IMPLEMENTATION_DISPOSE: RefcountedImplementationDisposer =
    missing_refcounted_implementation_dispose;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn firmware_refcounted_implementation_dispose(implementation: *mut u8) -> *mut u8 {
    let disposer = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_IMPLEMENTATION_DISPOSE));
    disposer(implementation)
}

/// ABI of the direct two-argument disposer at 0x081f7328.
type RefcountedRetainCountDisposer = unsafe extern "C" fn(*mut u8, i32);

/// Calls the unported direct disposer used only by
/// [`refcounted_body_release_retain_count`] on device.
///
/// The raw ARM enters it with the implementation pointer in r0 and the
/// just-decremented body refcount in r1. On a final release that count is
/// necessarily zero, but the direct call remains observable and is retained.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_refcounted_retain_count_dispose(implementation: *mut u8, refcount: i32) {
    let disposer: RefcountedRetainCountDisposer = core::mem::transmute(0x081f_7328usize);
    disposer(implementation, refcount)
}

/// Host default for the unported direct 0x081f7328 disposal call.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refcounted_retain_count_dispose(_implementation: *mut u8, _refcount: i32) {}

/// Host-only test injection for the raw direct 0x081f7328 call.
#[cfg(not(target_os = "none"))]
static mut REFCOUNTED_RETAIN_COUNT_DISPOSE: RefcountedRetainCountDisposer =
    missing_refcounted_retain_count_dispose;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn firmware_refcounted_retain_count_dispose(implementation: *mut u8, refcount: i32) {
    let disposer =
        core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_RETAIN_COUNT_DISPOSE));
    disposer(implementation, refcount)
}

/// refcounted_body_release_owned_variant — original: `FUN_0839cf4c` @
/// 0x0839cf4c (144 bytes — Ghidra's 136-byte extent omits the trailing
/// `str r6,[r4]` / `pop {r4,r5,r6,pc}`; the next separately linked
/// mutex-lock helper begins at 0x0839cfdc). Decoding every ARM B/BL word in
/// osos.dec finds 19 direct `bl` callers, all unconditional: no predicated
/// calls, no tail `b` sites, and no data-word references.
///
/// Owning sibling of [`refcounted_body_release_owned`]: it drops the signed
/// refcount under the optional mutex, NULLs the slot after every non-NULL
/// body path, and destroys the mutex and body on the final transition only.
/// Unlike the sibling, its NULL-guarded implementation word is passed to the
/// unported direct callee at 0x0816f5c0, whose return feeds tag-2
/// [`operator_delete`] directly. Raw bytes establish that the callee returns
/// its input after teardown; no class identity is inferred for it.
///
/// Deliberate host deviation: 0x0816f5c0 remains unported, so host builds use
/// an identity test seam for that call; target builds dispatch to its firmware
/// address directly.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. Its non-NULL body, mutex, and
/// implementation must be live for every operation the firmware performs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_body_release_owned_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_owned_variant(
    slot: *mut *mut RefcountedBody,
) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let body = slot.read();
    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            let implementation = firmware_refcounted_implementation_dispose(implementation);
            operator_delete(implementation);
        }

        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_body_release_slot1_copy — original: `FUN_0839d038` @
/// 0x0839d038 (144 bytes — Ghidra's reported 136-byte extent misses the
/// trailing `str r6,[r4]` / `pop {r4,r5,r6,pc}`; the separately linked
/// mutex-lock helper starts at 0x0839d0c8 and the unlock helper at
/// 0x0839d0d8). Decoding every ARM B/BL word in osos.dec finds 13 direct
/// `bl` callers, all unconditional: no predicated forms, no tail `b` sites,
/// and no data-word references.
///
/// A separately linked copy of [`refcounted_body_release_dtor`] over the same
/// [`RefcountedBody`] layout (+0 implementation, +4 i32 refcount, +8
/// [`Mutex`]). A NULL body leaves its slot untouched. Otherwise it locks the
/// optional mutex, decrements the count with wrapping `subs`, and clears the
/// slot. A non-final reference only unlocks. The final reference
/// NULL-guardedly dispatches vtable word 1 (+4) of the implementation, never
/// frees that implementation block, unlocks, deletes and tag-2-frees the
/// mutex, then tag-2-frees the body.
///
/// Deliberate codegen deviation: LLVM inlines the ported mutex and heap
/// helpers where retailOS calls its local 16-byte helpers and
/// `mutex_delete`; the guard/decrement/slot-1-dispatch/teardown order stays
/// the same. Its target-only section keeps this hookable copy distinct from
/// byte-identical siblings.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its mutex,
/// its implementation, and the implementation's vtable (with a live virtual
/// destructor at word index 1) must all be valid. As in retailOS, `slot`
/// itself is never NULL-checked and the mutex helpers guard only the mutex
/// word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_body_release_slot1_copy")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_slot1_copy(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            let vtable = (implementation as *const usize).read() as *const usize;
            let destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(1).read());
            destructor(implementation);
        }

        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_body_release_dtor — original: `FUN_0839cbc0` @
/// 0x0839cbc0 (144 bytes — Ghidra's 136-byte extent drops the trailing
/// `str r6,[r4]` / `pop {r4,r5,r6,pc}`; the body runs to 0x0839cc50,
/// where the separately linked 16-byte mutex-lock helper starts
/// (0x0839cc50 locks, 0x0839cc60 unlocks; each loads body+8, NULL-checks
/// it and tail-branches to mutex_lock 0x0807f5c4 / mutex_unlock
/// 0x0807f6a0). 24 `bl` call sites: 23 unconditional plus one `blne` at
/// 0x083c64d0, verified by decoding every ARM B/BL word in osos.dec — no
/// `b` sites, and the address appears in no data word, so it is never
/// virtually dispatched).
///
/// A third template instantiation of [`refcounted_body_release`] @
/// 0x0839cd98 over the same [`RefcountedBody`] layout (+0 implementation,
/// +4 i32 refcount, +8 Mutex*): the two bodies are byte-identical modulo
/// `bl` displacements except for ONE word — the final drop's virtual
/// dispatch loads vtable slot 1 (+4) here where the sibling loads slot 7
/// (+0x1c). So the final reference runs the implementation's plain
/// virtual destructor through its first-word vtable (impl NULL-guarded,
/// vtable dispatch predicated on the impl word) and, like the slot-7
/// sibling, never frees the implementation block itself. Everything else
/// matches: NULL body early-out (the slot is left untouched), refcount
/// decremented under the optional mutex with a plain wrapping `subs`
/// (zero underflows to -1 and takes the shared path), non-final drop
/// unlocks through the carried fresh slot load and NULLs the slot, final
/// drop unlocks through a FRESH slot load, then — gated on a second fresh
/// slot load being non-NULL — destroys the mutex (mutex_delete
/// 0x0807f650, ported), tag-2-deletes the reloaded mutex word
/// (operator_delete 0x082aad24, ported), clears the mutex field,
/// tag-2-deletes the body, and NULLs the slot on every path that reached
/// the decrement.
///
/// Codegen deviation: LLVM inlines the ported mutex lock/unlock/delete
/// (ROM_KERNEL dispatch included) where the original `bl`s the two
/// 16-byte helpers and 0x0807f650; match.py shows the same
/// guard/destruct/unlock/teardown structure inside a larger body.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its
/// mutex, its implementation, and the implementation's vtable (with a
/// live virtual destructor at word index 1) must all be valid for the
/// operations encoded by the original. As in the original, the slot
/// pointer itself is not NULL-checked, and the lock/unlock helpers guard
/// only the mutex word — never the body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_dtor(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    // Lock helper @ 0x0839cc50, entered with the body's first load.
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    // Fresh slot load; the ARM carries it in r0 across the `bne`.
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            // `ldrne r1,[r0]; ldrne r1,[r1,#4]; blxne r1` — the plain
            // virtual destructor at vtable word 1. The implementation
            // block itself is NOT freed, unlike the owned sibling.
            let vtable = (implementation as *const usize).read() as *const usize;
            let destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(1).read());
            destructor(implementation);
        }

        // Unlock helper @ 0x0839cc60 on its own fresh slot load; like
        // the lock helper it guards only the mutex word.
        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                // Reloaded between the delete and the tag-2 free, exactly
                // as the ARM does, then cleared after that free.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_body_release_dtor_variant — original: `FUN_0839d3ac` @
/// 0x0839d3ac (144 bytes — Ghidra's 136-byte extent drops the trailing
/// `str r6,[r4]` / `pop {r4,r5,r6,pc}`; the body runs to 0x0839d43c,
/// where the separately linked 16-byte mutex-lock helper starts
/// (0x0839d43c locks, 0x0839d44c unlocks; each loads body+8, NULL-checks
/// it and tail-branches to mutex_lock 0x0807f5c4 / mutex_unlock
/// 0x0807f6a0). 23 `bl` call sites, all unconditional — verified by
/// decoding every ARM B/BL word in osos.dec: no `b` sites, no predicated
/// forms, and the address appears in no data word, so it is never
/// virtually dispatched).
///
/// A fourth separately linked copy of the slot-1 teardown: the 36 words
/// are byte-identical to [`refcounted_body_release_dtor`] @ 0x0839cbc0
/// except the three absolute `bl` displacements to mutex_delete @
/// 0x0807f650 and operator_delete @ 0x082aad24 (both ported). Same
/// [`RefcountedBody`] layout (+0 implementation, +4 i32 refcount, +8
/// Mutex*): NULL body early-out (slot untouched), lock the optional
/// mutex, wrapping `subs` decrement (zero underflows to -1 and takes the
/// shared path), non-final drop unlocks and NULLs the slot, final drop
/// dispatches the implementation's plain virtual destructor at vtable
/// word 1 (+4) — impl NULL-guarded, block never freed — unlocks through
/// a fresh slot load, then destroys the mutex, tag-2-deletes the
/// reloaded mutex word, clears the mutex field, tag-2-deletes the body,
/// and NULLs the slot on every path that reached the decrement.
///
/// Deliberate codegen deviation: like its siblings, LLVM inlines the
/// ported mutex lock/unlock/delete (ROM_KERNEL dispatch included) where
/// the original `bl`s the two 16-byte helpers and 0x0807f650; match.py
/// shows the same guard/destruct/unlock/teardown structure inside a
/// larger body. A dedicated target section prevents LLVM from folding
/// this hookable copy into [`refcounted_body_release_dtor`], whose body
/// is source-identical.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its
/// mutex, its implementation, and the implementation's vtable (with a
/// live virtual destructor at word index 1) must all be valid for the
/// operations encoded by the original. As in the original, the slot
/// pointer itself is not NULL-checked, and the lock/unlock helpers guard
/// only the mutex word — never the body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_body_release_dtor_variant")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_dtor_variant(
    slot: *mut *mut RefcountedBody,
) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    // Lock helper @ 0x0839d43c, entered with the body's first load.
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    // Fresh slot load; the ARM carries it in r0 across the `bne`.
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            // `ldrne r1,[r0]; ldrne r1,[r1,#4]; blxne r1` — the plain
            // virtual destructor at vtable word 1. The implementation
            // block itself is NOT freed, unlike the owned sibling.
            let vtable = (implementation as *const usize).read() as *const usize;
            let destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(1).read());
            destructor(implementation);
        }

        // Unlock helper @ 0x0839d44c on its own fresh slot load; like
        // the lock helper it guards only the mutex word.
        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                // Reloaded between the delete and the tag-2 free, exactly
                // as the ARM does, then cleared after that free.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_body_release_retain_count — original: `FUN_0839d498` @
/// 0x0839d498 (152 bytes — Ghidra reports 144 but omits the final
/// `str r6,[r4]` / `pop {r4,r5,r6,pc}`; raw ARM ends at 0x0839d530, where
/// the separately linked mutex-lock helper begins). Decoding every ARM B/BL
/// word in osos.dec finds 11 direct `bl` callers, all unconditional: no
/// predicated forms and no tail `b` sites.
///
/// A refcounted-handle release over [`RefcountedBody`] (+0 implementation,
/// +4 signed refcount, +8 optional [`Mutex`]). A NULL body leaves `slot`
/// untouched. Otherwise it locks the optional mutex, wrapping-decrements
/// the count, then clears `slot`. Non-final releases unlock only. The final
/// release NULL-guardedly calls the direct, unported 0x081f7328 with the
/// implementation and the count just stored as zero, then unlocks, destroys
/// and tag-2-deletes the mutex, clears body+8, and tag-2-deletes the body.
///
/// Deliberate host deviation: 0x081f7328 is unported and no identity is
/// inferred for it. Target builds call that address directly; host tests use
/// a recording seam. LLVM may inline the ported mutex and heap helpers, while
/// retaining the guard/decrement/dispose/unlock/teardown sequence.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its mutex,
/// and its implementation must be live for each operation encoded by the
/// original. As in retailOS, `slot` itself is never NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_body_release_retain_count")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_retain_count(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            // `ldmia r5,{r0,r1}` passes the just-zeroed count in r1.
            firmware_refcounted_retain_count_dispose(implementation, (*body).refcount);
        }

        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_ptr_release — original: `FUN_0816cd44` @ 0x0816cd44
/// (20 bytes; 90 `bl` call sites, mostly the 0x0822xxxx application
/// layer releasing stack- and member-slot handles).
///
/// The drop counterpart of [`refcounted_ptr_assign`]: drops the body in
/// `slot` through [`refcounted_body_release`] and returns `slot` unchanged
/// — the ADS destroy-and-return-this idiom.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot; when the body pointer
/// it holds is non-NULL it must point at a live [`RefcountedBody`]. As
/// in the original, the slot pointer itself is not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_release(
    slot: *mut *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    refcounted_body_release(slot);
    slot
}

/// refcounted_body_release_slot1 — original: `FUN_0839d1d4` @ 0x0839d1d4.
/// Ghidra reports 136 bytes; the raw extent is 144 (0x0839d1d4..0x0839d264):
/// the `str r6,[r4]` / `pop {r4,r5,r6,pc}` tail at 0x0839d25c..0x0839d260 is
/// shared by both exits and Ghidra stops short of it. Two separately linked
/// 16-byte helpers follow at 0x0839d264 (lock) and 0x0839d274 (unlock), each
/// loading body+8, NULL-checking it and tail-branching to `mutex_lock`
/// 0x0807f5c4 / `mutex_unlock` 0x0807f6a0; the next function starts at
/// 0x0839d284. 20 `bl` call sites, all unconditional — verified by decoding
/// every ARM B/BL word in osos.dec: no `b` sites, no predicated forms.
///
/// Third template instantiation of the refcounted-handle release over the
/// same [`RefcountedBody`] layout (+0 implementation, +4 i32 refcount, +8
/// Mutex*). It is instruction-for-instruction the same as
/// [`refcounted_body_release`] @ 0x0839cd98 except in what the final drop
/// does with the implementation: this one dispatches VIRTUAL SLOT 1 (+4) of
/// the implementation's vtable (`ldr r1,[r0]; ldr r1,[r1,#4]; blx r1`) and
/// never frees the implementation, where the sibling dispatches slot 7 and
/// [`refcounted_body_release_owned`] disposes and deletes it. No identity is
/// inferred for slot 1. Everything else matches: NULL body early-out (slot
/// untouched), refcount decremented under the optional mutex with a plain
/// wrapping `subs` (zero underflows to -1 and takes the shared path), the
/// unlock helper entered on a FRESH slot load and guarding only the mutex
/// word, then — gated on another fresh slot load being non-NULL — the mutex
/// destroyed (`mutex_delete` 0x0807f650), the reloaded mutex word and the
/// body tag-2-deleted (`operator_delete` 0x082aad24), and the slot NULLed on
/// every path that reached the decrement.
///
/// Codegen deviation: LLVM inlines the ported mutex lock/unlock/delete where
/// the original `bl`s the two helpers and 0x0807f650; match.py shows the
/// same guard/decrement/dispatch/delete structure inside a larger body.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. A non-NULL body, its mutex,
/// its implementation and that implementation's vtable must all be live and
/// valid for the operations encoded by the original. As in the original, the
/// slot pointer itself is not NULL-checked, and the lock/unlock helpers
/// guard only the mutex word — never the body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release_slot1(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    // Lock helper @ 0x0839d264, entered with the body's first load.
    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    // `ldr r1,[r4]`: the decrement works on a fresh slot load.
    let body = slot.read();
    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    // `ldr r0,[r4]`: and another one is carried across the `bne`.
    let body = slot.read();
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            let vtable = (implementation as *const usize).read() as *const usize;
            let slot1: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(1).read());
            slot1(implementation);
        }

        // Unlock helper @ 0x0839d274 on its own fresh slot load.
        let body = slot.read();
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }

        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_delete(mutex);
                // Reload after mutex_delete, exactly as the ARM does before
                // the tag-2 delete, then clear the field after that delete.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        // Unlock helper on the load carried in r0; guards only the mutex.
        let mutex = (*body).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }

    slot.write(core::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_both_levels() {
        unsafe {
            let mut target: u8 = 0;
            let mut cell: *mut u8 = &mut target;
            let slot: *const *mut u8 = &mut cell;
            assert_eq!(handle_deref_or_null(&slot), &mut target as *mut u8);
        }
    }

    #[test]
    fn null_cell_yields_null_without_a_second_load() {
        unsafe {
            let slot: *const *mut u8 = core::ptr::null();
            assert!(handle_deref_or_null(&slot).is_null());
        }
    }

    /// The inner pointer is returned verbatim, NULL included — the
    /// original has no second guard.
    #[test]
    fn null_target_is_passed_through() {
        unsafe {
            let mut cell: *mut u8 = core::ptr::null_mut();
            let slot: *const *mut u8 = &mut cell;
            assert!(handle_deref_or_null(&slot).is_null());
        }
    }

    #[test]
    fn field12_reads_the_cells_fourth_word() {
        unsafe {
            let mut target: u8 = 0;
            let mut cell: [*mut u8; 5] = [
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut target,
                0x5555 as *mut u8,
            ];
            let slot: *const *mut u8 = cell.as_mut_ptr();
            assert_eq!(handle_deref_field12(&slot), &mut target as *mut u8);
        }
    }

    #[test]
    fn field12_null_cell_yields_null_without_a_second_load() {
        unsafe {
            let slot: *const *mut u8 = core::ptr::null();
            assert!(handle_deref_field12(&slot).is_null());
        }
    }

    #[test]
    fn field12_null_field_is_passed_through() {
        unsafe {
            let mut cell: [*mut u8; 4] = [core::ptr::null_mut(); 4];
            let slot: *const *mut u8 = cell.as_mut_ptr();
            assert!(handle_deref_field12(&slot).is_null());
        }
    }

    /// Both indirection levels, then a word-scaled add: element 3 sits
    /// 12 bytes past the array base.
    #[test]
    fn elem_ptr_walks_both_levels_and_scales_the_index_by_four() {
        unsafe {
            let words = [0x1111_1111u32; 6];
            let cell: *const u32 = words.as_ptr();
            let slot: *const *const u32 = &cell;
            assert_eq!(handle_elem_ptr(&slot, 3), words.as_ptr().add(3) as *mut u32);
            assert_eq!(handle_elem_ptr(&slot, 0), words.as_ptr() as *mut u32);
        }
    }

    /// A NULL cell skips the second load — and the element add still
    /// runs, so the result is `index * 4` as a bare address, NOT NULL.
    #[test]
    fn elem_ptr_null_cell_yields_index_times_four_not_null() {
        unsafe {
            let slot: *const *const u32 = core::ptr::null();
            assert!(handle_elem_ptr(&slot, 0).is_null());
            assert_eq!(handle_elem_ptr(&slot, 3) as usize, 12);
        }
    }

    /// A non-NULL cell holding a NULL base passes the NULL through the
    /// same unconditional add — no second guard, as in the original.
    #[test]
    fn elem_ptr_null_base_is_scaled_without_a_second_guard() {
        unsafe {
            let cell: *const u32 = core::ptr::null();
            let slot: *const *const u32 = &cell;
            assert!(handle_elem_ptr(&slot, 0).is_null());
            assert_eq!(handle_elem_ptr(&slot, 5) as usize, 20);
        }
    }

    /// NULL source body: the slot is overwritten with NULL, nothing
    /// else is touched, and `dst` comes back.
    #[test]
    fn assign_null_body_stores_null_and_returns_dst() {
        unsafe {
            let mut slot: *mut RefcountedBody = 0xdead_beefusize as *mut RefcountedBody;
            let src: *mut RefcountedBody = core::ptr::null_mut();
            let ret = refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert!(slot.is_null());
        }
    }

    /// Unguarded body (mutex NULL): the count is bumped and the slot
    /// repointed, with no kernel interaction.
    #[test]
    fn assign_bumps_refcount_when_mutex_is_null() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: 3,
                mutex: core::ptr::null_mut(),
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let ret = refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 4);
            assert_eq!(body.opaque0, 0x1111_2222);
        }
    }

    /// Guarded body whose mutex cell is absent: lock/unlock take the
    /// NULL-cell early-out inside `mutex_lock`/`mutex_unlock`, so the
    /// bump still happens with no ROM_KERNEL table installed.
    #[test]
    fn assign_bumps_refcount_with_empty_mutex_cell() {
        unsafe {
            let mut mutex = Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: &mut mutex,
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 1);
        }
    }

    /// Self-assign (dst == src): the load happens before the store, so
    /// the slot keeps its pointer and the count rises exactly once.
    #[test]
    fn self_assign_bumps_once() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = &mut body;
            let ret = refcounted_ptr_assign(&mut slot, &slot);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 8);
        }
    }

    /// Distinct slots release the old owned body first, then attach the
    /// source body's current value. Non-final release keeps the old fixture
    /// live, making both count transitions observable.
    #[test]
    fn owned_assign_releases_then_attaches() {
        unsafe {
            let mut old = RefcountedBody {
                opaque0: 0,
                refcount: 2,
                mutex: core::ptr::null_mut(),
            };
            let mut replacement = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut destination: *mut RefcountedBody = &mut old;
            let source: *mut RefcountedBody = &mut replacement;

            let ret = refcounted_ptr_assign_owned(&mut destination, &source);

            assert_eq!(ret, &mut destination as *mut *mut RefcountedBody);
            assert_eq!(destination, &mut replacement as *mut RefcountedBody);
            assert_eq!(old.refcount, 1);
            assert_eq!(replacement.refcount, 8);
        }
    }

    /// A NULL source is loaded after the release and unconditionally stored
    /// by the attach helper, leaving the destination NULL.
    #[test]
    fn owned_assign_null_source_releases_then_stores_null() {
        unsafe {
            let mut old = RefcountedBody {
                opaque0: 0,
                refcount: 2,
                mutex: core::ptr::null_mut(),
            };
            let mut destination: *mut RefcountedBody = &mut old;
            let source: *mut RefcountedBody = core::ptr::null_mut();

            let ret = refcounted_ptr_assign_owned(&mut destination, &source);

            assert_eq!(ret, &mut destination as *mut *mut RefcountedBody);
            assert!(destination.is_null());
            assert_eq!(old.refcount, 1);
        }
    }

    /// Equal slot pointers skip both the owning release and attach.
    #[test]
    fn owned_assign_self_assignment_preserves_body_and_count() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = &mut body;

            let ret = refcounted_ptr_assign_owned(&mut slot, &slot);

            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 7);
        }
    }

    /// The increment is a plain ARM `add` — it wraps at i32::MAX.
    #[test]
    fn refcount_increment_wraps() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: i32::MAX,
                mutex: core::ptr::null_mut(),
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(body.refcount, i32::MIN);
        }
    }

    /// The copy constructor's NULL source still overwrites initialized-looking
    /// destination storage and returns that destination slot.
    #[test]
    fn copy_construct_null_source_stores_null_and_returns_destination() {
        unsafe {
            let source: *mut RefcountedBody = core::ptr::null_mut();
            let mut destination = 0xdead_beefusize as *mut RefcountedBody;

            let result = refcounted_ptr_copy_construct(&mut destination, &source);

            assert_eq!(result, &mut destination as *mut *mut RefcountedBody);
            assert!(destination.is_null());
        }
    }

    /// The source is read once, then the signed count receives the raw ARM
    /// wrapping increment while the copied pointer becomes the destination.
    #[test]
    fn copy_construct_copies_body_and_wraps_refcount() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: i32::MAX,
                mutex: core::ptr::null_mut(),
            };
            let source: *mut RefcountedBody = &mut body;
            let mut destination: *mut RefcountedBody = core::ptr::null_mut();

            let result = refcounted_ptr_copy_construct(&mut destination, &source);

            assert_eq!(result, &mut destination as *mut *mut RefcountedBody);
            assert_eq!(destination, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, i32::MIN);
            assert_eq!(body.opaque0, 0x1111_2222);
        }
    }

    /// Acquire with a NULL body: the store is unconditional, so the slot
    /// is overwritten with NULL and nothing else is touched.
    #[test]
    fn acquire_null_body_stores_null() {
        unsafe {
            let mut slot: *mut RefcountedBody = 0xdead_beefusize as *mut RefcountedBody;
            refcounted_body_acquire(&mut slot, core::ptr::null_mut());
            assert!(slot.is_null());
        }
    }

    /// Unguarded body (mutex NULL): the count is bumped and the slot
    /// repointed, with no kernel interaction.
    #[test]
    fn attach_bumps_refcount_when_mutex_is_null() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: 3,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_body_attach(&mut slot, &mut body);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 4);
            assert_eq!(body.opaque0, 0x1111_2222);
        }
    }

    /// Guarded body whose mutex cell is absent: lock/unlock take the
    /// NULL-cell early-out inside `mutex_lock`/`mutex_unlock`, so the
    /// acquire bump still happens with no ROM_KERNEL table installed.
    #[test]
    fn acquire_bumps_refcount_with_empty_mutex_cell() {
        unsafe {
            let mut mutex = Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: &mut mutex,
            };
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_body_acquire(&mut slot, &mut body);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 1);
        }
    }

    /// The acquire increment is the plain ARM `add`, so it wraps.
    #[test]
    fn acquire_refcount_increment_wraps() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: i32::MAX,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_body_acquire(&mut slot, &mut body);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, i32::MIN);
        }
    }

    /// Self-assign through the SAME slot: the guard compares slot
    /// pointers, so nothing runs — no release, no bump — and `dst`
    /// comes back.
    #[test]
    fn copy_assign_same_slot_is_a_no_op() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = &mut body;
            let ret = refcounted_ptr_copy_assign(&mut slot, &slot);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 7);
        }
    }

    /// Both slots NULL: the release early-outs, the attach stores NULL,
    /// and `dst` comes back.
    #[test]
    fn copy_assign_both_null_stays_null() {
        unsafe {
            let mut dst: *mut RefcountedBody = core::ptr::null_mut();
            let src: *mut RefcountedBody = core::ptr::null_mut();
            let ret = refcounted_ptr_copy_assign(&mut dst, &src);
            assert_eq!(ret, &mut dst as *mut *mut RefcountedBody);
            assert!(dst.is_null());
        }
    }

    /// Ordinary transfer between shared bodies: the old body's drop is
    /// non-final (refcount 2 -> 1, no destructor, no frees), the slot
    /// is repointed, and the new body is bumped. NULL mutexes mean no
    /// kernel interaction, so this needs no recording bench.
    #[test]
    fn copy_assign_shared_transfer() {
        unsafe {
            let mut old = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: 2,
                mutex: core::ptr::null_mut(),
            };
            let mut new = RefcountedBody {
                opaque0: 0x3333_4444,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let mut dst: *mut RefcountedBody = &mut old;
            let src: *mut RefcountedBody = core::ptr::addr_of!(new).cast_mut();
            let ret = refcounted_ptr_copy_assign(&mut dst, &src);
            assert_eq!(ret, &mut dst as *mut *mut RefcountedBody);
            assert_eq!(dst, &mut new as *mut RefcountedBody);
            assert_eq!(old.refcount, 1, "non-final drop, body survives");
            assert_eq!(old.opaque0, 0x1111_2222);
            assert_eq!(new.refcount, 2);
        }
    }

    /// The target's slot-address guard skips both body operations on
    /// self-assignment and returns the destination slot unchanged.
    #[test]
    fn handle_copy_assign_same_slot_is_a_no_op() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = &mut body;

            let ret = refcounted_handle_copy_assign(&mut slot, &slot);

            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 7);
        }
    }

    /// A distinct source is loaded only after the old body loses its reference:
    /// the non-final old body survives, while the replacement is attached and
    /// increments from one to two.
    #[test]
    fn handle_copy_assign_releases_then_attaches_source() {
        unsafe {
            let mut old = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: 2,
                mutex: core::ptr::null_mut(),
            };
            let mut new = RefcountedBody {
                opaque0: 0x3333_4444,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let mut dst: *mut RefcountedBody = &mut old;
            let src: *mut RefcountedBody = core::ptr::addr_of!(new).cast_mut();

            let ret = refcounted_handle_copy_assign(&mut dst, &src);

            assert_eq!(ret, &mut dst as *mut *mut RefcountedBody);
            assert_eq!(dst, &mut new as *mut RefcountedBody);
            assert_eq!(old.refcount, 1, "non-final drop leaves the old body live");
            assert_eq!(new.refcount, 2);
        }
    }


    /// Direct tests of the body release use the ported mutex and heap
    /// surfaces with recording kernel/heap hooks. The crate's test
    /// configuration serializes hook-swapping tests; this atomic also keeps
    /// the fixture safe when a runner overrides that configuration.
    mod release {
        extern crate std;

        use super::super::*;
        use crate::heap::types::HeapDescriptorDescriptor;
        use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
        use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::vec::Vec;

        static OPS_LOCK: AtomicBool = AtomicBool::new(false);
        static mut EVENTS: Vec<Event> = Vec::new();

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Event {
            Wait(u32),
            Destructor(usize),
            CallbackRelease(usize),
            Slot1Release(usize),
            OwnedVariantDispose(usize),
            RetainCountDispose(usize, i32),
            Signal(u32),
            Delete(u32),
            MutexCellFree(usize),
            HeapFree(usize, usize),
        }

        unsafe extern "C" fn recording_wait(handle: u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Wait(handle));
        }

        unsafe extern "C" fn recording_signal(handle: u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Signal(handle));
        }

        unsafe extern "C" fn recording_delete(_kind: u32, cell: *mut u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Delete(cell.read()));
            cell.write(0);
        }

        unsafe extern "C" fn recording_mutex_cell_free(cell: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::MutexCellFree(cell as usize));
        }

        unsafe extern "C" fn recording_body_free(
            _heap: *mut HeapDescriptorDescriptor,
            ptr: *mut u8,
            tag: usize,
        ) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::HeapFree(ptr as usize, tag));
        }

        unsafe extern "C" fn recording_destructor(implementation: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Destructor(implementation as usize));
        }

        /// Records the callback interface's virtual slot 1, dispatched by
        /// the host model of the 0x0827948c implementation disposal.
        unsafe extern "C" fn recording_callback_release(callback: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::CallbackRelease(callback as usize));
        }

        unsafe extern "C" fn recording_owned_variant_dispose(implementation: *mut u8) -> *mut u8 {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::OwnedVariantDispose(implementation as usize));
            implementation
        }

        unsafe extern "C" fn recording_retain_count_dispose(
            implementation: *mut u8,
            refcount: i32,
        ) {
            (*core::ptr::addr_of_mut!(EVENTS))
                .push(Event::RetainCountDispose(implementation as usize, refcount));
        }

        struct Bench {
            old_kernel: RomKernelOps,
            old_heap: HeapVeneerOps,
            old_owned_variant_dispose: RefcountedImplementationDisposer,
            old_retain_count_dispose: RefcountedRetainCountDisposer,
        }

        fn bench() -> Bench {
            while OPS_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                std::thread::yield_now();
            }
            unsafe {
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                let old_kernel = core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL));
                let old_heap = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
                let old_owned_variant_dispose = core::ptr::read_volatile(
                    core::ptr::addr_of!(REFCOUNTED_IMPLEMENTATION_DISPOSE),
                );
                let old_retain_count_dispose = core::ptr::read_volatile(
                    core::ptr::addr_of!(REFCOUNTED_RETAIN_COUNT_DISPOSE),
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(ROM_KERNEL),
                    RomKernelOps {
                        sema_wait: recording_wait,
                        sema_signal: recording_signal,
                        sema_delete: recording_delete,
                        heap_free: recording_mutex_cell_free,
                        ..old_kernel
                    },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(HEAP_OPS),
                    HeapVeneerOps {
                        free: recording_body_free,
                        ..old_heap
                    },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(REFCOUNTED_IMPLEMENTATION_DISPOSE),
                    recording_owned_variant_dispose,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(REFCOUNTED_RETAIN_COUNT_DISPOSE),
                    recording_retain_count_dispose,
                );
                Bench {
                    old_kernel,
                    old_heap,
                    old_owned_variant_dispose,
                    old_retain_count_dispose,
                }
            }
        }

        impl Drop for Bench {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROM_KERNEL), self.old_kernel);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.old_heap);
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!(REFCOUNTED_IMPLEMENTATION_DISPOSE),
                        self.old_owned_variant_dispose,
                    );
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!(REFCOUNTED_RETAIN_COUNT_DISPOSE),
                        self.old_retain_count_dispose,
                    );
                }
                OPS_LOCK.store(false, Ordering::Release);
            }
        }

        fn events() -> Vec<Event> {
            unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
        }

        /// A non-final reference is decremented and unlocked; neither the
        /// virtual destructor nor either heap delete runs, but the slot is
        /// always cleared.
        #[test]
        fn shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(events(), std::vec![Event::Wait(0x42), Event::Signal(0x42)]);
        }

        /// The final reference dispatches vtable[7], unlocks before semaphore
        /// teardown, releases the mutex before its body, and preserves the
        /// wrapper's destroy-and-return-this postcondition.
        #[test]
        fn final_reference_cleans_up_in_firmware_order_and_returns_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 8];
            vtable[7] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            let returned = unsafe { refcounted_ptr_release(slot_ptr) };

            assert_eq!(returned, slot_ptr, "destroy-and-return-this");
            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "lock/destructor/unlock/delete ordering follows the ARM body"
            );
        }

        /// The target's `subs` treats zero as an underflow, not a final
        /// release. It wraps and takes the shared-reference path.
        #[test]
        fn zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A NULL body is the early-out: the slot is not even written.
        #[test]
        fn owned_null_body_returns_without_touching_anything() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A non-final owned drop decrements under the mutex, unlocks,
        /// and NULLs the slot; the implementation is neither disposed
        /// nor freed.
        #[test]
        fn owned_shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut implementation = [0usize; 3];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(implementation[1], 0, "the StringObject member is untouched");
            assert_eq!(events(), std::vec![Event::Wait(0x42), Event::Signal(0x42)]);
        }

        /// The owned final drop runs the full 0x0827948c disposal chain —
        /// the callback interface's virtual slot 1, then the embedded
        /// StringObject destructor (observed through its planted vtable
        /// and its tag-0x34 payload free) — then tag-2-deletes the
        /// implementation, and only then unlocks and tears the mutex and
        /// body down in the sibling's order.
        #[test]
        fn owned_final_reference_disposes_deletes_and_cleans_up_in_order() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut callback_vtable = [0usize; 2];
            callback_vtable[1] = recording_callback_release as usize;
            let mut callback = [callback_vtable.as_mut_ptr() as usize];
            let mut payload = 0x5a_u8;
            let mut implementation: [usize; 3] = [
                callback.as_mut_ptr() as usize,
                0,
                &mut payload as *mut u8 as usize,
            ];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let callback_ptr = callback.as_mut_ptr() as *mut u8;
            let payload_ptr = &mut payload as *mut u8;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert!(body.mutex.is_null(), "the mutex field is cleared after its free");
            assert_eq!(
                implementation[1],
                &crate::cxx::string_object::STRING_OBJECT_VTABLE
                    as *const crate::cxx::string_object::StringObjectVtable
                    as usize,
                "the StringObject member ran the planted-vtable destructor"
            );
            assert_eq!(implementation[2], 0, "the payload release NULLs its word");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::CallbackRelease(callback_ptr as usize),
                    Event::HeapFree(payload_ptr as usize, 0x34),
                    Event::HeapFree(implementation_ptr as usize, 2),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "lock/dispose/delete/unlock/teardown ordering follows the ARM body"
            );
        }

        /// A NULL implementation word skips the disposal AND its tag-2
        /// delete; the unlock and the mutex/body teardown still run.
        #[test]
        fn owned_final_reference_with_null_implementation_skips_disposal() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert!(slot.is_null());
            assert!(body.mutex.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// A NULL callback word inside the implementation skips only the
        /// virtual slot-1 call; the StringObject member is still
        /// destroyed and the implementation still tag-2-deleted. A NULL
        /// mutex means no kernel interaction at all.
        #[test]
        fn owned_final_reference_with_null_callback_and_no_mutex() {
            let _bench = bench();
            let mut implementation: [usize; 3] = [0, 0, 0];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let body_ptr = &mut body as *mut RefcountedBody;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert!(slot.is_null());
            assert_eq!(
                implementation[1],
                &crate::cxx::string_object::STRING_OBJECT_VTABLE
                    as *const crate::cxx::string_object::StringObjectVtable
                    as usize,
                "the StringObject destructor runs even without a callback"
            );
            assert_eq!(
                events(),
                std::vec![
                    Event::HeapFree(implementation_ptr as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// The target's `subs` wraps: a zero refcount underflows to -1
        /// and takes the shared path — no disposal, no deletes.
        #[test]
        fn owned_zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut implementation = [0usize; 3];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_owned(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert_eq!(implementation[1], 0, "the implementation is untouched");
            assert!(events().is_empty());
        }

        /// The final transition calls the unported 0x0816f5c0 disposer,
        /// tag-2-deletes its returned implementation, then tears down the
        /// mutex and body in the raw ARM order.
        #[test]
        fn owned_variant_final_reference_disposes_then_cleans_up_in_order() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut implementation = 0x5a_u8;
            let mut body = RefcountedBody {
                opaque0: &mut implementation as *mut u8 as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let implementation_ptr = &mut implementation as *mut u8;
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_owned_variant(&mut slot) };

            assert!(slot.is_null());
            assert!(body.mutex.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::OwnedVariantDispose(implementation_ptr as usize),
                    Event::HeapFree(implementation_ptr as usize, 2),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// The target's plain `subs` underflows zero to -1, leaving the
        /// implementation and teardown paths untouched while still NULLing
        /// the caller slot.
        #[test]
        fn owned_variant_zero_refcount_wraps_without_disposal() {
            let _bench = bench();
            let mut implementation = 0x5a_u8;
            let mut body = RefcountedBody {
                opaque0: &mut implementation as *mut u8 as usize,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_owned_variant(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A final release calls 0x081f7328 with the implementation and the
        /// just-stored zero count, then unlocks and frees body resources in
        /// the same order as the ARM.
        #[test]
        fn retain_count_final_reference_calls_disposer_with_zero_then_cleans_up() {
            let _bench = bench();
            let mut semaphore = 0x54;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut implementation = 0x5a_u8;
            let mut body = RefcountedBody {
                opaque0: &mut implementation as *mut u8 as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let implementation_ptr = &mut implementation as *mut u8;
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_retain_count(&mut slot) };

            assert!(slot.is_null());
            assert!(body.mutex.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x54),
                    Event::RetainCountDispose(implementation_ptr as usize, 0),
                    Event::Signal(0x54),
                    Event::Delete(0x54),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// A zero refcount wraps to -1 and follows the non-final path, so
        /// neither the direct disposer nor the heap teardown is reached.
        #[test]
        fn retain_count_zero_refcount_wraps_without_disposal() {
            let _bench = bench();
            let mut implementation = 0x5a_u8;
            let mut body = RefcountedBody {
                opaque0: &mut implementation as *mut u8 as usize,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_retain_count(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A normal shared release decrements, unlocks, and clears the slot
        /// without reaching the direct disposer or either free.
        #[test]
        fn retain_count_shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x55;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0xdead_0000,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_retain_count(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null());
            assert_eq!(events(), std::vec![Event::Wait(0x55), Event::Signal(0x55)]);
        }

        /// NULL body is the original early-out: the slot is left untouched
        /// and none of the lock, direct-disposer, or heap paths run.
        #[test]
        fn retain_count_null_body_leaves_slot_untouched() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();

            unsafe { refcounted_body_release_retain_count(&mut slot) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A NULL body is the early-out for the slot-1 sibling too: the
        /// slot is not even written.
        #[test]
        fn dtor_null_body_returns_without_touching_anything() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A non-final slot-1 drop decrements under the mutex, unlocks,
        /// and NULLs the slot; the virtual destructor never runs.
        #[test]
        fn dtor_shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(events(), std::vec![Event::Wait(0x42), Event::Signal(0x42)]);
        }

        /// The final slot-1 drop runs the implementation's vtable word 1
        /// (and does NOT free the implementation block, unlike the owned
        /// sibling), then unlocks and tears the mutex and body down in
        /// the canonical sibling's order.
        #[test]
        fn dtor_final_reference_destructs_and_cleans_up_in_order() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert!(body.mutex.is_null(), "the mutex field is cleared after its free");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "no HeapFree of the implementation: slot 1 never frees it"
            );
        }

        /// A NULL implementation word skips the virtual dispatch; the
        /// unlock and the mutex/body teardown still run.
        #[test]
        fn dtor_final_reference_with_null_implementation_skips_destructor() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert!(slot.is_null());
            assert!(body.mutex.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// A NULL mutex means no kernel interaction at all: the final
        /// drop is just the virtual dispatch plus the body free.
        #[test]
        fn dtor_final_reference_with_no_mutex() {
            let _bench = bench();
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert!(slot.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Destructor(implementation_ptr as usize),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }

        /// The target's `subs` wraps: a zero refcount underflows to -1
        /// and takes the shared path — no destructor, no deletes.
        #[test]
        fn dtor_zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_dtor(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }
        /// The 0x0839d038 copy preserves the NULL-body early-out: it does
        /// not write the slot or touch the release machinery.
        #[test]
        fn slot1_copy_null_body_leaves_slot_untouched() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();

            unsafe { refcounted_body_release_slot1_copy(&mut slot) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A non-final release only decrements and NULLs its caller slot;
        /// with no mutex it performs no external operation.
        #[test]
        fn slot1_copy_shared_reference_decrements_and_nulls_slot() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0xdead_0000,
                refcount: 2,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_slot1_copy(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// The final release uses vtable word 1 under the mutex, never
        /// frees the implementation, and tears the mutex and body down in
        /// the raw ARM order.
        #[test]
        fn slot1_copy_final_reference_dispatches_and_tears_down_in_order() {
            let _bench = bench();
            let mut semaphore = 0x53;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_slot1_copy(&mut slot) };

            assert!(slot.is_null());
            assert!(mutex.sem_cell.is_null());
            assert!(body.mutex.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x53),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x53),
                    Event::Delete(0x53),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ]
            );
        }


        /// The 0x0839d3ac copy's NULL body early-out: the slot is not
        /// even written.
        #[test]
        fn dtor_variant_null_body_returns_without_touching_anything() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();

            unsafe { refcounted_body_release_dtor_variant(&mut slot) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// The 0x0839d3ac copy's non-final drop decrements under the
        /// mutex, unlocks, and NULLs the slot; the virtual destructor
        /// never runs.
        #[test]
        fn dtor_variant_shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_dtor_variant(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(events(), std::vec![Event::Wait(0x42), Event::Signal(0x42)]);
        }

        /// The 0x0839d3ac copy's final drop runs vtable word 1 (and does
        /// NOT free the implementation block), then unlocks and tears the
        /// mutex and body down in the sibling's order.
        #[test]
        fn dtor_variant_final_reference_destructs_and_cleans_up_in_order() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_dtor_variant(&mut slot) };

            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert!(body.mutex.is_null(), "the mutex field is cleared after its free");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "no HeapFree of the implementation: slot 1 never frees it"
            );
        }

        /// The 0x0839d3ac copy's `subs` wraps: a zero refcount underflows
        /// to -1 and takes the shared path — no destructor, no deletes.
        #[test]
        fn dtor_variant_zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_dtor_variant(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        // --- refcounted_ptr_copy_assign @ 0x0839f28c ----------------------

        /// The final-drop transfer: the old body is destructed (vtable
        /// word 1), unlocked, and torn down in the slot-1 sibling's
        /// order; only then is the new body attached and bumped. The
        /// attach adds no events — the new body is unguarded.
        #[test]
        fn copy_assign_final_drop_destructs_then_attaches() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 2];
            vtable[1] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut old = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let mut new = RefcountedBody {
                opaque0: 0x3333_4444,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let old_ptr = &mut old as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut dst = old_ptr;
            let src: *mut RefcountedBody = core::ptr::addr_of!(new).cast_mut();

            let ret = unsafe { refcounted_ptr_copy_assign(&mut dst, &src) };

            assert_eq!(ret, &mut dst as *mut *mut RefcountedBody);
            assert_eq!(dst, &mut new as *mut RefcountedBody);
            assert_eq!(new.refcount, 2);
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert!(old.mutex.is_null(), "the mutex field is cleared after its free");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(old_ptr as *mut u8 as usize, 2),
                ],
                "the full slot-1 teardown runs BEFORE the attach"
            );
        }

        /// The aliasing hazard, pinned: the guard compares slot pointers,
        /// not bodies. Two DISTINCT slots holding the same body with
        /// refcount 1 destroy the body in the release, then attach the
        /// dangling pointer and bump the FREED body's refcount back to
        /// 1. The recording heap free does not actually reclaim, so the
        /// host can observe the exact sequence the target executes.
        #[test]
        fn copy_assign_aliased_slots_destroy_then_reattach_the_freed_body() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mut dst = body_ptr;
            let mut src = body_ptr;

            let ret = unsafe { refcounted_ptr_copy_assign(&mut dst, &src) };

            assert_eq!(ret, &mut dst as *mut *mut RefcountedBody);
            assert_eq!(dst, body_ptr, "the freed body is re-attached");
            assert_eq!(src, body_ptr, "the source slot was never written");
            assert_eq!(
                body.refcount, 1,
                "release took it 1 -> 0 and freed it; attach bumped the freed word 0 -> 1"
            );
            assert_eq!(
                events(),
                std::vec![Event::HeapFree(body_ptr as *mut u8 as usize, 2)]
            );
        }

        // --- refcounted_body_release_slot1 @ 0x0839d1d4 ---------------------

        unsafe extern "C" fn recording_slot1(implementation: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Slot1Release(implementation as usize));
        }

        /// The final reference dispatches vtable[1] — not the sibling's
        /// vtable[7] — then unlocks, destroys the mutex, and deletes mutex
        /// and body in the ARM order. The implementation is never freed.
        #[test]
        fn slot1_final_reference_dispatches_vtable_slot1_and_tears_down_in_order() {
            let _bench = bench();
            let mut semaphore = 0x51;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 8];
            vtable[1] = recording_slot1 as usize;
            vtable[7] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_slot1(&mut slot) };

            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x51),
                    Event::Slot1Release(implementation_ptr as usize),
                    Event::Signal(0x51),
                    Event::Delete(0x51),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "vtable[1] runs under the lock; vtable[7] and any implementation free never do"
            );
        }

        /// A non-final reference decrements, unlocks, and clears the slot
        /// without dispatching anything or freeing anything.
        #[test]
        fn slot1_shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x52;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0xdead_0000,
                refcount: 3,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_slot1(&mut slot) };

            assert_eq!(body.refcount, 2);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(events(), std::vec![Event::Wait(0x52), Event::Signal(0x52)]);
        }

        /// With no implementation and no mutex, the final drop is just the
        /// tag-2 body delete: nothing is dispatched and no mutex call runs.
        #[test]
        fn slot1_final_reference_without_implementation_or_mutex_only_deletes_body() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 1,
                mutex: core::ptr::null_mut(),
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mut slot = body_ptr;

            unsafe { refcounted_body_release_slot1(&mut slot) };

            assert!(slot.is_null());
            assert_eq!(events(), std::vec![Event::HeapFree(body_ptr as *mut u8 as usize, 2)]);
        }

        /// The target's `subs` wraps zero to -1 and takes the shared path.
        #[test]
        fn slot1_zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release_slot1(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }

        /// A NULL body is the early-out: the slot is not even written.
        #[test]
        fn slot1_null_body_leaves_slot_untouched() {
            let _bench = bench();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            unsafe { refcounted_body_release_slot1(slot_ptr) };

            assert!(slot.is_null());
            assert!(events().is_empty());
        }
    }

    /// Direct tests of the constructor use recording heap/kernel hooks
    /// over the ported `operator_new` and `mutex_create` surfaces — the
    /// same bench pattern as `release`.
    mod construct {
        extern crate std;

        use super::super::*;
        use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
        use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
        use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::vec::Vec;

        static OPS_LOCK: AtomicBool = AtomicBool::new(false);
        static mut EVENTS: Vec<Event> = Vec::new();

        /// Writable stand-ins for the two tag-2 allocations (body, then
        /// mutex) and the 4-byte kernel semaphore cell. Oversized on
        /// purpose: the original's immediates (12/8/4) are the 32-bit
        /// target sizes; the host structs are wider.
        static mut ARENAS: [[usize; 8]; 3] = [[0; 8]; 3];
        static mut FAKE_HEAP_HANDLE: usize = 0;

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Event {
            Alloc(usize, usize),
            KernelAlloc(usize),
            SemaDefine(u32, usize),
        }

        /// Kernel semaphore handle the mock define writes into `*cell`.
        const KERNEL_SEM_HANDLE: u32 = 0x5e4a_0007;

        unsafe extern "C" fn recording_alloc(
            _heap: *mut HeapDescriptorDescriptor,
            size: usize,
            tag: usize,
        ) -> *mut u8 {
            let events = &mut *core::ptr::addr_of_mut!(EVENTS);
            let index = events
                .iter()
                .filter(|event| matches!(event, Event::Alloc(..)))
                .count();
            events.push(Event::Alloc(size, tag));
            assert!(index < 2, "the constructor allocates at most twice");
            (*core::ptr::addr_of_mut!(ARENAS))[index].as_mut_ptr().cast()
        }

        /// The lazy default-heap init runs through the swapped table too;
        /// hand back a fake handle so the real heap core stays untouched.
        unsafe extern "C" fn recording_create(
            _desc: *mut HeapDescriptor,
            _start: *mut u8,
            _size: usize,
        ) -> *mut HeapDescriptorDescriptor {
            core::ptr::addr_of_mut!(FAKE_HEAP_HANDLE).cast()
        }

        unsafe extern "C" fn recording_sema_define(initial_count: u32, cell: *mut u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::SemaDefine(initial_count, cell as usize));
            cell.write(KERNEL_SEM_HANDLE);
        }

        unsafe extern "C" fn recording_kernel_alloc(size: usize) -> *mut u8 {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::KernelAlloc(size));
            (*core::ptr::addr_of_mut!(ARENAS))[2].as_mut_ptr().cast()
        }

        unsafe extern "C" fn heap_is_past_early_boot() -> u32 {
            0
        }

        struct Bench {
            old_kernel: RomKernelOps,
            old_heap: HeapVeneerOps,
        }

        fn bench() -> Bench {
            while OPS_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                std::thread::yield_now();
            }
            unsafe {
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                (*core::ptr::addr_of_mut!(ARENAS)) = [[0; 8]; 3];
                let old_kernel = core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL));
                let old_heap = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(ROM_KERNEL),
                    RomKernelOps {
                        sema_define: recording_sema_define,
                        heap_early_flag: heap_is_past_early_boot,
                        heap_alloc: recording_kernel_alloc,
                        ..old_kernel
                    },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(HEAP_OPS),
                    HeapVeneerOps {
                        alloc: recording_alloc,
                        create: recording_create,
                        ..old_heap
                    },
                );
                Bench {
                    old_kernel,
                    old_heap,
                }
            }
        }

        impl Drop for Bench {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROM_KERNEL), self.old_kernel);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.old_heap);
                }
                OPS_LOCK.store(false, Ordering::Release);
            }
        }

        fn events() -> Vec<Event> {
            unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
        }

        /// NULL implementation: the slot is cleared and handed back with
        /// no allocation at all — even when `want_mutex` is nonzero.
        #[test]
        fn null_implementation_clears_slot_without_allocating() {
            let _bench = bench();
            let mut slot = 0xdead_beefusize as *mut RefcountedBody;
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            let returned = unsafe { refcounted_ptr_construct_tertiary_variant(slot_ptr, 0, 1) };

            assert_eq!(returned, slot_ptr, "construct-and-return-this");
            assert!(slot.is_null(), "the unconditional first store wins");
            assert!(events().is_empty());
        }

        /// `want_mutex == 0`: one tag-2 `operator_new(12)` whose block
        /// becomes `{ implementation, refcount = 1, mutex = NULL }`.
        #[test]
        fn construct_without_mutex_builds_unguarded_body() {
            let _bench = bench();
            let body_arena = unsafe { (*core::ptr::addr_of_mut!(ARENAS))[0].as_mut_ptr() as usize };
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            let returned = unsafe { refcounted_ptr_construct_tertiary_variant(slot_ptr, 0x1122_3344, 0) };

            assert_eq!(returned, slot_ptr);
            assert_eq!(slot as usize, body_arena);
            let body = unsafe { &*(body_arena as *const RefcountedBody) };
            assert_eq!(body.opaque0, 0x1122_3344);
            assert_eq!(body.refcount, 1);
            assert!(body.mutex.is_null());
            assert_eq!(events(), std::vec![Event::Alloc(12, 2)]);
        }

        /// `want_mutex != 0`: a second tag-2 `operator_new(8)` becomes the
        /// mutex, is installed at body+8, and is then initialized by
        /// `mutex_create` — observed as the ROM define filling the fresh
        /// 4-byte cell after both allocations.
        #[test]
        fn construct_with_mutex_installs_created_mutex() {
            let _bench = bench();
            let (body_arena, mutex_arena, cell_arena) = unsafe {
                let arenas = &mut *core::ptr::addr_of_mut!(ARENAS);
                (
                    arenas[0].as_mut_ptr() as usize,
                    arenas[1].as_mut_ptr() as usize,
                    arenas[2].as_mut_ptr() as usize,
                )
            };
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            let returned = unsafe { refcounted_ptr_construct_tertiary_variant(slot_ptr, 0xaabb_ccdd, 1) };

            assert_eq!(returned, slot_ptr);
            assert_eq!(slot as usize, body_arena);
            let body = unsafe { &*(body_arena as *const RefcountedBody) };
            assert_eq!(body.opaque0, 0xaabb_ccdd);
            assert_eq!(body.refcount, 1);
            assert_eq!(body.mutex as usize, mutex_arena);
            let mutex = unsafe { &*(mutex_arena as *const Mutex) };
            assert_eq!(mutex.sem_cell as usize, cell_arena);
            assert_eq!(unsafe { *(cell_arena as *const u32) }, KERNEL_SEM_HANDLE);
            assert_eq!(mutex.unused, 0);
            assert_eq!(
                events(),
                std::vec![
                    Event::Alloc(12, 2),
                    Event::Alloc(8, 2),
                    Event::KernelAlloc(4),
                    Event::SemaDefine(1, cell_arena),
                ],
                "both allocations precede the mutex cell create, in ARM order"
            );
        }
    }
}
