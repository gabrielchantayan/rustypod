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
//! Also here: [`refcounted_ptr_assign`], the mutex-guarded shared-body
//! assign that backs the C++ layer's refcounted handles (it sits outside
//! the 0x083c0000-0x083dffff block, at 0x0839eda0, so it is not one of
//! the byte-identical families above).

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

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

/// Shared body of the C++ layer's refcounted handles — the object a
/// `*mut RefcountedBody` slot points at. [`refcounted_ptr_assign`]
/// touches only the two trailing fields; the leading word is
/// owner-defined (a vtable or first datum) and opaque to the assign.
#[repr(C)]
pub struct RefcountedBody {
    /// +0: owner-defined word; never read or written by the assign.
    pub opaque0: u32,
    /// +4: intrusive reference count, bumped under the mutex.
    pub refcount: i32,
    /// +8: optional mutex guarding the refcount (NULL = unguarded).
    pub mutex: *mut Mutex,
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
}
