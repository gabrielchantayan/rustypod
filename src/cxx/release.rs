//! The NULL-guarded release forwarder into retailOS's C++ object model.
//!
//! - `release_via_field_0x48` — original: `FUN_0836761c` @ 0x0836761c
//!   (16 bytes; 51 `bl` call sites, binary-scanned). The whole body is
//!   four instructions:
//!
//!   ```text
//!   cmp   r0, #0        ; owner == NULL?
//!   ldrne r0, [r0, #0x48] ; child = owner->field_0x48
//!   bne   release_object  ; tail-call the refcount-drop teardown
//!   bx    lr              ; NULL owner: return (r0 already 0)
//!   ```
//!
//! Algorithm: a NULL owner is a no-op that returns NULL. Otherwise the
//! child pointer at +0x48 is loaded unconditionally (even a NULL child
//! is forwarded — the callee NULL-guards on its own) and ownership is
//! handed, tail-call style, to the refcount-drop teardown @ 0x0837ee98,
//! whose return value propagates. That teardown (200 bytes, unported)
//! drops the 16-bit refcount at child+0x22 and, at zero, runs C++
//! teardown through 0x082dd3d8 / 0x082d7fdc and a cascading release of
//! its own owner; every path returns 0, so this forwarder in fact
//! always returns NULL.
//!
//! Deviations:
//! - The teardown @ 0x0837ee98 is not ported (its chain is C++ and
//!   outside the cxx sweep), so the tail call goes through the
//!   [`CXX_RELEASE_OPS`] dispatch boundary. The default stub returns
//!   NULL — matching the real callee's return value — but performs no
//!   refcount drop: the child is leaked, exactly the
//!   `VDBE_P4_OPS`/`missing_free_p4` house rule for unported
//!   destructors. Host tests install a recording mock.
//! - The child field is addressed by WORD INDEX, not the literal target
//!   byte offset: on the 32-bit target `18 * WORD` reproduces +0x48
//!   exactly, while on a 64-bit host the pointer field stays
//!   pointer-sized (precedent: `heap/block_region.rs`,
//!   `sqlite/name_from_token.rs`).

/// Width of a pointer field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Word index of the released child pointer (byte offset +0x48 on the
/// 32-bit target; original: `ldrne r0, [r0, #0x48]`).
const CHILD_INDEX: usize = 0x48 / 4;

/// Indirect dispatch for the unported refcount-drop teardown
/// @ 0x0837ee98 (see the module header).
#[derive(Clone, Copy)]
pub struct CxxReleaseOps {
    /// The teardown the forwarder tail-calls: drop the object's 16-bit
    /// refcount at +0x22 and, at zero, run C++ teardown. Returns NULL.
    pub release_object: unsafe extern "C" fn(object: *mut u8) -> *mut u8,
}

/// Default stub: returns NULL like the real teardown but performs no
/// refcount drop — the object is leaked, not freed (see the module
/// header). Deliberately not a passthrough to a global free: the real
/// teardown walks a vtable-owned chain, and guessing wrong corrupts.
unsafe extern "C" fn missing_release_object(_object: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired default (documented leak until 0x0837ee98 is ported).
pub const DEFAULT_CXX_RELEASE_OPS: CxxReleaseOps = CxxReleaseOps {
    release_object: missing_release_object,
};

/// The active teardown. Host tests install recording mocks.
pub static mut CXX_RELEASE_OPS: CxxReleaseOps = DEFAULT_CXX_RELEASE_OPS;

/// Reads the release_object slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn release_op() -> unsafe extern "C" fn(*mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_RELEASE_OPS.release_object))
}

/// release_via_field_0x48 — original: `FUN_0836761c` @ 0x0836761c
/// (16 bytes; 51 `bl` call sites).
///
/// NULL-guarded release forwarder: a NULL `owner` returns NULL without
/// touching anything; otherwise the child pointer at owner+0x48 is
/// forwarded to the refcount-drop teardown and its (always NULL) return
/// value propagates.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_via_field_0x48(owner: *mut u8) -> *mut u8 {
    if owner.is_null() {
        return core::ptr::null_mut();
    }
    let child = (owner.add(CHILD_INDEX * WORD) as *const *mut u8).read();
    release_op()(child)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests — the ops table and the recorder are shared
    /// globals.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Objects handed to the recording teardown, in call order.
    static mut CALLS: Vec<usize> = Vec::new();

    /// Marker the recording teardown returns; the forwarder must
    /// propagate it verbatim (tail-call semantics).
    const MARKER: usize = 0x5a5a_5a5a;

    unsafe extern "C" fn recording_release(object: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CALLS)).push(object as usize);
        MARKER as *mut u8
    }

    /// Installs the recording teardown; restores the default ops on
    /// drop.
    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = OPS_LOCK.lock().unwrap();
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(CXX_RELEASE_OPS),
                CxxReleaseOps { release_object: recording_release },
            );
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(CXX_RELEASE_OPS),
                    DEFAULT_CXX_RELEASE_OPS,
                );
            }
        }
    }

    fn calls() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// An owner with the firmware layout: pointer words, the released
    /// child at word index 18 (byte offset +0x48 on target). Aligned so
    /// the pointer read is aligned, as it is on target.
    #[repr(align(8))]
    struct Owner {
        words: [*mut u8; CHILD_INDEX + 1],
    }

    impl Owner {
        fn new(child: *mut u8) -> Self {
            let mut owner = Owner {
                words: [core::ptr::null_mut(); CHILD_INDEX + 1],
            };
            owner.words[CHILD_INDEX] = child;
            owner
        }
        fn ptr(&mut self) -> *mut u8 {
            self.words.as_mut_ptr() as *mut u8
        }
    }

    #[test]
    fn null_owner_returns_null_without_releasing() {
        let _bench = bench();
        let result = unsafe { release_via_field_0x48(core::ptr::null_mut()) };
        assert!(result.is_null());
        assert!(calls().is_empty(), "the teardown must not be called");
    }

    #[test]
    fn non_null_owner_forwards_child_and_return_value() {
        let _bench = bench();
        let mut child_storage = [0u8; 8];
        let child = child_storage.as_mut_ptr();
        let mut owner = Owner::new(child);

        let result = unsafe { release_via_field_0x48(owner.ptr()) };
        assert_eq!(calls(), std::vec![child as usize]);
        assert_eq!(result as usize, MARKER, "the tail call's return propagates");
    }

    #[test]
    fn null_child_is_still_forwarded() {
        // The forwarder guards the owner only; a NULL child goes to the
        // callee, which NULL-guards on its own (`movs r5,r0 / bne`).
        let _bench = bench();
        let mut owner = Owner::new(core::ptr::null_mut());

        let result = unsafe { release_via_field_0x48(owner.ptr()) };
        assert_eq!(calls(), std::vec![0]);
        assert_eq!(result as usize, MARKER);
    }

    #[test]
    fn words_before_the_child_are_untouched_and_unread() {
        let _bench = bench();
        let mut child_storage = [0u8; 8];
        let child = child_storage.as_mut_ptr();
        let mut owner = Owner::new(child);
        // Poison the fields the function must not consult.
        for word in owner.words[..CHILD_INDEX].iter_mut() {
            *word = 0xdead_beef as *mut u8;
        }

        let result = unsafe { release_via_field_0x48(owner.ptr()) };
        assert_eq!(calls(), std::vec![child as usize]);
        assert_eq!(result as usize, MARKER);
        assert!(
            owner.words[..CHILD_INDEX].iter().all(|&w| w == 0xdead_beef as *mut u8),
            "only field 0x48 may be accessed"
        );
    }

    #[test]
    fn default_ops_release_is_a_null_returning_noop() {
        let _lock = OPS_LOCK.lock().unwrap();
        let mut child_storage = [0u8; 8];
        let child = child_storage.as_mut_ptr();
        let mut owner = Owner::new(child);

        let result = unsafe { release_via_field_0x48(owner.ptr()) };
        assert!(result.is_null(), "the stub returns NULL like the real teardown");
    }
}
