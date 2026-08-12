//! `cxx_mutex_construct` — original: `FUN_08261e28` @ 0x08261e28
//! (44 bytes, all code — no literal-pool word; the next function
//! starts at 0x08261e54; 52 `bl` call sites, binary-scanned).
//!
//! Source: `ipod-decomp/decomp/c/025/08261e28_FUN_08261e28.c`.
//!
//! The constructor of the C++ layer's mutex wrapper class: a 0x1c-byte
//! object embedding a `PosixMutex` (kernel/posix_mutex.rs, 24 bytes)
//! at +0x00 plus the initialization status word at +0x18. Decoded from
//! the raw ARM at 0x08261e28:
//!
//! ```text
//! push {r2, r3, r4, lr}  ; the pushed r2/r3 ARE the 8-byte stack scope
//! mov  r4, r0            ; r4 = this
//! mov  r0, sp
//! bl   0x08261d1c        ; scope attr init wrapper
//! mov  r1, sp
//! mov  r0, r4
//! bl   0x08261de8        ; settype-NORMAL + mutex init, status to +0x18
//! mov  r0, sp
//! bl   0x08261d30        ; scope attr destroy wrapper
//! mov  r0, r4            ; return this
//! pop  {r2, r3, r4, pc}
//! ```
//!
//! The constructor builds an 8-byte scoped mutex-attribute object on
//! its own stack frame — the `push {r2, r3}` is the allocation, so the
//! scope's two words START as the incoming r2/r3 (param_3/param_4)
//! register values; call sites pass no meaningful seeds, so this is the
//! ADS uninitialized-frame idiom — and runs init -> operation ->
//! teardown on it:
//!
//! - 0x08261d1c wraps **pthread_mutexattr_init** @ 0x082e84a4: plants
//!   the attr magic 0x4d545841 ("MTXA"; its literal @ 0x082e84d8,
//!   binary-verified — the same word the destroy and settype literals
//!   @ 0x082e84a0/0x082e852c hold, and the attribute twin of the mutex
//!   object's 0x4d545853 "MTXS" static-init magic) at scope+0x00, the
//!   default halfword 0xffc2 at +0x04, and read-modify-writes the
//!   halfword at +0x06 (clears bits 0..5, sets bit 3).
//! - 0x08261de8 wraps **pthread_mutexattr_settype** @ 0x082e84dc with
//!   kind 0 (NORMAL — bits 4..5 of the attr halfword at +0x06, the
//!   field the PosixMutex layout records at mutex+0x0e) and stores the
//!   status at this+0x18; only when the status is 0 does it call the
//!   mutex initializer @ 0x082e82f8 (the lazy initializer the ported
//!   `posix_mutex_lock` documents) with (this, &scope) and store ITS
//!   status at this+0x18 instead.
//! - 0x08261d30 wraps **pthread_mutexattr_destroy** @ 0x082e8474:
//!   checks the magic and clears scope+0x00.
//!
//! So despite the lock-guard SHAPE (scope init / work / scope teardown)
//! this is a constructor, not a guard: the scope is a mutexattr, and
//! the work is the embedded mutex's one-time initialization as a
//! NORMAL (non-recursive, non-error-checking) mutex with its status
//! recorded. Call sites pin the class: 0x08153348 constructs the
//! wrapper member at this+0x04 and the next member at
//! return+0x1c (the wrapper size), and the same object's lock/unlock
//! methods route the member through the posix_mutex_lock/unlock
//! veneers @ 0x08261e20/0x08261e24 (0x0815331c).
//!
//! Deviations: the attr destroy wrapper @ 0x08261d30 is unported, so
//! it rides the [`CXX_MUTEX_CONSTRUCT_OPS`] dispatch slot (the
//! settings.rs `SETTINGS_CTOR` pattern) with a no-op default — **not
//! hook-ready** until it is ported (with the default the scope attr is
//! never torn down; the mutex itself IS initialized by the wired
//! defaults). The attr init wrapper @ 0x08261d1c is ported
//! ([`super::mutex_attr_init`]) and wired as the `attr_init` default,
//! and the settype+init operation @ 0x08261de8 is ported
//! ([`super::mutex_settype_init`]) and wired as the `mutex_init`
//! default. The scope is
//! modeled as two pointer-sized words (the pfr_face_done face-word
//! model): byte-exact on the 32-bit target, disjoint slots on a 64-bit
//! host. `param_2` exists only to keep the register shape — the
//! original never reads r1.

/// Byte offset of the initialization status word inside the wrapper
/// (the mutex initializer's/strtype's return lands here; the wrapper
/// is 0x1c bytes total: 24-byte PosixMutex + this word).
pub const CXX_MUTEX_STATUS_OFFSET: usize = 0x18;

/// Wired default for the scope attr init wrapper @ 0x08261d1c: the
/// ported [`super::mutex_attr_init::cxx_mutexattr_init`]. Its returned
/// pointer is discarded here — the original call site's next
/// instruction overwrites r0, so this slot stays unit-returning.
unsafe extern "C" fn attr_init_port(scope: *mut usize) {
    super::mutex_attr_init::cxx_mutexattr_init(scope);
}

/// No-op default for the unported scope attr destroy wrapper @
/// 0x08261d30.
unsafe extern "C" fn attr_destroy_stub(_scope: *mut usize) {}

/// Indirect dispatch for the three scoped-attribute callees of
/// [`cxx_mutex_construct`] (the settings.rs `SETTINGS_CTOR` pattern).
/// Host tests install recording mocks; a later port of each callee
/// replaces its default without changing this caller.
#[derive(Clone, Copy)]
pub struct CxxMutexConstructOps {
    /// Original 0x08261d1c: the pthread_mutexattr_init wrapper over the
    /// two-word stack scope (ported in [`super::mutex_attr_init`]).
    pub attr_init: unsafe extern "C" fn(scope: *mut usize),
    /// Original 0x08261de8: mutexattr_settype(scope, NORMAL) then, on
    /// success, the mutex initializer @ 0x082e82f8 — either status
    /// stored at this+0x18.
    pub mutex_init: unsafe extern "C" fn(this: *mut u8, scope: *mut usize),
    /// Original 0x08261d30: the pthread_mutexattr_destroy wrapper over
    /// the scope.
    pub attr_destroy: unsafe extern "C" fn(scope: *mut usize),
}

/// Wired defaults: the ported attr-init wrapper and the ported
/// settype+init operation, plus one documented no-op (see the module
/// header).
pub const DEFAULT_CXX_MUTEX_CONSTRUCT_OPS: CxxMutexConstructOps = CxxMutexConstructOps {
    attr_init: attr_init_port,
    mutex_init: super::mutex_settype_init::cxx_mutex_settype_init,
    attr_destroy: attr_destroy_stub,
};

/// The active callee set. Host tests install recording mocks.
pub static mut CXX_MUTEX_CONSTRUCT_OPS: CxxMutexConstructOps =
    DEFAULT_CXX_MUTEX_CONSTRUCT_OPS;

/// cxx_mutex_construct — original: `FUN_08261e28` @ 0x08261e28
/// (44 bytes; 52 `bl` call sites, binary-scanned).
///
/// Constructs the mutex wrapper at `this`: seeds the two-word stack
/// scope with `scope_word0`/`scope_word1` (the original's `push {r2,
/// r3}` — the incoming register values, not a deliberate initializer),
/// then runs attr init, the settype-NORMAL-plus-init operation, and
/// attr teardown on it in that order, and returns `this` unchanged.
/// No NULL guard on `this`, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_construct(
    this: *mut u8,
    _param_2: usize,
    scope_word0: usize,
    scope_word1: usize,
) -> *mut u8 {
    let mut scope = [scope_word0, scope_word1];
    let scope_ptr = scope.as_mut_ptr();
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_MUTEX_CONSTRUCT_OPS.attr_init))(scope_ptr);
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_MUTEX_CONSTRUCT_OPS.mutex_init))(
        this, scope_ptr,
    );
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_MUTEX_CONSTRUCT_OPS.attr_destroy))(scope_ptr);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the dispatch slots and their recorders.
    static CXX_MUTEX_OPS_LOCK: Mutex<()> = Mutex::new(());
    /// The callee sequence observed by the recording mocks:
    /// ("attr_init"/"mutex_init"/"attr_destroy", this-or-zero,
    /// scope-first-word, scope-second-word).
    static mut CALLS: Vec<(&'static str, usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_attr_init(scope: *mut usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push(("attr_init", 0, scope.read(), scope.add(1).read()));
        // Model the real attr init's read-modify-write so the mutex_init
        // recorder can prove the SAME mutable scope object flows on.
        scope.write(0x4d545841);
    }

    unsafe extern "C" fn recording_mutex_init(this: *mut u8, scope: *mut usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push((
            "mutex_init",
            this as usize,
            scope.read(),
            scope.add(1).read(),
        ));
    }

    unsafe extern "C" fn recording_attr_destroy(scope: *mut usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push(("attr_destroy", 0, scope.read(), scope.add(1).read()));
    }

    /// Restores the stub boundary even when a test panics.
    struct CxxMutexOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CxxMutexOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_MUTEX_CONSTRUCT_OPS)
                    .write_volatile(DEFAULT_CXX_MUTEX_CONSTRUCT_OPS);
            }
        }
    }

    fn cxx_mutex_bench() -> CxxMutexOpsGuard {
        let lock = CXX_MUTEX_OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(CXX_MUTEX_CONSTRUCT_OPS).write_volatile(CxxMutexConstructOps {
                attr_init: recording_attr_init,
                mutex_init: recording_mutex_init,
                attr_destroy: recording_attr_destroy,
            });
        }
        CxxMutexOpsGuard { _lock: lock }
    }

    fn calls() -> Vec<(&'static str, usize, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[test]
    fn construct_runs_init_op_teardown_in_order_and_returns_this() {
        let mut wrapper = [0xa5u8; 0x1c];
        let this = wrapper.as_mut_ptr();
        let _bench = cxx_mutex_bench();

        let returned = unsafe { cxx_mutex_construct(this, 0xdead_beef, 0x1111_2222, 0x3333_4444) };

        assert_eq!(returned, this, "the constructor returns this (mov r0, r4)");
        let observed = calls();
        assert_eq!(
            observed.len(),
            3,
            "exactly attr_init, mutex_init, attr_destroy"
        );
        assert_eq!(observed[0].0, "attr_init");
        assert_eq!(observed[1].0, "mutex_init");
        assert_eq!(observed[2].0, "attr_destroy");
        assert_eq!(observed[1].1, this as usize, "the op receives this");
        assert_eq!(
            wrapper,
            [0xa5u8; 0x1c],
            "the constructor itself never writes the wrapper (the callees own it)"
        );
    }

    #[test]
    fn the_scope_words_are_the_incoming_registers_and_stay_mutable_across_calls() {
        let mut wrapper = [0u8; 0x1c];
        let this = wrapper.as_mut_ptr();
        let _bench = cxx_mutex_bench();

        unsafe { cxx_mutex_construct(this, 0, 0x0bad_cafe, 0xc001_d00d) };

        let observed = calls();
        // attr_init sees the raw param_3/param_4 seeds (the push {r2,r3}),
        // then plants its magic — and mutex_init/attr_destroy observe the
        // SAME scope object, including the attr_init mutation.
        assert_eq!(
            observed[0],
            ("attr_init", 0, 0x0bad_cafe, 0xc001_d00d),
            "the pushed r2/r3 are the scope's initial contents"
        );
        assert_eq!(
            observed[1].2, 0x4d545841,
            "mutex_init sees the attr magic the init wrote into the shared scope"
        );
        assert_eq!(observed[1].3, 0xc001_d00d, "the unwritten word survives");
        assert_eq!(observed[2].2, 0x4d545841);
    }

    #[test]
    fn wired_defaults_initialize_the_wrapper_on_host() {
        // No bench: the attr_init default is the ported veneer and the
        // mutex_init default is the ported cxx_mutex_settype_init
        // (whose callees default to the host models); only
        // attr_destroy is still a no-op stub. The constructor
        // therefore initializes the embedded mutex and records the
        // status, end to end.
        #[repr(align(8))]
        struct Wrapper([u8; 0x1c]);
        let mut wrapper = Wrapper([0x5au8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();

        let returned = unsafe { cxx_mutex_construct(this, 1, 2, 3) };

        assert_eq!(returned, this);
        let word = |offset: usize| {
            u32::from_le_bytes(wrapper.0[offset..offset + 4].try_into().unwrap())
        };
        assert_eq!(
            word(0x00),
            super::super::mutex_settype_init::MUTEX_LIVE_MAGIC,
            "the wired defaults ran the modeled initializer"
        );
        assert_eq!(word(0x04), 0, "owner zeroed");
        assert_eq!(word(0x08), 0, "reserved word zeroed");
        assert_eq!(
            word(0x0c),
            0x0008_ffc2,
            "the attr+0x04 word copied to mutex+0x0c: default halfword 0xffc2, \
             scope halfword with bits 0..5 cleared, bit 3 set, type NORMAL"
        );
        assert_eq!(
            word(0x14),
            super::super::mutex_settype_init::HOST_MODEL_SEM_HANDLE,
            "the (modeled) semaphore handle"
        );
        assert_eq!(word(0x18), 0, "settype 0 overwritten by init 0");
        assert_eq!(
            &wrapper.0[0x10..0x12],
            &[0x5au8; 2],
            "the +0x10 halfword is nobody's business"
        );
    }
}
