//! `cxx_recursive_mutex_construct` — original: `FUN_082621b0` @ 0x082621b0
//! (44 bytes, all code — no literal pool; the next function starts at
//! 0x082621dc; 14 unconditional `bl` call sites, binary-scanned; no
//! predicated calls).
//!
//! Source: `ipod-decomp/decomp/c/025/082621b0_FUN_082621b0.c`.
//!
//! This C++ recursive-mutex-wrapper constructor creates an 8-byte
//! `pthread_mutexattr` scope in its frame from incoming r2/r3, invokes the
//! ported attr initializer, initializes `this` as a recursive mutex through
//! 0x08262170, destroys the scope, and returns `this`. The scoped attr is
//! transient: only the initialized mutex at `this` is observable afterward.
//!
//! Raw ARM @ 0x082621b0:
//!
//! ```text
//! push {r2,r3,r4,lr}    ; r2/r3 are the two-word attr scope
//! mov  r4,r0            ; r4 = this
//! mov  r0,sp
//! bl   0x08261d1c       ; cxx_mutexattr_init(scope)
//! mov  r1,sp
//! mov  r0,r4
//! bl   0x08262170       ; set type RECURSIVE, then initialize mutex
//! mov  r0,sp
//! bl   0x08261d30       ; cxx_mutexattr_destroy(scope)
//! mov  r0,r4
//! pop  {r2,r3,r4,pc}
//! ```
//!
//! Deliberate deviations: the two direct callees not yet ported,
//! 0x08262170 and 0x08261d30, cross volatile dispatch slots. Their wired
//! target defaults call the retailOS entries directly. Host defaults model
//! their decoded observable stores: kind 2 in the attr's type field, mutex
//! initialization, and clearing a valid attr magic respectively. This makes
//! host tests deterministic while leaving a target hook faithful.

use super::mutex_attr_init::cxx_mutexattr_init;
#[cfg(not(target_os = "none"))]
use super::mutex::CXX_MUTEX_STATUS_OFFSET;
#[cfg(not(target_os = "none"))]
use super::mutex_attr_init::MUTEXATTR_MAGIC;
#[cfg(not(target_os = "none"))]
use super::mutex_settype_init::{
    HOST_MODEL_SEM_HANDLE, MUTEXATTR_TYPE_MASK, MUTEX_INIT_INVALID, MUTEX_LIVE_MAGIC,
    MUTEX_SETTYPE_INVALID,
};

/// Load address of the unported recursive settype-and-init helper.
#[cfg(target_os = "none")]
const RECURSIVE_MUTEX_INIT_ADDRESS: usize = 0x08262170;
/// Load address of the unported C++ mutexattr-destroy wrapper.
#[cfg(target_os = "none")]
const CXX_MUTEXATTR_DESTROY_ADDRESS: usize = 0x08261d30;

/// `pthread_mutexattr_settype` kind 2: recursive ownership is permitted.
pub const MUTEX_KIND_RECURSIVE: u32 = 2;

/// ABI of the direct helper @ 0x08262170. Its r0 status is ignored by this
/// constructor, so the port declares its observable interface as unit.
pub type RecursiveMutexInit = unsafe extern "C" fn(this: *mut u8, attr: *mut usize);

/// ABI of the direct C++ wrapper @ 0x08261d30. It returns its attr argument,
/// which this constructor overwrites before returning `this`.
pub type CxxMutexattrDestroy = unsafe extern "C" fn(attr: *mut usize);

/// Host model of 0x08262170. The retailOS helper records the settype status at
/// `this`+0x18, calls the mutex initializer only on success, then records that
/// initializer status in the same word.
#[cfg(not(target_os = "none"))]
unsafe fn host_model_recursive_mutex_init(this: *mut u8, attr: *mut usize) {
    let status = if attr.is_null() || attr.cast::<u32>().read() != MUTEXATTR_MAGIC {
        MUTEX_SETTYPE_INVALID
    } else {
        let type_halfword = attr.cast::<u8>().add(6).cast::<u16>();
        type_halfword.write(
            (type_halfword.read() & !MUTEXATTR_TYPE_MASK)
                | ((MUTEX_KIND_RECURSIVE as u16) << 4 & MUTEXATTR_TYPE_MASK),
        );
        0
    };
    this.add(CXX_MUTEX_STATUS_OFFSET).cast::<u32>().write(status);
    if status != 0 {
        return;
    }
    if attr.cast::<u32>().read() != MUTEXATTR_MAGIC {
        this.add(CXX_MUTEX_STATUS_OFFSET)
            .cast::<u32>()
            .write(MUTEX_INIT_INVALID);
        return;
    }
    this.add(0x14).cast::<u32>().write(HOST_MODEL_SEM_HANDLE);
    let attr_word = attr.cast::<u8>().add(4).cast::<u32>().read();
    this.add(0x0c).cast::<u32>().write(attr_word);
    this.add(0x04).cast::<u32>().write(0);
    this.add(0x08).cast::<u32>().write(0);
    this.add(0x12).cast::<u16>().write(0);
    this.cast::<u32>().write(MUTEX_LIVE_MAGIC);
    this.add(CXX_MUTEX_STATUS_OFFSET).cast::<u32>().write(0);
}

/// Host model of 0x08261d30's wrapped pthread_mutexattr_destroy: invalid
/// attrs are unchanged; valid ones have only their magic cleared.
#[cfg(not(target_os = "none"))]
unsafe fn host_model_cxx_mutexattr_destroy(attr: *mut usize) {
    if !attr.is_null() && attr.cast::<u32>().read() == MUTEXATTR_MAGIC {
        attr.cast::<u32>().write(0);
    }
}

/// Target firmware direct calls; host behavioral models above.
unsafe extern "C" fn default_recursive_mutex_init(this: *mut u8, attr: *mut usize) {
    #[cfg(target_os = "none")]
    {
        let init: RecursiveMutexInit = core::mem::transmute(RECURSIVE_MUTEX_INIT_ADDRESS);
        init(this, attr);
    }

    #[cfg(not(target_os = "none"))]
    {
        host_model_recursive_mutex_init(this, attr);
    }
}

/// Target firmware direct call; host behavioral model above.
unsafe extern "C" fn default_cxx_mutexattr_destroy(attr: *mut usize) {
    #[cfg(target_os = "none")]
    {
        let destroy: CxxMutexattrDestroy = core::mem::transmute(CXX_MUTEXATTR_DESTROY_ADDRESS);
        destroy(attr);
    }

    #[cfg(not(target_os = "none"))]
    {
        host_model_cxx_mutexattr_destroy(attr);
    }
}

/// Indirect direct-callee boundary of [`cxx_recursive_mutex_construct`].
/// Host tests install recording mocks; later ports can replace each default.
#[derive(Clone, Copy)]
pub struct CxxRecursiveMutexConstructOps {
    /// Original 0x08262170: sets attr type RECURSIVE, then initializes `this`.
    pub recursive_mutex_init: RecursiveMutexInit,
    /// Original 0x08261d30: tears down the scoped attr after initialization.
    pub attr_destroy: CxxMutexattrDestroy,
}

/// Wired defaults preserve the retailOS direct calls on target and model them
/// on host.
pub const DEFAULT_CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS: CxxRecursiveMutexConstructOps =
    CxxRecursiveMutexConstructOps {
        recursive_mutex_init: default_recursive_mutex_init,
        attr_destroy: default_cxx_mutexattr_destroy,
    };

/// Active direct-callee set. Host tests replace it with recording mocks.
pub static mut CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS: CxxRecursiveMutexConstructOps =
    DEFAULT_CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS;

/// `cxx_recursive_mutex_construct` — original: `FUN_082621b0` @ 0x082621b0
/// (44 bytes; 14 unconditional `bl` call sites, binary-scanned; no predicated
/// calls).
///
/// Seeds its two-word stack scope from `scope_word0` and `scope_word1` (the
/// original pushed r2/r3), runs attr initialization, recursive mutex
/// initialization, and attr teardown in that order, then returns `this`.
/// `param_2` is unread, and there is no NULL guard on `this`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_recursive_mutex_construct(
    this: *mut u8,
    _param_2: usize,
    scope_word0: usize,
    scope_word1: usize,
) -> *mut u8 {
    let mut scope = [scope_word0, scope_word1];
    let attr = scope.as_mut_ptr();
    cxx_mutexattr_init(attr);
    core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS.recursive_mutex_init
    ))(this, attr);
    core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS.attr_destroy
    ))(attr);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(&'static str, usize, u32)> = Vec::new();

    unsafe extern "C" fn recording_recursive_init(this: *mut u8, attr: *mut usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push((
            "recursive_init",
            this as usize,
            attr.cast::<u32>().read(),
        ));
        attr.cast::<u32>().write(0xaabb_ccdd);
    }

    unsafe extern "C" fn recording_attr_destroy(attr: *mut usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push(("destroy", 0, attr.cast::<u32>().read()));
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS)
                    .write_volatile(DEFAULT_CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS);
            }
        }
    }

    fn recording_bench() -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(CXX_RECURSIVE_MUTEX_CONSTRUCT_OPS).write_volatile(
                CxxRecursiveMutexConstructOps {
                    recursive_mutex_init: recording_recursive_init,
                    attr_destroy: recording_attr_destroy,
                },
            );
        }
        OpsGuard { _lock: lock }
    }

    fn calls() -> Vec<(&'static str, usize, u32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[test]
    fn initializes_then_tears_down_the_same_attr_and_returns_this() {
        let _bench = recording_bench();
        let mut wrapper = [0xa5u8; 0x1c];
        let this = wrapper.as_mut_ptr();

        let returned = unsafe {
            cxx_recursive_mutex_construct(this, 0xdead_beef, 0x1111_2222, 0x3333_4444)
        };

        assert_eq!(returned, this, "the constructor returns saved r0 (mov r0,r4)");
        assert_eq!(
            calls(),
            vec![
                ("recursive_init", this as usize, MUTEXATTR_MAGIC),
                ("destroy", 0, 0xaabb_ccdd),
            ],
            "attr init precedes recursive init; teardown sees that same mutable scope"
        );
        assert_eq!(wrapper, [0xa5; 0x1c], "the outer constructor writes only its scope");
    }

    #[test]
    fn host_default_builds_a_recursive_mutex_and_preserves_unowned_bytes() {
        #[repr(align(8))]
        struct Wrapper([u8; 0x1c]);

        let mut wrapper = Wrapper([0x5au8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();
        let returned = unsafe { cxx_recursive_mutex_construct(this, 7, 0, 0) };
        let word = |offset: usize| u32::from_le_bytes(wrapper.0[offset..offset + 4].try_into().unwrap());

        assert_eq!(returned, this);
        assert_eq!(word(0x00), MUTEX_LIVE_MAGIC);
        assert_eq!(word(0x04), 0, "owner is cleared");
        assert_eq!(word(0x08), 0, "reserved word is cleared");
        assert_eq!(word(0x0c), 0x0028_ffc2, "attr type is kind 2 (recursive)");
        assert_eq!(word(0x14), HOST_MODEL_SEM_HANDLE);
        assert_eq!(word(CXX_MUTEX_STATUS_OFFSET), 0, "initializer success replaces settype success");
        assert_eq!(&wrapper.0[0x10..0x12], &[0x5a; 2], "the helper does not own +0x10");
    }
}
