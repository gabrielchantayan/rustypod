//! `cxx_mutexattr_init` — original: `FUN_08261d1c` @ 0x08261d1c
//! (20 bytes, all code — no literal-pool word; the next function, the
//! pthread_mutexattr_destroy wrapper @ 0x08261d30, follows immediately;
//! 2 `bl` call sites, binary-scanned: 0x08261e34 in `cxx_mutex_construct`
//! (src/cxx/mutex.rs) and 0x082621bc in the twin constructor
//! `FUN_082621b0`).
//!
//! Source: `ipod-decomp/decomp/c/025/08261d1c_FUN_08261d1c.c`.
//!
//! A five-instruction C++-layer veneer over **pthread_mutexattr_init**
//! @ 0x082e84a4:
//!
//! ```text
//! stmdb sp!,{r4,lr}
//! mov r4,r0          ; r4 = attr
//! bl 0x082e84a4      ; pthread_mutexattr_init — status discarded
//! mov r0,r4          ; return the attr pointer, NOT the status
//! ldmia sp!,{r4,pc}
//! ```
//!
//! What the wrapped initializer plants (0x082e84a4..0x082e84d4, decoded
//! from the raw ARM): on a NULL attr it returns 0x1a with no stores;
//! otherwise it stores the attr magic 0x4d545841 ("MTXA"; its literal @
//! 0x082e84d8, binary-verified in osos.dec — the same word the destroy
//! and settype literals @ 0x082e84a0/0x082e852c hold) at attr+0x00, the
//! default halfword 0xffc2 at +0x04 (`mvn r1, #0x3d`), read-modify-
//! writes the halfword at +0x06 (`bic r1, r1, #0x3f` clears bits 0..5 —
//! which also resets the type field, bits 4..5, to NORMAL, the field
//! pthread_mutexattr_settype @ 0x082e84dc rewrites and the PosixMutex
//! layout records at mutex+0x0e — then `orr r1, r1, #0x8` sets bit 3,
//! the process-scope default; the mutex initializer @ 0x082e82f8 copies
//! the whole attr+0x04 word into mutex+0x0c), and returns 0.
//!
//! Deviations: pthread_mutexattr_init itself is unported, so the call
//! rides the [`CXX_MUTEXATTR_INIT_OPS`] dispatch slot (the
//! facade_registry_walk fixed-address pattern): on target the wired
//! default transmutes 0x082e84a4 (hook-ready); on host it is a
//! behavioral model of the decoded stores so tests can observe the
//! planted fields. The attr object is passed as `*mut usize`, matching
//! the two-word stack scope model of src/cxx/mutex.rs (byte-exact on
//! the 32-bit target).

/// Load address of the wrapped `pthread_mutexattr_init`; the wired
/// target default branches here (the facade_registry_walk
/// fixed-address pattern).
#[cfg(target_os = "none")]
const PTHREAD_MUTEXATTR_INIT_ADDRESS: usize = 0x082e84a4;

/// Status `pthread_mutexattr_init` @ 0x082e84a4 returns on success
/// (`mov r0, #0x0`).
pub const MUTEXATTR_INIT_OK: u32 = 0;

/// Status it returns for a NULL attribute (`mov r0, #0x1a`).
pub const MUTEXATTR_INIT_INVALID: u32 = 0x1a;

/// The attribute magic planted at attr+0x00 ("MTXA"; literal @
/// 0x082e84d8, binary-verified).
pub const MUTEXATTR_MAGIC: u32 = 0x4d54_5841;

/// The default halfword planted at attr+0x04 (`mvn r1, #0x3d`, stored
/// by `strh`).
pub const MUTEXATTR_DEFAULT_HALFWORD: u16 = 0xffc2;

/// The bits the initializer clears in the attr+0x06 halfword (`bic r1,
/// r1, #0x3f`): the low six, including the type field (bits 4..5 →
/// NORMAL).
pub const MUTEXATTR_SCOPE_CLEAR_MASK: u16 = 0x003f;

/// The process-scope bit the initializer then sets in the attr+0x06
/// halfword (`orr r1, r1, #0x8`).
pub const MUTEXATTR_PROCESS_SCOPE_BIT: u16 = 0x0008;

/// ABI of `pthread_mutexattr_init` @ 0x082e84a4: the attribute pointer
/// in r0, a status (0 or 0x1a) back in r0.
pub type PthreadMutexattrInit = unsafe extern "C" fn(attr: *mut usize) -> u32;

/// Host model of the wrapped initializer: the decoded stores of
/// 0x082e84a4..0x082e84d4. Not compiled on target, where the wired
/// default calls the firmware body.
#[cfg(not(target_os = "none"))]
unsafe fn host_model_pthread_mutexattr_init(attr: *mut usize) -> u32 {
    if attr.is_null() {
        return MUTEXATTR_INIT_INVALID;
    }
    let base = attr.cast::<u8>();
    base.cast::<u32>().write(MUTEXATTR_MAGIC);
    base.add(4).cast::<u16>().write(MUTEXATTR_DEFAULT_HALFWORD);
    let scope = base.add(6).cast::<u16>();
    scope.write((scope.read() & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT);
    MUTEXATTR_INIT_OK
}

/// Wired default for the unported `pthread_mutexattr_init` @
/// 0x082e84a4: the firmware body on target, the behavioral host model
/// elsewhere.
unsafe extern "C" fn default_pthread_mutexattr_init(attr: *mut usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        let init: PthreadMutexattrInit = core::mem::transmute(PTHREAD_MUTEXATTR_INIT_ADDRESS);
        init(attr)
    }

    #[cfg(not(target_os = "none"))]
    {
        host_model_pthread_mutexattr_init(attr)
    }
}

/// Indirect dispatch for the wrapped `pthread_mutexattr_init` (the
/// settings.rs `SETTINGS_CTOR` pattern). Host tests install a recording
/// mock; a later port of the callee replaces the default without
/// changing this caller.
#[derive(Clone, Copy)]
pub struct CxxMutexattrInitOps {
    /// Original 0x082e84a4: the initializer the veneer forwards to.
    pub pthread_mutexattr_init: PthreadMutexattrInit,
}

/// Wired default: the firmware body on target, the behavioral host
/// model elsewhere (see the module header).
pub const DEFAULT_CXX_MUTEXATTR_INIT_OPS: CxxMutexattrInitOps = CxxMutexattrInitOps {
    pthread_mutexattr_init: default_pthread_mutexattr_init,
};

/// The active callee. Host tests install a recording mock.
pub static mut CXX_MUTEXATTR_INIT_OPS: CxxMutexattrInitOps = DEFAULT_CXX_MUTEXATTR_INIT_OPS;

/// cxx_mutexattr_init — original: `FUN_08261d1c` @ 0x08261d1c
/// (20 bytes; 2 `bl` call sites, binary-scanned).
///
/// Forwards `attr` to the wrapped `pthread_mutexattr_init` @ 0x082e84a4
/// and returns `attr` itself (`mov r0, r4`) — the initializer's status
/// is discarded. No NULL guard of its own, matching the original: the
/// callee guards, and the veneer still returns the NULL pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutexattr_init(attr: *mut usize) -> *mut usize {
    core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_MUTEXATTR_INIT_OPS.pthread_mutexattr_init
    ))(attr);
    attr
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Serializes the dispatch slot and its recorder.
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    /// The attr pointer each mock call received, in order.
    static mut CALLS: Vec<usize> = Vec::new();

    /// Records the forwarded pointer and returns a nonzero status the
    /// wrapper must discard.
    unsafe extern "C" fn recording_attr_init(attr: *mut usize) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(attr as usize);
        MUTEXATTR_INIT_INVALID
    }

    /// Restores the wired default even when a test panics.
    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_MUTEXATTR_INIT_OPS)
                    .write_volatile(DEFAULT_CXX_MUTEXATTR_INIT_OPS);
            }
        }
    }

    fn bench(ops: CxxMutexattrInitOps) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(CXX_MUTEXATTR_INIT_OPS).write_volatile(ops);
        }
        OpsGuard { _lock: lock }
    }

    fn recording_bench() -> OpsGuard {
        bench(CxxMutexattrInitOps {
            pthread_mutexattr_init: recording_attr_init,
        })
    }

    fn default_bench() -> OpsGuard {
        bench(DEFAULT_CXX_MUTEXATTR_INIT_OPS)
    }

    fn calls() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// 8-byte-aligned backing for an attr object plus a guard word, so
    /// the host model's word/halfword stores stay aligned.
    #[repr(align(8))]
    struct AttrBytes([u8; 16]);

    /// Byte-level reference for the wrapped initializer's decoded
    /// stores (0x082e84a4..0x082e84d4): plant the magic and the default
    /// halfword, then read-modify-write the +0x06 halfword.
    fn reference_init(attr: &mut [u8; 8]) {
        attr[0..4].copy_from_slice(&MUTEXATTR_MAGIC.to_le_bytes());
        attr[4..6].copy_from_slice(&MUTEXATTR_DEFAULT_HALFWORD.to_le_bytes());
        let halfword = u16::from_le_bytes([attr[6], attr[7]]);
        attr[6..8].copy_from_slice(
            &((halfword & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT)
                .to_le_bytes(),
        );
    }

    #[test]
    fn forwards_the_pointer_and_returns_it_discarding_the_status() {
        let _bench = recording_bench();
        let mut scope = [0x1111_2222usize, 0x3333_4444];
        let attr = scope.as_mut_ptr();

        let returned = unsafe { cxx_mutexattr_init(attr) };

        assert_eq!(
            returned, attr,
            "the veneer returns its saved r0 (mov r0, r4), not the callee status"
        );
        assert_eq!(
            calls(),
            vec![attr as usize],
            "exactly one forwarded call with the same pointer"
        );
        assert_eq!(
            scope,
            [0x1111_2222usize, 0x3333_4444],
            "the veneer itself performs no stores"
        );
    }

    #[test]
    fn null_attr_is_forwarded_and_returned_unguarded() {
        let _bench = recording_bench();

        let returned = unsafe { cxx_mutexattr_init(core::ptr::null_mut()) };

        assert!(
            returned.is_null(),
            "no guard of its own: NULL comes straight back (mov r0, r4)"
        );
        assert_eq!(calls(), vec![0], "NULL is forwarded to the callee");
    }

    #[test]
    fn default_model_plants_the_decoded_fields() {
        let _bench = default_bench();
        for seed6 in [0x0000u16, 0xffff, 0x003f, 0xffc0, 0xaa95] {
            let mut buf = AttrBytes([0xa5; 16]);
            buf.0[6..8].copy_from_slice(&seed6.to_le_bytes());
            let mut expected = buf.0;
            reference_init((&mut expected[..8]).try_into().unwrap());
            let attr = buf.0.as_mut_ptr().cast::<usize>();

            let returned = unsafe { cxx_mutexattr_init(attr) };

            assert_eq!(returned, attr, "seed +6 = {seed6:#06x}");
            assert_eq!(
                buf.0, expected,
                "seed +6 = {seed6:#06x}: magic at +0, 0xffc2 at +4, bits 0..5 \
                 cleared and bit 3 set at +6, the guard word untouched"
            );
        }
    }

    #[test]
    fn host_model_reports_invalid_for_null_and_ok_otherwise() {
        assert_eq!(
            unsafe { host_model_pthread_mutexattr_init(core::ptr::null_mut()) },
            MUTEXATTR_INIT_INVALID,
            "cmp r0,#0x0 / moveq r0,#0x1a"
        );
        let mut scope = [0usize; 2];
        assert_eq!(
            unsafe { host_model_pthread_mutexattr_init(scope.as_mut_ptr()) },
            MUTEXATTR_INIT_OK,
            "mov r0,#0x0 on the store path"
        );
    }
}
