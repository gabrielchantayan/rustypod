//! `cxx_mutex_settype_init` — original: `FUN_08261de8` @ 0x08261de8
//! (56 bytes, all code — no literal-pool word; the posix_mutex_lock/
//! unlock veneers @ 0x08261e20/0x08261e24 follow immediately; 1 `bl`
//! call site, binary-scanned: 0x08261e40 in `cxx_mutex_construct`
//! (src/cxx/mutex.rs) — the twin constructor `FUN_082621b0` inlines
//! the same settype/init pair itself at 0x08262184/0x0826219c instead
//! of calling this veneer).
//!
//! Source: `ipod-decomp/decomp/c/025/08261de8_FUN_08261de8.c`.
//!
//! The middle operation of the C++ mutex wrapper's scoped-attribute
//! construction (see src/cxx/mutex.rs): set the attribute's type to
//! NORMAL and initialize the wrapper's embedded `PosixMutex`
//! (src/kernel/posix_mutex.rs) from it, recording either status in the
//! wrapper's status word at this+0x18:
//!
//! ```text
//! stmdb sp!,{r4,r5,r6,lr}
//! mov r5,r1            ; r5 = attr (the two-word stack scope)
//! mov r4,r0            ; r4 = this
//! mov r0,r5
//! mov r1,#0x0          ; kind 0 = NORMAL
//! bl 0x082e84dc        ; pthread_mutexattr_settype(attr, NORMAL)
//! cmp r0,#0x0
//! str r0,[r4,#0x18]    ; settype status -> this+0x18
//! ldmiane sp!,{r4,r5,r6,pc}   ; nonzero: bail with it recorded
//! mov r1,r5
//! mov r0,r4
//! bl 0x082e82f8        ; the mutex initializer (this, attr)
//! str r0,[r4,#0x18]    ; ITS status replaces the recorded 0
//! ldmia sp!,{r4,r5,r6,pc}
//! ```
//!
//! What the wrapped callees do (both decoded from the raw ARM, both
//! still unported):
//!
//! - **pthread_mutexattr_settype** @ 0x082e84dc (80 bytes): a NULL
//!   attr, a bad magic at attr+0x00 (its literal @ 0x082e852c holds
//!   0x4d545841 "MTXA", binary-verified in osos.dec — the word
//!   pthread_mutexattr_init @ 0x082e84a4 plants), or a kind outside
//!   {0, 1, 2} (`cmp`/`cmpne`/`cmpne` chain) all return 0x1a with no
//!   stores; otherwise it rewrites bits 4..5 of the halfword at
//!   attr+0x06 with `0x30 & (kind << 4)` (`ldrh` / `and` /
//!   `bic #0x30` / `orr` / `strh`) and returns 0. Kind 0 (NORMAL)
//!   therefore CLEARS those bits — the field the PosixMutex layout
//!   records at mutex+0x0e.
//! - **the mutex initializer** @ 0x082e82f8 (140 bytes — the lazy
//!   initializer src/kernel/posix_mutex.rs documents): a NULL mutex,
//!   or an attr whose +0x00 word is not the MTXA magic (literal @
//!   0x082e8384, binary-verified), returns 0x1a; a NULL attr selects
//!   the process-wide default attr object @ 0x089cfcbc (literal @
//!   0x082e8388), which is lazily run through pthread_mutexattr_init
//!   first (its bytes in the static image are "act\0", not the magic).
//!   It then allocates the inline semaphore via the kernel-object
//!   allocator @ 0x0808b1c0 (object type 3 — the handle lands at
//!   mutex+0x14 and an allocation failure returns 0x27), and plants
//!   the object: the whole attr+0x04 word is copied to mutex+0x0c (so
//!   the type halfword lands at +0x0e), mutex+0x04 and mutex+0x08 are
//!   zeroed, the halfword at mutex+0x12 is zeroed, and the live-object
//!   magic 0x4d555458 "MUTX" (literal @ 0x082e838c, binary-verified —
//!   distinct from the 0x4d545853 "MTXS" static-init magic the
//!   lock/unlock pair @ 0x082e8390/0x082e83d8 match for lazy init,
//!   literals @ 0x082e83d4/0x082e8470) is stored at mutex+0x00;
//!   returns 0.
//!
//! The status word at this+0x18 is written BEFORE the branch on it —
//! `cmp` sets the flags and `str` does not clobber them — so a failing
//! settype still leaves its status recorded and the initializer never
//! runs, while on success the initializer's status (0 included)
//! OVERWRITES the recorded 0.
//!
//! Deviations: both callees ride the [`CXX_MUTEX_SETTYPE_INIT_OPS`]
//! dispatch slots (the facade_registry_walk fixed-address pattern): on
//! target the wired defaults transmute 0x082e84dc / 0x082e82f8
//! (hook-ready); on host they are behavioral models of the decoded
//! bodies so tests can observe the planted fields — with one
//! simplification: the kernel-object allocator @ 0x0808b1c0 is
//! mask-ROM machinery, so the init model plants a fixed nonzero
//! sentinel handle at mutex+0x14 instead of allocating. The attr is
//! passed as `*mut usize`, matching the two-word stack scope model of
//! src/cxx/mutex.rs (byte-exact on the 32-bit target). The port is
//! wired as src/cxx/mutex.rs's `CXX_MUTEX_CONSTRUCT_OPS.mutex_init`
//! default (that module's documented "a later port replaces its
//! default" pattern).

use super::mutex_attr_init::{
    MUTEXATTR_DEFAULT_HALFWORD, MUTEXATTR_MAGIC, MUTEXATTR_PROCESS_SCOPE_BIT,
    MUTEXATTR_SCOPE_CLEAR_MASK,
};

/// Load address of the wrapped `pthread_mutexattr_settype`; the wired
/// target default branches here (the facade_registry_walk
/// fixed-address pattern).
#[cfg(target_os = "none")]
const PTHREAD_MUTEXATTR_SETTYPE_ADDRESS: usize = 0x082e84dc;

/// Load address of the wrapped mutex initializer; the wired target
/// default branches here.
#[cfg(target_os = "none")]
const POSIX_MUTEX_INIT_ADDRESS: usize = 0x082e82f8;

/// The `kind` argument the veneer always passes (`mov r1, #0x0`):
/// NORMAL — non-recursive, non-error-checking; clearing bits 4..5 of
/// the attr+0x06 halfword.
pub const MUTEX_KIND_NORMAL: u32 = 0;

/// The largest `kind` pthread_mutexattr_settype @ 0x082e84dc accepts
/// (`cmp`/`cmpne`/`cmpne` against 0, 1, 2).
pub const MUTEX_KIND_MAX: u32 = 2;

/// Status pthread_mutexattr_settype @ 0x082e84dc returns for a NULL
/// attr, a bad magic, or a kind outside {0, 1, 2} (`mov r0, #0x1a`).
pub const MUTEX_SETTYPE_INVALID: u32 = 0x1a;

/// Status the mutex initializer @ 0x082e82f8 returns for a NULL mutex
/// or an attr without the MTXA magic (`mov r0, #0x1a`).
pub const MUTEX_INIT_INVALID: u32 = 0x1a;

/// Status the mutex initializer @ 0x082e82f8 returns when the
/// kernel-object allocator @ 0x0808b1c0 fails (`movne r0, #0x27`).
pub const MUTEX_INIT_ALLOC_FAILED: u32 = 0x27;

/// The bits of the attr+0x06 halfword pthread_mutexattr_settype
/// rewrites: bits 4..5, the type field (`mov r3, #0x30`; the PosixMutex
/// layout records the same field at mutex+0x0e).
pub const MUTEXATTR_TYPE_MASK: u16 = 0x0030;

/// The live-object magic the mutex initializer @ 0x082e82f8 plants at
/// mutex+0x00 ("MUTX"; literal @ 0x082e838c, binary-verified — an
/// object carrying it is initialized, unlike the 0x4d545853 "MTXS"
/// static-init magic src/kernel/posix_mutex.rs's `STATIC_INIT_MAGIC`
/// documents).
pub const MUTEX_LIVE_MAGIC: u32 = 0x4d55_5458;

/// The nonzero semaphore handle the host init model plants at
/// mutex+0x14 in place of the kernel-object allocator @ 0x0808b1c0
/// (mask-ROM machinery; see the module header).
#[cfg(not(target_os = "none"))]
pub const HOST_MODEL_SEM_HANDLE: u32 = 1;

/// ABI of `pthread_mutexattr_settype` @ 0x082e84dc: the attr pointer
/// in r0, the kind in r1, a status (0 or 0x1a) back in r0.
pub type PthreadMutexattrSettype = unsafe extern "C" fn(attr: *mut usize, kind: u32) -> u32;

/// ABI of the mutex initializer @ 0x082e82f8: the mutex pointer in r0,
/// the attr pointer (nullable — selects the process-wide default) in
/// r1, a status (0, 0x1a or 0x27) back in r0.
pub type PosixMutexInit = unsafe extern "C" fn(mutex: *mut u8, attr: *mut usize) -> u32;

/// Host model of the wrapped settype: the decoded body of
/// 0x082e84dc..0x082e8528. Not compiled on target, where the wired
/// default calls the firmware body.
#[cfg(not(target_os = "none"))]
unsafe fn host_model_pthread_mutexattr_settype(attr: *mut usize, kind: u32) -> u32 {
    if attr.is_null() {
        return MUTEX_SETTYPE_INVALID;
    }
    if attr.cast::<u32>().read() != MUTEXATTR_MAGIC {
        return MUTEX_SETTYPE_INVALID;
    }
    if kind > MUTEX_KIND_MAX {
        return MUTEX_SETTYPE_INVALID;
    }
    let halfword = attr.cast::<u8>().add(6).cast::<u16>();
    halfword.write(
        (halfword.read() & !MUTEXATTR_TYPE_MASK) | ((kind as u16) << 4 & MUTEXATTR_TYPE_MASK),
    );
    0
}

/// Host backing for the process-wide default attr object @ 0x089cfcbc:
/// 8 bytes, lazily run through the attr initializer's stores on first
/// use, exactly like the firmware's (whose static image bytes there
/// are "act\0", not the magic).
#[cfg(not(target_os = "none"))]
static mut HOST_DEFAULT_ATTR: [u8; 8] = [0; 8];

/// Host model of the wrapped mutex initializer: the decoded body of
/// 0x082e82f8..0x082e8380, minus the kernel-object allocator (a fixed
/// nonzero sentinel handle stands in for it). Not compiled on target,
/// where the wired default calls the firmware body.
#[cfg(not(target_os = "none"))]
unsafe fn host_model_posix_mutex_init(mutex: *mut u8, attr: *mut usize) -> u32 {
    if mutex.is_null() {
        return MUTEX_INIT_INVALID;
    }
    // A NULL attr selects the process-wide default attr object, which
    // is lazily run through pthread_mutexattr_init's stores first.
    let attr = if attr.is_null() {
        let default = core::ptr::addr_of_mut!(HOST_DEFAULT_ATTR).cast::<u8>();
        if default.cast::<u32>().read() != MUTEXATTR_MAGIC {
            default.cast::<u32>().write(MUTEXATTR_MAGIC);
            default.add(4).cast::<u16>().write(MUTEXATTR_DEFAULT_HALFWORD);
            let halfword = default.add(6).cast::<u16>();
            halfword.write(
                (halfword.read() & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT,
            );
        }
        default.cast::<usize>()
    } else {
        attr
    };
    if attr.cast::<u32>().read() != MUTEXATTR_MAGIC {
        return MUTEX_INIT_INVALID;
    }
    // The kernel-object allocator @ 0x0808b1c0 (mask ROM): the model
    // plants a fixed nonzero handle instead of allocating.
    mutex.add(0x14).cast::<u32>().write(HOST_MODEL_SEM_HANDLE);
    let attr_word = attr.cast::<u8>().add(4).cast::<u32>().read();
    mutex.add(0x0c).cast::<u32>().write(attr_word);
    mutex.add(0x04).cast::<u32>().write(0);
    mutex.add(0x08).cast::<u32>().write(0);
    mutex.add(0x12).cast::<u16>().write(0);
    mutex.cast::<u32>().write(MUTEX_LIVE_MAGIC);
    0
}

/// Wired default for the unported `pthread_mutexattr_settype` @
/// 0x082e84dc: the firmware body on target, the behavioral host model
/// elsewhere.
unsafe extern "C" fn default_pthread_mutexattr_settype(attr: *mut usize, kind: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let settype: PthreadMutexattrSettype =
            core::mem::transmute(PTHREAD_MUTEXATTR_SETTYPE_ADDRESS);
        settype(attr, kind)
    }

    #[cfg(not(target_os = "none"))]
    {
        host_model_pthread_mutexattr_settype(attr, kind)
    }
}

/// Wired default for the unported mutex initializer @ 0x082e82f8: the
/// firmware body on target, the behavioral host model elsewhere.
unsafe extern "C" fn default_posix_mutex_init(mutex: *mut u8, attr: *mut usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        let init: PosixMutexInit = core::mem::transmute(POSIX_MUTEX_INIT_ADDRESS);
        init(mutex, attr)
    }

    #[cfg(not(target_os = "none"))]
    {
        host_model_posix_mutex_init(mutex, attr)
    }
}

/// Indirect dispatch for the two wrapped callees of
/// [`cxx_mutex_settype_init`] (the settings.rs `SETTINGS_CTOR`
/// pattern). Host tests install recording mocks; a later port of each
/// callee replaces its default without changing this caller.
#[derive(Clone, Copy)]
pub struct CxxMutexSettypeInitOps {
    /// Original 0x082e84dc: sets the attr type; the veneer always
    /// passes kind 0 (NORMAL).
    pub pthread_mutexattr_settype: PthreadMutexattrSettype,
    /// Original 0x082e82f8: initializes the embedded mutex from the
    /// attr; runs only when settype reported 0.
    pub posix_mutex_init: PosixMutexInit,
}

/// Wired defaults: the firmware bodies on target, the behavioral host
/// models elsewhere (see the module header).
pub const DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS: CxxMutexSettypeInitOps =
    CxxMutexSettypeInitOps {
        pthread_mutexattr_settype: default_pthread_mutexattr_settype,
        posix_mutex_init: default_posix_mutex_init,
    };

/// The active callee set. Host tests install recording mocks.
pub static mut CXX_MUTEX_SETTYPE_INIT_OPS: CxxMutexSettypeInitOps =
    DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS;

/// cxx_mutex_settype_init — original: `FUN_08261de8` @ 0x08261de8
/// (56 bytes; 1 `bl` call site, binary-scanned).
///
/// Sets `attr`'s type to NORMAL through the wrapped
/// `pthread_mutexattr_settype` @ 0x082e84dc and stores its status at
/// `this`+0x18; only when that status is 0 does it invoke the mutex
/// initializer @ 0x082e82f8 with (`this`, `attr`) and store ITS status
/// at `this`+0x18 instead. Unit-returning, matching the original (the
/// decompiled void; the caller's next instruction overwrites r0). No
/// NULL guard of its own, matching the original: the callees guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_settype_init(this: *mut u8, attr: *mut usize) {
    let status = core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_MUTEX_SETTYPE_INIT_OPS.pthread_mutexattr_settype
    ))(attr, MUTEX_KIND_NORMAL);
    this.add(super::mutex::CXX_MUTEX_STATUS_OFFSET)
        .cast::<u32>()
        .write(status);
    if status != 0 {
        return;
    }
    let status = core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_MUTEX_SETTYPE_INIT_OPS.posix_mutex_init
    ))(this, attr);
    this.add(super::mutex::CXX_MUTEX_STATUS_OFFSET)
        .cast::<u32>()
        .write(status);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::mutex::CXX_MUTEX_STATUS_OFFSET;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the dispatch slots and their recorders.
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    /// The callee sequence observed by the recording mocks, newest
    /// last: ("settype", attr, kind, status-word-at-entry) or
    /// ("init", mutex, attr, status-word-at-entry).
    static mut CALLS: Vec<(&'static str, usize, usize, u32)> = Vec::new();

    /// What the recording settype mock returns.
    static mut SETTYPE_STATUS: u32 = 0;
    /// What the recording init mock returns.
    static mut INIT_STATUS: u32 = 0;

    unsafe extern "C" fn recording_settype(attr: *mut usize, kind: u32) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(("settype", attr as usize, kind as usize, 0));
        *core::ptr::addr_of!(SETTYPE_STATUS)
    }

    /// Also snapshots the status word at mutex+0x18 on entry, proving
    /// the veneer planted the settype status BEFORE branching.
    unsafe extern "C" fn recording_init(mutex: *mut u8, attr: *mut usize) -> u32 {
        let status_word = mutex.add(CXX_MUTEX_STATUS_OFFSET).cast::<u32>().read();
        (*core::ptr::addr_of_mut!(CALLS)).push((
            "init",
            mutex as usize,
            attr as usize,
            status_word,
        ));
        *core::ptr::addr_of!(INIT_STATUS)
    }

    /// Restores the wired defaults even when a test panics.
    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_MUTEX_SETTYPE_INIT_OPS)
                    .write_volatile(DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS);
            }
        }
    }

    fn bench(ops: CxxMutexSettypeInitOps, settype_status: u32, init_status: u32) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(SETTYPE_STATUS).write_volatile(settype_status);
            core::ptr::addr_of_mut!(INIT_STATUS).write_volatile(init_status);
            core::ptr::addr_of_mut!(CXX_MUTEX_SETTYPE_INIT_OPS).write_volatile(ops);
        }
        OpsGuard { _lock: lock }
    }

    fn recording_bench(settype_status: u32, init_status: u32) -> OpsGuard {
        bench(
            CxxMutexSettypeInitOps {
                pthread_mutexattr_settype: recording_settype,
                posix_mutex_init: recording_init,
            },
            settype_status,
            init_status,
        )
    }

    fn default_bench() -> OpsGuard {
        bench(DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS, 0, 0)
    }

    fn calls() -> Vec<(&'static str, usize, usize, u32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// 8-byte-aligned backing for the 0x1c-byte wrapper, so the
    /// status-word and model stores stay aligned.
    #[repr(align(8))]
    struct Wrapper([u8; 0x1c]);

    /// 8-byte-aligned backing for an attr object plus a guard word.
    #[repr(align(8))]
    struct AttrBytes([u8; 16]);

    fn wrapper_word(wrapper: &Wrapper, offset: usize) -> u32 {
        u32::from_le_bytes(wrapper.0[offset..offset + 4].try_into().unwrap())
    }

    /// Byte-level reference for the wrapped attr initializer's decoded
    /// stores (pthread_mutexattr_init @ 0x082e84a4, see
    /// src/cxx/mutex_attr_init.rs): plant the magic and the default
    /// halfword, then read-modify-write the +0x06 halfword. Seeds the
    /// attr for the end-to-end tests WITHOUT touching the
    /// CXX_MUTEXATTR_INIT_OPS slot (mutex_attr_init's own tests race
    /// it in the shared test process).
    fn reference_attr_init(attr: &mut [u8; 8]) {
        attr[0..4].copy_from_slice(&MUTEXATTR_MAGIC.to_le_bytes());
        attr[4..6].copy_from_slice(&MUTEXATTR_DEFAULT_HALFWORD.to_le_bytes());
        let halfword = u16::from_le_bytes([attr[6], attr[7]]);
        attr[6..8].copy_from_slice(
            &((halfword & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT)
                .to_le_bytes(),
        );
    }

    /// Byte-level reference for the wrapped settype's decoded store:
    /// rewrite bits 4..5 of the +0x06 halfword with (kind << 4).
    fn reference_settype(attr: &mut [u8; 8], kind: u32) {
        let halfword = u16::from_le_bytes([attr[6], attr[7]]);
        attr[6..8].copy_from_slice(
            &((halfword & !MUTEXATTR_TYPE_MASK) | ((kind as u16) << 4 & MUTEXATTR_TYPE_MASK))
                .to_le_bytes(),
        );
    }

    #[test]
    fn settype_gets_normal_and_a_failure_is_recorded_without_init() {
        let _bench = recording_bench(MUTEX_SETTYPE_INVALID, 0);
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();
        let mut scope = [0x1111_2222usize, 0x3333_4444];
        let attr = scope.as_mut_ptr();

        unsafe { cxx_mutex_settype_init(this, attr) };

        assert_eq!(
            calls(),
            std::vec![("settype", attr as usize, MUTEX_KIND_NORMAL as usize, 0)],
            "one settype call with kind 0 (mov r1, #0x0), and no init"
        );
        assert_eq!(
            wrapper_word(&wrapper, 0x18),
            MUTEX_SETTYPE_INVALID,
            "the settype status is stored at this+0x18 before the bail"
        );
        assert_eq!(
            &wrapper.0[..0x18],
            &[0xa5u8; 0x18],
            "the mutex itself is untouched when settype fails"
        );
        assert_eq!(
            scope,
            [0x1111_2222usize, 0x3333_4444],
            "the veneer itself performs no stores on the attr"
        );
    }

    #[test]
    fn on_settype_success_init_runs_and_its_status_overwrites() {
        let _bench = recording_bench(0, MUTEX_INIT_ALLOC_FAILED);
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();
        let mut scope = [0usize; 2];
        let attr = scope.as_mut_ptr();

        unsafe { cxx_mutex_settype_init(this, attr) };

        let observed = calls();
        assert_eq!(observed.len(), 2, "settype then init");
        assert_eq!(observed[0], ("settype", attr as usize, 0, 0));
        assert_eq!(
            observed[1].0, "init",
            "init runs only after a successful settype"
        );
        assert_eq!(observed[1].1, this as usize, "init receives this");
        assert_eq!(observed[1].2, attr as usize, "init receives the attr");
        assert_eq!(
            observed[1].3, 0,
            "the settype status 0 was already planted at this+0x18 when init was entered"
        );
        assert_eq!(
            wrapper_word(&wrapper, 0x18),
            MUTEX_INIT_ALLOC_FAILED,
            "the init status OVERWRITES the recorded settype 0"
        );
    }

    #[test]
    fn a_successful_init_records_zero_at_the_status_word() {
        let _bench = recording_bench(0, 0);
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();
        let mut scope = [0usize; 2];

        unsafe { cxx_mutex_settype_init(this, scope.as_mut_ptr()) };

        assert_eq!(wrapper_word(&wrapper, 0x18), 0);
        assert_eq!(calls().len(), 2);
    }

    #[test]
    fn defaults_end_to_end_plant_normal_type_and_the_mutex_fields() {
        let _bench = default_bench();
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();
        let mut buf = AttrBytes([0u8; 16]);
        reference_attr_init((&mut buf.0[..8]).try_into().unwrap());
        // Set the type bits to a non-NORMAL value first, so the NORMAL
        // settype is observable (it must CLEAR them).
        reference_settype((&mut buf.0[..8]).try_into().unwrap(), 2);
        assert_eq!(buf.0[6] & 0x30, 0x20, "fixture: kind 2 planted");
        let attr = buf.0.as_mut_ptr().cast::<usize>();

        unsafe { cxx_mutex_settype_init(this, attr) };

        assert_eq!(wrapper_word(&wrapper, 0x18), 0, "both statuses 0");
        assert_eq!(
            buf.0[6] & 0x30,
            0,
            "the settype cleared the type bits back to NORMAL"
        );
        assert_eq!(
            &buf.0[8..],
            &[0u8; 8],
            "bytes past the 8-byte attr untouched"
        );
        let attr_word = u32::from_le_bytes(buf.0[4..8].try_into().unwrap());
        assert_eq!(
            wrapper_word(&wrapper, 0x00),
            MUTEX_LIVE_MAGIC,
            "the live-object magic at mutex+0x00"
        );
        assert_eq!(wrapper_word(&wrapper, 0x04), 0, "owner zeroed");
        assert_eq!(wrapper_word(&wrapper, 0x08), 0, "reserved word zeroed");
        assert_eq!(
            wrapper_word(&wrapper, 0x0c),
            attr_word,
            "the whole attr+0x04 word copied to mutex+0x0c"
        );
        assert_eq!(
            &wrapper.0[0x10..0x12],
            &[0xa5u8; 2],
            "the halfword at +0x10 is not the initializer's business"
        );
        assert_eq!(
            &wrapper.0[0x12..0x14],
            &[0u8; 2],
            "the halfword at +0x12 zeroed"
        );
        assert_eq!(
            wrapper_word(&wrapper, 0x14),
            HOST_MODEL_SEM_HANDLE,
            "the semaphore handle planted by the (modeled) kernel allocator"
        );
    }

    #[test]
    fn defaults_with_a_null_attr_record_invalid_and_skip_init() {
        let _bench = default_bench();
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();

        unsafe { cxx_mutex_settype_init(this, core::ptr::null_mut()) };

        assert_eq!(
            wrapper_word(&wrapper, 0x18),
            MUTEX_SETTYPE_INVALID,
            "the settype model's NULL guard status is recorded"
        );
        assert_eq!(
            &wrapper.0[..0x18],
            &[0xa5u8; 0x18],
            "init never ran, so the mutex bytes are untouched"
        );
    }

    #[test]
    fn default_settype_model_matches_the_reference_and_guards() {
        let _bench = default_bench();
        let settype = DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS.pthread_mutexattr_settype;

        // Accepted kinds 0..=2 plant exactly the reference bits,
        // preserving the rest of the halfword.
        for kind in 0..=MUTEX_KIND_MAX {
            for seed6 in [0x0000u16, 0xffff, 0xffcf, 0x0008, 0xaa95] {
                let mut buf = AttrBytes([0xa5; 16]);
                reference_attr_init((&mut buf.0[..8]).try_into().unwrap());
                buf.0[6..8].copy_from_slice(&seed6.to_le_bytes());
                let mut expected = buf.0;
                reference_settype((&mut expected[..8]).try_into().unwrap(), kind);

                let status = unsafe { settype(buf.0.as_mut_ptr().cast::<usize>(), kind) };

                assert_eq!(status, 0, "kind {kind} accepted");
                assert_eq!(
                    &buf.0[..8],
                    &expected[..8],
                    "kind {kind}, seed {seed6:#06x}: bits 4..5 rewritten, the rest preserved"
                );
                assert_eq!(&buf.0[8..], &expected[8..], "no stores past the attr");
            }
        }

        // A kind outside {0, 1, 2}, a bad magic and NULL are all
        // rejected with 0x1a and no stores.
        let mut buf = AttrBytes([0xa5; 16]);
        reference_attr_init((&mut buf.0[..8]).try_into().unwrap());
        let snapshot = buf.0;
        assert_eq!(
            unsafe { settype(buf.0.as_mut_ptr().cast::<usize>(), 3) },
            MUTEX_SETTYPE_INVALID
        );
        assert_eq!(buf.0, snapshot, "rejected kind leaves the attr alone");

        buf.0[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let snapshot = buf.0;
        assert_eq!(
            unsafe { settype(buf.0.as_mut_ptr().cast::<usize>(), MUTEX_KIND_NORMAL) },
            MUTEX_SETTYPE_INVALID
        );
        assert_eq!(buf.0, snapshot, "bad magic leaves the attr alone");

        assert_eq!(
            unsafe { settype(core::ptr::null_mut(), MUTEX_KIND_NORMAL) },
            MUTEX_SETTYPE_INVALID
        );
    }

    #[test]
    fn default_init_model_guards_and_uses_the_default_attr_for_null() {
        let _bench = default_bench();
        let init = DEFAULT_CXX_MUTEX_SETTYPE_INIT_OPS.posix_mutex_init;

        // NULL mutex -> 0x1a, nothing else happens.
        let mut buf = AttrBytes([0u8; 16]);
        reference_attr_init((&mut buf.0[..8]).try_into().unwrap());
        assert_eq!(
            unsafe { init(core::ptr::null_mut(), buf.0.as_mut_ptr().cast::<usize>()) },
            MUTEX_INIT_INVALID
        );

        // An attr without the MTXA magic -> 0x1a and no stores.
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let mut bad = AttrBytes([0x5au8; 16]);
        let snapshot = bad.0;
        assert_eq!(
            unsafe {
                init(
                    wrapper.0.as_mut_ptr(),
                    bad.0.as_mut_ptr().cast::<usize>(),
                )
            },
            MUTEX_INIT_INVALID
        );
        assert_eq!(bad.0, snapshot, "the attr is untouched");
        assert_eq!(wrapper.0, [0xa5u8; 0x1c], "the mutex is untouched");

        // A NULL attr selects the process-wide default attr object,
        // lazily initialized on first use — and the mutex is planted
        // from ITS fields (type NORMAL, process-scope bit set).
        unsafe { core::ptr::addr_of_mut!(HOST_DEFAULT_ATTR).write_bytes(0, 1) };
        let mut wrapper = Wrapper([0xa5u8; 0x1c]);
        let this = wrapper.0.as_mut_ptr();

        assert_eq!(unsafe { init(this, core::ptr::null_mut()) }, 0);

        let mut expected_attr = [0u8; 8];
        reference_attr_init(&mut expected_attr);
        assert_eq!(
            unsafe { *core::ptr::addr_of!(HOST_DEFAULT_ATTR) },
            expected_attr,
            "the default attr object was lazily initialized"
        );
        let attr_word = u32::from_le_bytes(expected_attr[4..8].try_into().unwrap());
        assert_eq!(wrapper_word(&wrapper, 0x00), MUTEX_LIVE_MAGIC);
        assert_eq!(wrapper_word(&wrapper, 0x0c), attr_word);
        assert_eq!(wrapper_word(&wrapper, 0x14), HOST_MODEL_SEM_HANDLE);
        assert_eq!(
            wrapper.0[0x0f] & 0x30,
            0,
            "the default attr's type field is NORMAL"
        );
    }
}
