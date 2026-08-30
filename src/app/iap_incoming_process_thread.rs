//! The **`CIapIncomingProcessThread` singleton** — the iAP (iPod
//! Accessory Protocol) worker that processes packets arriving from an
//! attached accessory — and the two entry points that hand it out.
//!
//! | address | name | size | `bl` sites |
//! |---|---|---|---|
//! | 0x081d71c0 | [`iap_incoming_process_thread_instance`] | 24 | 8 direct |
//! | 0x08139210 | [`iap_incoming_process_thread_instance_veneer`] | 4 | **65** |
//! | 0x081d7270 | [`iap_incoming_process_thread_slot_poll`] | 68 | **36** + 1 tail `b` |
//!
//! Both counts are binary-scanned out of `work/firmware/osos.dec` by
//! decoding every ARM `B`/`BL` word in the image (load base
//! 0x08000000) and resolving its target: 8 `BL` reach 0x081d71c0
//! directly, 65 `BL` reach the veneer, and the *only* plain `B` at
//! 0x081d71c0 is the veneer itself — 73 call sites in total.
//!
//! ## Extent
//!
//! 24 bytes, 0x081d71c0..0x081d71d8, **not** the 20 a Ghidra-style
//! instruction scan reports: the five instructions are followed by the
//! holder literal at 0x081d71d4 (0x089cca0c), which the first
//! instruction reaches with `ldr r0, [pc, #12]`, and the next function
//! opens at 0x081d71d8 with `push {r4, r5, r6, lr}`. The veneer really
//! is 4 bytes — a direct `B` (0xea0277ea), not the `ldr pc, [pc, #-4]`
//! + target-word form whose true extent is 8, and not an empty `bx lr`
//! destructor; the word after it (0x08139214, `mov r0, #1`) belongs to
//! an unrelated function.
//!
//! ## The holder global
//!
//! The instance lives in the `+4` slot of a holder struct @
//! 0x089cca0c. Exactly three words in the whole image name that
//! address — the literal-pool entries at 0x081d6a9c, 0x081d6db0 and
//! 0x081d71d4, all inside the one compilation unit — so the holder is
//! private to this file.
//!
//! 0x089cca0c is one of the runtime-initialized RW pages: the image
//! holds stale UI data there, exactly the situation `app/singletons.rs`
//! documents for the other 0x089cxxxx caches. The instance slot is
//! therefore the crate static [`IAP_INCOMING_PROCESS_THREAD_INSTANCE`],
//! which starts NULL — the pre-init state.
//!
//! ## What the object is
//!
//! A 0x44-byte C++ object built once by the lazy creator @ 0x081d68f0,
//! *not* ported here. That creator is what names the class: it forms
//! the string literal address with `add r9, pc, #388` @ 0x081d6914,
//! which resolves to 0x081d6aa0, and the bytes there are
//! `"CIapIncomingProcessThread\0"`. It measures that literal, builds a
//! `std::string` from it, `operator new(0x44)`s the object
//! (`mov r0, #0x44` @ 0x081d6970), initializes the embedded sub-object
//! at `+0x0c`, and starts it with `FUN_081d7240(object, argument)`. A
//! non-zero result from that start call is treated as failure: the
//! object is destroyed through its own vtable slot `+0x08` and **NULL**
//! is what gets published, so the holder slot legitimately stays NULL
//! when accessory processing never came up.
//!
//! The 65 veneer call sites run from 0x08164134 to 0x08201278, the
//! bulk of them in 0x081fxxxx (25), 0x0819xxxx (13) and 0x081axxxx
//! (11). They share one shape: take the returned pointer as a `this`,
//! pull a request word out of the caller's own object and dispatch —
//! e.g. `bl veneer; ldr r1, [r6, #8]; bl ...` @ 0x08164134.
//!
//! ## What the holder actually hands out
//!
//! A correction to the 0x44-byte reading above, proven while porting
//! [`iap_incoming_process_thread_slot_poll`]: the creator's publish
//! sequence is `ldr r4, [r4]` @ 0x081d69fc — it reads the 0x44-byte
//! wrapper's **+0x00 field** and stores THAT at holder+4 @ 0x081d6a38.
//! The spawn helper 0x0839e874 (stack 0x3800, priority 15, called @
//! 0x081d69b8) fills wrapper+0x00 through its lazy getter @ 0x0839e80c,
//! whose factory @ 0x081d7058 `operator new(0x240)`s a **0x240-byte
//! context object** and constructs it @ 0x081d72c8 (vtable
//! 0x0898e05c). `FUN_081d7240` is that context's locked +0x150 setter
//! (it touches this+0x114/+0x150), and the failed-start destroy @
//! 0x081d6a24 runs the context's own vtable slot +0x08. Every
//! call site confirms it: the accessor's return goes straight in as
//! `this` to methods touching +0x114/+0x150/+0x154 — e.g. the
//! `bl 0x08139210; ldr r1, [r5, #0x30]; bl 0x081d7270` sequence @
//! 0x081f1ca8. `app/pending_event_take`'s "mutex at thread+0x114"
//! note is the same object.
//!
//! The 0x240-byte context (layout recovered from its ctor @ 0x081d72c8
//! and the register/poll family 0x081d6dbc..0x081d7270):
//!
//! ```text
//! +0x000  vtable 0x0898e05c (base: kind-0x1e message machinery,
//!         base vtable 0x089a758c planted by base ctor 0x0825788c)
//! +0x110  ctor argument (the owner's name/word at [owner+8])
//! +0x114  registry mutex: C++ mutex wrapper (0x1c bytes, ctor
//!         0x08261e28), the PosixMutex embedded at +0
//! +0x130  second mutex wrapper (0x1c), guards the +0x23c count
//! +0x14c  byte flag, +0x150 object pointer (locked setter
//!         0x081d7240, consumer 0x081d708c)
//! +0x154  registration table: 29 slots of 8 bytes
//!         { object: u32, context: u32 }; a slot's object is a
//!         0x24-byte wait registration (operator_new(0x24), ctor
//!         0x08257cc8 with owner=this) carrying a condition variable
//!         at its own +0x10
//! +0x23c  remaining-count, initialised to 30
//! ```
//!
//! ## Deviations
//!
//! - The holder's `+4` slot is the crate static
//!   [`IAP_INCOMING_PROCESS_THREAD_INSTANCE`] rather than the word @
//!   0x089cca10 (see above).
//! - Nothing here constructs. The original 0x081d71c0 does not either:
//!   a NULL instance is fatal, and the only thing that fills the slot
//!   is the creator @ 0x081d68f0, which is not ported. That makes both
//!   symbols **hook-ready only once something publishes the
//!   instance** — branching stock code at 0x081d71c0 today would turn
//!   all 73 call sites into a `heap_panic`. This is the same contract
//!   `app/service_manager.rs` records for its own accessor pair.
//! - The fatal path is not exercised by the host tests:
//!   [`heap_panic`] is `-> !` and runs the raise/exit/terminate chain,
//!   so a host call cannot return.

use crate::heap::veneers::heap_panic;

/// The `CIapIncomingProcessThread` singleton (original: the `+4` slot
/// of the holder global @ 0x089cca0c — see the module header's
/// deviation note).
///
/// NULL until the unported creator @ 0x081d68f0 publishes an instance,
/// which is the pre-init state of the original word.
pub static mut IAP_INCOMING_PROCESS_THREAD_INSTANCE: *mut u8 = core::ptr::null_mut();

/// iap_incoming_process_thread_instance — original: `FUN_081d71c0` @
/// 0x081d71c0 (24 bytes: five instructions plus the trailing holder
/// literal @ 0x081d71d4; 8 direct `bl` call sites, 73 including the
/// veneer).
///
/// Returns the `CIapIncomingProcessThread` singleton. A NULL instance
/// is fatal — the original falls straight through into
/// `bl 0x08030f44` ([`heap_panic`], non-returning), so this accessor
/// never hands out NULL:
///
/// ```text
/// ldr r0, [pc, #12]   ; &holder
/// ldr r0, [r0, #4]    ; holder->instance
/// cmp r0, #0
/// bxne lr             ; return it
/// bl  0x08030f44      ; heap_panic
/// ```
///
/// The holder word is re-read on every call — the original caches
/// nothing.
///
/// # Safety
///
/// The returned pointer is only as valid as whatever published
/// [`IAP_INCOMING_PROCESS_THREAD_INSTANCE`]; callers treat it as a
/// `this` for virtual dispatch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_incoming_process_thread_instance() -> *mut u8 {
    let instance = core::ptr::read_volatile(core::ptr::addr_of!(
        IAP_INCOMING_PROCESS_THREAD_INSTANCE
    ));
    if instance.is_null() {
        heap_panic();
    }
    instance
}

/// iap_incoming_process_thread_instance_veneer — original:
/// `thunk_FUN_08139210` @ 0x08139210 (4 bytes; **65** `bl` call
/// sites).
///
/// One instruction — `b 0x081d71c0` — the long-branch veneer the
/// linker planted so the 0x0816xxxx/0x0820xxxx iAP callers could reach
/// [`iap_incoming_process_thread_instance`]. It sits in the same
/// long-branch veneer region as `app/service_manager`'s @ 0x081391ec,
/// nine words above it.
///
/// Kept as its own `#[inline(never)]` symbol rather than an alias so a
/// hook at 0x08139210 lands on a real veneer that branches on to the
/// accessor, exactly as the image has it.
///
/// # Safety
///
/// Same contract as [`iap_incoming_process_thread_instance`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_incoming_process_thread_instance_veneer() -> *mut u8 {
    iap_incoming_process_thread_instance()
}

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

/// Offset of the registration-table mutex inside the 0x240-byte
/// context object (original `add r4, r0, #0x114`). A C++ mutex wrapper
/// whose embedded [`PosixMutex`] sits at +0, so the offset addresses
/// the PosixMutex directly.
pub const REGISTRY_MUTEX_OFFSET: usize = 0x114;

/// Offset of the registration table: [`SLOT_COUNT`] entries of
/// [`SLOT_STRIDE`] bytes, `{ object: u32, context: u32 }` (original
/// `ldr r0, [r0, #0x154]`).
pub const SLOT_TABLE_OFFSET: usize = 0x154;

/// Number of registration slots (original `cmp r6, #29`; the register
/// path's find-free loop @ 0x081d70d4 stops at the same bound).
pub const SLOT_COUNT: u32 = 29;

/// Bytes per registration slot (original `add r0, r5, r6, lsl #3`).
pub const SLOT_STRIDE: usize = 8;

/// Indirect dispatch for the one unported callee (see the function's
/// deviation note). Host tests install a recording model; a later port
/// of 0x08257cb4 replaces the default without touching this caller.
#[derive(Clone, Copy)]
pub struct IapThreadSlotPollOps {
    /// Callee 0x08257cb4 `(slot_object)`: a 4-instruction veneer
    /// (`add r0, r0, #16; b 0x8261f78`) that runs a **zero-timeout**
    /// condition wait on the registration object's condvar at +0x10 —
    /// 0x8261f78 stacks a zeroed `{sec, nsec}` and calls 0x8261f28 ->
    /// 0x8261f94 -> the posix timed-wait body @ 0x0826269c (see
    /// `fp/fp_misc`'s `cond_wait_attr_clock` notes). A pending signal
    /// is consumed; an empty condvar times out immediately. The status
    /// is discarded by the original.
    pub poll_slot_object: unsafe extern "C" fn(slot_object: *mut u8),
}

/// Target default: the ROM poll veneer.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_poll_slot_object(slot_object: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0825_7cb4usize);
    f(slot_object)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_poll_slot_object(_slot_object: *mut u8) {}

/// Wired default: the ROM address on target, a documented inert stub
/// on host.
pub const DEFAULT_IAP_THREAD_SLOT_POLL_OPS: IapThreadSlotPollOps =
    IapThreadSlotPollOps {
        poll_slot_object: firmware_poll_slot_object,
    };

/// The active callee set, read through `read_volatile` so LLVM cannot
/// fold the indirect call to the default.
pub static mut IAP_THREAD_SLOT_POLL_OPS: IapThreadSlotPollOps =
    DEFAULT_IAP_THREAD_SLOT_POLL_OPS;

#[inline(always)]
fn iap_thread_slot_poll_ops() -> IapThreadSlotPollOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IAP_THREAD_SLOT_POLL_OPS)) }
}

/// iap_incoming_process_thread_slot_poll — original: `FUN_081d7270` @
/// 0x081d7270 (**68 bytes**, 0x081d7270..0x081d72b4, all code, no
/// literal pool; Ghidra's 68 is exact — the next function opens at
/// 0x081d72b4 with `mov r1, #0`. Byte-decoded from osos.dec).
/// **36 `bl` call sites plus one plain tail `b`** @ 0x081f2210,
/// binary-verified by decoding every B/BL word in osos.dec — zero
/// predicated forms (`blne`/`bleq`), and no DATA word anywhere
/// references the address, so it is only ever direct-called, never
/// dispatched virtually.
///
/// A method of the 0x240-byte iAP incoming-process context the
/// accessor above hands out. Under the registry mutex at `this +
/// 0x114`: resolve registration slot `index` and run a non-blocking
/// (zero-timeout) condition wait on the registered object's condvar,
/// draining one pending signal if the iAP thread posted one. An
/// out-of-range index or an empty slot is FATAL — the original falls
/// into [`heap_panic`] **with the mutex still held** (it never
/// returns, so there is no unlock on that path). Returns the unlock
/// status, the original tail-branching into the unlock veneer:
///
/// ```text
/// 081d7270  push {r4, r5, r6, lr}
/// 081d7274  mov  r5, r0              @ this
/// 081d7278  add  r4, r0, #0x114      @ &this->registry_mutex
/// 081d727c  mov  r0, r4
/// 081d7280  mov  r6, r1              @ index
/// 081d7284  bl   0x08261e20          @ posix_mutex_lock (alias veneer)
/// 081d7288  cmp  r6, #29
/// 081d728c  bcs  0x081d72a0          @ index >= 29 -> fatal
/// 081d7290  add  r0, r5, r6, lsl #3
/// 081d7294  ldr  r0, [r0, #0x154]    @ object = table[index].object
/// 081d7298  cmp  r0, #0
/// 081d729c  bne  0x081d72a4          @ slot live -> poll it
/// 081d72a0  bl   0x08030f44          @ heap_panic (non-returning)
/// 081d72a4  bl   0x08257cb4          @ zero-timeout cond wait, object+0x10
/// 081d72a8  mov  r0, r4
/// 081d72ac  pop  {r4, r5, r6, lr}
/// 081d72b0  b    0x08261e24          @ posix_mutex_unlock; status in r0
/// ```
///
/// Callers hold their own session mutex around the pair
/// `iap_incoming_process_thread_instance(); slot_poll(thread,
/// session->slot_index)` (e.g. @ 0x081f1ca8, index from `[r5, #0x30]`)
/// — this is how a session drains the signal the incoming-process
/// thread posts to its registration. The sibling @ 0x081d6e68 has the
/// identical guard shape but calls the two-argument setter 0x08257ca0
/// instead of the poll veneer.
///
/// # Deviations
///
/// - The poll callee 0x08257cb4 is unported and dispatches through
///   [`IAP_THREAD_SLOT_POLL_OPS`] (the `app/pending_event_take`
///   pattern): target builds transmute the ROM address, the host
///   default is inert and every test installs a recording model.
/// - Lock/unlock call the canonical ported
///   [`posix_mutex_lock`]/[`posix_mutex_unlock`] directly — the
///   original calls the 4-byte alias veneers 0x08261e20/0x08261e24,
///   which names.yaml resolves to those symbols (no separate Rust
///   symbol exists for a bare `b` alias).
/// - The fatal paths call the ported [`heap_panic`] exactly like the
///   original's `bl 0x08030f44`. They are not exercised on host:
///   `heap_panic` runs the raise/exit/terminate chain whose default
///   terminate spins (the `app/pending_event_take` precedent).
///
/// # Safety
///
/// `this` must point at a live 0x240-byte context object (at least
/// [`SLOT_TABLE_OFFSET`] + [`SLOT_COUNT`] * [`SLOT_STRIDE`] bytes with
/// an initialised [`PosixMutex`] at [`REGISTRY_MUTEX_OFFSET`]). The
/// registered slot object is handed to the firmware poll callee.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_incoming_process_thread_slot_poll(
    this: *mut u8,
    index: u32,
) -> u32 {
    let mutex = this.wrapping_add(REGISTRY_MUTEX_OFFSET) as *mut PosixMutex;
    posix_mutex_lock(mutex);
    if index >= SLOT_COUNT {
        heap_panic();
    }
    let slot = this.wrapping_add(SLOT_TABLE_OFFSET + index as usize * SLOT_STRIDE);
    let slot_object = *(slot as *const u32) as *mut u8;
    if slot_object.is_null() {
        heap_panic();
    }
    (iap_thread_slot_poll_ops().poll_slot_object)(slot_object);
    posix_mutex_unlock(mutex)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    /// Byte size of the object the creator @ 0x081d68f0 allocates
    /// (`mov r0, #0x44` @ 0x081d6970).
    const OBJECT_SIZE: usize = 0x44;

    /// Serializes the tests that write the one shared instance slot.
    static INSTANCE_LOCK: Mutex<()> = Mutex::new(());

    /// Installs `instance` and returns the lock guard; the slot is
    /// restored to its NULL pre-init state by `clear`.
    fn publish(instance: *mut u8) -> std::sync::MutexGuard<'static, ()> {
        let guard = INSTANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                instance,
            )
        };
        guard
    }

    fn clear(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                ptr::null_mut(),
            )
        };
        drop(guard);
    }

    #[test]
    fn the_slot_starts_null_like_the_uninitialized_holder_word() {
        let guard = INSTANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(unsafe {
            ptr::read_volatile(ptr::addr_of!(IAP_INCOMING_PROCESS_THREAD_INSTANCE))
        }
        .is_null());
        drop(guard);
    }

    #[test]
    fn the_accessor_returns_the_published_instance() {
        let mut object = [0u8; OBJECT_SIZE];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        assert_eq!(unsafe { iap_incoming_process_thread_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_accessor_never_caches_and_follows_the_slot() {
        let mut first = [0u8; OBJECT_SIZE];
        let mut second = [0u8; OBJECT_SIZE];
        let guard = publish(first.as_mut_ptr());
        unsafe {
            assert_eq!(iap_incoming_process_thread_instance(), first.as_mut_ptr());
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                second.as_mut_ptr(),
            );
            assert_eq!(
                iap_incoming_process_thread_instance(),
                second.as_mut_ptr(),
                "the original re-loads the holder word on every call"
            );
        }
        clear(guard);
    }

    #[test]
    fn a_misaligned_instance_pointer_is_passed_through_unchanged() {
        // The original returns the holder word verbatim: no masking, no
        // offsetting (contrast media_player_interface_get's `addne #0x14`).
        let mut storage = [0u8; OBJECT_SIZE + 1];
        let instance = unsafe { storage.as_mut_ptr().add(1) };
        let guard = publish(instance);
        assert_eq!(unsafe { iap_incoming_process_thread_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_veneer_reaches_the_same_accessor() {
        let mut object = [0u8; OBJECT_SIZE];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        unsafe {
            assert_eq!(iap_incoming_process_thread_instance_veneer(), instance);
            assert_eq!(
                iap_incoming_process_thread_instance_veneer(),
                iap_incoming_process_thread_instance()
            );
        }
        clear(guard);
    }

    #[test]
    fn the_veneer_is_a_distinct_symbol_from_its_target() {
        // The image has two separate entry points; an alias would make a
        // hook at 0x08139210 meaningless.
        assert_ne!(
            iap_incoming_process_thread_instance_veneer as *const () as usize,
            iap_incoming_process_thread_instance as *const () as usize
        );
    }
}

#[cfg(test)]
mod slot_poll_tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test here: they share one fixture slab (the
    /// mapper never unmaps, so a second mapping would land above 4 GiB
    /// and skip silently) and swap the global ops table.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// The fixture is one whole 0x240-byte context object, rounded up:
    /// mutex at +0x114, 29 eight-byte slots at +0x154..+0x23c.
    const SLAB_LEN: usize = 0x300;

    /// Slot-object pointers the poll mock has received, in order.
    static mut POLLED: Vec<usize> = Vec::new();

    /// When set, the mock drops the mutex's owner word before
    /// returning — the function's own unlock then reports non-owner.
    static mut MOCK_CLEARS_OWNER: bool = false;

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: IapThreadSlotPollOps,
        available: bool,
    }

    unsafe fn slab() -> *mut u8 {
        // Mapped once per process at the unique hint; every later call
        // gets the same block back because the region stays occupied.
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::IAP_THREAD_SLOT_POLL, SLAB_LEN) {
                Some(p) => SLAB = p,
                None => {
                    note_missing_u32_fixture("app::iap_incoming_process_thread::slot_poll");
                }
            }
        }
        SLAB
    }

    unsafe fn set_word(offset: usize, value: u32) {
        (slab().wrapping_add(offset) as *mut u32).write_volatile(value);
    }

    unsafe fn registry_mutex() -> *mut PosixMutex {
        slab().wrapping_add(REGISTRY_MUTEX_OFFSET) as *mut PosixMutex
    }

    /// Distinct sentinel for the slot-object pointer of slot `n`: an
    /// address inside the slab, so it is a believable object pointer,
    /// but never dereferenced by anything (the poll callee is mocked).
    unsafe fn fake_slot_object(n: usize) -> u32 {
        slab().wrapping_add(0x240 + n * 4) as usize as u32
    }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let available = unsafe { !slab().is_null() };
        let previous_ops = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(IAP_THREAD_SLOT_POLL_OPS))
        };
        if available {
            unsafe {
                core::ptr::write_bytes(slab(), 0, SLAB_LEN);
                POLLED.clear();
                MOCK_CLEARS_OWNER = false;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(IAP_THREAD_SLOT_POLL_OPS),
                    IapThreadSlotPollOps {
                        poll_slot_object: mock_poll_slot_object,
                    },
                );
            }
        }
        Bench {
            _lock: lock,
            previous_ops,
            available,
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            if self.available {
                unsafe {
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!(IAP_THREAD_SLOT_POLL_OPS),
                        self.previous_ops,
                    );
                }
            }
        }
    }

    unsafe extern "C" fn mock_poll_slot_object(slot_object: *mut u8) {
        POLLED.push(slot_object as usize);
        // The registry mutex must be held while the poll runs (owner =
        // us): the original locks before the slot resolution and
        // tail-unlocks after the callee returns.
        assert_eq!(
            (*registry_mutex()).owner,
            crate::kernel::posix_mutex::PRE_KERNEL_THREAD,
            "the registry mutex is held during the poll"
        );
        if MOCK_CLEARS_OWNER {
            (*registry_mutex()).owner = 0;
            (*registry_mutex()).recursion = 0;
        }
    }

    #[test]
    fn the_registered_slot_object_is_polled_under_the_mutex() {
        let bench = bench();
        if !bench.available {
            return;
        }
        unsafe {
            set_word(SLOT_TABLE_OFFSET + 3 * SLOT_STRIDE, fake_slot_object(3));
            let status =
                iap_incoming_process_thread_slot_poll(slab(), 3);
            assert_eq!(POLLED.len(), 1, "exactly one poll call");
            assert_eq!(
                POLLED[0],
                fake_slot_object(3) as usize,
                "the poll receives the slot's +0 object pointer verbatim"
            );
            assert_eq!(
                (*registry_mutex()).owner,
                0,
                "the mutex is released before the function returns"
            );
            assert_eq!(status, 0, "a clean unlock reports 0");
        }
    }

    #[test]
    fn the_first_and_last_valid_slots_are_in_range() {
        let bench = bench();
        if !bench.available {
            return;
        }
        unsafe {
            // 0 and 28 are the bounds of the `cmp r6, #29` window; 29
            // and a NULL slot are fatal and not host-testable
            // (heap_panic never returns).
            set_word(SLOT_TABLE_OFFSET, fake_slot_object(0));
            set_word(SLOT_TABLE_OFFSET + 28 * SLOT_STRIDE, fake_slot_object(28));
            assert_eq!(iap_incoming_process_thread_slot_poll(slab(), 0), 0);
            assert_eq!(iap_incoming_process_thread_slot_poll(slab(), 28), 0);
            assert_eq!(
                POLLED.as_slice(),
                &[fake_slot_object(0) as usize, fake_slot_object(28) as usize],
                "both edge indices resolve their own slot, in call order"
            );
        }
    }

    #[test]
    fn the_slot_index_scales_by_eight_and_the_context_word_is_unread() {
        let bench = bench();
        if !bench.available {
            return;
        }
        unsafe {
            // Two adjacent slots: index 7's object lives at
            // +0x154 + 7*8; its +4 context word is poisoned to prove
            // the poll never consumes it (the original reads only the
            // slot's first word).
            set_word(SLOT_TABLE_OFFSET + 6 * SLOT_STRIDE, fake_slot_object(6));
            set_word(SLOT_TABLE_OFFSET + 6 * SLOT_STRIDE + 4, 0xdead_beef);
            set_word(SLOT_TABLE_OFFSET + 7 * SLOT_STRIDE, fake_slot_object(7));
            set_word(SLOT_TABLE_OFFSET + 7 * SLOT_STRIDE + 4, 0xa5a5_5a5a);
            assert_eq!(iap_incoming_process_thread_slot_poll(slab(), 7), 0);
            assert_eq!(
                POLLED.as_slice(),
                &[fake_slot_object(7) as usize],
                "the index strides by 8 and the +4 context word is ignored"
            );
        }
    }

    #[test]
    fn the_unlock_status_is_forwarded_as_the_return_value() {
        let bench = bench();
        if !bench.available {
            return;
        }
        unsafe {
            set_word(SLOT_TABLE_OFFSET + SLOT_STRIDE, fake_slot_object(1));
            // The original tail-branches into posix_mutex_unlock, so
            // the function's r0 IS the unlock's status. The mock
            // dropping the owner word makes the function's own unlock
            // report the non-owner status 0x05 (posix_mutex_unlock's
            // contract, returned before the semaphore is touched) -
            // proof the return is the unlock's, not a hardwired 0.
            MOCK_CLEARS_OWNER = true;
            let status = iap_incoming_process_thread_slot_poll(slab(), 1);
            assert_eq!(
                status, 0x05,
                "the unlock's non-owner status is forwarded verbatim"
            );
            assert_eq!(POLLED.len(), 1, "the poll still ran");
        }
    }
}
