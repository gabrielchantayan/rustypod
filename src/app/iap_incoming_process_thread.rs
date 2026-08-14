//! The **`CIapIncomingProcessThread` singleton** — the iAP (iPod
//! Accessory Protocol) worker that processes packets arriving from an
//! attached accessory — and the two entry points that hand it out.
//!
//! | address | name | size | `bl` sites |
//! |---|---|---|---|
//! | 0x081d71c0 | [`iap_incoming_process_thread_instance`] | 24 | 8 direct |
//! | 0x08139210 | [`iap_incoming_process_thread_instance_veneer`] | 4 | **65** |
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
