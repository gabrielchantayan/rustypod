//! The **service-manager singleton** — the framework object that owns
//! retailOS's per-hardware subsystem handlers — and the two entry
//! points that hand it out.
//!
//! | address | name | size | `bl` sites |
//! |---|---|---|---|
//! | 0x08165520 | [`service_manager_instance`] | 24 | 17 direct |
//! | 0x081391ec | [`service_manager_instance_veneer`] | 4 | **213** |
//!
//! Both counts are binary-scanned out of `work/firmware/osos.dec` by
//! decoding every ARM `B`/`BL` word in the image (load base
//! 0x08000000) and resolving its target: 17 `BL` reach 0x08165520
//! directly, 213 `BL` reach the veneer, and the *only* plain `B` at
//! 0x08165520 is the veneer itself — 230 call sites in total, which is
//! what makes a 24-byte accessor worth porting.
//!
//! ## The holder global
//!
//! The instance lives in the `+4` slot of a small holder struct @
//! 0x089ca948. Only six words in the whole image name that address, all
//! of them literal-pool entries inside the one compilation unit at
//! 0x081653xx-0x0816592c (0x08165360, 0x08165518, 0x08165534,
//! 0x0816557c, 0x08165614, 0x08165930), so the holder is private to
//! this file. Its observed layout:
//!
//! ```text
//! +0x00  u8    constructed   (set to 1 by the ctor @ 0x0816566c)
//! +0x01  u8    ready         (set to 1 by the ctor)
//! +0x04  ptr   instance      <- what this module returns
//! +0x08  u32   hardware model id (0xffffffff when >= 26)
//! +0x0c  u32   capability mask
//! +0x10  u32   capability extra
//! ```
//!
//! 0x089ca948 is one of the runtime-initialized RW pages: the image
//! holds stale UI strings there ("NowPlaying_Font", "Search_Font"),
//! exactly the situation `app/singletons.rs` documents for the
//! 0x089cxxxx caches. The instance slot is therefore the crate static
//! [`SERVICE_MANAGER_INSTANCE`], which starts NULL — the pre-init
//! state.
//!
//! ## What the object is
//!
//! A 0xE8-byte C++ object built once by the lazy constructor-getter @
//! 0x081655e0 (`operator new(0xe8)` then `FUN_0816566c`), *not* ported
//! here. Its constructor reads the hardware model id through the
//! platform-info singleton (`FUN_08259928`, vtable slot +0x34), indexes
//! a 26-entry x 12-byte capability table by it, and then builds up to
//! thirteen subsystem handler objects — one per bit of the 0x1fbf
//! default mask — into the slot table embedded at `this + 4`
//! (`FUN_08193ed4(this + 4, slot, handler)`), plus three more into a
//! second bank (`FUN_08193e98`). Callers reach a handler with
//! `FUN_08193e84`/`FUN_08194080(instance + 4, slot)` and then dispatch
//! through its vtable +0x14 with a (code, arg) pair; the sweep at
//! 0x08165364 walks `slot` 0..12 exactly.
//!
//! **The class name does not survive in the image** — the constructor
//! hands no literal to the class-name factory and no name string sits
//! in its body, the same dead end `app/singletons.rs` records for the
//! 0x8900/0x6200/0x7f80 singletons. `service_manager` names the
//! object's *role* (it owns and dispatches to the subsystem handlers)
//! and nothing more; inventing a `TC...` class name would be worse than
//! saying so.
//!
//! ## Deviations
//!
//! - The holder's `+4` slot is the crate static
//!   [`SERVICE_MANAGER_INSTANCE`] rather than a word in the 0x089caxxx
//!   page (see above).
//! - Nothing here constructs. The original 0x08165520 does not either:
//!   a NULL instance is fatal, and the only thing that fills the slot
//!   is 0x081655e0 / `FUN_0816566c`, neither of which is ported. That
//!   makes these two symbols **hook-ready only once something publishes
//!   the instance** — branching stock code at 0x08165520 today would
//!   turn every one of the 230 call sites into a `heap_panic`.
//! - The fatal path is not exercised by the host tests:
//!   [`heap_panic`] is `-> !` and runs the raise/exit/terminate chain,
//!   so a host call cannot return. `cxx/list_splice.rs` leaves its own
//!   `heap_panic` branch untested for the same reason.

use crate::heap::veneers::heap_panic;

/// The service-manager singleton (original: the `+4` slot of the holder
/// global @ 0x089ca948 — see the module header's deviation note).
///
/// NULL until the unported constructor-getter @ 0x081655e0 publishes an
/// instance, which is the pre-init state of the original word.
pub static mut SERVICE_MANAGER_INSTANCE: *mut u8 = core::ptr::null_mut();

/// service_manager_instance — original: `FUN_08165520` @ 0x08165520
/// (24 bytes: five instructions plus the trailing holder literal @
/// 0x08165534; 17 direct `bl` call sites, 230 including the veneer).
///
/// Returns the service-manager singleton. A NULL instance is fatal —
/// the original falls straight through into `bl 0x08030f44`
/// ([`heap_panic`], non-returning), so this accessor never hands out
/// NULL:
///
/// ```text
/// ldr r0, [pc, #12]   ; &holder
/// ldr r0, [r0, #4]    ; holder->instance
/// cmp r0, #0
/// bxne lr             ; return it
/// bl  0x08030f44      ; heap_panic
/// ```
///
/// # Safety
///
/// The returned pointer is only as valid as whatever published
/// [`SERVICE_MANAGER_INSTANCE`]; callers treat it as a `this` for
/// virtual dispatch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_instance() -> *mut u8 {
    let instance = core::ptr::read_volatile(core::ptr::addr_of!(SERVICE_MANAGER_INSTANCE));
    if instance.is_null() {
        heap_panic();
    }
    instance
}

/// service_manager_instance_veneer — original: `thunk_FUN_08165520` @
/// 0x081391ec (4 bytes; **213** `bl` call sites).
///
/// One instruction — `b 0x08165520` — the long-branch veneer the
/// linker planted so the 0x0813xxxx/0x0816xxxx callers could reach
/// [`service_manager_instance`]. The word after it (0x081391f0,
/// `add r1, r0, #0x18`) is the entry of an unrelated function, so the
/// extent really is 4 bytes: this is a direct `B`, not the
/// `ldr pc, [pc, #-4]` + target-word form whose true extent is 8.
///
/// Kept as its own `#[inline(never)]` symbol rather than an alias so a
/// hook at 0x081391ec lands on a real veneer that branches on to the
/// accessor, exactly as the image has it — the built ARM body is
/// `push {fp,lr}; mov fp,sp; pop {fp,lr}; b service_manager_instance`,
/// i.e. the original's tail branch plus the target's mandatory
/// non-leaf frame pointer.
///
/// # Safety
///
/// Same contract as [`service_manager_instance`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_instance_veneer() -> *mut u8 {
    service_manager_instance()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    /// Serializes the tests that write the one shared instance slot.
    static INSTANCE_LOCK: Mutex<()> = Mutex::new(());

    /// Installs `instance` and returns the lock guard; the slot is
    /// restored to its NULL pre-init state by `clear`.
    fn publish(instance: *mut u8) -> std::sync::MutexGuard<'static, ()> {
        let guard = INSTANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), instance) };
        guard
    }

    fn clear(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut()) };
        drop(guard);
    }

    #[test]
    fn the_slot_starts_null_like_the_uninitialized_holder_word() {
        let guard = INSTANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(unsafe { ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE)) }.is_null());
        drop(guard);
    }

    #[test]
    fn the_accessor_returns_the_published_instance() {
        let mut object = [0u8; 0xe8];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        assert_eq!(unsafe { service_manager_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_accessor_never_caches_and_follows_the_slot() {
        let mut first = [0u8; 0xe8];
        let mut second = [0u8; 0xe8];
        let guard = publish(first.as_mut_ptr());
        unsafe {
            assert_eq!(service_manager_instance(), first.as_mut_ptr());
            assert_eq!(service_manager_instance(), first.as_mut_ptr(), "repeat call");
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), second.as_mut_ptr());
            assert_eq!(
                service_manager_instance(),
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
        let mut storage = [0u8; 0xe9];
        let instance = unsafe { storage.as_mut_ptr().add(1) };
        let guard = publish(instance);
        assert_eq!(unsafe { service_manager_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_veneer_reaches_the_same_accessor() {
        let mut object = [0u8; 0xe8];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        unsafe {
            assert_eq!(service_manager_instance_veneer(), instance);
            assert_eq!(service_manager_instance_veneer(), service_manager_instance());
        }
        clear(guard);
    }

    #[test]
    fn the_veneer_is_a_distinct_symbol_from_its_target() {
        // The image has two separate entry points; an alias would make a
        // hook at 0x081391ec meaningless.
        assert_ne!(
            service_manager_instance_veneer as usize,
            service_manager_instance as usize
        );
    }

}
