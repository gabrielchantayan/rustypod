//! Three-mode refcounted-handle callback dispatcher.
//!
//! `handle_callback_dispatch` — original: `FUN_08131e00` @ **0x08131e00**
//! (132 bytes). Raw osos.dec establishes the body through `bx r3` at
//! 0x08131e80; the following word is a literal and the next function starts at
//! 0x08131e88. Decoding the body finds three plain, unconditional direct `bl`
//! instructions, all to `handle_deref_or_null_alias_6190` @ 0x083d6190, and
//! zero predicated `bl` forms. There are five inbound direct `bl` call sites.
//!
//! # Algorithm
//!
//! Selects one of three unrecovered virtual callbacks at target vtable offsets
//! +0x164, +0x168, and +0x16c from the implementation held through
//! `owner+0x28`, then calls it with `(implementation, callback.value, context)`.
//! Modes outside 0..=2 tail-branch to the unrecovered failure path at
//! 0x0814459c with `(context, &literal)`, so they do not reach a callback.
//!
//! # Deliberate deviation
//!
//! The target failure path remains unported and its identity is not inferred.
//! Target builds branch to its verified address; host builds panic after proving
//! invalid modes do not dispatch. ARM vtable entries are four bytes, while host
//! callback pointers use pointer-width cells.

use crate::cxx::handle::handle_deref_or_null;

const CALLBACK_SLOT_BASE: usize = 0x164 / 4;
#[cfg(target_os = "none")]
static INVALID_MODE_LITERAL: u32 = 0;


type HandleCallback = unsafe extern "C" fn(*mut u8, u32, *mut u8);

#[repr(C)]
pub struct HandleCallbackRequest {
    pub value: u32,
    pub mode: u8,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invalid_callback_mode(context: *mut u8) -> ! {
    let failure: unsafe extern "C" fn(*mut u8, *const u8) -> ! =
        unsafe { core::mem::transmute(0x0814_459cusize) };
    unsafe { failure(context, core::ptr::addr_of!(INVALID_MODE_LITERAL).cast()) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invalid_callback_mode(_context: *mut u8) -> ! {
    panic!("retailOS handle callback mode is outside 0..=2")
}

/// Dispatches the selected callback of the implementation held by `owner`.
///
/// # Safety
/// `owner+0x28` must be a readable refcounted-handle slot. Its non-NULL body,
/// implementation, vtable, and selected callback must be live and valid. The
/// request and context have the ABI expected by that unrecovered callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.handle_callback_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn handle_callback_dispatch(
    owner: *mut u8,
    request: *const HandleCallbackRequest,
    context: *mut u8,
) {
    let mode = unsafe { (*request).mode };
    if mode > 2 {
        unsafe { invalid_callback_mode(context) };
    }

    let handle_slot = unsafe { owner.add(0x28) as *const *const *mut u8 };
    let implementation = unsafe { handle_deref_or_null(handle_slot) };
    let vtable = unsafe { (implementation as *const *const usize).read() };
    let entry = unsafe { vtable.add(CALLBACK_SLOT_BASE + mode as usize).read() };
    let callback: HandleCallback = unsafe { core::mem::transmute(entry) };
    unsafe { callback(implementation, (*request).value, context) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static VALUE: AtomicU32 = AtomicU32::new(0);
    static CONTEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_slot_0(_implementation: *mut u8, value: u32, context: *mut u8) {
        SLOT.store(0, Ordering::SeqCst);
        VALUE.store(value, Ordering::SeqCst);
        CONTEXT.store(context as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn record_slot_1(_implementation: *mut u8, value: u32, context: *mut u8) {
        SLOT.store(1, Ordering::SeqCst);
        VALUE.store(value, Ordering::SeqCst);
        CONTEXT.store(context as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn record_slot_2(_implementation: *mut u8, value: u32, context: *mut u8) {
        SLOT.store(2, Ordering::SeqCst);
        VALUE.store(value, Ordering::SeqCst);
        CONTEXT.store(context as usize, Ordering::SeqCst);
    }

    #[test]
    fn dispatches_each_mode_to_its_target_vtable_slot() {
        let mut vtable = [0usize; CALLBACK_SLOT_BASE + 3];
        vtable[CALLBACK_SLOT_BASE] = record_slot_0 as usize;
        vtable[CALLBACK_SLOT_BASE + 1] = record_slot_1 as usize;
        vtable[CALLBACK_SLOT_BASE + 2] = record_slot_2 as usize;
        let mut implementation = [vtable.as_ptr() as usize];
        let mut body = [implementation.as_mut_ptr() as usize];
        let mut owner = [0usize; 8];
        unsafe { (owner.as_mut_ptr() as *mut u8).add(0x28).cast::<usize>().write(body.as_mut_ptr() as usize) };
        let mut context = 0u8;

        for mode in 0..=2 {
            SLOT.store(usize::MAX, Ordering::SeqCst);
            let request = HandleCallbackRequest { value: 0xa5a5_0000 | mode, mode: mode as u8 };
            unsafe { handle_callback_dispatch(owner.as_mut_ptr().cast(), &request, &mut context) };
            assert_eq!(SLOT.load(Ordering::SeqCst), mode as usize);
            assert_eq!(VALUE.load(Ordering::SeqCst), request.value);
            assert_eq!(CONTEXT.load(Ordering::SeqCst), &mut context as *mut u8 as usize);
        }
    }

}
