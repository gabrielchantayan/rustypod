//! `vtable_slot_1bc_context_dispatch` — original: `FUN_081688e4` @
//! `0x081688e4` (48 bytes; true extent `0x081688e4..0x08168914`, followed
//! by the separately entered `FUN_08168914`). Ghidra's 216-byte extent absorbs
//! `FUN_08168914`; raw firmware words establish the actual boundary.
//!
//! Raw ARM decoding finds no direct `bl` instructions or predicated direct
//! `bl` forms in the body; its sole call is the unconditional indirect `blx`
//! through vtable slot `+0x1bc`. Full-image decoding finds one inbound plain
//! `bl` (`0x0812f964`) and no predicated inbound forms; the other two Ghidra
//! call sites land in the mistakenly absorbed adjacent function.
//!
//! Algorithm: call `object`'s unresolved vtable slot `+0x1bc` with `object`,
//! then tail-transfer `(output, prototype, returned_context)` to the retail
//! helper at `0x08168838`. The callee's semantic identity does not survive,
//! so its verified address is retained rather than inventing a name.
//!
//! Deliberate deviation: Rust returns after the retail call rather than using
//! the ARM `b` tail transfer. The tail target is not ported; target builds call
//! its verified fixed address, while host tests replace it with a callback.

use core::mem;

const CONTEXT_VTABLE_SLOT: usize = 0x1bc / 4;

type ContextGetter = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Retail08168838 = unsafe extern "C" fn(*mut u8, *const u8, *mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_08168838(_output: *mut u8, _prototype: *const u8, _context: *mut u8) {}

/// Host-only replacement for the unported retail tail target at `0x08168838`.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_08168838: Retail08168838 = missing_retail_08168838;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn dispatch_slot_1bc(object: *mut u8) -> *mut u8 {
    let vtable = object.cast::<*const usize>().read();
    let getter: ContextGetter = mem::transmute(vtable.add(CONTEXT_VTABLE_SLOT).read());
    getter(object)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch_slot_1bc(object: *mut u8) -> *mut u8 {
    let vtable = object.cast::<*const *const usize>().read();
    let getter: ContextGetter = mem::transmute(vtable.add(CONTEXT_VTABLE_SLOT).read());
    getter(object)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_08168838(output: *mut u8, prototype: *const u8, context: *mut u8) {
    let retail: Retail08168838 = mem::transmute(0x0816_8838usize);
    retail(output, prototype, context);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn retail_08168838(output: *mut u8, prototype: *const u8, context: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_08168838))(output, prototype, context);
}

/// Dispatches an object's vtable slot `+0x1bc` and forwards its result to the
/// retail context helper.
///
/// # Safety
/// `object` must point to an object with a readable vtable and callable slot
/// `+0x1bc`; `output`, `prototype`, and the returned context must satisfy the
/// unchecked contract of retail helper `0x08168838`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_1bc_context_dispatch(
    output: *mut u8,
    prototype: *const u8,
    object: *mut u8,
) {
    let context = dispatch_slot_1bc(object);
    retail_08168838(output, prototype, context);
}

#[cfg(test)]
mod tests {
    use super::{vtable_slot_1bc_context_dispatch, ContextGetter, Retail08168838, RETAIL_08168838, CONTEXT_VTABLE_SLOT};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut RETAIL_ARGS: (*mut u8, *const u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());
    static mut RETURNED_CONTEXT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn getter(object: *mut u8) -> *mut u8 {
        unsafe {
            GETTER_OBJECT = object;
            RETURNED_CONTEXT
        }
    }

    unsafe extern "C" fn retail(output: *mut u8, prototype: *const u8, context: *mut u8) {
        unsafe { RETAIL_ARGS = (output, prototype, context); }
    }

    struct RetailRestore(Retail08168838);

    impl Drop for RetailRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_08168838 = self.0; }
        }
    }

    #[test]
    fn forwards_virtual_context_and_original_arguments() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_08168838;
            RETAIL_08168838 = retail;
            GETTER_OBJECT = core::ptr::null_mut();
            RETAIL_ARGS = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());
            RetailRestore(previous)
        };
        let mut vtable = [0usize; CONTEXT_VTABLE_SLOT + 1];
        vtable[CONTEXT_VTABLE_SLOT] = getter as ContextGetter as usize;
        let mut object = vtable.as_ptr();
        let mut output = 0u8;
        let prototype = [0x51u8; 1];
        let mut context = 0x7au8;
        unsafe {
            RETURNED_CONTEXT = core::ptr::addr_of_mut!(context);
            vtable_slot_1bc_context_dispatch(
                core::ptr::addr_of_mut!(output),
                prototype.as_ptr(),
                core::ptr::addr_of_mut!(object).cast(),
            );
        }
        assert_eq!(unsafe { GETTER_OBJECT }, core::ptr::addr_of_mut!(object).cast());
        assert_eq!(unsafe { RETAIL_ARGS }, (core::ptr::addr_of_mut!(output), prototype.as_ptr(), core::ptr::addr_of_mut!(context)));
    }
}
