//! `selection_index_adjust` — original: `FUN_0819adfc` @ **0x0819adfc**
//! (100 bytes; true extent `0x0819adfc..0x0819ae60`, followed by the distinct
//! `FUN_0819ae60`).
//!
//! Raw `osos.dec` establishes the actual fall-through after the predicated
//! `popeq`: a zero delta returns the incoming r0; otherwise the function adds
//! the signed delta to object word +0xb0, wraps an out-of-range index to zero
//! for a positive delta or count - 1 otherwise, refreshes the selection, then
//! tail-calls the retail continuation with r0 = 1. The body has five plain
//! unconditional `bl` instructions (two to 0x080ffa00, then 0x0819ae74,
//! 0x082040ec, and 0x08203e48), no predicated `bl`, and a final plain `b` to
//! 0x081bb29c. Deliberate deviation: unknown retail callee identities remain
//! address-named host seams; target builds use literal veneers so relocated
//! payload code still reaches the observed addresses.

use core::ffi::c_void;

pub type RetailItemCount = unsafe extern "C" fn() -> u32;
pub type RetailRefreshSelection = unsafe extern "C" fn(*mut c_void);
pub type RetailSelectionContext = unsafe extern "C" fn() -> u32;
pub type RetailSetSelection = unsafe extern "C" fn(u32, u32);
pub type RetailContinuation = unsafe extern "C" fn(u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_count() -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_refresh(_: *mut c_void) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_context() -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_set_selection(_: u32, _: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_continuation(value: u32) -> u32 { value }

#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_ITEM_COUNT: RetailItemCount = missing_count;
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_REFRESH_SELECTION: RetailRefreshSelection = missing_refresh;
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_SELECTION_CONTEXT: RetailSelectionContext = missing_context;
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_SET_SELECTION: RetailSetSelection = missing_set_selection;
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_CONTINUATION: RetailContinuation = missing_continuation;

/// Adjusts the object's selected index and resumes the retail selection flow.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_index_adjust(object: *mut c_void, delta: i32) -> u32 {
    if delta == 0 {
        return object as usize as u32;
    }
    let index = object.cast::<u8>().add(0xb0).cast::<u32>();
    *index = (*index).wrapping_add(delta as u32);
    let count = core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_ITEM_COUNT))();
    if count <= *index {
        *index = if delta > 0 { 0 } else { count.wrapping_sub(1) };
    }
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_REFRESH_SELECTION))(object);
    let context = core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_SELECTION_CONTEXT))();
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_SET_SELECTION))(context, *index);
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_CONTINUATION))(1)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl selection_index_adjust
    .type selection_index_adjust, %function
selection_index_adjust:
    push    {{r4, r5, r6, lr}}
    movs    r5, r1
    mov     r4, r0
    popeq   {{r4, r5, r6, pc}}
    ldr     r0, [r4, #176]
    add     r0, r0, r5
    str     r0, [r4, #176]
    bl      retail_080ffa00
    ldr     r1, [r4, #176]
    cmp     r0, r1
    bhi     1f
    cmp     r5, #0
    movgt   r0, #0
    bgt     2f
    bl      retail_080ffa00
    sub     r0, r0, #1
2:  str     r0, [r4, #176]
1:  mov     r0, r4
    bl      retail_0819ae74
    bl      retail_082040ec
    ldr     r1, [r4, #176]
    bl      retail_08203e48
    pop     {{r4, r5, r6, lr}}
    mov     r0, #1
    b       retail_081bb29c
    .size selection_index_adjust, . - selection_index_adjust

retail_080ffa00:
    ldr     pc, [pc, #-4]
    .word   0x080ffa00
retail_0819ae74:
    ldr     pc, [pc, #-4]
    .word   0x0819ae74
retail_082040ec:
    ldr     pc, [pc, #-4]
    .word   0x082040ec
retail_08203e48:
    ldr     pc, [pc, #-4]
    .word   0x08203e48
retail_081bb29c:
    ldr     pc, [pc, #-4]
    .word   0x081bb29c
"#);

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut COUNT: u32 = 0;
    static mut REFRESHED: bool = false;
    static mut SET: (u32, u32) = (0, 0);
    static mut CONTINUATION_ARG: u32 = 0;
    unsafe extern "C" fn count() -> u32 { unsafe { COUNT } }
    unsafe extern "C" fn refresh(_: *mut c_void) { unsafe { REFRESHED = true } }
    unsafe extern "C" fn context() -> u32 { 0x2468_ace0 }
    unsafe extern "C" fn set(context: u32, index: u32) { unsafe { SET = (context, index) } }
    unsafe extern "C" fn continuation(value: u32) -> u32 { unsafe { CONTINUATION_ARG = value }; 0xa5a5_5a5a }

    #[test]
    fn zero_delta_preserves_r0_and_skips_retail_calls() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut object = [0u8; 0xb4];
        unsafe { REFRESHED = false; CONTINUATION_ARG = 0; }
        let returned = unsafe { selection_index_adjust(object.as_mut_ptr().cast(), 0) };
        assert_eq!(returned, object.as_mut_ptr() as usize as u32);
        assert!(!unsafe { REFRESHED });
        assert_eq!(unsafe { CONTINUATION_ARG }, 0);
    }

    #[test]
    fn wraps_positive_and_negative_out_of_range_indices() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            RETAIL_ITEM_COUNT = count; RETAIL_REFRESH_SELECTION = refresh;
            RETAIL_SELECTION_CONTEXT = context; RETAIL_SET_SELECTION = set; RETAIL_CONTINUATION = continuation;
            COUNT = 3; REFRESHED = false; SET = (0, 0); CONTINUATION_ARG = 0;
        }
        let mut object = [0u8; 0xb4];
        unsafe { *(object.as_mut_ptr().add(0xb0).cast::<u32>()) = 2; }
        assert_eq!(unsafe { selection_index_adjust(object.as_mut_ptr().cast(), 1) }, 0xa5a5_5a5a);
        assert_eq!(unsafe { *(object.as_ptr().add(0xb0).cast::<u32>()) }, 0);
        assert_eq!(unsafe { SET }, (0x2468_ace0, 0));
        unsafe { *(object.as_mut_ptr().add(0xb0).cast::<u32>()) = 0; COUNT = 3; }
        unsafe { selection_index_adjust(object.as_mut_ptr().cast(), -1); }
        assert_eq!(unsafe { *(object.as_ptr().add(0xb0).cast::<u32>()) }, 2);
        assert!(unsafe { REFRESHED });
        assert_eq!(unsafe { CONTINUATION_ARG }, 1);
    }
}
