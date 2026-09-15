//! `u16_be_vtable_dispatch` — original: `FUN_081667d8` @ `0x081667d8`
//! (68 bytes; next real function starts at `0x0816681c`).
//!
//! Verified call count: five plain unconditional `bl` callers and zero
//! predicated `bl` callers. The routine splits `message` into its big-endian
//! high and low bytes, invoking the receiver's vtable slot `+0xa4` once for
//! each. The second invocation is a tail dispatch in retailOS.
//!
//! The virtual target has no recovered identity in `names.yaml`, so this port
//! deliberately models it only as a byte-dispatch slot. The ARM build keeps
//! the exact instruction sequence in assembly; the host representation uses
//! native function pointers because host pointers are wider than retailOS
//! vtable words.

/// Receiver whose first word points at the byte-dispatch vtable.
#[repr(C)]
pub struct U16BeDispatchTarget {
    pub vtable: *const U16BeDispatchVtable,
}

/// Vtable portion decoded by [`u16_be_vtable_dispatch`].
#[repr(C)]
pub struct U16BeDispatchVtable {
    /// Slots `+0x00..+0xa0`, outside this port's recovered contract.
    pub unresolved_00_a0: [usize; 41],
    /// Slot `+0xa4`: receives the context and one byte of the message.
    pub dispatch_byte: unsafe extern "C" fn(
        this: *mut U16BeDispatchTarget,
        context: *mut u8,
        byte: u32,
    ),
}

/// Splits `message` into big-endian bytes and dispatches each through vtable
/// slot `+0xa4`; the low-byte dispatch is the retail function's tail call.
///
/// # Safety
/// `this` must be non-NULL and its vtable must provide a valid `+0xa4` byte
/// dispatch entry. `context` is forwarded without validation.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u16_be_vtable_dispatch(
    this: *mut U16BeDispatchTarget,
    context: *mut u8,
    message: u32,
) {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!((*(*this).vtable).dispatch_byte));
    dispatch(this, context, (message >> 8) & 0xff);
    dispatch(this, context, message & 0xff);
}

// Rust cannot represent the final tail virtual dispatch without introducing a
// local return edge. Preserve the raw ARM sequence for the firmware build.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl u16_be_vtable_dispatch
    .type u16_be_vtable_dispatch, %function
u16_be_vtable_dispatch:
    push    {{r4, r5, r6, lr}}
    mov     r4, r0
    and     r0, r2, #0xff00
    mov     r5, r2
    lsr     r2, r0, #8
    ldr     r0, [r4]
    mov     r6, r1
    ldr     r3, [r0, #0xa4]
    mov     r0, r4
    blx     r3
    ldr     r0, [r4]
    and     r2, r5, #0xff
    ldr     r3, [r0, #0xa4]
    mov     r0, r4
    mov     r1, r6
    pop     {{r4, r5, r6, lr}}
    bx      r3
    .size u16_be_vtable_dispatch, . - u16_be_vtable_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<std::vec::Vec<(usize, u32)>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_byte(
        _this: *mut U16BeDispatchTarget,
        context: *mut u8,
        byte: u32,
    ) {
        CALLS.lock().push((context as usize, byte));
    }

    #[test]
    fn dispatches_big_endian_bytes_in_order_and_preserves_context() {
        let _guard = TEST_LOCK.lock();
        CALLS.lock().clear();
        let vtable = U16BeDispatchVtable {
            unresolved_00_a0: [0; 41],
            dispatch_byte: record_byte,
        };
        let mut target = U16BeDispatchTarget { vtable: &vtable };
        let context = 0x1234usize as *mut u8;

        unsafe { u16_be_vtable_dispatch(&mut target, context, 0xabcd) };

        assert_eq!(*CALLS.lock(), [(context as usize, 0xab), (context as usize, 0xcd)]);
    }

    #[test]
    fn ignores_message_bits_above_the_low_u16() {
        let _guard = TEST_LOCK.lock();
        CALLS.lock().clear();
        let vtable = U16BeDispatchVtable {
            unresolved_00_a0: [0; 41],
            dispatch_byte: record_byte,
        };
        let mut target = U16BeDispatchTarget { vtable: &vtable };

        unsafe { u16_be_vtable_dispatch(&mut target, ptr::null_mut(), 0xfeed_0102) };

        assert_eq!(*CALLS.lock(), [(0, 1), (0, 2)]);
    }
}
