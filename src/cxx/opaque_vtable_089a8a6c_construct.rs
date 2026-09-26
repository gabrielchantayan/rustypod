//! `opaque_vtable_089a8a6c_construct` — retailOS `FUN_083e71bc` @
//! **0x083e71bc** (28 bytes: 24 instruction bytes plus the vtable literal at
//! 0x083e71d4).
//!
//! Raw words establish six instruction words at 0x083e71bc..0x083e71d0 and
//! literal-pool word 0x089a8a6c at 0x083e71d4; `push {r4,r5,r6,lr}` at
//! 0x083e71d8 begins the next independently entered function. There are two
//! inbound plain `bl` calls, at 0x083b63b8 and 0x083b63d0, and no inbound
//! predicated `bl` calls.
//! The body has one plain `bl`, to base constructor 0x082a89b4, and no
//! predicated `bl` calls.
//!
//! # Algorithm
//!
//! Call the opaque base constructor with the incoming `this` and value plus
//! the fixed kind 0x80, replace word +0x00 of its returned object with
//! 0x089a8a6c, then return that object. The class identity and full base layout
//! are unrecovered, so neither is invented. Deliberate host deviation: the
//! unported base constructor is a replaceable seam; target builds use the
//! verified direct retail call.

const RETAIL_BASE_CONSTRUCT_ADDRESS: usize = 0x082a_89b4;
/// Vtable-like literal installed after opaque base construction.
pub const OPAQUE_VTABLE_089A8A6C: u32 = 0x089a_8a6c;

/// ABI of the still-retail base constructor at `0x082a89b4`.
pub type OpaqueBaseConstruct = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(_: *mut u8, _: u32, _: u32) -> *mut u8 {
    panic!("opaque_vtable_089a8a6c_construct requires base constructor 0x082a89b4")
}

/// Host boundary for the unported base constructor.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_BASE_CONSTRUCT: OpaqueBaseConstruct = missing_base_construct;

/// Constructs the opaque derived object and returns the base constructor result.
///
/// # Safety
///
/// `this` must satisfy the opaque base constructor's storage contract, and its
/// returned pointer must identify at least one writable, word-aligned target word.
#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_vtable_089a8a6c_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_089a8a6c_construct(this: *mut u8, value: u32) -> *mut u8 {
    let construct = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_BASE_CONSTRUCT)) };
    let constructed = unsafe { construct(this, value, 0x80) };
    unsafe { constructed.cast::<u32>().write_volatile(OPAQUE_VTABLE_089A8A6C) };
    constructed
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl opaque_vtable_089a8a6c_construct
    .type opaque_vtable_089a8a6c_construct, %function
opaque_vtable_089a8a6c_construct:
    mov     r2, #128
    str     lr, [sp, #-4]!
    bl      retail_opaque_base_construct
    ldr     r1, 1f
    str     r1, [r0]
    ldr     pc, [sp], #4
2:
1:  .word   0x089a8a6c
    .size opaque_vtable_089a8a6c_construct, 2b - opaque_vtable_089a8a6c_construct

retail_opaque_base_construct:
    ldr     pc, [pc, #-4]
    .word   0x082a89b4
    .size retail_opaque_base_construct, . - retail_opaque_base_construct
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_ARGUMENTS: (*mut u8, u32, u32) = (core::ptr::null_mut(), 0, 0);
    static mut BASE_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_base_construct(this: *mut u8, value: u32, kind: u32) -> *mut u8 {
        unsafe {
            addr_of_mut!(BASE_ARGUMENTS).write((this, value, kind));
            BASE_RETURN
        }
    }

    struct Reset { _lock: MutexGuard<'static, ()>, base: OpaqueBaseConstruct }
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { OPAQUE_BASE_CONSTRUCT = self.base; }
        }
    }
    fn reset() -> Reset {
        let lock = LOCK.lock();
        unsafe {
            let reset = Reset { _lock: lock, base: OPAQUE_BASE_CONSTRUCT };
            OPAQUE_BASE_CONSTRUCT = recording_base_construct;
            BASE_ARGUMENTS = (core::ptr::null_mut(), 0, 0);
            BASE_RETURN = core::ptr::null_mut();
            reset
        }
    }

    #[test]
    fn forwards_value_and_installs_the_derived_vtable() {
        let _reset = reset();
        let mut object = [0x1111_1111u32, 0x2222_2222];
        unsafe {
            addr_of_mut!(BASE_RETURN).write(object.as_mut_ptr().cast());
            let returned = opaque_vtable_089a8a6c_construct(object.as_mut_ptr().cast(), 0x1357_9bdf);
            assert_eq!(addr_of!(BASE_ARGUMENTS).read(), (object.as_mut_ptr().cast(), 0x1357_9bdf, 0x80));
            assert_eq!(returned, object.as_mut_ptr().cast());
            assert_eq!(object, [OPAQUE_VTABLE_089A8A6C, 0x2222_2222]);
        }
    }

    #[test]
    fn writes_the_base_returned_object_not_the_input() {
        let _reset = reset();
        let mut input = [0x1111_1111u32];
        let mut returned_object = [0x2222_2222u32];
        unsafe {
            addr_of_mut!(BASE_RETURN).write(returned_object.as_mut_ptr().cast());
            assert_eq!(opaque_vtable_089a8a6c_construct(input.as_mut_ptr().cast(), 0), returned_object.as_mut_ptr().cast());
            assert_eq!(addr_of!(BASE_ARGUMENTS).read(), (input.as_mut_ptr().cast(), 0, 0x80));
            assert_eq!(input[0], 0x1111_1111);
            assert_eq!(returned_object[0], OPAQUE_VTABLE_089A8A6C);
        }
    }
}
