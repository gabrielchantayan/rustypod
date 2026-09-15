//! `flagged_base_construct` — original: `FUN_081de250` @ `0x081de250` (32
//! bytes: 28 bytes of code plus its vtable literal). The next real function
//! begins at `0x081de270`.
//!
//! Raw decoding finds five inbound direct `bl` call sites, all unconditional;
//! there are no predicated `bl` call sites. The body has one unconditional
//! `bl`, at `0x081de254`, to the unported base constructor `0x08148600`.
//!
//! # Algorithm
//!
//! Constructs the base into caller-provided storage, replaces its vtable with
//! `0x0898e99c`, sets byte `+0x61` to one, and returns the base constructor's
//! returned `this` pointer. The four argument registers pass unchanged to the
//! base constructor.
//!
//! # Deliberate deviations
//!
//! The target export is the exact seven-word ARM implementation with a
//! relocation-safe literal veneer for the unported base constructor. Host
//! builds use a replaceable constructor seam because retailOS code at
//! `0x08148600` is not host-mapped.

/// ABI of the unported base constructor at `0x08148600`.
pub type BaseConstructor = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_constructor(this: *mut u8, _a1: u32, _a2: u32, _a3: u32) -> *mut u8 {
    this
}

/// Host seam for the base constructor at `0x08148600`.
#[cfg(not(target_os = "none"))]
pub static mut BASE_CONSTRUCTOR: BaseConstructor = missing_base_constructor;

/// flagged_base_construct — original: `FUN_081de250` @ `0x081de250` (32
/// bytes including literal; 5 inbound plain `bl`, 0 predicated `bl`).
#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_base_construct(
    this: *mut u8,
    arg1: u32,
    arg2: u32,
    arg3: u32,
) -> *mut u8 {
    let object = core::ptr::read_volatile(core::ptr::addr_of!(BASE_CONSTRUCTOR))(this, arg1, arg2, arg3);
    object.cast::<u32>().write_volatile(0x0898_e99c);
    object.add(0x61).write_volatile(1);
    object
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl flagged_base_construct
    .type flagged_base_construct, %function
flagged_base_construct:
    push    {{r4, lr}}
    bl      retail_base_construct
    ldr     r1, 1f
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #0x61]
    pop     {{r4, pc}}
1:  .word   0x0898e99c
    .size flagged_base_construct, . - flagged_base_construct

retail_base_construct:
    ldr     pc, [pc, #-4]
    .word   0x08148600
    .size retail_base_construct, . - retail_base_construct
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    static mut SEEN_ARGS: (usize, u32, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn recording_base_constructor(
        this: *mut u8,
        arg1: u32,
        arg2: u32,
        arg3: u32,
    ) -> *mut u8 {
        SEEN_ARGS = (this as usize, arg1, arg2, arg3);
        this.add(4).write_volatile(0xa5);
        this
    }

    #[test]
    fn installs_derived_state_after_base_construction() {
        unsafe {
            let mut storage = [0u32; 25];
            let object = storage.as_mut_ptr().cast::<u8>();
            BASE_CONSTRUCTOR = recording_base_constructor;
            let result = flagged_base_construct(object, 0x11, 0x22, 0x33);

            assert_eq!(result, object);
            assert_eq!(SEEN_ARGS, (object as usize, 0x11, 0x22, 0x33));
            assert_eq!(storage[0].to_le_bytes(), 0x0898_e99cu32.to_le_bytes());
            assert_eq!(object.add(4).read_volatile(), 0xa5);
            assert_eq!(object.add(0x61).read_volatile(), 1);
        }
    }
}
