//! `dispatch_if_optional_link_valid` — original: `FUN_08046ac8` @
//! `0x08046ac8` (84 bytes; true extent `0x08046ac8..0x08046b1c`, followed by
//! `store_u32_be_bytes` at `0x08046b1c`).
//!
//! Raw ARM contains one plain direct `bl` to `0x080dad3c`, no predicated
//! direct `bl` instructions, and one conditional tail branch to `0x080d189c`.
//! Algorithm: reject a null node, a node with a null first word, or a zero
//! dispatcher; then call the optional-link validator.  A nonzero validator
//! result tail-dispatches the original four arguments, otherwise returns zero.
//! Deliberate deviation: the two unported callees are exposed as host seams;
//! the ARM build retains their verified retail addresses and tail-call contract.

/// Validates that an optional link permits dispatching through `dispatcher`.
pub type OptionalLinkValidator = unsafe extern "C" fn(u32, *const u32) -> u32;
/// Performs the unported tree dispatch after validation.
pub type TreeDispatcher = unsafe extern "C" fn(*const u32, u32, *mut u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_optional_link_validator(_dispatcher: u32, _link: *const u32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_tree_dispatcher(_node: *const u32, _dispatcher: u32, _link: *mut u32, _value: u32) -> u32 { 0 }

/// Host-only replacements for retailOS `FUN_080dad3c` and `FUN_080d189c`.
#[cfg(not(target_arch = "arm"))]
pub static mut DISPATCH_IF_OPTIONAL_LINK_VALID_OPS: (OptionalLinkValidator, TreeDispatcher) =
    (missing_optional_link_validator, missing_tree_dispatcher);

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_if_optional_link_valid(
    node: *const u32,
    dispatcher: u32,
    link: *mut u32,
    value: u32,
) -> u32 {
    if node.is_null() || (*node).eq(&0) || dispatcher == 0 {
        return 0;
    }
    let (validate, dispatch) = core::ptr::read_volatile(core::ptr::addr_of!(DISPATCH_IF_OPTIONAL_LINK_VALID_OPS));
    if validate(dispatcher, link) == 0 {
        return 0;
    }
    dispatch(node, dispatcher, link, value)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_if_optional_link_valid
    .type dispatch_if_optional_link_valid, %function
dispatch_if_optional_link_valid:
    push    {{r4, r5, r6, r7, r8, lr}}
    movs    r4, r0
    ldrne   r0, [r4]
    mov     r5, r1
    cmpne   r0, #0
    cmpne   r5, #0
    mov     r7, r3
    mov     r6, r2
    beq     1f
    mov     r1, r6
    mov     r0, r5
    bl      0x080dad3c
    cmp     r0, #0
    movne   r3, r7
    movne   r2, r6
    movne   r1, r5
    movne   r0, r4
    popne  {{r4, r5, r6, r7, r8, lr}}
    bne     0x080d189c
1:  mov     r0, #0
    pop     {{r4, r5, r6, r7, r8, pc}}
    .size dispatch_if_optional_link_valid, . - dispatch_if_optional_link_valid
"#
);

#[cfg(test)]
mod tests {
    use super::{dispatch_if_optional_link_valid, OptionalLinkValidator, TreeDispatcher, DISPATCH_IF_OPTIONAL_LINK_VALID_OPS};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATOR_CALLS: u32 = 0;
    static mut DISPATCH_CALLS: u32 = 0;
    static mut DISPATCH_ARGS: (*const u32, u32, *mut u32, u32) = (core::ptr::null(), 0, core::ptr::null_mut(), 0);

    unsafe extern "C" fn rejecting_validator(_dispatcher: u32, _link: *const u32) -> u32 {
        VALIDATOR_CALLS += 1;
        0
    }
    unsafe extern "C" fn accepting_validator(_dispatcher: u32, _link: *const u32) -> u32 {
        VALIDATOR_CALLS += 1;
        1
    }
    unsafe extern "C" fn recording_dispatcher(node: *const u32, dispatcher: u32, link: *mut u32, value: u32) -> u32 {
        DISPATCH_CALLS += 1;
        DISPATCH_ARGS = (node, dispatcher, link, value);
        0x5a
    }

    struct OpsRestore((OptionalLinkValidator, TreeDispatcher));
    impl Drop for OpsRestore {
        fn drop(&mut self) { unsafe { DISPATCH_IF_OPTIONAL_LINK_VALID_OPS = self.0; } }
    }
    fn install(validator: OptionalLinkValidator) -> OpsRestore {
        unsafe {
            let previous = DISPATCH_IF_OPTIONAL_LINK_VALID_OPS;
            DISPATCH_IF_OPTIONAL_LINK_VALID_OPS = (validator, recording_dispatcher);
            VALIDATOR_CALLS = 0;
            DISPATCH_CALLS = 0;
            DISPATCH_ARGS = (core::ptr::null(), 0, core::ptr::null_mut(), 0);
            OpsRestore(previous)
        }
    }

    #[test]
    fn invalid_inputs_return_zero_without_validation() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install(accepting_validator);
        let null_first_word = [0u32];
        assert_eq!(unsafe { dispatch_if_optional_link_valid(core::ptr::null(), 3, core::ptr::null_mut(), 4) }, 0);
        assert_eq!(unsafe { dispatch_if_optional_link_valid(null_first_word.as_ptr(), 3, core::ptr::null_mut(), 4) }, 0);
        assert_eq!(unsafe { dispatch_if_optional_link_valid([1u32].as_ptr(), 0, core::ptr::null_mut(), 4) }, 0);
        assert_eq!(unsafe { VALIDATOR_CALLS }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn rejected_link_returns_zero_without_dispatch() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install(rejecting_validator);
        let node = [1u32];
        assert_eq!(unsafe { dispatch_if_optional_link_valid(node.as_ptr(), 3, core::ptr::null_mut(), 4) }, 0);
        assert_eq!(unsafe { VALIDATOR_CALLS }, 1);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn accepted_link_forwards_original_arguments_and_result() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install(accepting_validator);
        let node = [1u32];
        let mut link = [0u32; 2];
        assert_eq!(unsafe { dispatch_if_optional_link_valid(node.as_ptr(), 0x1234, link.as_mut_ptr(), 0x5678) }, 0x5a);
        assert_eq!(unsafe { VALIDATOR_CALLS }, 1);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { DISPATCH_ARGS }, (node.as_ptr(), 0x1234, link.as_mut_ptr(), 0x5678));
    }
}
