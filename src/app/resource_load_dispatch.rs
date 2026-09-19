//! `resource_load_dispatch` — original: `FUN_08070884` @ 0x08070884 (128 bytes,
//! `0x08070884..0x08070903`; the next real function starts at 0x08070904).
//!
//! Raw decoding verifies four plain, unconditional `bl` instructions in the
//! body (`resource_op_dispatch` twice, state preparation, and index
//! normalization) and no predicated calls. The four inbound direct calls are
//! likewise plain `bl` instructions.
//!
//! Algorithm: when state flag `+0x24 & 0x100` is clear, bracket preparation
//! with resource operations `(9, 3, 0, 0)` and `(10, 3, 0, 0)`. A selector of
//! `-1` then succeeds. Otherwise normalize the selector; return `-1` on a
//! failed normalization, or tail-dispatch the resolved handler's `+0x0c` slot
//! with `(handler, state, payload)`.
//!
//! Deliberate deviations: host pointers use typed structures rather than the
//! target's physical four-byte function-pointer slots. Target builds retain
//! the stock callees and the final tail dispatch in one assembly fragment.

/// Host representation of the handler's target `+0x0c` virtual slot.
#[repr(C)]
pub struct ResourceLoadHandler {
    pub opaque_00: usize,
    pub opaque_04: usize,
    pub opaque_08: usize,
    pub dispatch: unsafe extern "C" fn(*mut ResourceLoadHandler, *mut u8, u32) -> u32,
}

/// Host seams for the three unported retailOS dependencies.
#[derive(Clone, Copy)]
pub struct ResourceLoadDispatchOps {
    pub resource_operation: unsafe extern "C" fn(u32, i32, u32, u32),
    pub prepare_state: unsafe extern "C" fn(*mut u8),
    pub normalize_selector: unsafe extern "C" fn(i32) -> i32,
    pub handler_for_selector: unsafe extern "C" fn(i32) -> *mut ResourceLoadHandler,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_resource_operation(_op: u32, _resource: i32, _arg0: u32, _arg1: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_prepare_state(_state: *mut u8) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_normalize_selector(_selector: i32) -> i32 { -1 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_handler_for_selector(_selector: i32) -> *mut ResourceLoadHandler {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_RESOURCE_LOAD_DISPATCH_OPS: ResourceLoadDispatchOps = ResourceLoadDispatchOps {
    resource_operation: missing_resource_operation,
    prepare_state: missing_prepare_state,
    normalize_selector: missing_normalize_selector,
    handler_for_selector: missing_handler_for_selector,
};
#[cfg(not(target_arch = "arm"))]
pub static mut RESOURCE_LOAD_DISPATCH_OPS: ResourceLoadDispatchOps = DEFAULT_RESOURCE_LOAD_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_load_dispatch(state: *mut u8, selector: i32, payload: u32) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LOAD_DISPATCH_OPS));
    if core::ptr::read_volatile(state.add(0x24).cast::<u32>()) & 0x100 == 0 {
        (ops.resource_operation)(9, 3, 0, 0);
        (ops.prepare_state)(state);
        (ops.resource_operation)(10, 3, 0, 0);
    }
    if selector == -1 {
        return 1;
    }
    let normalized = (ops.normalize_selector)(selector);
    if normalized == -1 {
        return u32::MAX;
    }
    let handler = (ops.handler_for_selector)(normalized);
    ((*handler).dispatch)(handler, state, payload)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .section .text.resource_load_dispatch,"ax",%progbits
    .global resource_load_dispatch
    .type resource_load_dispatch,%function
resource_load_dispatch:
    push {{r4,r5,r6,lr}}
    mov r4,r0
    ldr r0,[r0,#36]
    mov r6,r2
    tst r0,#256
    mov r5,r1
    bne 1f
    mov r3,#0
    mov r2,#0
    mov r1,#3
    mov r0,#9
    ldr ip,=0x08043b94
    blx ip
    mov r0,r4
    ldr ip,=0x080ce220
    blx ip
    mov r3,#0
    mov r2,#0
    mov r1,#3
    mov r0,#10
    ldr ip,=0x08043b94
    blx ip
1:  cmn r5,#1
    moveq r0,#1
    popeq {{r4,r5,r6,pc}}
    mov r0,r5
    ldr ip,=0x0806fdec
    blx ip
    cmn r0,#1
    popeq {{r4,r5,r6,pc}}
    ldr ip,=0x0806fdb4
    blx ip
    ldr r3,[r0,#12]
    mov r2,r6
    mov r1,r4
    pop {{r4,r5,r6,lr}}
    bx r3
"#);

#[cfg(test)]
mod tests {
    use super::*;

    static mut LOG: [u32; 8] = [0; 8];
    static mut LOG_LEN: usize = 0;
    static mut NORMALIZED: i32 = -1;
    static mut HANDLER: *mut ResourceLoadHandler = core::ptr::null_mut();
    static mut RECEIVED: (*mut u8, u32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn operation(op: u32, resource: i32, _arg0: u32, _arg1: u32) {
        unsafe { LOG[LOG_LEN] = (op << 8) | resource as u32; LOG_LEN += 1; }
    }
    unsafe extern "C" fn prepare(_state: *mut u8) { unsafe { LOG[LOG_LEN] = 0xfeed; LOG_LEN += 1; } }
    unsafe extern "C" fn normalize(_selector: i32) -> i32 { unsafe { NORMALIZED } }
    unsafe extern "C" fn resolve(_selector: i32) -> *mut ResourceLoadHandler { unsafe { HANDLER } }
    unsafe extern "C" fn dispatch(_handler: *mut ResourceLoadHandler, state: *mut u8, payload: u32) -> u32 {
        unsafe { RECEIVED = (state, payload); 0x72 }
    }

    unsafe fn install(handler: *mut ResourceLoadHandler, normalized: i32) {
        unsafe {
            LOG = [0; 8]; LOG_LEN = 0; RECEIVED = (core::ptr::null_mut(), 0);
            HANDLER = handler; NORMALIZED = normalized;
            RESOURCE_LOAD_DISPATCH_OPS = ResourceLoadDispatchOps { resource_operation: operation, prepare_state: prepare, normalize_selector: normalize, handler_for_selector: resolve };
        }
    }

    #[test]
    fn prepares_then_dispatches_normalized_selector() {
        let mut state = [0u32; 10];
        let mut handler = ResourceLoadHandler { opaque_00: 0, opaque_04: 0, opaque_08: 0, dispatch };
        unsafe {
            install(&mut handler, 4);
            assert_eq!(resource_load_dispatch(state.as_mut_ptr().cast(), 99, 0x55), 0x72);
            assert_eq!(&LOG[..LOG_LEN], &[0x903, 0xfeed, 0xa03]);
            assert_eq!(RECEIVED, (state.as_mut_ptr().cast(), 0x55));
        }
    }

    #[test]
    fn initialized_state_skips_preparation_and_minus_one_succeeds() {
        let mut state = [0u32; 10];
        state[9] = 0x100;
        unsafe {
            install(core::ptr::null_mut(), -1);
            assert_eq!(resource_load_dispatch(state.as_mut_ptr().cast(), -1, 0), 1);
            assert_eq!(LOG_LEN, 0);
        }
    }

    #[test]
    fn invalid_normalized_selector_returns_minus_one_after_preparation() {
        let mut state = [0u32; 10];
        unsafe {
            install(core::ptr::null_mut(), -1);
            assert_eq!(resource_load_dispatch(state.as_mut_ptr().cast(), 8, 0), u32::MAX);
            assert_eq!(&LOG[..LOG_LEN], &[0x903, 0xfeed, 0xa03]);
        }
    }
}
