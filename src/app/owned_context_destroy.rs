//! Destruction transition for an owned application context.

/// `owned_context_destroy` — original: `FUN_0817e0fc` @ **0x0817e0fc**
/// (100 bytes, `0x0817e0fc..0x0817e15f`; the next independently entered
/// function begins at `0x0817e160`). Raw ARM has **four plain unconditional
/// `bl` instructions** and no predicated `bl` forms. Three inbound plain `bl`
/// sites are at 0x0817c000, 0x0817ccd4, and 0x0817d8bc.
///
/// The first byte is a destruction state: state 5 is already complete and
/// returns untouched. Otherwise the function prepares the embedded scoped
/// context at +4 using the requested value, checks the owner's capability bit
/// 2, optionally substitutes the owner's +0x60 value after a successful
/// preparation, applies the selected value, then stores state 6.
///
/// Deliberate deviations: the three unrecovered direct callee contracts remain
/// target-address calls on firmware builds and narrow recording seams on host
/// builds. The existing port of `FUN_082a2ac0` is likewise reached through a
/// seam here, avoiding host pointer-width assumptions for the target's +4
/// scoped-context subobject.

const CONTEXT_OFFSET: usize = 4;
const DESTROY_COMPLETE_STATE: u8 = 5;
const DESTROYING_STATE: u8 = 6;
const CONTEXT_PREPARE_ADDRESS: usize = 0x0826_ffec;
const OWNER_CAPABILITY_BIT_2_ADDRESS: usize = 0x082a_2ac0;
const OWNER_VALUE_ADDRESS: usize = 0x082a_2de4;
const CONTEXT_APPLY_VALUE_ADDRESS: usize = 0x0826_fd38;

type ContextPrepare = unsafe extern "C" fn(*mut u8, u32) -> u32;
type OwnerCapabilityBit2 = unsafe extern "C" fn(*mut u8) -> u32;
type OwnerValue = unsafe extern "C" fn(*mut u8) -> u32;
type ContextApplyValue = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_prepare(context: *mut u8, value: u32) -> u32 {
    let call: ContextPrepare = core::mem::transmute(CONTEXT_PREPARE_ADDRESS);
    call(context, value)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_capability_bit_2(context: *mut u8) -> u32 {
    let call: OwnerCapabilityBit2 = core::mem::transmute(OWNER_CAPABILITY_BIT_2_ADDRESS);
    call(context)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_value(context: *mut u8) -> u32 {
    let call: OwnerValue = core::mem::transmute(OWNER_VALUE_ADDRESS);
    call(context)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_apply_value(context: *mut u8, value: u32) {
    let call: ContextApplyValue = core::mem::transmute(CONTEXT_APPLY_VALUE_ADDRESS);
    call(context, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_context: *mut u8, _value: u32) -> u32 { panic!("owned_context_destroy requires 0x0826ffec") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_capability(_context: *mut u8) -> u32 { panic!("owned_context_destroy requires 0x082a2ac0") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_value(_context: *mut u8) -> u32 { panic!("owned_context_destroy requires 0x082a2de4") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_apply(_context: *mut u8, _value: u32) { panic!("owned_context_destroy requires 0x0826fd38") }

/// Host replacements for the four direct retailOS calls.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct OwnedContextDestroyOps {
    pub prepare: ContextPrepare,
    pub owner_capability_bit_2: OwnerCapabilityBit2,
    pub owner_value: OwnerValue,
    pub apply_value: ContextApplyValue,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_OWNED_CONTEXT_DESTROY_OPS: OwnedContextDestroyOps = OwnedContextDestroyOps {
    prepare: missing_prepare,
    owner_capability_bit_2: missing_capability,
    owner_value: missing_owner_value,
    apply_value: missing_apply,
};

/// Target builds call the original direct callees; host tests install this seam.
#[cfg(not(target_os = "none"))]
pub static mut OWNED_CONTEXT_DESTROY_OPS: OwnedContextDestroyOps = DEFAULT_OWNED_CONTEXT_DESTROY_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_prepare(context: *mut u8, value: u32) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(OWNED_CONTEXT_DESTROY_OPS.prepare)))(context, value)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn owner_capability_bit_2(context: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(OWNED_CONTEXT_DESTROY_OPS.owner_capability_bit_2)))(context)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn owner_value(context: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(OWNED_CONTEXT_DESTROY_OPS.owner_value)))(context)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_apply_value(context: *mut u8, value: u32) {
    (core::ptr::read_volatile(core::ptr::addr_of!(OWNED_CONTEXT_DESTROY_OPS.apply_value)))(context, value)
}

/// # Safety
///
/// `owned_context` must point to a writable retailOS owned-context allocation
/// whose embedded scoped context starts at +4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_context_destroy(owned_context: *mut u8, requested_value: u32) {
    if owned_context.read() == DESTROY_COMPLETE_STATE { return; }

    let context = owned_context.add(CONTEXT_OFFSET);
    let prepared = context_prepare(context, requested_value);
    let mut value = requested_value;
    if owner_capability_bit_2(context) != 0 {
        if prepared != 0 { value = owner_value(context); }
        context_apply_value(context, value);
    }
    owned_context.write(DESTROYING_STATE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PREPARED: u32 = 0;
    static mut CAPABLE: u32 = 0;
    static mut OWNER_VALUE: u32 = 0;
    static mut PREPARE_ARGS: (usize, u32) = (0, 0);
    static mut OWNER_VALUE_CALLS: u32 = 0;
    static mut APPLY_ARGS: (usize, u32) = (0, 0);

    unsafe extern "C" fn prepare(context: *mut u8, value: u32) -> u32 { PREPARE_ARGS = (context as usize, value); PREPARED }
    unsafe extern "C" fn capable(_context: *mut u8) -> u32 { CAPABLE }
    unsafe extern "C" fn owner_value(_context: *mut u8) -> u32 { OWNER_VALUE_CALLS += 1; OWNER_VALUE }
    unsafe extern "C" fn apply(context: *mut u8, value: u32) { APPLY_ARGS = (context as usize, value); }

    unsafe fn install(prepared: u32, capability: u32, owner_value_result: u32) {
        PREPARED = prepared; CAPABLE = capability; OWNER_VALUE = owner_value_result;
        PREPARE_ARGS = (0, 0); OWNER_VALUE_CALLS = 0; APPLY_ARGS = (0, 0);
        OWNED_CONTEXT_DESTROY_OPS = OwnedContextDestroyOps { prepare, owner_capability_bit_2: capable, owner_value, apply_value: apply };
    }

    #[test]
    fn complete_state_skips_every_callee() {
        let _lock = TEST_LOCK.lock();
        let mut context = [0u8; 32]; context[0] = DESTROY_COMPLETE_STATE;
        unsafe { install(1, 1, 9); owned_context_destroy(context.as_mut_ptr(), 7); }
        unsafe { assert_eq!(PREPARE_ARGS, (0, 0)); assert_eq!(APPLY_ARGS, (0, 0)); assert_eq!(context[0], DESTROY_COMPLETE_STATE); }
    }

    #[test]
    fn applies_requested_or_owner_value_only_for_capable_contexts() {
        let _lock = TEST_LOCK.lock();
        let mut context = [0u8; 32];
        unsafe {
            install(0, 0, 99); owned_context_destroy(context.as_mut_ptr(), 7);
            assert_eq!(PREPARE_ARGS, (context.as_mut_ptr().add(4) as usize, 7)); assert_eq!(APPLY_ARGS, (0, 0)); assert_eq!(context[0], DESTROYING_STATE);
            context[0] = 0; install(0, 1, 99); owned_context_destroy(context.as_mut_ptr(), 7);
            assert_eq!(OWNER_VALUE_CALLS, 0); assert_eq!(APPLY_ARGS, (context.as_mut_ptr().add(4) as usize, 7));
            context[0] = 0; install(1, 1, 99); owned_context_destroy(context.as_mut_ptr(), 7);
            assert_eq!(OWNER_VALUE_CALLS, 1); assert_eq!(APPLY_ARGS, (context.as_mut_ptr().add(4) as usize, 99)); assert_eq!(context[0], DESTROYING_STATE);
        }
    }
}
