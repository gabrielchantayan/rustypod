//! Gate an opaque component, rearm the class-0x8c00 timeout, and continue.
//!
//! `component_gate_rearm_continue` — original: `FUN_0811666c` @ **0x0811666c**.
//! Raw `osos.dec` establishes the true 68-byte A32 body
//! `0x0811666c..0x0811666caf`; `0x0811666cb0` is its `0x1d4c0` literal and
//! `0x0811666cb4` begins the next real function. Ghidra's 192-byte extent
//! incorrectly absorbs the tail target. The body has two unconditional direct
//! `bl` calls, zero predicated direct `bl` calls, and one indirect `blx` through
//! the component vtable's `+0x9c` slot.
//!
//! It returns when `owner+0x4d2` is set or the component's virtual gate returns
//! zero. Otherwise it gets the class-0x8c00 singleton, rearms its two-minute
//! timer, then tail-branches to the as-yet-unported `0x08115f38` continuation.
//! Deliberate deviations: Rust expresses the tail branch as a call; host builds
//! use explicit seams for the two otherwise-ported calls and the unported
//! continuation, while target builds call the verified retail addresses.

const COMPONENT_WORD: usize = 0x430 / 4;
const COMPONENT_GATE_SLOT: usize = 0x9c / 4;
const REARM_DELAY_MS: u32 = 0x1d4c0;
const RETAIL_CONTINUATION: usize = 0x0811_5f38;

type ComponentGate = unsafe extern "C" fn(*mut u8) -> u32;
type SingletonClass8c00 = unsafe extern "C" fn() -> *mut u8;
type RearmTimer = unsafe extern "C" fn(*mut u8, u32);
type Continue = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn component_at(owner: *mut u8) -> *mut u8 {
    unsafe { (owner.add(0x430) as *const *mut u8).read() }
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn component_at(owner: *mut u8) -> *mut u8 {
    unsafe { (owner as *const *mut u8).add(COMPONENT_WORD).read() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn component_gate(component: *mut u8) -> ComponentGate {
    let vtable = unsafe { (component as *const *const u8).read() };
    unsafe { (vtable.add(0x9c) as *const ComponentGate).read() }
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn component_gate(component: *mut u8) -> ComponentGate {
    let vtable = unsafe { (component as *const *const usize).read() };
    unsafe { core::mem::transmute(vtable.add(COMPONENT_GATE_SLOT).read()) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_singleton() -> *mut u8 { unsafe { crate::app::singletons::singleton_class_8c00() } }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn rearm_timer(object: *mut u8) { unsafe { crate::app::class_8c00::class_8c00_rearm_timer_post_0x11(object, REARM_DELAY_MS) } }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn continue_after_gate(owner: *mut u8) {
    let continuation: Continue = unsafe { core::mem::transmute(RETAIL_CONTINUATION) };
    unsafe { continuation(owner) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_singleton() -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rearm(_object: *mut u8, _delay: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_continuation(_owner: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ComponentGateRearmContinueOps {
    pub singleton: SingletonClass8c00,
    pub rearm_timer: RearmTimer,
    pub continuation: Continue,
}
#[cfg(not(target_os = "none"))]
pub static mut COMPONENT_GATE_REARM_CONTINUE_OPS: ComponentGateRearmContinueOps = ComponentGateRearmContinueOps {
    singleton: missing_singleton,
    rearm_timer: missing_rearm,
    continuation: missing_continuation,
};

/// Performs the component gate and starts its follow-on flow.
///
/// # Safety
/// `owner` must have a readable flag at `+0x4d2`, an opaque component pointer
/// at `+0x430`, and a callable component vtable slot `+0x9c` when the flag is
/// clear. Target continuation preconditions are inherited unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn component_gate_rearm_continue(owner: *mut u8) {
    if unsafe { owner.add(0x4d2).read_volatile() } != 0 { return; }
    let component = unsafe { component_at(owner) };
    if unsafe { component_gate(component)(component) } == 0 { return; }
    #[cfg(target_os = "none")]
    let singleton = unsafe { invoke_singleton() };
    #[cfg(not(target_os = "none"))]
    let singleton = unsafe { (COMPONENT_GATE_REARM_CONTINUE_OPS.singleton)() };
    #[cfg(target_os = "none")]
    unsafe { rearm_timer(singleton) };
    #[cfg(not(target_os = "none"))]
    unsafe { (COMPONENT_GATE_REARM_CONTINUE_OPS.rearm_timer)(singleton, REARM_DELAY_MS) };
    #[cfg(target_os = "none")]
    unsafe { continue_after_gate(owner) };
    #[cfg(not(target_os = "none"))]
    unsafe { (COMPONENT_GATE_REARM_CONTINUE_OPS.continuation)(owner) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut GATE_RESULT: u32 = 0;
    static mut GATE_CALLS: u32 = 0;
    static mut REARM: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut CONTINUATION: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn gate(_component: *mut u8) -> u32 { unsafe { GATE_CALLS += 1; GATE_RESULT } }
    unsafe extern "C" fn singleton() -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn rearm(object: *mut u8, delay: u32) { unsafe { REARM = (object, delay) } }
    unsafe extern "C" fn continuation(owner: *mut u8) { unsafe { CONTINUATION = owner } }
    #[test]
    fn skips_set_flag_and_closed_gate_but_rearms_then_continues_when_open() {
        let _lock = LOCK.lock();
        let old = unsafe { COMPONENT_GATE_REARM_CONTINUE_OPS };
        unsafe { COMPONENT_GATE_REARM_CONTINUE_OPS = ComponentGateRearmContinueOps { singleton, rearm_timer: rearm, continuation }; GATE_CALLS = 0; REARM = (core::ptr::null_mut(), 0); CONTINUATION = core::ptr::null_mut(); }
        let mut owner = std::vec![0usize; COMPONENT_WORD + 1];
        let mut vtable = [0usize; COMPONENT_GATE_SLOT + 1];
        vtable[COMPONENT_GATE_SLOT] = gate as usize;
        let mut component_vtable = vtable.as_mut_ptr();
        let component = &mut component_vtable as *mut *mut usize as *mut u8;
        unsafe { (owner.as_mut_ptr() as *mut *mut u8).add(COMPONENT_WORD).write(component); (owner.as_mut_ptr() as *mut u8).add(0x4d2).write(1); component_gate_rearm_continue(owner.as_mut_ptr() as *mut u8); }
        unsafe { assert_eq!(GATE_CALLS, 0); }
        unsafe { (owner.as_mut_ptr() as *mut u8).add(0x4d2).write(0); GATE_RESULT = 0; component_gate_rearm_continue(owner.as_mut_ptr() as *mut u8); }
        unsafe { assert_eq!(GATE_CALLS, 1); assert_eq!(REARM.1, 0); }
        unsafe { GATE_RESULT = 1; component_gate_rearm_continue(owner.as_mut_ptr() as *mut u8); }
        unsafe { assert_eq!(GATE_CALLS, 2); assert_eq!(REARM, (0x1234usize as *mut u8, REARM_DELAY_MS)); assert_eq!(CONTINUATION, owner.as_mut_ptr() as *mut u8); COMPONENT_GATE_REARM_CONTINUE_OPS = old; }
    }
}
