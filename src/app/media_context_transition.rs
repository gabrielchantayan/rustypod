//! Context-result transition — `FUN_0817dc98` @ `0x0817dc98`.
//!
//! True extent [0x0817dc98,0x0817dd3c), 164 bytes, ending before the next
//! push prologue. Raw A32 words: four plain BLs, two BLNEs, one BLX through
//! vtable slot +0x1c, and tail B to 0x081df124. Whole-image decoding finds
//! two plain incoming BLs and no predicated incoming BLs.
//! Store state 3 before testing the old state; refresh old zero, accept old
//! 5/6, otherwise return. Forward nonzero values, enqueue the current handle,
//! obtain a virtual context result into the embedded +4 context, then enqueue
//! that result using a freshly obtained dispatcher.
//! Deviations: repr(C) pointer fields widen on hosts. The retail singleton
//! getter is retained because the existing Rust getter is not hook-ready
//! (its constructor/cache differ). Unported enqueue callees remain verified
//! retail calls. Host active execution requires private test adapters; the
//! public entry rejects unsupported active execution rather than faking it.

#[repr(C)]
pub struct MediaContextTransition {
    pub state: u8,
    pub padding: [u8; 3],
    pub context: [u32; 6],
    pub handle: u32,
    pub target: *mut *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x20] = [(); core::mem::offset_of!(MediaContextTransition, target)];

type Forward = unsafe extern "C" fn(*mut u8, u32, u32);
type Get = unsafe extern "C" fn() -> *mut u8;
type Enqueue = unsafe extern "C" fn(*mut u8, u32);
type ContextResult = unsafe extern "C" fn(*mut u8, *mut u32) -> u32;

struct Calls {
    refresh: unsafe extern "C" fn(*mut u8),
    first: Forward,
    second: Forward,
    get: Get,
    enqueue_handle: Enqueue,
    enqueue_result: Enqueue,
}

#[inline(always)]
unsafe fn execute(object: *mut MediaContextTransition, first: u32, second: u32, calls: &Calls) {
    let old = object.cast::<u8>().read();
    object.cast::<u8>().write(3);
    if old == 0 { (calls.refresh)(object.cast()); }
    else if old != 5 && old != 6 { return; }
    if first != 0 { (calls.first)(*(*object).target, (*object).handle, first); }
    if second != 0 { (calls.second)(*(*object).target, (*object).handle, second); }
    let dispatcher = (calls.get)();
    (calls.enqueue_handle)(dispatcher, (*object).handle);
    let receiver = *(*object).target;
    let vtable = receiver.cast::<*const usize>().read();
    let method: ContextResult = core::mem::transmute(vtable.add(7).read());
    let result = method(receiver, core::ptr::addr_of_mut!((*object).context).cast());
    let dispatcher = (calls.get)();
    (calls.enqueue_result)(dispatcher, result);
}

/// # Safety
/// Active states require a live, aligned retail object, target handle and
/// receiver with a callable vtable slot +0x1c. Inactive states need only the
/// writable state byte. Callees may mutate fields; every use reloads them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_context_transition(object: *mut MediaContextTransition, first: u32, second: u32) {
    #[cfg(target_os = "none")]
    {
        let calls = Calls {
            refresh: crate::app::active_context_refresh::active_context_refresh,
            first: crate::app::scoped_context_dispatch_and_store_result::scoped_context_dispatch_and_store_result,
            second: core::mem::transmute(crate::app::scoped_context_dispatch_and_store_secondary_result::scoped_context_dispatch_and_store_secondary_result as *const ()),
            get: core::mem::transmute(0x081d_ed14usize),
            enqueue_handle: core::mem::transmute(0x081d_ecd8usize),
            enqueue_result: core::mem::transmute(0x081d_f124usize),
        };
        execute(object, first, second, &calls);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (first, second);
        let old = object.cast::<u8>().read();
        object.cast::<u8>().write(3);
        assert!(old != 0 && old != 5 && old != 6, "retail enqueue/getter unavailable on host");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    std::thread_local! { static DISPATCHER: core::cell::Cell<*mut u8> = const { core::cell::Cell::new(core::ptr::null_mut()) }; }

    #[test]
    fn every_rejected_state_needs_only_one_byte() {
        for old in 0..=255u8 {
            if old == 0 || old == 5 || old == 6 { continue; }
            let mut byte = old;
            unsafe { media_context_transition((&mut byte as *mut u8).cast(), u32::MAX, u32::MAX); }
            assert_eq!(byte, 3);
        }
    }

    #[repr(C)]
    struct Receiver { vtable: *const usize, object: *mut MediaContextTransition, phase: u32, queued: u32 }
    unsafe extern "C" fn refresh(object: *mut u8) {
        let object = object.cast::<MediaContextTransition>();
        assert_eq!((*object).state, 3);
        (*object).handle = 11;
    }
    unsafe extern "C" fn first(receiver: *mut u8, handle: u32, value: u32) {
        let receiver = receiver.cast::<Receiver>();
        assert_eq!(handle, (*(*receiver).object).handle);
        (*(*receiver).object).handle = handle.wrapping_add(value);
        (*receiver).phase |= 1;
    }
    unsafe extern "C" fn second(receiver: *mut u8, handle: u32, value: u32) {
        let receiver = receiver.cast::<Receiver>();
        assert_eq!(handle, (*(*receiver).object).handle);
        (*(*receiver).object).handle = handle.wrapping_mul(value);
        (*receiver).phase |= 2;
    }
    unsafe extern "C" fn get() -> *mut u8 { DISPATCHER.with(|slot| slot.get()) }
    unsafe extern "C" fn enqueue_handle(dispatcher: *mut u8, handle: u32) {
        let receiver = dispatcher.cast::<Receiver>();
        assert_eq!((*receiver).phase & 4, 0);
        (*receiver).queued = handle;
    }
    unsafe extern "C" fn result(receiver: *mut u8, context: *mut u32) -> u32 {
        let receiver = receiver.cast::<Receiver>();
        context.write((*(*receiver).object).handle);
        (*receiver).phase |= 4;
        (*(*receiver).object).handle ^ 0x8000_0000
    }
    unsafe extern "C" fn enqueue_result(dispatcher: *mut u8, result: u32) {
        let receiver = dispatcher.cast::<Receiver>();
        assert_eq!((*receiver).phase & 4, 4);
        assert_eq!(result, (*receiver).queued ^ 0x8000_0000);
        (*receiver).queued = result;
    }

    #[test]
    fn accepted_states_preserve_reload_order_and_zero_value_skips() {
        let calls = Calls { refresh, first, second, get, enqueue_handle, enqueue_result };
        for old in [0, 5, 6] {
            for (a, b) in [(0, 0), (7, 0), (0, 3), (7, 3)] {
                let mut table = [0usize; 8];
                table[7] = result as *const () as usize;
                let mut object = MediaContextTransition { state: old, padding: [0; 3], context: [0; 6], handle: 5, target: core::ptr::null_mut() };
                let mut receiver = Receiver { vtable: table.as_ptr(), object: &mut object, phase: 0, queued: 0 };
                let mut target = (&mut receiver as *mut Receiver).cast::<u8>();
                object.target = &mut target;
                DISPATCHER.with(|slot| slot.set(target));
                unsafe { execute(&mut object, a, b, &calls); }
                let expected = (if old == 0 { 11u32 } else { 5 }).wrapping_add(a);
                let expected = if b == 0 { expected } else { expected.wrapping_mul(b) };
                assert_eq!(object.state, 3);
                assert_eq!(object.context[0], expected);
                assert_eq!(receiver.phase, 4 | u32::from(a != 0) | (u32::from(b != 0) << 1));
                assert_eq!(receiver.queued, expected ^ 0x8000_0000);
            }
        }
    }
}
