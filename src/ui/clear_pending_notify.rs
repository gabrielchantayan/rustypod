//! Clear a pending UI-object flag and notify its virtual observers.
//!
//! `ui_clear_pending_notify` — original: `FUN_0811e1c4` @ **0x0811e1c4**,
//! 84 bytes (`0x0811e1c4..0x0811e218`). The next real function starts with
//! `str r1,[r0,#0xfc]` at 0x0811e218. Raw ARM decoding finds five direct,
//! unconditional `bl` callers and no predicated direct calls; this body itself
//! has one direct `bl` and two indirect `blx` calls.
//!
//! # Algorithm
//!
//! While `object + 0x48` carries bit 0x40, clear that bit, call virtual slot
//! +0x88 with `object`, then call the unrecovered `FUN_08110fb4(5, NULL)`.
//! Finally tail-dispatch virtual slot +0x8c with `object`. Callers establish
//! this as pending-object notification; the concrete object type and event-5
//! helper identity remain unrecovered.
//!
//! # Deliberate deviation
//!
//! The ARM build calls `FUN_08110fb4` at its verified load address. Host
//! fixtures use native-width vtable slots at doubled offsets and a replaceable
//! event-5 callback, because 8-byte host function pointers cannot occupy the
//! firmware's adjacent 32-bit +0x88/+0x8c slots.

const PENDING_FLAGS_OFFSET: usize = 0x48;
const PENDING_FLAG: u32 = 0x40;
const PENDING_NOTIFY_OFFSET: usize = 0x88;
const FINAL_NOTIFY_OFFSET: usize = 0x8c;
const EVENT_5_DISPATCH_ADDRESS: usize = 0x0811_0fb4;

type VirtualNotify = unsafe extern "C" fn(*mut u8);
type Event5Dispatch = unsafe extern "C" fn(u32, *mut u8);

#[cfg(target_os = "none")]
unsafe fn virtual_notify(object: *mut u8, offset: usize) -> VirtualNotify {
    let vtable = object.cast::<u32>().read() as usize as *const u8;
    vtable.add(offset).cast::<VirtualNotify>().read()
}

#[cfg(not(target_os = "none"))]
unsafe fn virtual_notify(object: *mut u8, offset: usize) -> VirtualNotify {
    let vtable = object.cast::<*const u8>().read();
    vtable.add(offset * 2).cast::<VirtualNotify>().read_unaligned()
}

#[cfg(target_os = "none")]
unsafe fn dispatch_event_5() {
    let dispatch: Event5Dispatch = core::mem::transmute(EVENT_5_DISPATCH_ADDRESS);
    dispatch(5, core::ptr::null_mut());
}

#[cfg(not(target_os = "none"))]
static mut HOST_EVENT_5_DISPATCH: Event5Dispatch = host_event_5_noop;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_event_5_noop(_: u32, _: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe fn dispatch_event_5() {
    HOST_EVENT_5_DISPATCH(5, core::ptr::null_mut());
}

/// Drains pending bit 0x40 notifications before issuing the object's final
/// virtual notification.
///
/// # Safety
///
/// `object` must point to a retailOS object with a readable/writable word at
/// +0x48 and virtual methods at vtable slots +0x88 and +0x8c. The retail body
/// has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_clear_pending_notify(object: *mut u8) {
    let flags = object.add(PENDING_FLAGS_OFFSET).cast::<u32>();
    while flags.read() & PENDING_FLAG != 0 {
        flags.write(flags.read() & !PENDING_FLAG);
        virtual_notify(object, PENDING_NOTIFY_OFFSET)(object);
        dispatch_event_5();
    }
    virtual_notify(object, FINAL_NOTIFY_OFFSET)(object);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PENDING_CALLS: usize = 0;
    static mut FINAL_CALLS: usize = 0;
    static mut EVENT_CALLS: usize = 0;
    static mut OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn pending_notify(object: *mut u8) {
        PENDING_CALLS += 1;
        assert_eq!(object, OBJECT);
        if PENDING_CALLS == 1 {
            object.add(PENDING_FLAGS_OFFSET).cast::<u32>().write(PENDING_FLAG);
        }
    }

    unsafe extern "C" fn final_notify(object: *mut u8) {
        FINAL_CALLS += 1;
        assert_eq!(object, OBJECT);
    }

    unsafe extern "C" fn event_5(code: u32, context: *mut u8) {
        EVENT_CALLS += 1;
        assert_eq!(code, 5);
        assert!(context.is_null());
    }

    #[test]
    fn drains_reasserted_pending_flag_before_final_notification() {
        let _guard = TEST_LOCK.lock();
        let Some(object) = try_map_u32_slab(hints::UI_CLEAR_PENDING_NOTIFY, 0x400) else {
            assert!(note_missing_u32_fixture("ui/clear_pending_notify"));
            return;
        };
        unsafe {
            let vtable = object.add(0x100);
            object.cast::<*const u8>().write(vtable);
            vtable.add(PENDING_NOTIFY_OFFSET * 2).cast::<VirtualNotify>().write_unaligned(pending_notify);
            vtable.add(FINAL_NOTIFY_OFFSET * 2).cast::<VirtualNotify>().write_unaligned(final_notify);
            object.add(PENDING_FLAGS_OFFSET).cast::<u32>().write(PENDING_FLAG);
            PENDING_CALLS = 0;
            FINAL_CALLS = 0;
            EVENT_CALLS = 0;
            OBJECT = object;
            HOST_EVENT_5_DISPATCH = event_5;

            ui_clear_pending_notify(object);

            assert_eq!(PENDING_CALLS, 2);
            assert_eq!(EVENT_CALLS, 2);
            assert_eq!(FINAL_CALLS, 1);
            assert_eq!(object.add(PENDING_FLAGS_OFFSET).cast::<u32>().read(), 0);
            object.add(PENDING_FLAGS_OFFSET).cast::<u32>().write(0);
            PENDING_CALLS = 0;
            FINAL_CALLS = 0;
            EVENT_CALLS = 0;
            ui_clear_pending_notify(object);
            assert_eq!(PENDING_CALLS, 0);
            assert_eq!(EVENT_CALLS, 0);
            assert_eq!(FINAL_CALLS, 1);
            HOST_EVENT_5_DISPATCH = host_event_5_noop;
        }
    }

}
