//! `global_event_dispatch` — original: `FUN_0809ca70` @ `0x0809ca70`
//! (36 bytes).
//!
//! # Verified call count
//!
//! Decoding every aligned ARM `B`/`BL`-immediate word in `osos.dec` finds five
//! direct inbound `bl` calls: four unconditional at `0x081f48dc`,
//! `0x081f4910`, `0x081f49d4`, and `0x081f49f4`, plus one predicated `blhi` at
//! `0x08a0e99c`. The body has no direct `bl`; its only call is the predicated
//! indirect `bxne` through the global object's `+0x0c` entry.
//!
//! # Algorithm
//!
//! Reads the optional global dispatch object from `0x089ca95c`. When absent it
//! returns status `0x11`; otherwise it tail-dispatches the supplied event word
//! through that object's `+0x0c` entry and returns the result.
//!
//! # Deliberate deviation
//!
//! The Rust source expresses the tail dispatch as a normal call, leaving tail
//! call selection to LLVM. Host builds use a native-pointer global seam because
//! the retail object contains 32-bit function-pointer words in firmware memory.

/// RetailOS address of the optional global event-dispatch object pointer.
pub const GLOBAL_EVENT_DISPATCH_OBJECT_ADDRESS: usize = 0x089c_a95c;
const NO_GLOBAL_EVENT_DISPATCH_STATUS: u32 = 0x11;
const GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET: usize = 3;

/// Recovered host representation of the global dispatch object.
#[repr(C)]
pub struct GlobalEventDispatchObject {
    pub unresolved_00_to_08: [usize; GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET],
    pub dispatch_event: unsafe extern "C" fn(u32) -> u32,
    pub unresolved_10_to_18: [usize; 4],
    pub dispatch_slot_1c: unsafe extern "C" fn(u32) -> u32,
}

/// Host-side replacement for the firmware global object pointer.
#[cfg(not(target_arch = "arm"))]
pub static mut GLOBAL_EVENT_DISPATCH_OBJECT: *mut GlobalEventDispatchObject = core::ptr::null_mut();

/// Dispatches `event_code` through the optional process-global event receiver.
///
/// # Safety
///
/// On ARM, `0x089ca95c` must contain either zero or a valid object with a
/// callable function-pointer word at `+0x0c`. Host callers must install an
/// equivalent object through [`GLOBAL_EVENT_DISPATCH_OBJECT`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_event_dispatch(event_code: u32) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        let object = core::ptr::read_volatile(GLOBAL_EVENT_DISPATCH_OBJECT_ADDRESS as *const u32);
        if object == 0 {
            return NO_GLOBAL_EVENT_DISPATCH_STATUS;
        }
        let dispatch_word = core::ptr::read_volatile(
            (object as *const u32).add(GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET),
        );
        let dispatch: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(dispatch_word as usize);
        return dispatch(event_code);
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let object = core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_EVENT_DISPATCH_OBJECT));
        if object.is_null() {
            return NO_GLOBAL_EVENT_DISPATCH_STATUS;
        }
        return ((*object).dispatch_event)(event_code);
    }
}

/// `global_event_dispatch_slot_1c` — original: `FUN_080c9944` @ `0x080c9944`
/// (36 bytes).
///
/// # Verified call count
///
/// Decoding every aligned ARM `B`/`BL`-immediate word in `osos.dec` finds four
/// direct inbound calls: three unconditional `bl` at `0x081e687c`,
/// `0x081f48e4`, and `0x081f49a4`, plus one predicated `bleq` at
/// `0x081f475c`. The body has no direct `bl`; its only call is the predicated
/// indirect `bxne` through the global object's `+0x1c` entry.
///
/// # Algorithm
///
/// Reads the optional global dispatch object from `0x089ca95c`. When absent it
/// returns status `0x11`; otherwise it tail-dispatches the supplied event word
/// through that object's `+0x1c` entry and returns the result.
///
/// # Deliberate deviation
///
/// The Rust source expresses the tail dispatch as a normal call, leaving tail
/// call selection to LLVM. Host builds use the existing native-pointer global
/// seam because the retail object contains 32-bit function-pointer words in
/// firmware memory.
///
/// # Safety
///
/// On ARM, `0x089ca95c` must contain either zero or a valid object with a
/// callable function-pointer word at `+0x1c`. Host callers must install an
/// equivalent object through [`GLOBAL_EVENT_DISPATCH_OBJECT`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_event_dispatch_slot_1c(event_code: u32) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        let object = core::ptr::read_volatile(GLOBAL_EVENT_DISPATCH_OBJECT_ADDRESS as *const u32);
        if object == 0 {
            return NO_GLOBAL_EVENT_DISPATCH_STATUS;
        }
        let dispatch_word = core::ptr::read_volatile(
            (object as *const u32).add(GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET + 4),
        );
        let dispatch: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(dispatch_word as usize);
        return dispatch(event_code);
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let object = core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_EVENT_DISPATCH_OBJECT));
        if object.is_null() {
            return NO_GLOBAL_EVENT_DISPATCH_STATUS;
        }
        return ((*object).dispatch_slot_1c)(event_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static EVENT: AtomicU32 = AtomicU32::new(0);
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn record_event(event_code: u32) -> u32 {
        EVENT.store(event_code, Ordering::Relaxed);
        event_code ^ 0x5a5a_5a5a
    }


    #[test]
    fn absent_global_returns_retail_status() {
        let _guard = TEST_LOCK.lock();
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::null_mut(); }
        assert_eq!(unsafe { global_event_dispatch(0xffff_ffff) }, NO_GLOBAL_EVENT_DISPATCH_STATUS);
    }

    #[test]
    fn present_global_forwards_event_and_result() {
        let _guard = TEST_LOCK.lock();
        let mut object = GlobalEventDispatchObject {
            unresolved_00_to_08: [0; GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET],
            dispatch_event: record_event,
            unresolved_10_to_18: [0; 4],
            dispatch_slot_1c: record_event,
        };
        EVENT.store(0, Ordering::Relaxed);
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::addr_of_mut!(object); }
        assert_eq!(unsafe { global_event_dispatch(0x200) }, 0x5a5a_5a5a ^ 0x200);
        assert_eq!(EVENT.load(Ordering::Relaxed), 0x200);
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::null_mut(); }
    }

    #[test]
    fn slot_1c_absent_global_returns_retail_status() {
        let _guard = TEST_LOCK.lock();
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::null_mut(); }
        assert_eq!(unsafe { global_event_dispatch_slot_1c(0xffff_ffff) }, NO_GLOBAL_EVENT_DISPATCH_STATUS);
    }

    #[test]
    fn slot_1c_present_global_forwards_event_and_result() {
        let _guard = TEST_LOCK.lock();
        let mut object = GlobalEventDispatchObject {
            unresolved_00_to_08: [0; GLOBAL_EVENT_DISPATCH_ENTRY_OFFSET],
            dispatch_event: record_event,
            unresolved_10_to_18: [0; 4],
            dispatch_slot_1c: record_event,
        };
        EVENT.store(0, Ordering::Relaxed);
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::addr_of_mut!(object); }
        assert_eq!(unsafe { global_event_dispatch_slot_1c(0) }, 0x5a5a_5a5a);
        assert_eq!(EVENT.load(Ordering::Relaxed), 0);
        unsafe { GLOBAL_EVENT_DISPATCH_OBJECT = core::ptr::null_mut(); }
    }
}
