//! `teardown_work` — original: `FUN_0814848c` @ `0x0814848c`.
//!
//! **84 bytes** (`0x0814848c..0x0814848e0`; the next function starts with
//! `push {r4, r5, r6, lr}` at `0x081484e0`) and **3 direct `bl` call sites**,
//! all unconditional: `0x081482cc`, `0x08148590`, `0x08148698`. Decoding
//! every ARM B/BL word in `osos.dec` found no predicated direct call.
//!
//! # Algorithm
//!
//! Calls vtable slot `+0x1c` on the embedded callback target at `record+0x14`,
//! passing the record word at `+0x04`. If the mode word at `+0x5c` is three,
//! it calls the same slot on `record+0x30`, passing the first target. Finally
//! it tail-dispatches the slot on `record+0x08`, passing the most recent target.
//! Deliberate deviation: the ARM tail dispatch is an ordinary final call in
//! Rust; its return value is unobserved. Host vtables are widened structurally
//! because host pointers do not fit the target's 32-bit vtable words.

#[cfg(target_os = "none")]
pub type WorkTeardownCallback = unsafe extern "C" fn(*mut WorkTeardownTarget, *mut u8);

#[cfg(target_os = "none")]
#[repr(C)]
pub struct WorkTeardownTarget {
    pub vtable: u32,
}

#[cfg(target_os = "none")]
#[repr(C)]
pub struct WorkTeardownRecord {
    pub header: u32,
    pub argument: u32,
    pub final_target: WorkTeardownTarget,
    pub unresolved_0c_10: [u32; 2],
    pub first_target: WorkTeardownTarget,
    pub unresolved_18_2c: [u32; 6],
    pub mode_target: WorkTeardownTarget,
    pub unresolved_34_5b: [u32; 10],
    pub mode: u32,
}

#[cfg(target_os = "none")]
const _: [u8; 0x5c] = [0; core::mem::offset_of!(WorkTeardownRecord, mode)];

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkTeardownVtable {
    pub unresolved_00_18: [usize; 7],
    pub callback: unsafe extern "C" fn(*mut HostWorkTeardownTarget, *mut u8),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkTeardownTarget {
    pub vtable: *const HostWorkTeardownVtable,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkTeardownRecord {
    pub header: usize,
    pub argument: usize,
    pub final_target: HostWorkTeardownTarget,
    pub unresolved_0c_10: [usize; 2],
    pub first_target: HostWorkTeardownTarget,
    pub unresolved_18_2c: [usize; 6],
    pub mode_target: HostWorkTeardownTarget,
    pub unresolved_34_5b: [usize; 10],
    pub mode: u32,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch(target: *mut WorkTeardownTarget, argument: *mut u8) {
    const CALLBACK_SLOT_WORD: usize = 7;
    let vtable = target.cast::<u32>().read_volatile() as usize as *const u32;
    let callback: WorkTeardownCallback = core::mem::transmute(vtable.add(CALLBACK_SLOT_WORD).read_volatile() as usize);
    callback(target, argument);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch(target: *mut HostWorkTeardownTarget, argument: *mut u8) {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*target).vtable));
    ((*vtable).callback)(target, argument);
}

/// Teardown callback chain — original: `FUN_0814848c` @ `0x0814848c`
/// (84 bytes; 3 unconditional `bl` call sites, no predicated calls).
///
/// # Safety
/// `record` and each selected vtable slot must satisfy the unchecked retailOS
/// object contracts.
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn teardown_work(record: *mut WorkTeardownRecord) {
    let first_target = core::ptr::addr_of_mut!((*record).first_target);
    dispatch(first_target, (*record).argument as usize as *mut u8);
    let mut previous = first_target.cast::<u8>();
    if (*record).mode == 3 {
        let mode_target = core::ptr::addr_of_mut!((*record).mode_target);
        dispatch(mode_target, previous);
        previous = mode_target.cast();
    }
    dispatch(core::ptr::addr_of_mut!((*record).final_target), previous);
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn teardown_work(record: *mut HostWorkTeardownRecord) {
    let first_target = core::ptr::addr_of_mut!((*record).first_target);
    dispatch(first_target, (*record).argument as *mut u8);
    let mut previous = first_target.cast::<u8>();
    if (*record).mode == 3 {
        let mode_target = core::ptr::addr_of_mut!((*record).mode_target);
        dispatch(mode_target, previous);
        previous = mode_target.cast();
    }
    dispatch(core::ptr::addr_of_mut!((*record).final_target), previous);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut ARGUMENTS: [usize; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn record_first(_target: *mut HostWorkTeardownTarget, argument: *mut u8) {
        EVENTS[EVENT_COUNT] = b'F';
        ARGUMENTS[EVENT_COUNT] = argument as usize;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_mode(_target: *mut HostWorkTeardownTarget, argument: *mut u8) {
        EVENTS[EVENT_COUNT] = b'M';
        ARGUMENTS[EVENT_COUNT] = argument as usize;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_final(_target: *mut HostWorkTeardownTarget, argument: *mut u8) {
        EVENTS[EVENT_COUNT] = b'L';
        ARGUMENTS[EVENT_COUNT] = argument as usize;
        EVENT_COUNT += 1;
    }

    static FIRST_VTABLE: HostWorkTeardownVtable = HostWorkTeardownVtable { unresolved_00_18: [0; 7], callback: record_first };
    static MODE_VTABLE: HostWorkTeardownVtable = HostWorkTeardownVtable { unresolved_00_18: [0; 7], callback: record_mode };
    static FINAL_VTABLE: HostWorkTeardownVtable = HostWorkTeardownVtable { unresolved_00_18: [0; 7], callback: record_final };

    fn record(mode: u32, argument: usize) -> HostWorkTeardownRecord {
        HostWorkTeardownRecord {
            header: 0, argument, final_target: HostWorkTeardownTarget { vtable: &FINAL_VTABLE },
            unresolved_0c_10: [0; 2], first_target: HostWorkTeardownTarget { vtable: &FIRST_VTABLE },
            unresolved_18_2c: [0; 6], mode_target: HostWorkTeardownTarget { vtable: &MODE_VTABLE },
            unresolved_34_5b: [0; 10], mode,
        }
    }

    #[test]
    fn non_three_mode_forwards_first_target_to_final_target() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            EVENTS = [0; 3]; ARGUMENTS = [0; 3]; EVENT_COUNT = 0;
            let mut value = record(2, 0x1234_5678);
            teardown_work(&mut value);
            assert_eq!(&EVENTS[..EVENT_COUNT], b"FL");
            assert_eq!(&ARGUMENTS[..EVENT_COUNT], &[0x1234_5678, core::ptr::addr_of!(value.first_target) as usize]);
        }
    }

    #[test]
    fn mode_three_inserts_mode_target_between_first_and_final() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            EVENTS = [0; 3]; ARGUMENTS = [0; 3]; EVENT_COUNT = 0;
            let mut value = record(3, 0xfeed_beef);
            teardown_work(&mut value);
            assert_eq!(&EVENTS[..EVENT_COUNT], b"FML");
            assert_eq!(&ARGUMENTS[..EVENT_COUNT], &[0xfeed_beef, core::ptr::addr_of!(value.first_target) as usize, core::ptr::addr_of!(value.mode_target) as usize]);
        }
    }
}
