//! Apply the retail control profile — original: `FUN_080f4bbc` @ 0x080f4bbc (100 bytes).
//!
//! Raw `osos.dec` words establish the exact A32 extent
//! `0x080f4bbc..0x080f4c20`; `0x080f4c20` begins the next function. It
//! contains eleven plain `bl` instructions and no predicated `bl` instruction.
//! It initializes the retail control service, sleeps for ten ticks, applies
//! three fixed field values (3, 12, and 31), reads selectors 6 and 5 into the
//! incoming r3 and r2 stack slots, submits code 24, rereads selector 6, then
//! commits selector 1. The return values are deliberately discarded.
//!
//! Deviation: the control-service entry points remain direct calls to their
//! verified retail addresses because none is ported yet; host tests install
//! equivalent operations through `RETAIL_CONTROL_PROFILE_OPS`.

pub type RetailControlProfileOps = RetailControlProfileOperations;

#[derive(Clone, Copy)]
pub struct RetailControlProfileOperations {
    pub initialize: unsafe extern "C" fn(),
    pub sleep: unsafe extern "C" fn(u32),
    pub apply_mode: unsafe extern "C" fn(),
    pub set_field_three: unsafe extern "C" fn(u32),
    pub set_field_four: unsafe extern "C" fn(u32),
    pub set_field_five: unsafe extern "C" fn(u32),
    pub read_selector: unsafe extern "C" fn(u32, *mut u32),
    pub submit_code: unsafe extern "C" fn(u32),
    pub commit_selector: unsafe extern "C" fn(u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_void() { panic!("install retail control profile fixture"); }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_u32(_: u32) { panic!("install retail control profile fixture"); }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read(_: u32, _: *mut u32) { panic!("install retail control profile fixture"); }

#[cfg(not(target_os = "none"))]
pub static mut RETAIL_CONTROL_PROFILE_OPS: RetailControlProfileOperations = RetailControlProfileOperations {
    initialize: missing_void,
    sleep: missing_u32,
    apply_mode: missing_void,
    set_field_three: missing_u32,
    set_field_four: missing_u32,
    set_field_five: missing_u32,
    read_selector: missing_read,
    submit_code: missing_u32,
    commit_selector: missing_u32,
};

#[cfg(target_os = "none")]
unsafe fn retail_void(address: usize) { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(address)() }; }
#[cfg(target_os = "none")]
unsafe fn retail_u32(address: usize, value: u32) { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u32)>(address)(value) }; }
#[cfg(target_os = "none")]
unsafe fn retail_read(address: usize, selector: u32, value: *mut u32) { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u32, *mut u32)>(address)(selector, value) }; }

/// Executes the fixed retail control-service profile.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_control_profile_apply(_unused_r0: u32, _unused_r1: u32, mut selector_five: u32, mut selector_six: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        retail_void(0x0836_e274);
        crate::kernel::task::task_sleep(10);
        retail_void(0x0836_e400);
        retail_u32(0x0836_e41c, 3);
        retail_u32(0x0836_e440, 12);
        retail_u32(0x0836_e450, 31);
        retail_read(0x0836_e36c, 6, &mut selector_six);
        retail_read(0x0836_e36c, 5, &mut selector_five);
        retail_u32(0x0836_e224, 24);
        retail_read(0x0836_e36c, 6, &mut selector_six);
        retail_u32(0x0836_e298, 1);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = RETAIL_CONTROL_PROFILE_OPS;
        (ops.initialize)();
        (ops.sleep)(10);
        (ops.apply_mode)();
        (ops.set_field_three)(3);
        (ops.set_field_four)(12);
        (ops.set_field_five)(31);
        (ops.read_selector)(6, &mut selector_six);
        (ops.read_selector)(5, &mut selector_five);
        (ops.submit_code)(24);
        (ops.read_selector)(6, &mut selector_six);
        (ops.commit_selector)(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 11] = [0; 11];
    static mut EVENT_COUNT: usize = 0;
    static mut READ_COUNT: usize = 0;
    static mut READ_VALUES: [u32; 3] = [0; 3];

    unsafe fn event(value: u32) { unsafe { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; } }
    unsafe extern "C" fn initialize() { unsafe { event(0); } }
    unsafe extern "C" fn sleep(value: u32) { unsafe { event(0x100 + value); } }
    unsafe extern "C" fn apply_mode() { unsafe { event(2); } }
    unsafe extern "C" fn set_three(value: u32) { unsafe { event(0x300 + value); } }
    unsafe extern "C" fn set_four(value: u32) { unsafe { event(0x400 + value); } }
    unsafe extern "C" fn set_five(value: u32) { unsafe { event(0x500 + value); } }
    unsafe extern "C" fn read(selector: u32, value: *mut u32) {
        unsafe { event(0x600 + selector); *value = READ_VALUES[READ_COUNT]; READ_COUNT += 1; }
    }
    unsafe extern "C" fn submit(value: u32) { unsafe { event(0x700 + value); } }
    unsafe extern "C" fn commit(value: u32) { unsafe { event(0x800 + value); } }

    #[test]
    fn applies_fixed_profile_and_rereads_selector_six() {
        let _lock = LOCK.lock();
        unsafe {
            EVENTS = [0; 11]; EVENT_COUNT = 0; READ_COUNT = 0; READ_VALUES = [0xa6, 0xb5, 0xc6];
            RETAIL_CONTROL_PROFILE_OPS = RetailControlProfileOperations {
                initialize, sleep, apply_mode, set_field_three: set_three, set_field_four: set_four,
                set_field_five: set_five, read_selector: read, submit_code: submit, commit_selector: commit,
            };
            retail_control_profile_apply(0xdeaf_beef, 0xcafe_babe, 0x5555_5555, 0x6666_6666);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0, 0x10a, 2, 0x303, 0x40c, 0x51f, 0x606, 0x605, 0x718, 0x606, 0x801]);
        }
    }
}
