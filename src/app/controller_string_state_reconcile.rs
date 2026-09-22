//! `controller_string_state_reconcile` — original: `FUN_0827f484` @
//! **0x0827f484**.
//!
//! True extent is 172 bytes, `0x0827f484..0x0827f530`: `push
//! {r0-r8,lr}` starts the body and the next separately linked function begins
//! at `0x0827f530`. Raw A32 decoding finds six unconditional plain `bl`
//! instructions and one predicated `blne`; full-image decoding finds three
//! inbound plain `bl` sites (0x0827eb6c, 0x0827f94c, 0x0827fa64) and no
//! predicated inbound `bl` sites.
//!
//! It clears the retry counter at +0x8c, builds a temporary StringObject from
//! the four-space literal, reports a mismatch against the StringObject at
//! +0x74, then destroys the temporary. In the alternate path it compares that
//! StringObject with the one at +0x6c, marks +0x94 on mismatch, and returns a
//! boolean. Otherwise the same mismatch invokes the opaque state-recovery
//! callee and stores its result at +0x68, also clearing the global byte at
//! 0x089caf44. Deliberate deviation: `FUN_0827ef04` has no recovered identity,
//! so the target invokes its verified address and host tests install a seam.

#[cfg(not(target_os = "none"))]
use core::ptr;
use crate::cxx::string_object::StringObject;
#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_assign_payload, string_object_construct_from_cstr, string_object_destroy, string_object_equals};

const STATE_RESULT_OFFSET: usize = 0x68;
const PRIMARY_STRING_OFFSET: usize = 0x6c;
const SECONDARY_STRING_OFFSET: usize = 0x74;
const RETRY_COUNT_OFFSET: usize = 0x8c;
const MISMATCH_FLAG_OFFSET: usize = 0x94;
const RECOVERY_GLOBAL_ADDRESS: usize = 0x089c_af44;
const SPACE_TEXT: &[u8; 5] = b"    \0";

type StringConstruct = unsafe extern "C" fn(*mut StringObject, *const u8) -> *mut StringObject;
type StringDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;
type StringEquals = unsafe extern "C" fn(*const StringObject, *const StringObject) -> i32;
type StringAssignPayload = unsafe extern "C" fn(*mut StringObject, *const u8);
type StateRecovery = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_string(this: *mut StringObject, text: *const u8) {
    string_object_construct_from_cstr(this, text);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_string(_: *mut StringObject, _: *const u8) -> *mut StringObject { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
static mut STRING_CONSTRUCT: StringConstruct = missing_construct_string;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_string(this: *mut StringObject, text: *const u8) {
    ptr::read_volatile(ptr::addr_of!(STRING_CONSTRUCT))(this, text);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_string(this: *mut StringObject) { string_object_destroy(this); }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_string(_: *mut StringObject) -> *mut StringObject { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
static mut STRING_DESTROY: StringDestroy = missing_destroy_string;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_string(this: *mut StringObject) { ptr::read_volatile(ptr::addr_of!(STRING_DESTROY))(this); }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn strings_equal(first: *const StringObject, second: *const StringObject) -> i32 { string_object_equals(first, second) }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_strings_equal(_: *const StringObject, _: *const StringObject) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
static mut STRING_EQUALS: StringEquals = missing_strings_equal;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn strings_equal(first: *const StringObject, second: *const StringObject) -> i32 { ptr::read_volatile(ptr::addr_of!(STRING_EQUALS))(first, second) }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn assign_payload(this: *mut StringObject, payload: *const u8) {
    string_object_assign_payload(this, payload);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assign_payload(_: *mut StringObject, _: *const u8) {}
#[cfg(not(target_os = "none"))]
static mut STRING_ASSIGN_PAYLOAD: StringAssignPayload = missing_assign_payload;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn assign_payload(this: *mut StringObject, payload: *const u8) {
    ptr::read_volatile(ptr::addr_of!(STRING_ASSIGN_PAYLOAD))(this, payload);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_recovery_global() { (RECOVERY_GLOBAL_ADDRESS as *mut u8).write_volatile(0); }
#[cfg(not(target_os = "none"))]
static mut RECOVERY_GLOBAL_CLEAR_COUNT: usize = 0;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn clear_recovery_global() { RECOVERY_GLOBAL_CLEAR_COUNT += 1; }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn recover_state(controller: *mut u8) -> u32 {
    let recovery: StateRecovery = core::mem::transmute(0x0827_ef04usize);
    recovery(controller, 0)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_state_recovery(_: *mut u8, _: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
static mut STATE_RECOVERY: StateRecovery = missing_state_recovery;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn recover_state(controller: *mut u8) -> u32 { ptr::read_volatile(ptr::addr_of!(STATE_RECOVERY))(controller, 0) }

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_string_state_reconcile(controller: *mut u8, alternate: u32) -> u32 {
    controller.add(RETRY_COUNT_OFFSET).cast::<u32>().write_volatile(0);

    let mut spaces = core::mem::MaybeUninit::<StringObject>::uninit();
    construct_string(spaces.as_mut_ptr(), SPACE_TEXT.as_ptr());
    let differs_from_spaces = strings_equal(
        controller.add(SECONDARY_STRING_OFFSET).cast(), spaces.as_ptr(),
    ) == 0;
    destroy_string(spaces.as_mut_ptr());

    if differs_from_spaces {
        assign_payload(controller.add(SECONDARY_STRING_OFFSET).cast(), 0x089c_afb0usize as *const u8);
    }

    let strings_differ = strings_equal(
        controller.add(SECONDARY_STRING_OFFSET).cast(),
        controller.add(PRIMARY_STRING_OFFSET).cast(),
    ) == 0;
    if alternate != 0 {
        if strings_differ {
            controller.add(MISMATCH_FLAG_OFFSET).write_volatile(1);
        }
        return (!strings_differ) as u32;
    }
    if strings_differ {
        controller.add(STATE_RESULT_OFFSET).cast::<u32>().write_volatile(recover_state(controller));
        clear_recovery_global();
    }
    controller.add(STATE_RESULT_OFFSET).cast::<u32>().read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EQUAL_RESULTS: [i32; 2] = [0; 2];
    static mut EQUAL_CALLS: usize = 0;
    static mut ASSIGN_CALLS: usize = 0;
    static mut RECOVERY_CALLS: usize = 0;

    unsafe extern "C" fn construct(this: *mut StringObject, text: *const u8) -> *mut StringObject {
        assert_eq!(core::slice::from_raw_parts(text, 5), SPACE_TEXT);
        this
    }
    unsafe extern "C" fn destroy(this: *mut StringObject) -> *mut StringObject { this }
    unsafe extern "C" fn equals(_: *const StringObject, _: *const StringObject) -> i32 {
        let result = EQUAL_RESULTS[EQUAL_CALLS];
        EQUAL_CALLS += 1;
        result
    }
    unsafe extern "C" fn assign(_: *mut StringObject, text: *const u8) {
        assert_eq!(text as usize, 0x089c_afb0);
        ASSIGN_CALLS += 1;
    }
    unsafe extern "C" fn recover(_: *mut u8, mode: u32) -> u32 {
        assert_eq!(mode, 0);
        RECOVERY_CALLS += 1;
        0xfeed_beef
    }

    struct Seams;
    impl Seams {
        unsafe fn install(results: [i32; 2]) -> Self {
            EQUAL_RESULTS = results;
            EQUAL_CALLS = 0;
            ASSIGN_CALLS = 0;
            RECOVERY_CALLS = 0;
            STRING_CONSTRUCT = construct;
            STRING_DESTROY = destroy;
            STRING_EQUALS = equals;
            STRING_ASSIGN_PAYLOAD = assign;
            STATE_RECOVERY = recover;
            RECOVERY_GLOBAL_CLEAR_COUNT = 0;
            Self
        }
    }
    impl Drop for Seams {
        fn drop(&mut self) { unsafe {
            STRING_CONSTRUCT = missing_construct_string;
            STRING_DESTROY = missing_destroy_string;
            STRING_EQUALS = missing_strings_equal;
            STRING_ASSIGN_PAYLOAD = missing_assign_payload;
            STATE_RECOVERY = missing_state_recovery;
        }}
    }

    #[test]
    fn alternate_path_marks_mismatch_and_returns_false() {
        let _lock = LOCK.lock();
        let _seams = unsafe { Seams::install([0, 0]) };
        let mut controller = [0u32; 40];
        controller[RETRY_COUNT_OFFSET / 4] = 9;
        assert_eq!(unsafe { controller_string_state_reconcile(controller.as_mut_ptr().cast(), 1) }, 0);
        assert_eq!(controller[RETRY_COUNT_OFFSET / 4], 0);
        assert_eq!(controller[MISMATCH_FLAG_OFFSET / 4], 1);
        assert_eq!(unsafe { ASSIGN_CALLS }, 1);
        assert_eq!(unsafe { RECOVERY_CALLS }, 0);
    }

    #[test]
    fn normal_matching_path_preserves_state_without_recovery() {
        let _lock = LOCK.lock();
        let _seams = unsafe { Seams::install([1, 1]) };
        let mut controller = [0u32; 40];
        controller[STATE_RESULT_OFFSET / 4] = 7;
        assert_eq!(unsafe { controller_string_state_reconcile(controller.as_mut_ptr().cast(), 0) }, 7);
        assert_eq!(unsafe { ASSIGN_CALLS }, 0);
        assert_eq!(unsafe { RECOVERY_CALLS }, 0);
    }

    #[test]
    fn normal_mismatch_recovers_and_replaces_state() {
        let _lock = LOCK.lock();
        let _seams = unsafe { Seams::install([1, 0]) };
        let mut controller = [0u32; 40];
        assert_eq!(unsafe { controller_string_state_reconcile(controller.as_mut_ptr().cast(), 0) }, 0xfeed_beef);
        assert_eq!(unsafe { ASSIGN_CALLS }, 0);
        assert_eq!(unsafe { RECOVERY_CALLS }, 1);
        assert_eq!(unsafe { RECOVERY_GLOBAL_CLEAR_COUNT }, 1);
    }
}
