//! `controller_transition_request` — original: `FUN_081eef50` @
//! **0x081eef50**. Raw A32 words prove the true extent is **156 bytes**
//! (`0x081eef50..0x081eeff0`): the next real function begins with
//! `push {r4,r5,r6,lr}` at `0x081eeff4`.
//!
//! Decoding every instruction finds **5 plain unconditional `bl` calls and
//! 0 predicated `bl` calls**, not Ghidra's reported three: `operator_new`,
//! the StringObject payload accessor, the transition-addon constructor, the
//! pending-addon replacement, and the addon string extraction helper.
//!
//! Allocates a 0x54-byte transition addon, constructs it from the request's
//! embedded StringObject payload and byte parameters, replaces the controller's
//! pending addon, then publishes its status and (when successful) extracted
//! string. Deliberate deviations: the three unported callees use role-named
//! volatile seams; the ported transition-addon constructor is called directly
//! on target. Rust makes the stock stack temporary an ordinary local pointer.

use crate::cxx::transition_addon::silver_controller_transition_addon_construct_from_cstr;

const ADDON_SIZE: usize = 0x54;
const REQUEST_SOURCE_PAYLOAD_OFFSET: usize = 0x08;
const REQUEST_BASE_HINT_OFFSET: usize = 0x0c;
const REQUEST_FLAG_OFFSET: usize = 0x0d;
const CONTROLLER_STRING_OFFSET: usize = 0x28;
const CONTROLLER_EXTRACTED_OFFSET: usize = 0x30;
const CONTROLLER_PENDING_OFFSET: usize = 0x34;
const ADDON_STATUS_OFFSET: usize = 0x1c;

pub type AllocateAddon = unsafe extern "C" fn(usize) -> *mut u8;
pub type RequestPayload = unsafe extern "C" fn(*const u8) -> *const u8;
pub type ReplacePendingAddon = unsafe extern "C" fn(*mut u8, *mut *mut u8) -> i32;
pub type ExtractAddonString = unsafe extern "C" fn(*mut u8, *mut u32);
pub type ConstructAddon = unsafe extern "C" fn(*mut u8, *const u8, u32, u32, u32, u32, u32) -> *mut u8;

#[derive(Clone, Copy)]
pub struct ControllerTransitionRequestOps {
    pub allocate_addon: AllocateAddon,
    pub request_payload: RequestPayload,
    pub replace_pending_addon: ReplacePendingAddon,
    pub extract_addon_string: ExtractAddonString,
    pub construct_addon: ConstructAddon,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_allocate_addon(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new(size) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate_addon(_size: usize) -> *mut u8 { core::ptr::null_mut() }
#[cfg(target_os = "none")]
const DEFAULT_ALLOCATE_ADDON: AllocateAddon = retail_allocate_addon;
#[cfg(not(target_os = "none"))]
const DEFAULT_ALLOCATE_ADDON: AllocateAddon = missing_allocate_addon;
unsafe extern "C" fn missing_request_payload(_string: *const u8) -> *const u8 { core::ptr::null() }
unsafe extern "C" fn missing_replace_pending_addon(_controller: *mut u8, _addon: *mut *mut u8) -> i32 { -1 }
unsafe extern "C" fn missing_extract_addon_string(_addon: *mut u8, _out: *mut u32) {}

#[cfg(target_os = "none")]
const DEFAULT_CONSTRUCT_ADDON: ConstructAddon = silver_controller_transition_addon_construct_from_cstr;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_addon(_: *mut u8, _: *const u8, _: u32, _: u32, _: u32, _: u32, _: u32) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
const DEFAULT_CONSTRUCT_ADDON: ConstructAddon = missing_construct_addon;

pub const DEFAULT_CONTROLLER_TRANSITION_REQUEST_OPS: ControllerTransitionRequestOps = ControllerTransitionRequestOps {
    allocate_addon: DEFAULT_ALLOCATE_ADDON,
    request_payload: missing_request_payload,
    replace_pending_addon: missing_replace_pending_addon,
    extract_addon_string: missing_extract_addon_string,
    construct_addon: DEFAULT_CONSTRUCT_ADDON,
};

pub static mut CONTROLLER_TRANSITION_REQUEST_OPS: ControllerTransitionRequestOps = DEFAULT_CONTROLLER_TRANSITION_REQUEST_OPS;

#[inline(always)]
unsafe fn ops() -> ControllerTransitionRequestOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_TRANSITION_REQUEST_OPS)) }
}

/// Processes a request whose target layout has a controller word at +0, an
/// embedded StringObject at +4, a signed base hint at +12, and a flag at +13.
/// `controller` must be writable through +0x34; addon and request pointers
/// carry 32-bit target words, so host fixtures use opaque byte storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_transition_request(controller: *mut u8, request: *mut u8) -> u32 {
    let ops = unsafe { ops() };
    let addon = unsafe { (ops.allocate_addon)(ADDON_SIZE) };
    let source = unsafe { (ops.request_payload)(request.add(4)) };
    let base_hint = unsafe { request.add(REQUEST_BASE_HINT_OFFSET).read() as i8 as i32 as u32 };
    let flag = unsafe { request.add(REQUEST_FLAG_OFFSET).read() as u32 };
    let mut constructed = unsafe { (ops.construct_addon)(addon, source, flag, base_hint, 0x400, 1, 0) };
    let replacement = unsafe { (ops.replace_pending_addon)(controller, &mut constructed) };
    unsafe { controller.add(CONTROLLER_PENDING_OFFSET).cast::<i32>().write(replacement) };
    if replacement == -1 {
        unsafe { controller.add(CONTROLLER_STRING_OFFSET).cast::<u32>().write(0x19) };
    } else {
        let status = unsafe { constructed.add(ADDON_STATUS_OFFSET).cast::<u32>().read() };
        unsafe { controller.add(CONTROLLER_STRING_OFFSET).cast::<u32>().write(status) };
        if status == 0 {
            unsafe { (ops.extract_addon_string)(constructed, controller.add(CONTROLLER_EXTRACTED_OFFSET).cast()) };
            let target = unsafe { controller.cast::<u32>().read() };
            if target != 0 {
                unsafe { (target as usize as *mut u8).add(8).cast::<u32>().write(controller.add(CONTROLLER_EXTRACTED_OFFSET).cast::<u32>().read()) };
            }
        }
    }
    0x400
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut ADDON: [u8; ADDON_SIZE] = [0; ADDON_SIZE];
    static mut CALLS: [u32; 5] = [0; 5];
    unsafe extern "C" fn alloc(size: usize) -> *mut u8 { unsafe { CALLS[0] = size as u32; ADDON.as_mut_ptr() } }
    unsafe extern "C" fn payload(string: *const u8) -> *const u8 { unsafe { CALLS[1] = string as usize as u32; b"x\0".as_ptr() } }
    unsafe extern "C" fn construct(addon: *mut u8, _: *const u8, flag: u32, hint: u32, quantum: u32, scale: u32, _: u32) -> *mut u8 { unsafe { CALLS[2] = flag | (hint << 8); CALLS[3] = quantum | (scale << 16); addon } }
    unsafe extern "C" fn replace(_: *mut u8, addon: *mut *mut u8) -> i32 { unsafe { CALLS[4] += 1; *addon = ADDON.as_mut_ptr(); 7 } }
    unsafe extern "C" fn extract(_: *mut u8, out: *mut u32) { unsafe { out.write(0x1234_5678) } }
    #[test]
    fn publishes_successful_addon_status_and_string() {
        let _lock = LOCK.lock();
        unsafe {
            CONTROLLER_TRANSITION_REQUEST_OPS = ControllerTransitionRequestOps { allocate_addon: alloc, request_payload: payload, replace_pending_addon: replace, extract_addon_string: extract, construct_addon: construct };
            ADDON = [0; ADDON_SIZE]; CALLS = [0; 5];
            ADDON.as_mut_ptr().add(ADDON_STATUS_OFFSET).cast::<u32>().write(0);
            let mut controller = [0u8; 0x38]; let mut request = [0u8; 0x10];
            request[12] = 0xfe; request[13] = 3;
            assert_eq!(controller_transition_request(controller.as_mut_ptr(), request.as_mut_ptr()), 0x400);
            assert_eq!(CALLS, [0x54, request.as_ptr().add(4) as usize as u32, 0xffff_fe03, 0x0001_0400, 1]);
            assert_eq!(controller.as_ptr().add(CONTROLLER_STRING_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(controller.as_ptr().add(CONTROLLER_EXTRACTED_OFFSET).cast::<u32>().read(), 0x1234_5678);
            CONTROLLER_TRANSITION_REQUEST_OPS = DEFAULT_CONTROLLER_TRANSITION_REQUEST_OPS;
        }
    }
}
