//! Checked payload-value update, original `FUN_0826fd38` at `0x0826fd38`.
//! True extent: 104 bytes through the literal at 0x0826fd9c; next function
//! starts at 0x0826fda0. Incoming BL: 2 plain, 0 predicated. Outgoing calls:
//! 2 plain BL and one indirect BLX through vtable slot 2.
//!
//! Check the object virtually, compare payload+0x68, store a changed value,
//! set its element's flag bit 2, then notify element+0x54 with raw event key
//! 0x6d746274 and payload context. Field/event identities are not recovered.
//! Deliberate deviations: none on target. repr(C) pointer fields expand on
//! hosts; the unported notification walker uses a replaceable retail seam.

use core::ptr;
use super::tdat_flag_20_bit_2::tdat_element_set_flag_20_bit_2;

#[repr(C)]
pub struct CheckedPayloadVtable {
    pub preceding_slots: [usize; 2],
    pub check: unsafe extern "C" fn(*mut CheckedPayloadObject) -> u32,
}

#[repr(C)]
pub struct CheckedPayloadObject {
    pub vtable: *const CheckedPayloadVtable,
    pub opaque_word: u32,
    pub payload: *mut CheckedPayload,
}

#[repr(C)]
pub struct CheckedPayload {
    pub element: *mut u8,
    pub opaque_words: [u32; 25],
    pub value: u32,
}

pub type PayloadValueNotify = unsafe extern "C" fn(*mut u8, u32, *mut CheckedPayload, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(list: *mut u8, tag: u32, context: *mut CheckedPayload, arg: u32, stack: u32) {
    let notify: PayloadValueNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, arg, stack);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_notify(_: *mut u8, _: u32, _: *mut CheckedPayload, _: u32, _: u32) {}

/// Unported tagged-handler walker at 0x08066bb8; read at each dispatch.
pub static mut PAYLOAD_VALUE_NOTIFY_OPS: PayloadValueNotify = retail_notify;

/// Update the payload value after its owner's virtual check succeeds.
/// Original: 0x0826fd38, 104 bytes, 2 plain incoming BL and no predicated BL.
/// Store precedes flagging; reload the payload after flagging because the
/// flag setter can call handlers that replace it. Both callee results are ignored.
///
/// # Safety
/// Object/vtable must be valid and the check callable. On success, payload
/// and its element must support the field accesses and retail callees.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn checked_payload_value_set(object: *mut CheckedPayloadObject, value: u32) {
    if ((*(*object).vtable).check)(object) == 0 {
        return;
    }
    let payload = (*object).payload;
    if (*payload).value == value {
        return;
    }
    (*payload).value = value;
    tdat_element_set_flag_20_bit_2((*(*object).payload).element, 1);
    let payload = (*object).payload;
    let notify = ptr::read_volatile(ptr::addr_of!(PAYLOAD_VALUE_NOTIFY_OPS));
    notify((*payload).element.add(0x54), 0x6d74_6274, payload, 0, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tdat_flag_20_bit_2::{TdatFlag20Ops, TDAT_FLAG_20_OPS};

    static mut NOTIFICATIONS: u32 = 0;
    static mut OBJECT: *mut CheckedPayloadObject = ptr::null_mut();
    static mut REPLACEMENT: *mut CheckedPayload = ptr::null_mut();
    static mut EXPECTED_VALUE: u32 = 0;
    static mut EXPECTED_CONTEXT: *mut CheckedPayload = ptr::null_mut();

    unsafe extern "C" fn accept(_: *mut CheckedPayloadObject) -> u32 { 7 }
    unsafe extern "C" fn reject(_: *mut CheckedPayloadObject) -> u32 { 0 }
    unsafe extern "C" fn release(_: *mut u8) -> u32 { panic!("unexpected release") }
    unsafe extern "C" fn flag_notify(_: *mut u8, _: u32, _: *mut u8, _: u32, _: u32) -> u32 { 0 }
    unsafe extern "C" fn addref(element: *mut u8) -> u32 {
        assert_eq!((*(*OBJECT).payload).value, EXPECTED_VALUE);
        assert_eq!(element.add(0x20).read() & 4, 4);
        if !REPLACEMENT.is_null() { (*OBJECT).payload = REPLACEMENT; }
        0
    }
    unsafe extern "C" fn notify(list: *mut u8, tag: u32, context: *mut CheckedPayload, arg: u32, stack: u32) {
        assert_eq!(context, EXPECTED_CONTEXT);
        assert_eq!(list, (*context).element.add(0x54));
        assert_eq!((tag, arg, stack), (0x6d74_6274, 0, 0));
        NOTIFICATIONS += 1;
    }
    struct Guard(PayloadValueNotify, TdatFlag20Ops);
    impl Drop for Guard {
        fn drop(&mut self) { unsafe { PAYLOAD_VALUE_NOTIFY_OPS = self.0; TDAT_FLAG_20_OPS = self.1; } }
    }

    #[test]
    fn rejected_check_does_not_touch_null_payload() {
        let vtable = CheckedPayloadVtable { preceding_slots: [0; 2], check: reject };
        let mut object = CheckedPayloadObject { vtable: &vtable, opaque_word: 0, payload: ptr::null_mut() };
        unsafe { checked_payload_value_set(&mut object, u32::MAX); }
        assert!(object.payload.is_null());
    }

    #[test]
    fn unchanged_and_changed_values_preserve_neighbors_and_reload_after_callbacks() {
        let _lock = crate::testing::TDAT_FLAG_20_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _guard = Guard(PAYLOAD_VALUE_NOTIFY_OPS, TDAT_FLAG_20_OPS);
            PAYLOAD_VALUE_NOTIFY_OPS = notify;
            TDAT_FLAG_20_OPS = TdatFlag20Ops { refcount_release: release, refcount_addref: addref, tagged_list_notify: flag_notify };
            NOTIFICATIONS = 0;
            REPLACEMENT = ptr::null_mut();
            let mut element = [0u32; 32];
            element[1] = 0x7464_6174;
            let mut other_element = [0u32; 32];
            other_element[1] = 0x7464_6174;
            let mut payload = CheckedPayload { element: element.as_mut_ptr().cast(), opaque_words: [0xabcdefff; 25], value: 0 };
            let mut replacement = CheckedPayload { element: other_element.as_mut_ptr().cast(), opaque_words: [0; 25], value: 99 };
            let vtable = CheckedPayloadVtable { preceding_slots: [0; 2], check: accept };
            let mut object = CheckedPayloadObject { vtable: &vtable, opaque_word: 0x12345678, payload: &mut payload };
            OBJECT = &mut object;
            EXPECTED_CONTEXT = &mut payload;
            checked_payload_value_set(&mut object, 0);
            assert_eq!(NOTIFICATIONS, 0);
            assert_eq!(element[8], 0);
            EXPECTED_VALUE = u32::MAX;
            checked_payload_value_set(&mut object, u32::MAX);
            assert_eq!(payload.value, u32::MAX);
            assert_eq!(NOTIFICATIONS, 1);
            checked_payload_value_set(&mut object, u32::MAX);
            assert_eq!(NOTIFICATIONS, 1);
            // Force the flag setter's callbacks and replace the payload there.
            element[8] = 0;
            REPLACEMENT = &mut replacement;
            EXPECTED_CONTEXT = &mut replacement;
            EXPECTED_VALUE = 0;
            checked_payload_value_set(&mut object, 0);
            assert_eq!(NOTIFICATIONS, 2);
            assert_eq!(payload.value, 0);
            assert_eq!(replacement.value, 99);
            assert_eq!(object.payload, &mut replacement as *mut _);
            assert_eq!(payload.opaque_words, [0xabcdefff; 25]);
            assert_eq!(object.opaque_word, 0x12345678);
            OBJECT = ptr::null_mut();
            REPLACEMENT = ptr::null_mut();
        }
    }
}
