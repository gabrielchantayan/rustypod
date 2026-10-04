//! Current registration value query — `FUN_0820d370` @ `0x0820d370`.
//! True extent: 104 bytes, [0x0820d370, 0x0820d3d8); the next real
//! function starts with push {r4-r7,lr}. Binary-wide ARM branch decoding
//! finds two inbound plain BLs (0x0820a280, 0x0821c150), zero predicated
//! BLs and no tail B callers. The body has four plain BLs, zero predicated
//! BLs and one register BLX through vtable +0x30.
//!
//! Initialize a stack registration wrapper from the stored context and both
//! selector words, obtain its current record, and call that record's +0x30
//! method with the output pointer. Return one for an absent record or any
//! nonzero method result, zero otherwise; destroy the wrapper on every path.
//! Callers compare the written value against another record value only on
//! success. No more specific virtual-method identity is established.
//! Deliberate deviations: named fields and native-width vtable slots support
//! host pointer widening, following registration_handle_current_status. Host
//! lookup uses the named owner/index fields; target uses the existing accessor.
//! The original dead stacked argument copies are omitted. No semantic changes.

#[cfg(target_os = "none")]
use crate::app::current_record_handle::{current_record_handle_from_owner, CurrentRecordCursorOwner};
use crate::app::registration_handle_wrapper::{
    registration_handle_wrapper_destroy, registration_handle_wrapper_init, RegistrationHandleWrapper,
};

#[repr(C)]
pub struct CurrentRegistrationValueTarget {
    pub vtable: *const CurrentRegistrationValueVtable,
}

#[repr(C)]
pub struct CurrentRegistrationValueVtable {
    pub preceding_slots: [usize; 12],
    pub query_value: unsafe extern "C" fn(*mut CurrentRegistrationValueTarget, *mut u32) -> i32,
}

#[inline(always)]
unsafe fn query_current_value(target: *mut CurrentRegistrationValueTarget, value_out: *mut u32) -> i32 {
    if target.is_null() {
        1
    } else {
        (((*(*target).vtable).query_value)(target, value_out) != 0) as i32
    }
}

/// # Safety
/// `context_source` is readable and aligned. Its stored context satisfies
/// registration_handle_wrapper_init's owner requirements. A selected record's
/// +4 word identifies a valid target and +0x30 callback; `value_out` satisfies
/// that callback's output contract. There are no added pointer/bounds guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_query_current_value(
    context_source: *const *mut u8,
    selector_first: u32,
    value_out: *mut u32,
    selector_second: u32,
) -> i32 {
    let mut wrapper = core::mem::MaybeUninit::<RegistrationHandleWrapper>::uninit();
    registration_handle_wrapper_init(wrapper.as_mut_ptr(), context_source.read(), selector_first, selector_second);
    let wrapper = wrapper.assume_init_mut();
    #[cfg(target_os = "none")]
    let target = current_record_handle_from_owner(
        wrapper as *mut RegistrationHandleWrapper as *const CurrentRecordCursorOwner,
    ) as usize as *mut CurrentRegistrationValueTarget;
    #[cfg(not(target_os = "none"))]
    let target = if wrapper.registration.slot_index == -1 {
        core::ptr::null_mut()
    } else {
        let record = (wrapper.registration.owner as usize)
            .wrapping_add((wrapper.registration.slot_index as usize).wrapping_mul(0x14));
        (record.wrapping_add(4) as *const u32).read() as usize as *mut CurrentRegistrationValueTarget
    };
    let result = query_current_value(target, value_out);
    registration_handle_wrapper_destroy(wrapper);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        target: CurrentRegistrationValueTarget,
        value: u32,
        result: i32,
    }

    unsafe extern "C" fn query(target: *mut CurrentRegistrationValueTarget, out: *mut u32) -> i32 {
        let fixture = target as *mut Fixture;
        out.write((*fixture).value);
        (*fixture).result
    }

    #[test]
    fn absent_record_preserves_output_and_does_not_dereference_it() {
        let context = core::ptr::null_mut();
        let mut output = 0xdead_beef;
        unsafe {
            assert_eq!(registration_handle_query_current_value(&context, u32::MAX, &mut output, 0x8000_0000), 1);
            assert_eq!(registration_handle_query_current_value(&context, 0, core::ptr::null_mut(), u32::MAX), 1);
        }
        assert_eq!(output, 0xdead_beef);
    }

    #[test]
    fn callback_writes_output_even_on_error_and_result_is_normalized() {
        let vtable = CurrentRegistrationValueVtable { preceding_slots: [0; 12], query_value: query };
        let mut fixture = Fixture {
            target: CurrentRegistrationValueTarget { vtable: &vtable }, value: 0, result: 0,
        };
        for status in [0, 1, -1, i32::MIN, i32::MAX] {
            for value in [0, u32::MAX, 0x8000_0000] {
                fixture.result = status;
                fixture.value = value;
                let mut output = !value;
                assert_eq!(unsafe { query_current_value(&mut fixture.target, &mut output) }, (status != 0) as i32);
                assert_eq!(output, value);
            }
        }
    }
}
