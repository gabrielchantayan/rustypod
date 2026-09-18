//! `range_result_collect` — original: `FUN_0814053c` @ `0x0814053c`.
//!
//! Raw ARM extent is exactly 168 bytes, `0x0814053c..0x081405e4`; the next
//! independently linked function begins at `0x081405e4`. It has four inbound
//! plain unconditional `bl` call sites and no predicated `bl` instructions,
//! plus six outbound plain unconditional `bl` instructions: `0x0829b86c`,
//! `0x081f7278`, `0x08158cf0`, `0x0829b1e8`, `0x081573f8`, and `0x0829bd50`.
//! # Algorithm
//!
//! If `context + 0x30` is nonzero, iterates the inclusive u32 range described
//! by `range[0]..=range[2]`. Each candidate constructs a 16-word range state
//! with resolution one, clears a four-word result, evaluates the retained
//! retail constraint, then dispatches successful states through the context's
//! result handler and appends the result. It returns one at the first successful
//! append, otherwise zero. The wrapping increment and unsigned `<=` comparison
//! deliberately preserve the retail loop's `u32::MAX` behavior.
//!
//! Deliberate deviations: the three unported calls are named, typed veneers on
//! firmware and replaceable host seams; direct calls use the already ported
//! range-state constructor and four-word clear.
use core::mem::MaybeUninit;

use crate::cxx::four_word_clear::four_word_clear;
use crate::util::range_state::{range_state_construct, RangeState};

/// ABI of retail constraint evaluation at `0x0829b1e8`.
type RetailRangeConstraintEvaluate = unsafe extern "C" fn(*const u32, *mut RangeState, *mut u32) -> u32;
/// ABI of retail result dispatch at `0x081573f8`.
type RetailRangeResultDispatch = unsafe extern "C" fn(u32, *mut RangeState, *mut u32);
/// ABI of retail result append at `0x0829bd50`.
type RetailRangeResultAppend = unsafe extern "C" fn(*const u32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_range_constraint_evaluate(_context: *const u32, _state: *mut RangeState, _result: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_range_result_dispatch(_handler: u32, _state: *mut RangeState, _result: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_range_result_append(_range: *const u32, _result: *mut u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
static mut RANGE_CONSTRAINT_EVALUATE: RetailRangeConstraintEvaluate = unavailable_range_constraint_evaluate;
#[cfg(not(target_os = "none"))]
static mut RANGE_RESULT_DISPATCH: RetailRangeResultDispatch = unavailable_range_result_dispatch;
#[cfg(not(target_os = "none"))]
static mut RANGE_RESULT_APPEND: RetailRangeResultAppend = unavailable_range_result_append;

#[cfg(target_os = "none")]
extern "C" {
    fn retail_range_constraint_evaluate(context: *const u32, state: *mut RangeState, result: *mut u32) -> u32;
    fn retail_range_result_dispatch(handler: u32, state: *mut RangeState, result: *mut u32);
    fn retail_range_result_append(range: *const u32, result: *mut u32) -> u32;
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_range_constraint_evaluate(context: *const u32, state: *mut RangeState, result: *mut u32) -> u32 {
    RANGE_CONSTRAINT_EVALUATE(context, state, result)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_range_result_dispatch(handler: u32, state: *mut RangeState, result: *mut u32) {
    RANGE_RESULT_DISPATCH(handler, state, result)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_range_result_append(range: *const u32, result: *mut u32) -> u32 {
    RANGE_RESULT_APPEND(range, result)
}

#[cfg(target_os = "none")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_range_constraint_evaluate
    .type retail_range_constraint_evaluate, %function
retail_range_constraint_evaluate:
    ldr pc, [pc, #-4]
    .word 0x0829b1e8
    .size retail_range_constraint_evaluate, . - retail_range_constraint_evaluate
    .globl retail_range_result_dispatch
    .type retail_range_result_dispatch, %function
retail_range_result_dispatch:
    ldr pc, [pc, #-4]
    .word 0x081573f8
    .size retail_range_result_dispatch, . - retail_range_result_dispatch
    .globl retail_range_result_append
    .type retail_range_result_append, %function
retail_range_result_append:
    ldr pc, [pc, #-4]
    .word 0x0829bd50
    .size retail_range_result_append, . - retail_range_result_append
"#);

/// Collects the first appendable result across an inclusive candidate range.
///
/// # Safety
/// `context` needs readable word 12; `range` needs readable words 0 and 2.
/// The retained retail evaluator, dispatcher, and appender define their own
/// pointer and object-layout requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.range_result_collect")]
#[inline(never)]
pub unsafe extern "C" fn range_result_collect(context: *const u32, range: *const u32, output: *mut u32) -> u32 {
    if context.add(12).read() == 0 {
        return 0;
    }

    let mut candidate = range.read();
    loop {
        let mut state = MaybeUninit::<RangeState>::uninit();
        let state = state.as_mut_ptr();
        range_state_construct(state, &candidate, 1);
        four_word_clear(output);
        if retail_range_constraint_evaluate(context, state, output) != 0 {
            retail_range_result_dispatch(context.add(12).read(), state, output);
            if retail_range_result_append(range, output) != 0 {
                return 1;
            }
        }
        candidate = candidate.wrapping_add(1);
        if range.add(2).read() < candidate {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVALUATED: [u32; 8] = [0; 8];
    static mut EVALUATED_LEN: usize = 0;
    static mut DISPATCHED: u32 = 0;
    static mut APPENDED: u32 = 0;
    static mut APPEND_ON: u32 = 0;

    unsafe extern "C" fn evaluate(_context: *const u32, _state: *mut RangeState, output: *mut u32) -> u32 {
        let call = EVALUATED_LEN as u32 + 1;
        EVALUATED[EVALUATED_LEN] = call;
        EVALUATED_LEN += 1;
        output.write(call ^ 0xa5a5_0000);
        call & 1
    }
    unsafe extern "C" fn dispatch(_handler: u32, _state: *mut RangeState, output: *mut u32) {
        DISPATCHED += 1;
        output.add(1).write(0xd15f_0000u32.wrapping_add(DISPATCHED));
    }
    unsafe extern "C" fn append(_range: *const u32, _output: *mut u32) -> u32 {
        APPENDED += 1;
        (APPENDED == APPEND_ON) as u32
    }

    unsafe fn install(append_on: u32) {
        RANGE_CONSTRAINT_EVALUATE = evaluate;
        RANGE_RESULT_DISPATCH = dispatch;
        RANGE_RESULT_APPEND = append;
        EVALUATED_LEN = 0;
        DISPATCHED = 0;
        APPENDED = 0;
        APPEND_ON = append_on;
    }

    #[test]
    fn skips_everything_when_context_has_no_result_handler() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            install(1);
            let context = [0u32; 13];
            let range = [2, 0, 4];
            let mut output = [0xfeed_face; 4];
            assert_eq!(range_result_collect(context.as_ptr(), range.as_ptr(), output.as_mut_ptr()), 0);
            assert_eq!(EVALUATED_LEN, 0);
            assert_eq!(output, [0xfeed_face; 4]);
        }
    }

    #[test]
    fn clears_each_output_then_stops_on_first_appendable_success() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            install(2);
            let mut context = [0u32; 13];
            context[12] = 0x1234;
            let range = [2, 0, 7];
            let mut output = [0xdead_beef; 4];
            assert_eq!(range_result_collect(context.as_ptr(), range.as_ptr(), output.as_mut_ptr()), 1);
            assert_eq!(&EVALUATED[..EVALUATED_LEN], &[1, 2, 3]);
            assert_eq!(DISPATCHED, 2);
            assert_eq!(APPENDED, 2);
            assert_eq!(output, [3 ^ 0xa5a5_0000, 0xd15f_0002, 0, 0]);
        }
    }

    #[test]
    fn completes_an_inclusive_range_when_no_append_succeeds() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            install(3);
            let mut context = [0u32; 13];
            context[12] = 1;
            let range = [0, 0, 2];
            let mut output = [9; 4];
            assert_eq!(range_result_collect(context.as_ptr(), range.as_ptr(), output.as_mut_ptr()), 0);
            assert_eq!(&EVALUATED[..EVALUATED_LEN], &[1, 2, 3]);
            assert_eq!(DISPATCHED, 2);
            assert_eq!(APPENDED, 2);
            assert_eq!(output, [3 ^ 0xa5a5_0000, 0xd15f_0002, 0, 0]);
        }
    }
}
