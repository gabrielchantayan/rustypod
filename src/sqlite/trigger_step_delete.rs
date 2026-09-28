//! SQLite trigger-step destruction.
//!
//! - `trigger_step_delete` — original: `FUN_08375378` @ 0x08375378 (88 bytes;
//!   2 inbound plain `bl` call sites, no predicated inbound `bl`; 5 plain and
//!   1 predicated outbound `bl`, binary-scanned).
//!
//! Raw ARM spans 0x08375378..0x083753cf; the separate token-dequote helper
//! begins at 0x083753d0. SQLite 3.5.x's `sqlite3DeleteTriggerStep` walks the
//! singly linked TriggerStep chain. For each node it conditionally frees the
//! target token text, releases its WHERE expression, expression list, SELECT,
//! and identifier list, then frees the node. The successor is loaded before
//! any release.
//! Deliberate deviations: typed `#[repr(C)]` fields replace target-word
//! offsets, widening pointers on host builds while retaining the ARM offsets
//! and stride; the Rust NULL guard returns before the ARM frame setup.

use super::expr_delete::expr_delete;
use super::expr_list_delete::expr_list_delete;
use super::id_list_delete::id_list_delete;
use super::select_delete::select_delete;
use crate::heap::tracked::tracked_free;

/// The fields of SQLite's `TriggerStep` used by its destructor.
#[repr(C)]
pub struct TriggerStep {
    /// +0x00..+0x0b: operation and trigger metadata, not read here.
    pub _prefix: [u8; 0x0c],
    /// +0x0c: SELECT body.
    pub p_select: *mut u8,
    /// +0x10: target token text.
    pub target_z: *mut u8,
    /// +0x14: target token length shifted left one, with dynamic bit zero.
    pub target_n_dyn: u32,
    /// +0x18: WHEN expression.
    pub p_where: *mut u8,
    /// +0x1c: SET expression list.
    pub p_expr_list: *mut u8,
    /// +0x20: UPDATE column list.
    pub p_id_list: *mut u8,
    /// +0x24: next TriggerStep.
    pub next: *mut TriggerStep,
}

#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_SELECT_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(TriggerStep, p_select)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_TARGET_Z_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(TriggerStep, target_z)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_TARGET_N_DYN_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(TriggerStep, target_n_dyn)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_WHERE_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(TriggerStep, p_where)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_EXPR_LIST_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(TriggerStep, p_expr_list)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_ID_LIST_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(TriggerStep, p_id_list)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_NEXT_OFFSET: [u8; 0x24] = [0; core::mem::offset_of!(TriggerStep, next)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_SIZE: [u8; 0x28] = [0; core::mem::size_of::<TriggerStep>()];

/// `trigger_step_delete` — original: `FUN_08375378` @ 0x08375378 (88 bytes;
/// 2 inbound plain `bl` call sites, no predicated inbound `bl`; 5 plain and
/// 1 predicated outbound `bl`, binary-scanned).
/// `next`, conditionally frees `target_z` when its packed dynamic bit is set,
/// then releases the expression, expression list, SELECT, identifier list, and
/// the step allocation in the original ARM order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn trigger_step_delete(mut step: *mut TriggerStep) {
    while !step.is_null() {
        let current = &*step;
        step = current.next;
        if current.target_n_dyn & 1 != 0 {
            tracked_free(current.target_z);
        }
        expr_delete(current.p_where);
        expr_list_delete(current.p_expr_list);
        select_delete(current.p_select);
        id_list_delete(current.p_id_list);
        tracked_free(current as *const TriggerStep as *mut u8);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    static SLOT_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    #[repr(align(32))]
    struct TrackedBlock([u8; 128]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = Self([0; 128]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }

        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn payload(&mut self) -> *mut u8 {
            unsafe { self.raw().add(32) }
        }
    }

    unsafe fn with_recording_free(body: impl FnOnce()) {
        let saved_heap_ops = core::ptr::read(core::ptr::addr_of!(HEAP_OPS));
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        body();
        core::ptr::write(core::ptr::addr_of_mut!(HEAP_OPS), saved_heap_ops);
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { with_recording_free(|| trigger_step_delete(core::ptr::null_mut())) };
        assert!(unsafe { (*core::ptr::addr_of!(FREED)).is_empty() });
    }

    #[test]
    fn walks_successors_before_releasing_each_step_and_honors_target_ownership() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut first = TrackedBlock::new(0x28);
        let mut second = TrackedBlock::new(0x28);
        let mut target = TrackedBlock::new(6);
        unsafe {
            let first_step = first.payload() as *mut TriggerStep;
            let second_step = second.payload() as *mut TriggerStep;
            core::ptr::write_bytes(first_step, 0, 1);
            core::ptr::write_bytes(second_step, 0, 1);
            (*first_step).target_z = target.payload();
            (*first_step).target_n_dyn = 1;
            (*first_step).next = second_step;
            (*second_step).target_z = target.payload();
            (*second_step).target_n_dyn = 0;
            with_recording_free(|| trigger_step_delete(first_step));
        }
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(FREED)).clone() },
            std::vec![
                (target.raw(), TAG_TRACKED),
                (first.raw(), TAG_TRACKED),
                (second.raw(), TAG_TRACKED),
            ],
            "the saved successor survives the first step free; only dyn target text is released"
        );
    }
}
