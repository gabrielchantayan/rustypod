//! SQLite trigger destruction.
//!
//! - `trigger_delete` — original: `FUN_08375328` @ 0x08375328 (80 bytes;
//!   five inbound `bl` forms: four unconditional at 0x083794f8,
//!   0x0838284c, 0x08382cb0, and 0x0838a1f8, plus `bleq` at 0x083701ec).
//!
//! Raw ARM is exactly 0x08375328..0x08375374: the next independently linked
//! function starts at 0x08375378. SQLite 3.5.x's `sqlite3DeleteTrigger` first
//! releases the linked TriggerStep chain, then releases the trigger name,
//! target table name, WHEN expression, identifier list, and dynamic name-token
//! text in that order. It tail-branches to `sqlite3_free` for the Trigger
//! allocation itself. The target's sole conditional call is `blne sqlite3_free`
//! for `nameToken.z`, gated by nameToken's bit-0 ownership flag.
//!
//! `sqlite3DeleteTriggerStep` @ 0x08375378 is ported as
//! [`trigger_step_delete`], so every target callee is invoked directly. The
//! typed `#[repr(C)]` view preserves all target offsets on ARM; host fields
//! widen without overlapping.

use super::expr_delete::expr_delete;
use super::trigger_step_delete::trigger_step_delete;
use super::id_list_delete::id_list_delete;
use crate::heap::tracked::tracked_free;


/// The `Trigger` fields consumed by `sqlite3DeleteTrigger`.
///
/// The target has unmodeled fields at +0x08 and +0x1c..+0x23. Pointer fields
/// intentionally remain typed rather than being addressed by host byte offsets.
#[repr(C)]
pub struct Trigger {
    /// +0x00: trigger name, released unconditionally.
    pub z_name: *mut u8,
    /// +0x04: table name, released unconditionally.
    pub table: *mut u8,
    /// +0x08: operation/timing metadata not read here.
    pub _gap_08: [u8; 0x04],
    /// +0x0c: optional WHEN expression.
    pub p_when: *mut u8,
    /// +0x10: optional column-name list.
    pub p_columns: *mut u8,
    /// +0x14: `nameToken.z`, released only when `name_token_dyn & 1 != 0`.
    pub name_token_z: *mut u8,
    /// +0x18: `nameToken.n:31 | dyn:1`.
    pub name_token_dyn: u32,
    /// +0x1c..+0x24: parser metadata not read here on the ARM target.
    #[cfg(target_pointer_width = "32")]
    pub _gap_1c: [u8; 0x08],
    /// +0x24: head of the `TriggerStep` chain on the ARM target.
    #[cfg(target_pointer_width = "32")]
    pub step_list: *mut u8,
    /// Host-only padding before the widened step-list pointer.
    #[cfg(target_pointer_width = "64")]
    pub _gap_host: [u8; 0x08],
    /// Host home of the widened `TriggerStep *`.
    #[cfg(target_pointer_width = "64")]
    pub step_list: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _TRIGGER_Z_NAME_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Trigger, z_name)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_TABLE_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(Trigger, table)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_WHEN_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Trigger, p_when)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_COLUMNS_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Trigger, p_columns)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_NAME_TOKEN_Z_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Trigger, name_token_z)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_NAME_TOKEN_DYN_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(Trigger, name_token_dyn)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_LIST_OFFSET: [u8; 0x24] = [0; core::mem::offset_of!(Trigger, step_list)];

/// `trigger_delete` — original: `FUN_08375328` @ 0x08375328 (80 bytes; five
/// inbound `bl` forms).
///
/// SQLite's `sqlite3DeleteTrigger`: NULL is a no-op. For a live trigger, its
/// step list is released first, followed by z_name, table, p_when, p_columns,
/// and conditional nameToken.z in the raw ARM call order. The trigger block is
/// the final `tracked_free`, matching the original's tail branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn trigger_delete(trigger: *mut u8) {
    if trigger.is_null() {
        return;
    }

    let trigger = &*(trigger as *const Trigger);
    trigger_step_delete(trigger.step_list.cast());
    tracked_free(trigger.z_name);
    tracked_free(trigger.table);
    expr_delete(trigger.p_when);
    id_list_delete(trigger.p_columns);
    if trigger.name_token_dyn & 1 != 0 {
        tracked_free(trigger.name_token_z);
    }
    tracked_free(trigger as *const Trigger as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use crate::sqlite::expr_delete::Expr;
    use crate::sqlite::id_list_delete::IdList;
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
    struct TrackedBlock([u8; 512]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = Self([0; 512]);
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

    unsafe fn with_ops(body: impl FnOnce()) {
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
        unsafe { with_ops(|| trigger_delete(core::ptr::null_mut())) };
        assert!(unsafe { (*core::ptr::addr_of!(FREED)).is_empty() });
    }

    #[test]
    fn releases_children_in_arm_order_and_frees_dynamic_token() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut trigger_block = TrackedBlock::new(0x28);
        let mut name = TrackedBlock::new(8);
        let mut table = TrackedBlock::new(8);
        let mut when = TrackedBlock::new(0x44);
        let mut columns = TrackedBlock::new(0x0c);
        let mut token = TrackedBlock::new(8);
        let trigger = trigger_block.payload() as *mut Trigger;
        let when_expr = when.payload() as *mut Expr;
        let id_list = columns.payload() as *mut IdList;
        unsafe {
            core::ptr::write_bytes(trigger, 0, 1);
            core::ptr::write_bytes(when_expr, 0, 1);
            core::ptr::write_bytes(id_list, 0, 1);
            (*trigger).z_name = name.payload();
            (*trigger).table = table.payload();
            (*trigger).p_when = when_expr.cast();
            (*trigger).p_columns = id_list.cast();
            (*trigger).name_token_z = token.payload();
            (*trigger).name_token_dyn = 1;
            (*trigger).step_list = core::ptr::null_mut();
            with_ops(|| trigger_delete(trigger.cast()));
        }

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(FREED)).clone() },
            std::vec![
                (name.raw(), TAG_TRACKED),
                (table.raw(), TAG_TRACKED),
                (when.raw(), TAG_TRACKED),
                (columns.raw(), TAG_TRACKED),
                (token.raw(), TAG_TRACKED),
                (trigger_block.raw(), TAG_TRACKED),
            ],
            "trigger fields are released before the owning allocation"
        );
    }

    #[test]
    fn borrowed_token_is_not_freed_but_step_teardown_still_runs() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut trigger_block = TrackedBlock::new(0x28);
        let mut token = TrackedBlock::new(8);
        let trigger = trigger_block.payload() as *mut Trigger;
        unsafe {
            core::ptr::write_bytes(trigger, 0, 1);
            (*trigger).name_token_z = token.payload();
            (*trigger).name_token_dyn = 0;
            (*trigger).step_list = core::ptr::null_mut();
            with_ops(|| trigger_delete(trigger.cast()));
        }

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(FREED)).clone() },
            std::vec![(trigger_block.raw(), TAG_TRACKED)],
            "clear dyn bit leaves borrowed nameToken.z alone"
        );
    }
}
