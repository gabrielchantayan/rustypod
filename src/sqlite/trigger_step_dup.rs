//! SQLite trigger-step cloning.
//!
//! `trigger_step_dup` — original: `FUN_08391954` at load address
//! `0x08391954`, 204 bytes (`0x08391954..0x08391a1f`, bounded by the next
//! `push` at `0x08391a20`), with three unconditional inbound `bl` call sites
//! (0x083851f8, 0x0839b310, and 0x0839b3f0) and no predicated forms.
//!
//! SQLite 3.5.x duplicates the owned children of a freshly assembled
//! `TriggerStep` in place: token text, SELECT, WHEN expression, expression
//! list, and identifier list. Each replacement is computed before its old
//! value is deleted. NULL fields are skipped. The copied token is marked
//! dynamic even when allocation fails, exactly as the ARM `orr #1` does.
//!
//! Deliberate deviation: on 64-bit hosts the typed view widens pointer fields,
//! so it preserves field relationships rather than target byte offsets. The
//! target's direct `sqlite3SelectDup` and `sqlite3ExprListDup` calls use their
//! existing volatile seams until those callees are ported.

use super::expr_delete::expr_delete;
use super::expr_dup::{expr_list_dup_op, expr_dup, select_dup_op};
use super::expr_list_delete::expr_list_delete;
use super::id_list_delete::id_list_delete;
use super::select_delete::select_delete;
use super::strdup::db_str_ndup;

/// The `TriggerStep` fields touched by `sqlite3TriggerStepListDup`.
#[repr(C)]
pub struct TriggerStep {
    /// +0x00..+0x0b: operation metadata and links not touched here.
    pub _head: [u8; 0x0c],
    /// +0x0c: SELECT to duplicate then delete.
    pub p_select: *mut u8,
    /// +0x10: target token text.
    pub target_z: *mut u8,
    /// +0x14: `target.n:31 | dyn:1`.
    pub target_n_dyn: u32,
    /// +0x18: WHEN expression.
    pub p_where: *mut u8,
    /// +0x1c: SET expression list.
    pub p_expr_list: *mut u8,
    /// +0x20: UPDATE column-name list.
    pub p_id_list: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_SELECT_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(TriggerStep, p_select)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_TARGET_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(TriggerStep, target_z)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_TOKEN_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(TriggerStep, target_n_dyn)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_WHERE_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(TriggerStep, p_where)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_EXPR_LIST_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(TriggerStep, p_expr_list)];
#[cfg(target_pointer_width = "32")]
const _TRIGGER_STEP_ID_LIST_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(TriggerStep, p_id_list)];

/// `trigger_step_dup` — original: `FUN_08391954` @ 0x08391954 (204 bytes;
/// three direct, unconditional inbound `bl` call sites).
///
/// Clone one trigger step's owned children in place, disposing each old child
/// only after obtaining its replacement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn trigger_step_dup(db: *mut u8, step: *mut TriggerStep) {
    let step = &mut *step;
    if !step.target_z.is_null() {
        step.target_z = db_str_ndup(db, step.target_z, (step.target_n_dyn >> 1) as i32);
        step.target_n_dyn |= 1;
    }
    if !step.p_select.is_null() {
        let copy = (select_dup_op())(db, step.p_select);
        select_delete(step.p_select);
        step.p_select = copy;
    }
    if !step.p_where.is_null() {
        let copy = expr_dup(db, step.p_where.cast());
        expr_delete(step.p_where);
        step.p_where = copy.cast();
    }
    if !step.p_expr_list.is_null() {
        let copy = (expr_list_dup_op())(db, step.p_expr_list);
        expr_list_delete(step.p_expr_list);
        step.p_expr_list = copy;
    }
    if !step.p_id_list.is_null() {
        let copy = super::id_list_dup::id_list_dup(db, step.p_id_list.cast());
        id_list_delete(step.p_id_list);
        step.p_id_list = copy.cast();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};

    #[test]
    fn null_children_are_unchanged_without_allocating() {
        let _allocator_guard = install_recorder(core::ptr::null_mut());
        let mut step: TriggerStep = unsafe { core::mem::zeroed() };

        unsafe { trigger_step_dup(core::ptr::null_mut(), &mut step) };

        assert!(step.target_z.is_null());
        assert!(step.p_select.is_null());
        assert!(step.p_where.is_null());
        assert!(step.p_expr_list.is_null());
        assert!(step.p_id_list.is_null());
        assert!(realloc_log().is_empty());
    }

    #[test]
    fn duplicates_target_token_and_sets_ownership_on_allocation_failure() {
        let _allocator_guard = install_recorder(core::ptr::null_mut());
        let mut db = [0u8; 0x20];
        let mut token = *b"update";
        let mut step: TriggerStep = unsafe { core::mem::zeroed() };
        step.target_z = token.as_mut_ptr();
        step.target_n_dyn = (token.len() as u32) << 1;

        unsafe { trigger_step_dup(db.as_mut_ptr(), &mut step) };

        assert!(step.target_z.is_null());
        assert_eq!(step.target_n_dyn, ((token.len() as u32) << 1) | 1);
        assert_eq!(db[0x1e], 1);
    }
}
