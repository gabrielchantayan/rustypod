//! Release a Select's owned contents without releasing the Select itself.
//!
//! `select_clear` — `FUN_082c36c4` @ 0x082c36c4, 84 bytes, ending
//! before the separate function at 0x082c3718. Raw-word scanning verifies
//! two incoming plain BL calls and zero predicated BL calls. The body has
//! eight plain BLs, zero predicated BLs, and a tail B to expr_delete.
//!
//! Release result list, FROM list, WHERE, GROUP BY, HAVING, ORDER BY,
//! prior Select, LIMIT, then OFFSET. Neither clear fields nor free the
//! containing Select. Unlike select_delete, the argument must be non-NULL.
//! Deliberate deviation: reuse the repr(C) Select view, whose pointer fields
//! widen on hosts while retaining verified retail offsets on 32-bit ARM.

use super::expr_delete::expr_delete;
use super::expr_list_delete::expr_list_delete;
use super::select_delete::{select_delete, Select};
use super::src_list_delete::src_list_delete;

/// Release owned contents of a valid Select, leaving its storage unchanged.
/// All non-NULL child pointers must satisfy their respective destructors.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_clear(select: *mut u8) {
    let node = select as *const Select;
    expr_list_delete((*node).p_elist);
    src_list_delete((*node).p_src);
    expr_delete((*node).p_where);
    expr_list_delete((*node).p_group_by);
    expr_delete((*node).p_having);
    expr_list_delete((*node).p_order_by);
    select_delete((*node).p_prior.cast());
    expr_delete((*node).p_limit);
    expr_delete((*node).p_offset);
}
