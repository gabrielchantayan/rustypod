#[cfg(test)]
use core::ptr;

/// State consumed by [`update_render_cell_state`].
///
/// The named fields are the twelve 32-bit words read or written by the retail
/// routine. The remaining rendering fields are retained as opaque words because
/// this routine only passes the whole state to the pending-cell flush.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenderCellState {
    pub opaque_00_08: [i32; 3],
    pub first_column: i32,
    pub column_limit: i32,
    pub first_row: i32,
    pub row_limit: i32,
    pub opaque_pending_1c: i32,
    pub opaque_pending_20: i32,
    pub outside_visible_range: i32,
    pub last_column: i32,
    pub last_row: i32,
}

const _: [(); 48] = [(); core::mem::size_of::<RenderCellState>()];

type FlushPendingCell = unsafe extern "C" fn(*mut RenderCellState);

/// Unported direct callee `FUN_0809b13c`, which flushes the pending cell.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn flush_pending_cell(state: *mut RenderCellState) {
    let flush: FlushPendingCell = core::mem::transmute(0x0809_b13cusize);
    flush(state);
}

#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn flush_pending_cell(_state: *mut RenderCellState) {}

#[cfg(test)]
unsafe extern "C" fn inert_flush_pending_cell(_state: *mut RenderCellState) {}

#[cfg(test)]
static mut FLUSH_PENDING_CELL: FlushPendingCell = inert_flush_pending_cell;

#[cfg(test)]
#[inline(always)]
unsafe fn flush_pending_cell(state: *mut RenderCellState) {
    let flush = ptr::addr_of!(FLUSH_PENDING_CELL).read_volatile();
    flush(state);
}

/// `update_render_cell_state` — original: `FUN_08084ae8` @ `0x08084ae8`
/// (156 bytes; seven verified inbound `bl` callers, all unconditional).
///
/// Determines whether `(column, row)` lies in the state’s visible row and
/// column limits. Visible columns below `first_column` canonicalize to the
/// preceding column. A changed visibility or cell flushes the pending cell;
/// pending geometry clears when the old cell is inactive or a new cell is
/// selected, then the state records the new visibility and coordinates. The
/// only outbound call is the predicated `blne` to `FUN_0809b13c`.
///
/// Deliberate deviation: the unported flush stays a fixed-address call on the
/// device and is a volatile, replaceable host-test seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.update_render_cell_state")]
#[inline(never)]
pub unsafe extern "C" fn update_render_cell_state(
    state: *mut RenderCellState,
    mut column: i32,
    row: i32,
) {
    let mut outside_visible_range = 1;
    if (*state).first_row <= row {
        if row < (*state).row_limit {
            if column < (*state).column_limit {
                outside_visible_range = 0;
            }
        }
    }

    let mut clear_pending = 1;
    let mut position_changed = false;
    if outside_visible_range == 0 {
        if column < (*state).first_column {
            column = (*state).first_column.wrapping_sub(1);
        }
        position_changed = (*state).last_column != column || (*state).last_row != row;
        if !position_changed {
            clear_pending = (*state).outside_visible_range;
        }
    }

    if (*state).outside_visible_range != outside_visible_range || position_changed {
        flush_pending_cell(state);
    }
    if clear_pending != 0 {
        (*state).opaque_pending_1c = 0;
        (*state).opaque_pending_20 = 0;
    }
    (*state).outside_visible_range = outside_visible_range;
    (*state).last_column = column;
    (*state).last_row = row;
}

#[cfg(test)]
mod tests {
    use super::{inert_flush_pending_cell, update_render_cell_state, RenderCellState, FLUSH_PENDING_CELL};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FLUSH_CALLS: u32 = 0;
    static mut FLUSHED_STATE: *mut RenderCellState = core::ptr::null_mut();

    unsafe extern "C" fn record_flush(state: *mut RenderCellState) {
        FLUSH_CALLS += 1;
        FLUSHED_STATE = state;
    }

    fn state() -> RenderCellState {
        RenderCellState {
            opaque_00_08: [0x1111_1111, 0x2222_2222, 0x3333_3333],
            first_column: 4,
            column_limit: 7,
            first_row: 10,
            row_limit: 12,
            opaque_pending_1c: 0x4444_4444,
            opaque_pending_20: 0x5555_5555,
            outside_visible_range: 1,
            last_column: -1,
            last_row: -1,
        }
    }

    unsafe fn install_recorder() {
        FLUSH_CALLS = 0;
        FLUSHED_STATE = core::ptr::null_mut();
        FLUSH_PENDING_CELL = record_flush;
    }

    unsafe fn remove_recorder() {
        FLUSH_PENDING_CELL = inert_flush_pending_cell;
    }

    #[test]
    fn entering_visible_cell_clamps_column_flushes_and_clears_pending_geometry() {
        let _guard = TEST_LOCK.lock();
        let mut render_state = state();
        unsafe {
            install_recorder();
            update_render_cell_state(&mut render_state, 2, 10);
            remove_recorder();
        }

        assert_eq!(unsafe { FLUSH_CALLS }, 1);
        assert_eq!(unsafe { FLUSHED_STATE }, &mut render_state as *mut RenderCellState);
        assert_eq!(render_state.opaque_pending_1c, 0);
        assert_eq!(render_state.opaque_pending_20, 0);
        assert_eq!(render_state.outside_visible_range, 0);
        assert_eq!((render_state.last_column, render_state.last_row), (3, 10));
        assert_eq!(render_state.opaque_00_08, [0x1111_1111, 0x2222_2222, 0x3333_3333]);
    }

    #[test]
    fn unchanged_visible_cell_preserves_pending_geometry_without_flush() {
        let _guard = TEST_LOCK.lock();
        let mut render_state = state();
        render_state.outside_visible_range = 0;
        render_state.last_column = 5;
        render_state.last_row = 11;
        unsafe {
            install_recorder();
            update_render_cell_state(&mut render_state, 5, 11);
            remove_recorder();
        }

        assert_eq!(unsafe { FLUSH_CALLS }, 0);
        assert_eq!(render_state.opaque_pending_1c, 0x4444_4444);
        assert_eq!(render_state.opaque_pending_20, 0x5555_5555);
        assert_eq!(render_state.outside_visible_range, 0);
    }

    #[test]
    fn unchanged_invisible_cell_clears_pending_geometry_without_flush() {
        let _guard = TEST_LOCK.lock();
        let mut render_state = state();
        render_state.last_column = 7;
        render_state.last_row = 10;
        unsafe {
            install_recorder();
            update_render_cell_state(&mut render_state, 7, 10);
            remove_recorder();
        }

        assert_eq!(unsafe { FLUSH_CALLS }, 0);
        assert_eq!(render_state.opaque_pending_1c, 0);
        assert_eq!(render_state.opaque_pending_20, 0);
        assert_eq!(render_state.outside_visible_range, 1);
    }

    #[test]
    fn visible_bounds_are_first_row_inclusive_and_limits_exclusive() {
        let _guard = TEST_LOCK.lock();
        let cases = [(6, 10, 0), (7, 10, 1), (6, 12, 1), (6, 9, 1)];

        for (column, row, expected_outside) in cases {
            let mut render_state = state();
            unsafe {
                install_recorder();
                update_render_cell_state(&mut render_state, column, row);
                remove_recorder();
            }
            assert_eq!(render_state.outside_visible_range, expected_outside, "({column}, {row})");
        }
    }
}
