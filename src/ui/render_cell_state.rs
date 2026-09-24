use crate::runtime::setjmp::{longjmp, JmpBuf};

/// State consumed by [`update_render_cell_state`] and [`flush_pending_cell`].
///
/// The named fields are the twelve 32-bit words read or written by the retail
/// routines. `cells` is a target-width pointer to 16-byte cell records.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenderCellState {
    pub cells: u32,
    pub cell_capacity: i32,
    pub cell_count: i32,
    pub first_column: i32,
    pub column_limit: i32,
    pub first_row: i32,
    pub row_limit: i32,
    pub pending_height: i32,
    pub pending_width: i32,
    pub outside_visible_range: i32,
    pub last_column: i32,
    pub last_row: i32,
}

const _: [(); 48] = [(); core::mem::size_of::<RenderCellState>()];

/// `flush_pending_cell` — original: `FUN_0809b13c` @ `0x0809b13c`
/// (120 bytes; three plain and one predicated inbound `bl` callers).
///
/// Returns when the current cell is outside the visible range or has no
/// pending geometry. Otherwise appends a 16-byte cell record containing the
/// position relative to the first row and column, followed by pending width
/// and height. A full cell array `longjmp`s through the enclosing renderer's
/// jump buffer at +0x4f0 with value one.
///
/// Deliberate deviation: target pointers remain `u32` on hosts; tests map
/// their record array below 4 GiB. The renderer's enclosing layout is not
/// modeled because this routine only addresses its jump buffer on overflow.
unsafe fn flush_pending_cell_impl(
    state: *mut RenderCellState,
    overflow: unsafe fn(*const JmpBuf, i32) -> !,
) {
    if (*state).outside_visible_range != 0 {
        return;
    }
    if (*state).pending_height == 0 && (*state).pending_width == 0 {
        return;
    }

    let cell_count = (*state).cell_count;
    if (*state).cell_capacity <= cell_count {
        overflow((state.cast::<u8>().add(0x4f0)).cast::<JmpBuf>(), 1);
    }
    (*state).cell_count = cell_count.wrapping_add(1);

    let cell = ((*state).cells as usize as *mut i32).add(cell_count as usize * 4);
    cell.write((*state).last_column.wrapping_sub((*state).first_column));
    cell.add(1).write((*state).last_row.wrapping_sub((*state).first_row));
    cell.add(2).write((*state).pending_width);
    cell.add(3).write((*state).pending_height);
}

unsafe fn longjmp_overflow(env: *const JmpBuf, value: i32) -> ! {
    longjmp(env, value)
}

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.flush_pending_cell")]
#[inline(never)]
pub unsafe extern "C" fn flush_pending_cell(state: *mut RenderCellState) {
    flush_pending_cell_impl(state, longjmp_overflow);
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
/// Deliberate deviation: the ported flush uses its direct Rust call; its
/// target-width cell pointer is exercised through a low-address host fixture.
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
        (*state).pending_height = 0;
        (*state).pending_width = 0;
    }
    (*state).outside_visible_range = outside_visible_range;
    (*state).last_column = column;
    (*state).last_row = row;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{flush_pending_cell_impl, update_render_cell_state, JmpBuf, RenderCellState};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OVERFLOW_ENV: *const JmpBuf = core::ptr::null();
    static mut OVERFLOW_VALUE: i32 = 0;

    unsafe fn record_overflow(env: *const JmpBuf, value: i32) -> ! {
        OVERFLOW_ENV = env;
        OVERFLOW_VALUE = value;
        panic!("recorded cell-array overflow");
    }

    fn state() -> RenderCellState {
        RenderCellState {
            cells: 0,
            cell_capacity: 0,
            cell_count: 0,
            first_column: 4,
            column_limit: 7,
            first_row: 10,
            row_limit: 12,
            pending_height: 0,
            pending_width: 0,
            outside_visible_range: 1,
            last_column: -1,
            last_row: -1,
        }
    }

    #[test]
    fn flush_appends_relative_position_and_pending_geometry() {
        let _guard = TEST_LOCK.lock();
        let Some(cells) = try_map_u32_slab(hints::UI_FLUSH_PENDING_CELL, 0x1000) else {
            note_missing_u32_fixture("ui/flush_pending_cell target-width cell fixture");
            return;
        };
        let mut render_state = state();
        render_state.cells = cells as u32;
        render_state.cell_capacity = 2;
        render_state.cell_count = 1;
        render_state.first_column = 4;
        render_state.first_row = 10;
        render_state.last_column = 7;
        render_state.last_row = 13;
        render_state.pending_width = 0x55;
        render_state.pending_height = 0x66;
        render_state.outside_visible_range = 0;

        unsafe {
            flush_pending_cell_impl(&mut render_state, record_overflow);
            assert_eq!(core::slice::from_raw_parts(cells.cast::<i32>(), 8), &[0, 0, 0, 0, 3, 3, 0x55, 0x66]);
        }
        assert_eq!(render_state.cell_count, 2);
    }

    #[test]
    fn flush_skips_inactive_or_empty_pending_cells() {
        let _guard = TEST_LOCK.lock();
        let mut render_state = state();
        render_state.cell_capacity = 0;
        render_state.outside_visible_range = 1;
        unsafe { flush_pending_cell_impl(&mut render_state, record_overflow) };
        render_state.outside_visible_range = 0;
        unsafe { flush_pending_cell_impl(&mut render_state, record_overflow) };
        assert_eq!(render_state.cell_count, 0);
    }

    #[test]
    fn flush_full_array_longjmps_to_renderer_buffer() {
        let _guard = TEST_LOCK.lock();
        let mut renderer = [0u8; 0x520];
        let renderer_state = renderer.as_mut_ptr().cast::<RenderCellState>();
        unsafe {
            (*renderer_state) = state();
            (*renderer_state).outside_visible_range = 0;
            (*renderer_state).pending_width = 1;
            OVERFLOW_ENV = core::ptr::null();
            OVERFLOW_VALUE = 0;
            assert!(std::panic::catch_unwind(|| flush_pending_cell_impl(renderer_state, record_overflow)).is_err());
            assert_eq!(OVERFLOW_ENV as usize, renderer_state as usize + 0x4f0);
            assert_eq!(OVERFLOW_VALUE, 1);
        }
    }

    #[test]
    fn entering_visible_cell_clamps_column_and_clears_pending_geometry() {
        let mut render_state = state();
        render_state.pending_height = 0x4444_4444;
        render_state.pending_width = 0x5555_5555;
        unsafe { update_render_cell_state(&mut render_state, 2, 10) };

        assert_eq!(render_state.pending_height, 0);
        assert_eq!(render_state.pending_width, 0);
        assert_eq!(render_state.outside_visible_range, 0);
        assert_eq!((render_state.last_column, render_state.last_row), (3, 10));
    }

    #[test]
    fn unchanged_visible_cell_preserves_pending_geometry_without_flush() {
        let mut render_state = state();
        render_state.outside_visible_range = 0;
        render_state.last_column = 5;
        render_state.last_row = 11;
        render_state.pending_height = 0x4444_4444;
        render_state.pending_width = 0x5555_5555;
        unsafe { update_render_cell_state(&mut render_state, 5, 11) };

        assert_eq!(render_state.pending_height, 0x4444_4444);
        assert_eq!(render_state.pending_width, 0x5555_5555);
        assert_eq!(render_state.outside_visible_range, 0);
    }

    #[test]
    fn visible_bounds_are_first_row_inclusive_and_limits_exclusive() {
        let cases = [(6, 10, 0), (7, 10, 1), (6, 12, 1), (6, 9, 1)];
        for (column, row, expected_outside) in cases {
            let mut render_state = state();
            unsafe { update_render_cell_state(&mut render_state, column, row) };
            assert_eq!(render_state.outside_visible_range, expected_outside, "({column}, {row})");
        }
    }
}
