//! SQLite b-tree cell deletion — `dropCell` in the retail SQLite 3.5.x
//! amalgamation.
//!
//! `btree_drop_cell` — original: `FUN_082c6850` @ 0x082c6850 (156 bytes;
//! six direct inbound `bl` sites, binary-scanned: 0x082b6148, 0x082b61bc,
//! 0x08371074, 0x08371120, 0x08371164, and 0x08371790; every form is plain
//! unconditional `bl`). The raw extent is exact: its `pop {r4-r7,pc}` is at
//! 0x082c68e8 and the separately linked next function begins at 0x082c68ec.
//! It makes one unconditional outbound `bl`, to the still-unported
//! `FUN_082cf5c8` @ 0x082cf5c8.
//!
//! SQLite's `dropCell`: find the selected big-endian cell offset in a
//! `MemPage`'s pointer array, release its cell space, shift later two-byte
//! entries left, decrement the page's cell count, store that count big-endian
//! in the page header, add two bytes to `nFree`, and set the page's +0x01
//! initialization marker. The raw call preserves r2, so Ghidra's two-argument
//! signature is incomplete: the third argument is the cell size passed through
//! unchanged to `FUN_082cf5c8`.
//!
//! Deliberate deviations: `FUN_082cf5c8` is not ported, so this port routes its
//! call through [`BTREE_DROP_CELL_OPS`]. Its device default calls the retail
//! body at 0x082cf5c8 through a volatile slot; the host default panics until a
//! test replaces it. Host tests prove the original argument order and timing.

/// Target-width `MemPage` fields used by `dropCell`.
///
/// The pointer fields are `u32` deliberately: retailOS is a 32-bit ARM ABI,
/// while host pointers are 64 bits. The test fixture therefore maps `a_data`
/// below 4 GiB before storing it here.
#[repr(C)]
struct MemPage {
    _state_00: u8,
    init_marker: u8,
    _state_02: u8,
    _int_key: u8,
    _state_04_06: [u8; 3],
    _leaf: u8,
    header_offset: u8,
    _child_ptr_size: u8,
    _max_local: u16,
    _min_local: u16,
    cell_offset: u16,
    _state_10: u16,
    n_free: u16,
    n_cell: u16,
    _state_16_3f: [u8; 0x2a],
    _p_bt: u32,
    a_data: u32,
}

/// The unported free-space service reached by [`btree_drop_cell`].
pub type FreeSpaceFn = unsafe extern "C" fn(*mut u8, u16, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_free_space(page: *mut u8, cell_offset: u16, cell_size: i32) {
    let free_space: FreeSpaceFn = core::mem::transmute(0x082c_f5c8usize);
    free_space(page, cell_offset, cell_size)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free_space(_page: *mut u8, _cell_offset: u16, _cell_size: i32) {
    panic!("btree_drop_cell requires FUN_082cf5c8 @ 0x082cf5c8")
}

/// The unported free-space service reached by [`btree_drop_cell`].
#[derive(Clone, Copy)]
pub struct BtreeDropCellOps {
    pub free_space: FreeSpaceFn,
}

/// Shipped dispatch boundary for the identified but unported free-space call.
#[cfg(target_os = "none")]
pub const DEFAULT_BTREE_DROP_CELL_OPS: BtreeDropCellOps = BtreeDropCellOps {
    free_space: retail_free_space,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_BTREE_DROP_CELL_OPS: BtreeDropCellOps = BtreeDropCellOps {
    free_space: missing_free_space,
};

/// Active model of the `FUN_082cf5c8` call. Tests swap this slot to observe
/// the recovered three-argument ABI.
pub static mut BTREE_DROP_CELL_OPS: BtreeDropCellOps = DEFAULT_BTREE_DROP_CELL_OPS;

/// Reads the unported callee slot volatilily so LLVM cannot erase the boundary.
#[inline(always)]
unsafe fn free_space_op() -> unsafe extern "C" fn(*mut u8, u16, i32) {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_DROP_CELL_OPS.free_space))
}

/// btree_drop_cell — original: `FUN_082c6850` @ 0x082c6850 (156 bytes;
/// six direct inbound `bl` sites).
///
/// Deletes `index` from `page`'s cell-pointer array, passes that cell's
/// big-endian offset and the caller-provided `cell_size` to the free-space
/// service, then applies the exact count, free-space, header, and +0x01 marker
/// updates observed in the ARM body. As in retailOS, all pointers and indices
/// must designate a valid initialized `MemPage`; there is no NULL, bounds, or
/// underflow guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_drop_cell(page: *mut u8, index: i32, cell_size: i32) {
    let page = &mut *page.cast::<MemPage>();
    let data = page.a_data as usize as *mut u8;
    let entry_offset = page.cell_offset as usize + (index as u32).wrapping_mul(2) as usize;
    let entry = data.add(entry_offset);
    let cell_offset = u16::from_be_bytes([entry.read(), entry.add(1).read()]);

    free_space_op()(page as *mut MemPage as *mut u8, cell_offset, cell_size);

    let mut source_index = index.wrapping_add(1);
    let mut destination = entry;
    while (page.n_cell as i32) > source_index {
        destination.write(destination.add(2).read());
        destination.add(1).write(destination.add(3).read());
        destination = destination.add(2);
        source_index = source_index.wrapping_add(1);
    }

    let n_cell = page.n_cell.wrapping_sub(1);
    core::ptr::write_volatile(core::ptr::addr_of_mut!(page.n_cell), n_cell);
    let header = data.add(page.header_offset as usize);
    core::ptr::write_volatile(header.add(3), (n_cell >> 8) as u8);
    core::ptr::write_volatile(header.add(4), n_cell as u8);
    let n_free = core::ptr::read_volatile(core::ptr::addr_of!(page.n_free)).wrapping_add(2);
    core::ptr::write_volatile(core::ptr::addr_of_mut!(page.n_free), n_free);
    core::ptr::write_volatile(core::ptr::addr_of_mut!(page.init_marker), 1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::BTREE_DROP_CELL, SLAB_LEN).map(|p| p as usize));
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, PartialEq, Eq)]
    struct FreeSpaceCall {
        page: usize,
        cell_offset: u16,
        cell_size: i32,
        n_cell: u16,
        n_free: u16,
        init_marker: u8,
        header_count: [u8; 2],
    }

    static FREE_SPACE_CALLS: Mutex<Vec<FreeSpaceCall>> = Mutex::new(Vec::new());

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe extern "C" fn record_free_space(page: *mut u8, cell_offset: u16, cell_size: i32) {
        let page_state = &*page.cast::<MemPage>();
        let data = page_state.a_data as usize as *const u8;
        FREE_SPACE_CALLS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(FreeSpaceCall {
                page: page as usize,
                cell_offset,
                cell_size,
                n_cell: page_state.n_cell,
                n_free: page_state.n_free,
                init_marker: page_state.init_marker,
                header_count: [data.add(page_state.header_offset as usize + 3).read(),
                    data.add(page_state.header_offset as usize + 4).read()],
            });
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        page: MemPage,
        data: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let data = match try_slab() {
                Some(data) => data,
                None => {
                    note_missing_u32_fixture("sqlite::btree_drop_cell_tests");
                    return None;
                }
            };
            unsafe {
                core::ptr::write_bytes(data, 0, SLAB_LEN);
                (*core::ptr::addr_of_mut!(BTREE_DROP_CELL_OPS)).free_space = record_free_space;
            }
            FREE_SPACE_CALLS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            Some(Fixture {
                _guard: guard,
                page: MemPage {
                    _state_00: 0,
                    init_marker: 0,
                    _state_02: 0,
                    _int_key: 0,
                    _state_04_06: [0; 3],
                    _leaf: 0,
                    header_offset: 0,
                    _child_ptr_size: 0,
                    _max_local: 0,
                    _min_local: 0,
                    cell_offset: 8,
                    _state_10: 0,
                    n_free: 0x20,
                    n_cell: 3,
                    _state_16_3f: [0; 0x2a],
                    _p_bt: 0,
                    a_data: data as usize as u32,
                },
                data,
            })
        }

        fn set_cells(&self, cells: &[u16]) {
            unsafe {
                for (index, cell) in cells.iter().enumerate() {
                    let entry = self.data.add(8 + index * 2);
                    entry.write((cell >> 8) as u8);
                    entry.add(1).write(*cell as u8);
                }
            }
        }

        fn cells(&self, count: usize) -> Vec<u16> {
            (0..count)
                .map(|index| unsafe {
                    let entry = self.data.add(8 + index * 2);
                    u16::from_be_bytes([entry.read(), entry.add(1).read()])
                })
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_DROP_CELL_OPS)).free_space =
                    DEFAULT_BTREE_DROP_CELL_OPS.free_space;
            }
        }
    }

    #[test]
    fn releases_selected_cell_then_shifts_entries_and_updates_page_metadata() {
        let mut fixture = match Fixture::new() {
            Some(fixture) => fixture,
            None => return,
        };
        fixture.set_cells(&[0x0020, 0x0088, 0x00e0]);
        unsafe {
            fixture.data.add(3).write(0);
            fixture.data.add(4).write(3);
            btree_drop_cell((&mut fixture.page as *mut MemPage).cast(), 1, 0x44);
        }

        assert_eq!(fixture.cells(2), vec![0x0020, 0x00e0]);
        assert_eq!(fixture.page.n_cell, 2);
        assert_eq!(fixture.page.n_free, 0x22);
        assert_eq!(fixture.page.init_marker, 1);
        assert_eq!(unsafe { [fixture.data.add(3).read(), fixture.data.add(4).read()] }, [0, 2]);
        assert_eq!(
            FREE_SPACE_CALLS.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
            &[FreeSpaceCall {
                page: (&mut fixture.page as *mut MemPage).cast::<u8>() as usize,
                cell_offset: 0x0088,
                cell_size: 0x44,
                n_cell: 3,
                n_free: 0x20,
                init_marker: 0,
                header_count: [0, 3],
            }],
        );
    }

    #[test]
    fn deleting_the_only_cell_keeps_pointer_data_and_wraps_n_free() {
        let mut fixture = match Fixture::new() {
            Some(fixture) => fixture,
            None => return,
        };
        fixture.page.n_cell = 1;
        fixture.page.n_free = u16::MAX;
        fixture.set_cells(&[0x0030]);
        unsafe {
            fixture.data.add(3).write(0);
            fixture.data.add(4).write(1);
            btree_drop_cell((&mut fixture.page as *mut MemPage).cast(), 0, 0);
        }

        assert_eq!(fixture.cells(1), vec![0x0030]);
        assert_eq!((fixture.page.n_cell, fixture.page.n_free), (0, 1));
        assert_eq!(unsafe { [fixture.data.add(3).read(), fixture.data.add(4).read()] }, [0, 0]);
        assert_eq!(
            FREE_SPACE_CALLS.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
            &[FreeSpaceCall {
                page: (&mut fixture.page as *mut MemPage).cast::<u8>() as usize,
                cell_offset: 0x0030,
                cell_size: 0,
                n_cell: 1,
                n_free: u16::MAX,
                init_marker: 0,
                header_count: [0, 1],
            }],
        );
    }
}
