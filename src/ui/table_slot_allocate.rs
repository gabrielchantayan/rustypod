//! UI table-entry allocation wrapper.
//!
//! `ui_allocate_table_slot` — original: `FUN_08004c78` @ `0x08004c78`
//! (40 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/08004c78_FUN_08004c78.c`;
//! raw ARM is `0x08004c78..0x08004ca0`.
//!
//! The wrapper calls the retailOS allocation veneer at `0x080036c0` (whose
//! literal target is `0x0804b8b0`) with no arguments, then stores its returned
//! word in the selected 0x20-byte row of the UI table at `0x2200ae7c`.

/// Base address of the two-row UI allocation table in retailOS RAM.
const UI_ALLOCATION_TABLE_BASE: usize = 0x2200_ae7c;
const UI_ALLOCATION_ROW_BYTES: isize = 0x20;
const UI_ALLOCATION_ENTRY_BYTES: isize = 4;

/// Calls outside this one-function port.
///
/// `allocate` preserves the original no-argument veneer boundary at
/// `0x080036c0`; its literal target `0x0804b8b0` is an unported allocator.
#[derive(Clone, Copy)]
pub struct UiTableAllocationOps {
    pub allocate: unsafe extern "C" fn() -> u32,
}

unsafe extern "C" fn firmware_allocate_ui_table_entry() -> u32 {
    #[cfg(target_os = "none")]
    {
        let allocate: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x0800_36c0usize);
        return allocate();
    }

    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Default target/host allocation boundary.
pub const DEFAULT_UI_TABLE_ALLOCATION_OPS: UiTableAllocationOps = UiTableAllocationOps {
    allocate: firmware_allocate_ui_table_entry,
};

/// Active allocation boundary. Target builds call the retailOS veneer; host
/// tests replace this with a deterministic allocator callback.
pub static mut UI_TABLE_ALLOCATION_OPS: UiTableAllocationOps = DEFAULT_UI_TABLE_ALLOCATION_OPS;

#[cfg(not(target_os = "none"))]
static mut HOST_UI_ALLOCATION_TABLE: [u32; 16] = [0; 16];

#[inline(always)]
fn allocation_ops() -> UiTableAllocationOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_TABLE_ALLOCATION_OPS)) }
}

#[inline(always)]
unsafe fn ui_allocation_slot(row: i32, entry: i32) -> *mut u32 {
    let offset = row as isize * UI_ALLOCATION_ROW_BYTES
        + entry as isize * UI_ALLOCATION_ENTRY_BYTES
        - UI_ALLOCATION_ROW_BYTES;

    #[cfg(target_os = "none")]
    {
        (UI_ALLOCATION_TABLE_BASE as *mut u8).wrapping_offset(offset) as *mut u32
    }

    #[cfg(not(target_os = "none"))]
    {
        (core::ptr::addr_of_mut!(HOST_UI_ALLOCATION_TABLE) as *mut u8).wrapping_offset(offset)
            as *mut u32
    }
}

/// ui_allocate_table_slot — original: `FUN_08004c78` @ `0x08004c78` (40 bytes).
///
/// Calls the no-argument UI allocator and stores the resulting word at
/// `0x2200ae7c + row * 0x20 + entry * 4 - 0x20`, then returns zero. Recovered
/// callers pass rows 1 or 2 and a signed table-entry index, making this the
/// allocation half of the adjacent `0x08004c4c` clear-and-release wrapper.
///
/// # Deviations
///
/// The allocator target at `0x0804b8b0` remains in retailOS. The explicit
/// [`UI_TABLE_ALLOCATION_OPS`] boundary retains its no-argument ABI on target
/// and makes the returned word observable in host tests. Target table access
/// uses the original absolute RAM base; host builds use same-shaped table
/// storage solely for those tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_allocate_table_slot(row: i32, entry: i32) -> u32 {
    let allocated = (allocation_ops().allocate)();
    core::ptr::write_volatile(ui_allocation_slot(row, entry), allocated);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATOR_CALLS: u32 = 0;
    static mut ALLOCATION_RESULT: u32 = 0;

    unsafe extern "C" fn mock_allocate() -> u32 {
        ALLOCATOR_CALLS = ALLOCATOR_CALLS.wrapping_add(1);
        ALLOCATION_RESULT
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: UiTableAllocationOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                UI_TABLE_ALLOCATION_OPS = self.previous_ops;
                core::ptr::write_bytes(
                    core::ptr::addr_of_mut!(HOST_UI_ALLOCATION_TABLE) as *mut u8,
                    0,
                    core::mem::size_of::<[u32; 16]>(),
                );
            }
        }
    }

    fn bench(allocation_result: u32) -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous_ops = unsafe { UI_TABLE_ALLOCATION_OPS };
        unsafe {
            ALLOCATOR_CALLS = 0;
            ALLOCATION_RESULT = allocation_result;
            HOST_UI_ALLOCATION_TABLE = [0; 16];
            UI_TABLE_ALLOCATION_OPS = UiTableAllocationOps {
                allocate: mock_allocate,
            };
        }
        Bench {
            _lock: lock,
            previous_ops,
        }
    }

    #[test]
    fn stores_allocator_result_at_exact_row_entry_and_returns_zero() {
        const ALLOCATION: u32 = 0xdead_beef;
        let _bench = bench(ALLOCATION);

        assert_eq!(unsafe { ui_allocate_table_slot(2, 5) }, 0);

        unsafe {
            assert_eq!(ALLOCATOR_CALLS, 1, "the allocator veneer is called exactly once");
            assert_eq!(HOST_UI_ALLOCATION_TABLE[13], ALLOCATION);
            assert_eq!(HOST_UI_ALLOCATION_TABLE[12], 0);
            assert_eq!(HOST_UI_ALLOCATION_TABLE[14], 0);
        }
    }
}
