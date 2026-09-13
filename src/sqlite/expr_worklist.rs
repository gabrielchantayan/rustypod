//! SQLite expression-worklist append.
//!
//! - `expr_worklist_push` — original: `FUN_083987f8` @ `0x083987f8`
//!   (196 bytes; 6 direct `bl` call sites, all unconditional: `0x082cd18c`,
//!   `0x082cd2dc`, `0x082cd54c`, `0x082cd69c`, `0x082cd6e8`, and
//!   `0x082cd804`, binary-scanned from `osos.dec`).
//! This appends an expression plus control byte to a 40-byte work item. When
//! full, it allocates `capacity * 80` bytes for the doubled capacity through
//! `sqlite3_malloc`, copies the used 40-byte entries, releases a previous heap
//! allocation, and doubles capacity. Allocation failure latches
//! `db->mallocFailed`; bit 0 of the control byte additionally releases the
//! incoming expression.
//!
//! Deliberate deviations: target pointers remain `u32` words in the views so
//! host pointer width cannot change firmware offsets; the port calls the
//! already-ported allocator, expression destructor, copy veneer, and free
//! directly instead of recreating dispatch seams.

use crate::heap::tracked::tracked_free;
use crate::libc::iram_veneers::iram_memcpy_veneer;

use super::expr_delete::expr_delete;
use super::mem::{sqlite3_malloc, MALLOC_FAILED_OFFSET};
/// Bytes occupied by each target work item (`add r1,r1,r0,lsl #3` after
/// `r0 = index * 5`, yielding `index * 40`).
pub const EXPR_WORK_ITEM_SIZE: usize = 0x28;
/// Allocation bytes per old-capacity entry (`mov r1,#0x50`).
const GROW_ALLOCATION_STRIDE: i32 = 0x50;
/// Bytes copied from each initialized work item during a grow (`mov r2,#0x28`).
const EXPR_WORK_ITEM_COPY_SIZE: i32 = 0x28;

/// The fixed 24-byte worklist header. All pointer-valued fields are target
/// words, including `owner`, which points to an object whose first word is the
/// owning `sqlite3 *`.
#[repr(C)]
pub struct ExprWorklist {
    /// +0x00: owner object; its first target word is `sqlite3 *`.
    pub owner: u32,
    /// +0x04: maintained by the caller, not inspected here.
    pub _reserved: u32,
    /// +0x08: entries currently occupied.
    pub count: i32,
    /// +0x0c: allocated entry capacity.
    pub capacity: i32,
    /// +0x10: target pointer to entries or to the inline first item at +0x18.
    pub entries: u32,
    /// +0x14: keeps inline storage at +0x18; not inspected here.
    pub _inline_padding: u32,
}

/// The portions of the 40-byte expression work item written by this function.
#[repr(C)]
pub struct ExprWorkItem {
    /// +0x00: expression pointer.
    pub expression: u32,
    /// +0x04: initialized to -1 (`mvn r2,#0; strh`).
    pub parent_index: i16,
    /// +0x06..+0x0b: filled by the expression compiler.
    pub _before_control: [u8; 6],
    /// +0x0c: caller's control byte.
    pub control: u8,
    /// +0x0d..+0x0f: filled by the expression compiler.
    pub _after_control: [u8; 3],
    /// +0x10: back-pointer to the containing worklist.
    pub owner: u32,
    /// +0x14..+0x27: filled by the expression compiler.
    pub _rest: [u8; EXPR_WORK_ITEM_SIZE - 0x14],
}

const _: [u8; 0x18] = [0; core::mem::size_of::<ExprWorklist>()];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ExprWorklist, count)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(ExprWorklist, entries)];
const _: [u8; EXPR_WORK_ITEM_SIZE] = [0; core::mem::size_of::<ExprWorkItem>()];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ExprWorkItem, control)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(ExprWorkItem, owner)];

/// `expr_worklist_push` — original `FUN_083987f8` @ `0x083987f8` (196 bytes;
/// 6 direct `bl` call sites, all unconditional).
///
/// Appends `expression` and `control`, returning its old count. A full list
/// moves its initialized 40-byte prefixes to a doubled allocation. On OOM,
/// marks the owning connection and returns zero; a control bit 0 request also
/// destroys `expression` before returning.
///
/// # Safety
/// `worklist` must describe target-width storage with a live owner and entry
/// allocation. Its count/capacity pair and entry span must be valid exactly as
/// required by the stock code; this function intentionally adds no guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_worklist_push(
    worklist: *mut ExprWorklist,
    expression: *mut u8,
    control: u8,
) -> i32 {
    let worklist = &mut *worklist;
    if worklist.count >= worklist.capacity {
        let previous_entries = worklist.entries;
        let replacement = sqlite3_malloc(worklist.capacity.wrapping_mul(GROW_ALLOCATION_STRIDE));
        worklist.entries = replacement as usize as u32;
        if replacement.is_null() {
            let db = (*(worklist.owner as usize as *const u32)) as usize as *mut u8;
            db.add(MALLOC_FAILED_OFFSET).write(1);
            if control & 1 != 0 {
                expr_delete(expression);
            }
            worklist.entries = previous_entries;
            return 0;
        }

        iram_memcpy_veneer(
            replacement,
            previous_entries as usize as *const u8,
            worklist.count.wrapping_mul(EXPR_WORK_ITEM_COPY_SIZE) as u32 as usize,
        );
        let inline_entries = (worklist as *mut ExprWorklist).cast::<u8>().add(core::mem::size_of::<ExprWorklist>());
        if previous_entries as usize != inline_entries as usize {
            tracked_free(previous_entries as usize as *mut u8);
        }
        worklist.capacity = worklist.capacity.wrapping_shl(1);
    }

    let index = worklist.count;
    let item = (worklist.entries as usize as *mut ExprWorkItem).offset(index as isize);
    worklist.count = worklist.count.wrapping_add(1);
    (*item).expression = expression as usize as u32;
    (*item).control = control;
    (*item).owner = worklist as *mut ExprWorklist as usize as u32;
    (*item).parent_index = -1;
    index
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{ALLOC_STATS, DEFAULT_TRACKED_STATS_OPS, TRACKED_STATS_OPS};
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps};
    use crate::sqlite::mem::{ALLOC_DENY_SCHEDULE, DEFAULT_ALLOC_PRESSURE_OPS, ALLOC_PRESSURE_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x3000;
    const OWNER_OFFSET: usize = 0x400;
    const DB_OFFSET: usize = 0x600;
    const HEAP_OLD_RAW_OFFSET: usize = 0x800;
    const ARENA_OFFSET: usize = 0x1000;
    const EXPR_RAW_OFFSET: usize = 0x1800;
    const EXPR_BLOCK_SIZE: usize = 0x80;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EXPR_WORKLIST, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut ARENA_BASE: *mut u8 = ptr::null_mut();
    static mut ARENA_FAIL: bool = false;
    static mut FREED_RAW: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        if ARENA_FAIL {
            ptr::null_mut()
        } else {
            ARENA_BASE.add(ARENA_OFFSET)
        }
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        raw: *mut u8,
        _tag: usize,
    ) {
        FREED_RAW = raw;
    }

    /// Serializes and replaces the target heap allocator while preserving the
    /// stock direct sqlite3_malloc -> tracked allocator path.
    struct HeapFixture {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl HeapFixture {
        unsafe fn new(base: *mut u8, fail: bool) -> Self {
            let guard = crate::heap::veneers::tests::mock_heap();
            ARENA_BASE = base;
            ARENA_FAIL = fail;
            FREED_RAW = ptr::null_mut();
            let ops: *mut HeapVeneerOps = ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            ALLOC_STATS.reserved = [0; 8];
            ALLOC_STATS.soft_limit = 0;
            ALLOC_STATS.soft_limit_callback = 0;
            ALLOC_STATS.soft_limit_callback_arg = 0;
            ALLOC_STATS.soft_limit_callback_active = 0;
            ALLOC_STATS.lock_flag = 0;
            ALLOC_STATS.current_bytes = 0;
            ALLOC_STATS.peak_bytes = 0;
            TRACKED_STATS_OPS = DEFAULT_TRACKED_STATS_OPS;
            ALLOC_DENY_SCHEDULE[0].active = 0;
            ALLOC_PRESSURE_OPS = DEFAULT_ALLOC_PRESSURE_OPS;
            Self { _guard: guard }
        }
    }

    unsafe fn target_pointer(pointer: *mut u8) -> u32 {
        u32::try_from(pointer as usize).expect("mapped fixture must fit target pointer width")
    }

    unsafe fn tracked_payload(raw: *mut u8, size: i32) -> *mut u8 {
        (raw as *mut i32).write(size);
        (raw.add(4) as *mut i32).write(size >> 31);
        let base = raw.add(8);
        let payload = ((base as usize + 36) & !31) as *mut u8;
        (payload.sub(4) as *mut u32).write((payload as usize - base as usize) as u32);
        payload
    }

    unsafe fn reset_worklist(base: *mut u8, count: i32, capacity: i32, entries: *mut u8) -> *mut ExprWorklist {
        ptr::write_bytes(base, 0, SLAB_LEN);
        let owner = base.add(OWNER_OFFSET);
        (owner as *mut u32).write(target_pointer(base.add(DB_OFFSET)));
        let worklist = base.cast::<ExprWorklist>();
        worklist.write(ExprWorklist {
            owner: target_pointer(owner),
            _reserved: 0,
            count,
            capacity,
            entries: target_pointer(entries),
            _inline_padding: 0,
        });
        worklist
    }

    #[test]
    fn appends_into_inline_capacity_with_target_width_fields() {
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/expr_worklist"));
            return;
        };
        unsafe {
            let worklist = reset_worklist(base as *mut u8, 9, 10, (base as *mut u8).add(0x18));
            let expression = base as *mut u8 as usize as *mut u8;
            assert_eq!(expr_worklist_push(worklist, expression, 0xa5), 9);
            assert_eq!((*worklist).count, 10);
            let item = (base as *mut u8).add(0x18).cast::<ExprWorkItem>().add(9);
            assert_eq!((*item).expression, target_pointer(expression));
            assert_eq!((*item).control, 0xa5);
            assert_eq!((*item).parent_index, -1);
            assert_eq!((*item).owner, target_pointer(worklist.cast()));
        }
    }

    #[test]
    fn grows_copies_initialized_prefixes_and_releases_heap_entries() {
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/expr_worklist"));
            return;
        };
        unsafe {
            let _heap = HeapFixture::new(base as *mut u8, false);
            let old_raw = (base as *mut u8).add(HEAP_OLD_RAW_OFFSET);
            let worklist = reset_worklist(base as *mut u8, 2, 2, (base as *mut u8).add(0x18));
            let old_entries = tracked_payload(old_raw, 160);
            (*worklist).entries = target_pointer(old_entries);
            for byte in 0..80usize {
                old_entries.add(byte).write((byte ^ 0x5a) as u8);
            }
            ALLOC_STATS.current_bytes = 160;

            assert_eq!(expr_worklist_push(worklist, (base as *mut u8).add(0x2c00), 2), 2);
            let replacement = (*worklist).entries as usize as *mut u8;
            assert_ne!(replacement, old_entries);
            for byte in 0..80usize {
                assert_eq!(replacement.add(byte).read(), (byte ^ 0x5a) as u8, "copy byte {byte}");
            }
            let item = replacement.cast::<ExprWorkItem>().add(2);
            assert_eq!((*item).expression, target_pointer((base as *mut u8).add(0x2c00)));
            assert_eq!((*item).control, 2);
            assert_eq!((*item).parent_index, -1);
            assert_eq!((*item).owner, target_pointer(worklist.cast()));
            assert_eq!((*worklist).count, 3);
            assert_eq!((*worklist).capacity, 4);
            assert_eq!(FREED_RAW, old_raw, "previous heap-backed entries are released after copy");
        }
    }

    #[test]
    fn oom_latches_connection_and_releases_owned_expression() {
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/expr_worklist"));
            return;
        };
        unsafe {
            let _heap = HeapFixture::new(base as *mut u8, true);
            let worklist = reset_worklist(base as *mut u8, 1, 1, (base as *mut u8).add(0x18));
            let expression_raw = (base as *mut u8).add(EXPR_RAW_OFFSET);
            let expression = tracked_payload(expression_raw, EXPR_BLOCK_SIZE as i32);
            ptr::write_bytes(expression, 0, EXPR_BLOCK_SIZE);

            assert_eq!(expr_worklist_push(worklist, expression, 1), 0);
            assert_eq!((base as *mut u8).add(DB_OFFSET + MALLOC_FAILED_OFFSET).read(), 1);
            assert_eq!((*worklist).entries, target_pointer((base as *mut u8).add(0x18)));
            assert_eq!((*worklist).count, 1);
            assert_eq!((*worklist).capacity, 1);
            assert_eq!(FREED_RAW, expression_raw, "control bit 0 destroys the rejected expression");
        }
    }
}
