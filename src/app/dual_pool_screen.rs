//! Dual-pool screen constructor.
//!
//! `dual_pool_screen_construct` — original: `FUN_0812d800` @ **0x0812d800**.
//! Raw `osos.dec` establishes a 164-byte true extent: 160 bytes of ARM code
//! through `pop {r4, r5, r6, pc}` at 0x0812d89c, followed by the vtable
//! literal 0x08983cf8 at 0x0812d8a0; the separately linked next function
//! starts at 0x0812d8a4. A complete decode of every ARM B/BL immediate finds
//! **eight direct inbound `bl` sites**, all unconditional (0x08103d10,
//! 0x081281b0, 0x081356b8, 0x0815b8f4, 0x081b292c, 0x081dfe48,
//! 0x0827e804, and 0x0828bf74); there are no predicated calls or direct tail
//! branches.
//!
//! The constructor delegates to [`screen_base_construct`] with `create_link =
//! 1`, replaces its primary vtable with 0x08983cf8 and the secondary vtable
//! with primary + 0xe4, then initializes two 24-byte pool headers at +0x28
//! and +0x40. Each header is cleared, reserves its first element with an
//! unported pool helper, stores that element as the header sentinel, and makes
//! its first two words self-referential. The first pool has 16-byte elements
//! (`FUN_083dcb1c`); the second has 36-byte elements (`FUN_083dc9b0`).
//!
//! # Deviations
//!
//! The two reserve helpers have no existing port or `names.yaml` entry. Device
//! builds call their verified retail addresses directly. Host builds cross
//! [`DUAL_POOL_SCREEN_OPS`] so tests can observe their ABI and the sentinel
//! initialization without inventing allocator behavior.

use crate::app::screen_base::{screen_base_construct, ScreenBase};
use core::ptr;

/// Literal primary vtable installed by the original (pool word @ 0x0812d8a0).
pub const DUAL_POOL_SCREEN_VTABLE_ADDRESS: u32 = 0x0898_3cf8;
/// Direct callee which reserves one 16-byte element from the first pool.
pub const DUAL_POOL_SCREEN_FIRST_POOL_RESERVE_ADDRESS: usize = 0x083d_cb1c;
/// Direct callee which reserves one 36-byte element from the second pool.
pub const DUAL_POOL_SCREEN_SECOND_POOL_RESERVE_ADDRESS: usize = 0x083d_c9b0;

/// The six-word allocator header both reserve helpers consume.
///
/// `sentinel` at +0x10 is not written by the helpers. The constructor assigns
/// it from their incidental r0 return — the old cursor, i.e. the newly
/// reserved element — then initializes that element as a circular sentinel.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoolHeader {
    pub chunk_list: u32,
    pub free_list: u32,
    pub cursor: u32,
    pub limit: u32,
    pub sentinel: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<PoolHeader>() == 0x18);
const _: [u8; 0x10] = [0; core::mem::offset_of!(PoolHeader, sentinel)];

/// The derived screen layout touched by this constructor.
///
/// The base is words rather than an embedded [`ScreenBase`]: its pointer
/// fields are four bytes on ARM but host-pointer-width in tests. The target
/// offsets remain exact while the delegated base constructor receives the
/// same address cast to `ScreenBase`.
#[repr(C)]
pub struct DualPoolScreen {
    pub base_words: [u32; 10],
    pub first_pool: PoolHeader,
    pub second_pool: PoolHeader,
}

const _: () = assert!(core::mem::size_of::<DualPoolScreen>() == 0x58);
const _: [u8; 0x28] = [0; core::mem::offset_of!(DualPoolScreen, first_pool)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(DualPoolScreen, second_pool)];

/// ABI of the two unported pool helpers. Their stock bodies leave r0 holding
/// the cursor before advancement, which this caller consumes as its sentinel.
pub type PoolReserve = unsafe extern "C" fn(*mut PoolHeader, u32) -> *mut u32;

/// The unported reserve operations reached by this constructor.
#[derive(Clone, Copy)]
pub struct DualPoolScreenOps {
    pub reserve_first: PoolReserve,
    pub reserve_second: PoolReserve,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reserve_first(pool: *mut PoolHeader, grow: u32) -> *mut u32 {
    let reserve: PoolReserve = core::mem::transmute(DUAL_POOL_SCREEN_FIRST_POOL_RESERVE_ADDRESS);
    reserve(pool, grow)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reserve_second(pool: *mut PoolHeader, grow: u32) -> *mut u32 {
    let reserve: PoolReserve = core::mem::transmute(DUAL_POOL_SCREEN_SECOND_POOL_RESERVE_ADDRESS);
    reserve(pool, grow)
}

#[cfg(target_os = "none")]
pub const DEFAULT_DUAL_POOL_SCREEN_OPS: DualPoolScreenOps = DualPoolScreenOps {
    reserve_first: retail_reserve_first,
    reserve_second: retail_reserve_second,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reserve_first(_pool: *mut PoolHeader, _grow: u32) -> *mut u32 {
    panic!("dual_pool_screen_construct requires first-pool reserve 0x083dcb1c")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reserve_second(_pool: *mut PoolHeader, _grow: u32) -> *mut u32 {
    panic!("dual_pool_screen_construct requires second-pool reserve 0x083dc9b0")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_DUAL_POOL_SCREEN_OPS: DualPoolScreenOps = DualPoolScreenOps {
    reserve_first: missing_reserve_first,
    reserve_second: missing_reserve_second,
};

/// Host-replaceable pool reserve operations. Device builds retain direct calls
/// to the fixed retailOS helpers above.
pub static mut DUAL_POOL_SCREEN_OPS: DualPoolScreenOps = DEFAULT_DUAL_POOL_SCREEN_OPS;

#[inline(always)]
unsafe fn dual_pool_screen_ops() -> DualPoolScreenOps {
    ptr::read_volatile(ptr::addr_of!(DUAL_POOL_SCREEN_OPS))
}

/// dual_pool_screen_construct — original: `FUN_0812d800` @ 0x0812d800
/// (164 bytes including its literal-pool word; eight unconditional direct
/// `bl` call sites, binary-scanned).
///
/// Constructs the shared screen base with `create_link = 1`, installs this
/// class's primary/secondary vtable pair, then makes a circular sentinel in
/// the first reserved element of each embedded pool. It has no NULL guard:
/// the delegated base constructor result and both reserve results are used
/// immediately. Device builds reproduce all three direct calls; host reserve
/// seams are the sole deliberate deviation documented in this module.
///
/// # Safety
///
/// `storage`, and the returned base-constructor result, must identify writable
/// [`DualPoolScreen`] storage. The reserve helpers must return writable,
/// word-aligned elements of at least eight bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dual_pool_screen_construct(
    storage: *mut DualPoolScreen,
    initial_target: u32,
    resource_id: u32,
) -> *mut DualPoolScreen {
    let this = screen_base_construct(storage.cast::<ScreenBase>(), initial_target, 1, resource_id)
        .cast::<DualPoolScreen>();
    let words = this.cast::<u32>();
    ptr::write_volatile(words, DUAL_POOL_SCREEN_VTABLE_ADDRESS);
    ptr::write_volatile(words.add(7), DUAL_POOL_SCREEN_VTABLE_ADDRESS + 0xe4);

    let first_pool = ptr::addr_of_mut!((*this).first_pool);
    ptr::write_bytes(first_pool, 0, 1);
    #[cfg(target_os = "none")]
    let first_sentinel = retail_reserve_first(first_pool, 1);
    #[cfg(not(target_os = "none"))]
    let first_sentinel = (dual_pool_screen_ops().reserve_first)(first_pool, 1);
    ptr::write_volatile(ptr::addr_of_mut!((*first_pool).sentinel), first_sentinel as usize as u32);
    ptr::write_volatile(first_sentinel, first_sentinel as usize as u32);
    ptr::write_volatile(first_sentinel.add(1), first_sentinel as usize as u32);

    let second_pool = ptr::addr_of_mut!((*this).second_pool);
    ptr::write_bytes(second_pool, 0, 1);
    #[cfg(target_os = "none")]
    let second_sentinel = retail_reserve_second(second_pool, 1);
    #[cfg(not(target_os = "none"))]
    let second_sentinel = (dual_pool_screen_ops().reserve_second)(second_pool, 1);
    ptr::write_volatile(ptr::addr_of_mut!((*second_pool).sentinel), second_sentinel as usize as u32);
    ptr::write_volatile(second_sentinel, second_sentinel as usize as u32);
    ptr::write_volatile(second_sentinel.add(1), second_sentinel as usize as u32);

    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::screen_base::{ScreenBaseOps, SCREEN_BASE_OPS};
    use crate::testing::{CLASS_REGISTRY_TEST_LOCK, TASK_CTX_BLOCK_TEST_LOCK};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;
    use core::mem;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_RESULT: *mut ScreenBase = ptr::null_mut();
    static mut BASE_ARGS: Option<(*mut ScreenBase, u32, u32)> = None;
    static mut FIRST_POOL: *mut PoolHeader = ptr::null_mut();
    static mut SECOND_POOL: *mut PoolHeader = ptr::null_mut();
    static mut FIRST_GROW: u32 = 0;
    static mut SECOND_GROW: u32 = 0;
    static mut FIRST_HEADER_BEFORE: [u32; 6] = [0; 6];
    static mut SECOND_HEADER_BEFORE: [u32; 6] = [0; 6];
    static mut FIRST_SENTINEL: [u32; 2] = [0; 2];
    static mut SECOND_SENTINEL: [u32; 2] = [0; 2];
    static mut TASK_CONTEXT: [u32; 13] = [0; 13];

    unsafe extern "C" fn recording_construct_base(
        storage: *mut ScreenBase,
        initial_target: u32,
        create_link: u32,
    ) -> *mut ScreenBase {
        BASE_ARGS = Some((storage, initial_target, create_link));
        if BASE_RESULT.is_null() { storage } else { BASE_RESULT }
    }

    unsafe extern "C" fn recording_set_next_link(_this: *mut ScreenBase, _next: *mut ScreenBase) {}

    unsafe extern "C" fn recording_task_context() -> *mut u8 {
        ptr::addr_of_mut!(TASK_CONTEXT).cast()
    }

    unsafe extern "C" fn recording_reserve_first(pool: *mut PoolHeader, grow: u32) -> *mut u32 {
        FIRST_POOL = pool;
        FIRST_GROW = grow;
        FIRST_HEADER_BEFORE = ptr::read(pool.cast::<[u32; 6]>());
        ptr::addr_of_mut!(FIRST_SENTINEL).cast()
    }

    unsafe extern "C" fn recording_reserve_second(pool: *mut PoolHeader, grow: u32) -> *mut u32 {
        SECOND_POOL = pool;
        SECOND_GROW = grow;
        SECOND_HEADER_BEFORE = ptr::read(pool.cast::<[u32; 6]>());
        ptr::addr_of_mut!(SECOND_SENTINEL).cast()
    }

    struct SlotsGuard {
        base_ops: ScreenBaseOps,
        pool_ops: DualPoolScreenOps,
        task_context: unsafe extern "C" fn() -> *mut u8,
    }

    impl SlotsGuard {
        fn install(relocated: *mut DualPoolScreen) -> SlotsGuard {
            unsafe {
                BASE_RESULT = relocated.cast();
                BASE_ARGS = None;
                FIRST_POOL = ptr::null_mut();
                SECOND_POOL = ptr::null_mut();
                FIRST_GROW = 0;
                SECOND_GROW = 0;
                FIRST_HEADER_BEFORE = [0xffff_ffff; 6];
                SECOND_HEADER_BEFORE = [0xffff_ffff; 6];
                FIRST_SENTINEL = [0; 2];
                SECOND_SENTINEL = [0; 2];
                TASK_CONTEXT[12] = 0x089a_b004;

                let base_slot = ptr::addr_of_mut!(SCREEN_BASE_OPS);
                let base_ops = ptr::read_volatile(base_slot);
                ptr::write_volatile(base_slot, ScreenBaseOps {
                    construct_base: recording_construct_base,
                    set_next_link: recording_set_next_link,
                });
                let pool_slot = ptr::addr_of_mut!(DUAL_POOL_SCREEN_OPS);
                let pool_ops = ptr::read_volatile(pool_slot);
                ptr::write_volatile(pool_slot, DualPoolScreenOps {
                    reserve_first: recording_reserve_first,
                    reserve_second: recording_reserve_second,
                });
                let task_slot = ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK);
                let task_context = ptr::read_volatile(task_slot);
                ptr::write_volatile(task_slot, recording_task_context);
                SlotsGuard { base_ops, pool_ops, task_context }
            }
        }
    }

    impl Drop for SlotsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(SCREEN_BASE_OPS), self.base_ops);
                ptr::write_volatile(ptr::addr_of_mut!(DUAL_POOL_SCREEN_OPS), self.pool_ops);
                ptr::write_volatile(ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK), self.task_context);
            }
        }
    }

    #[test]
    fn constructs_relocated_screen_and_circular_pool_sentinels() {
        let _test = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ctx = TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _registry = CLASS_REGISTRY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage: DualPoolScreen = unsafe { mem::zeroed() };
        let mut relocated: DualPoolScreen = unsafe { mem::zeroed() };
        storage.first_pool.chunk_list = 0x1111_1111;
        storage.second_pool.chunk_list = 0x2222_2222;
        relocated.first_pool = PoolHeader {
            chunk_list: 0xaaaa_aaaa,
            free_list: 0xbbbb_bbbb,
            cursor: 0xcccc_cccc,
            limit: 0xdddd_dddd,
            sentinel: 0xeeee_eeee,
            reserved: 0xffff_ffff,
        };
        relocated.second_pool = relocated.first_pool;
        let _slots = SlotsGuard::install(ptr::addr_of_mut!(relocated));

        let result = unsafe {
            dual_pool_screen_construct(ptr::addr_of_mut!(storage), 0xfeed_face, 0x1234_5678)
        };

        unsafe {
            assert_eq!(result, ptr::addr_of_mut!(relocated));
            assert_eq!(
                BASE_ARGS,
                Some((ptr::addr_of_mut!(storage).cast(), 0xfeed_face, 1)),
                "forwards storage and initial target, with the fixed create-link flag"
            );
            assert_eq!(FIRST_POOL, ptr::addr_of_mut!(relocated.first_pool));
            assert_eq!(SECOND_POOL, ptr::addr_of_mut!(relocated.second_pool));
            assert_eq!(FIRST_GROW, 1);
            assert_eq!(SECOND_GROW, 1);
            assert_eq!(FIRST_HEADER_BEFORE, [0; 6], "first pool is cleared before reserve");
            assert_eq!(SECOND_HEADER_BEFORE, [0; 6], "second pool is cleared before reserve");
            assert_eq!(relocated.base_words[0], DUAL_POOL_SCREEN_VTABLE_ADDRESS);
            assert_eq!(relocated.base_words[7], DUAL_POOL_SCREEN_VTABLE_ADDRESS + 0xe4);
            assert_eq!(relocated.first_pool.sentinel, ptr::addr_of!(FIRST_SENTINEL) as usize as u32);
            assert_eq!(relocated.second_pool.sentinel, ptr::addr_of!(SECOND_SENTINEL) as usize as u32);
            assert_eq!(FIRST_SENTINEL, [ptr::addr_of!(FIRST_SENTINEL) as usize as u32; 2]);
            assert_eq!(SECOND_SENTINEL, [ptr::addr_of!(SECOND_SENTINEL) as usize as u32; 2]);
            assert_eq!(storage.first_pool.chunk_list, 0x1111_1111, "writes follow the delegated return");
            assert_eq!(storage.second_pool.chunk_list, 0x2222_2222, "incoming storage remains untouched");
        }
    }
}
