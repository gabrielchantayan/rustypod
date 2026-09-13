//! SQLite b-tree page-balance dispatch.
//!
//! `btree_balance_page` is retailOS `FUN_082b5ab4` at load address
//! `0x082b5ab4`. Its raw extent is exactly 164 bytes: the next independently
//! entered function starts at `0x082b5b58`. Decoding every aligned ARM
//! `B`/`BL`-immediate word in `osos.dec` finds six inbound call sites, all
//! plain unconditional `bl` (`0x082b67f8`, `0x082b6a00`, `0x0837110c`,
//! `0x0837112c`, `0x08371170`, and `0x083717ec`); no caller predicates the
//! dispatch and no tail branch targets it.
//!
//! On a root page, it first makes the backing page writable, then dispatches
//! overflow pages to the deeper-balance helper and empty roots to the
//! shallower-balance helper. On a non-root page, it dispatches to the
//! non-root balancing helper only for overflow or, for deletion (`insert ==
//! 0`), when free space exceeds two thirds of the shared usable size.
//!
//! # Deliberate deviations
//!
//! The four resident helpers are not separately ported. Target builds call
//! their fixed verified addresses through named seams; host tests replace the
//! seams. This preserves their observed order, arguments, status propagation,
//! and short-circuiting without claiming identities beyond their recovered
//! page-write and balance roles.

use crate::runtime::rt_div::__rt_udiv;

/// Target-width subset of SQLite's `MemPage` used by the balance dispatcher.
#[repr(C)]
struct MemPage {
    _state_00_01: [u8; 2],
    n_overflow: u8,
    _state_03_11: [u8; 0x0f],
    n_free: u16,
    n_cell: u16,
    _state_16_3f: [u8; 0x2a],
    p_bt: u32,
    _a_data: u32,
    p_db_page: u32,
    _state_4c: u32,
    p_parent: u32,
}

/// Target-width subset of SQLite's shared b-tree state.
#[repr(C)]
struct BtShared {
    _state_00_1d: [u8; 0x1e],
    usable_size: u16,
}

pub type PageWriteFn = unsafe extern "C" fn(u32) -> i32;
pub type BalancePageFn = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_page_write(db_page: u32) -> i32 {
    let page_write: PageWriteFn = core::mem::transmute(0x0837_ef64usize);
    page_write(db_page)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_balance_deeper(page: *mut u8) -> i32 {
    let balance_deeper: BalancePageFn = core::mem::transmute(0x082b_5b58usize);
    balance_deeper(page)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_balance_shallower(page: *mut u8) -> i32 {
    let balance_shallower: BalancePageFn = core::mem::transmute(0x082b_6a08usize);
    balance_shallower(page)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_balance_nonroot(page: *mut u8) -> i32 {
    let balance_nonroot: BalancePageFn = core::mem::transmute(0x082b_5cb8usize);
    balance_nonroot(page)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_page_write(_db_page: u32) -> i32 {
    panic!("btree_balance_page requires FUN_0837ef64 @ 0x0837ef64")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_balance_page(_page: *mut u8) -> i32 {
    panic!("btree_balance_page requires a resident balance helper")
}

/// The resident service boundaries reached by [`btree_balance_page`].
#[derive(Clone, Copy)]
pub struct BtreeBalanceOps {
    pub page_write: PageWriteFn,
    pub balance_deeper: BalancePageFn,
    pub balance_shallower: BalancePageFn,
    pub balance_nonroot: BalancePageFn,
}

#[cfg(target_os = "none")]
pub const DEFAULT_BTREE_BALANCE_OPS: BtreeBalanceOps = BtreeBalanceOps {
    page_write: retail_page_write,
    balance_deeper: retail_balance_deeper,
    balance_shallower: retail_balance_shallower,
    balance_nonroot: retail_balance_nonroot,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_BTREE_BALANCE_OPS: BtreeBalanceOps = BtreeBalanceOps {
    page_write: missing_page_write,
    balance_deeper: missing_balance_page,
    balance_shallower: missing_balance_page,
    balance_nonroot: missing_balance_page,
};

/// Active service boundaries. Host tests replace these slots with recorders.
pub static mut BTREE_BALANCE_OPS: BtreeBalanceOps = DEFAULT_BTREE_BALANCE_OPS;

#[inline(always)]
unsafe fn balance_ops() -> BtreeBalanceOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_BALANCE_OPS))
}

/// SQLite b-tree balance dispatcher — original: `FUN_082b5ab4` @ `0x082b5ab4`
/// (164 bytes; six direct unconditional `bl` call sites, binary-verified).
///
/// The page pointer must name a valid target-layout `MemPage`. When `p_parent`
/// is zero, `p_db_page` must be valid for the resident write service. When the
/// non-root underfull path is considered, `p_bt` must name a valid `BtShared`.
/// The retail function performs no NULL or range checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_balance_page(page: *mut u8, insert: u32) -> i32 {
    let page_state = &mut *page.cast::<MemPage>();

    if page_state.p_parent == 0 {
        let ops = balance_ops();
        let rc = (ops.page_write)(page_state.p_db_page);
        if rc != 0 {
            return rc;
        }
        if page_state.n_overflow != 0 {
            return (ops.balance_deeper)(page);
        }
        if page_state.n_cell == 0 {
            return (ops.balance_shallower)(page);
        }
        return 0;
    }

    if page_state.n_overflow != 0 {
        return (balance_ops().balance_nonroot)(page);
    }
    if insert == 0 {
        let shared = &*(page_state.p_bt as usize as *const BtShared);
        let minimum_free = __rt_udiv((shared.usable_size as u32) << 1, 3);
        if minimum_free < page_state.n_free as u32 {
            return (balance_ops().balance_nonroot)(page);
        }
    }
    0
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
        LazyLock::new(|| try_map_u32_slab(hints::BTREE_BALANCE_PAGE, SLAB_LEN).map(|p| p as usize));
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    static RESULTS: Mutex<[i32; 4]> = Mutex::new([0; 4]);

    unsafe extern "C" fn record_page_write(_db_page: u32) -> i32 {
        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push("write");
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[0]
    }

    unsafe extern "C" fn record_deeper(_page: *mut u8) -> i32 {
        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push("deeper");
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[1]
    }

    unsafe extern "C" fn record_shallower(_page: *mut u8) -> i32 {
        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push("shallower");
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[2]
    }

    unsafe extern "C" fn record_nonroot(_page: *mut u8) -> i32 {
        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push("nonroot");
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[3]
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        page: *mut MemPage,
        shared: *mut BtShared,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let base = match *SLAB {
                Some(base) => base as *mut u8,
                None => {
                    note_missing_u32_fixture("sqlite::btree_balance_tests");
                    return None;
                }
            };
            unsafe {
                core::ptr::write_bytes(base, 0, SLAB_LEN);
                let page = base.add(0x100).cast::<MemPage>();
                let shared = base.add(0x200).cast::<BtShared>();
                core::ptr::write(page, MemPage {
                    _state_00_01: [0; 2],
                    n_overflow: 0,
                    _state_03_11: [0; 0x0f],
                    n_free: 0,
                    n_cell: 1,
                    _state_16_3f: [0; 0x2a],
                    p_bt: shared as usize as u32,
                    _a_data: 0,
                    p_db_page: base.add(0x300) as usize as u32,
                    _state_4c: 0,
                    p_parent: 0,
                });
                core::ptr::write(shared, BtShared {
                    _state_00_1d: [0; 0x1e],
                    usable_size: 100,
                });
                (*core::ptr::addr_of_mut!(BTREE_BALANCE_OPS)) = BtreeBalanceOps {
                    page_write: record_page_write,
                    balance_deeper: record_deeper,
                    balance_shallower: record_shallower,
                    balance_nonroot: record_nonroot,
                };
            }
            EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
            *RESULTS.lock().unwrap_or_else(|e| e.into_inner()) = [0; 4];
            Some(Fixture { _guard: guard, page: unsafe { base.add(0x100).cast() }, shared: unsafe { base.add(0x200).cast() } })
        }

        fn events(&self) -> Vec<&'static str> {
            EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_BALANCE_OPS)) = DEFAULT_BTREE_BALANCE_OPS;
            }
        }
    }

    #[test]
    fn root_propagates_write_failure_before_balance_dispatch() {
        let fixture = match Fixture::new() { Some(fixture) => fixture, None => return };
        unsafe { (*fixture.page).n_overflow = 1; }
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[0] = 11;

        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 0) }, 11);
        assert_eq!(fixture.events(), vec!["write"]);
    }

    #[test]
    fn root_selects_deeper_for_overflow_and_shallower_for_empty_page() {
        let fixture = match Fixture::new() { Some(fixture) => fixture, None => return };
        unsafe { (*fixture.page).n_overflow = 1; }
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[1] = 22;
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 0) }, 22);
        assert_eq!(fixture.events(), vec!["write", "deeper"]);

        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        unsafe {
            (*fixture.page).n_overflow = 0;
            (*fixture.page).n_cell = 0;
        }
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[2] = 33;
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 0) }, 33);
        assert_eq!(fixture.events(), vec!["write", "shallower"]);
    }

    #[test]
    fn nonroot_balances_only_overflow_or_delete_above_strict_threshold() {
        let fixture = match Fixture::new() { Some(fixture) => fixture, None => return };
        unsafe {
            (*fixture.page).p_parent = 1;
            (*fixture.page).p_bt = fixture.shared as usize as u32;
            (*fixture.shared).usable_size = 100;
            (*fixture.page).n_free = 66;
        }
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 0) }, 0);
        assert!(fixture.events().is_empty());

        unsafe { (*fixture.page).n_free = 67; }
        RESULTS.lock().unwrap_or_else(|e| e.into_inner())[3] = 44;
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 0) }, 44);
        assert_eq!(fixture.events(), vec!["nonroot"]);

        EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        unsafe {
            (*fixture.page).n_free = u16::MAX;
            (*fixture.page).p_bt = 0;
        }
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 1) }, 0);
        assert!(fixture.events().is_empty());

        unsafe { (*fixture.page).n_overflow = 1; }
        assert_eq!(unsafe { btree_balance_page(fixture.page.cast(), 1) }, 44);
        assert_eq!(fixture.events(), vec!["nonroot"]);
    }
}
