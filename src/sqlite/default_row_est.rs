//! Initialize SQLite's default per-index row estimates.
//!
//! - `default_row_est` — original: `FUN_08374a70` @ 0x08374a70 (80 bytes;
//!   2 direct inbound plain `bl` call sites, no predicated `bl`; no outbound
//!   `bl`).
//!
//! Raw ARM establishes the exact extent `0x08374a70..0x08374ac0`: `bx lr` is
//! followed by the literal `1000000` at `0x08374ac4`, then the separately
//! entered function at `0x08374ac8`. SQLite's `sqlite3DefaultRowEst` stores
//! the base estimate, assigns descending estimates 10 through 7 to the first
//! four indexed columns, assigns 5 to later columns, and gives a unique index
//! (nonzero `onError`) an estimate of 1 for its complete key.
//!
//! Deliberate deviation: target-width fields are addressed as raw byte
//! offsets instead of declaring a host-width `Index`; this preserves the
//! retail 32-bit pointer layout on host tests.

const INDEX_N_COLUMN_OFFSET: usize = 0x04;
const INDEX_ROW_ESTIMATES_OFFSET: usize = 0x0c;
const INDEX_ON_ERROR_OFFSET: usize = 0x18;
const DEFAULT_TABLE_ROWS: u32 = 1_000_000;

#[inline(always)]
unsafe fn read_word(address: *const u8) -> u32 {
    unsafe { address.cast::<u32>().read() }
}

/// default_row_est — original: `FUN_08374a70` @ 0x08374a70 (80 bytes; 2 `bl` call sites).
///
/// Populate `index->aiRowEst` from its signed `nColumn`. The retail loop uses
/// signed comparisons, so a negative count writes only the base estimate.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_row_est(index: *mut u8) {
    let estimates = unsafe { read_word(index.add(INDEX_ROW_ESTIMATES_OFFSET)) as usize as *mut u32 };
    unsafe { estimates.write(DEFAULT_TABLE_ROWS) };

    let mut column_count = unsafe { read_word(index.add(INDEX_N_COLUMN_OFFSET)) as i32 };
    while column_count >= 5 {
        unsafe { estimates.add(column_count as usize).write(5) };
        column_count -= 1;
    }
    while column_count >= 1 {
        unsafe { estimates.add(column_count as usize).write((11 - column_count) as u32) };
        column_count -= 1;
    }
    if unsafe { index.add(INDEX_ON_ERROR_OFFSET).read() } != 0 {
        let column_count = unsafe { read_word(index.add(INDEX_N_COLUMN_OFFSET)) as usize };
        unsafe { estimates.add(column_count).write(1) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const ESTIMATES_OFFSET: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_DEFAULT_ROW_EST, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u8> {
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("sqlite/default_row_est"));
            return None;
        };
        let base = base as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base)
    }

    #[test]
    fn populates_base_and_column_estimates_across_the_five_column_boundary() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(index) = fixture() else { return };
        let estimates = unsafe { index.add(ESTIMATES_OFFSET).cast::<u32>() };
        unsafe { index.add(INDEX_N_COLUMN_OFFSET).cast::<u32>().write(6) };
        unsafe { index.add(INDEX_ROW_ESTIMATES_OFFSET).cast::<u32>().write(estimates as usize as u32) };
        unsafe { estimates.add(7).write(0xa5a5_a5a5) };

        unsafe { default_row_est(index) };

        assert_eq!(unsafe { core::slice::from_raw_parts(estimates, 7) }, &[1_000_000, 10, 9, 8, 7, 5, 5]);
        assert_eq!(unsafe { estimates.add(7).read() }, 0xa5a5_a5a5);
    }

    #[test]
    fn unique_index_overwrites_its_final_estimate_with_one() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(index) = fixture() else { return };
        let estimates = unsafe { index.add(ESTIMATES_OFFSET).cast::<u32>() };
        unsafe { index.add(INDEX_N_COLUMN_OFFSET).cast::<u32>().write(3) };
        unsafe { index.add(INDEX_ROW_ESTIMATES_OFFSET).cast::<u32>().write(estimates as usize as u32) };
        unsafe { index.add(INDEX_ON_ERROR_OFFSET).write(1) };

        unsafe { default_row_est(index) };

        assert_eq!(unsafe { core::slice::from_raw_parts(estimates, 4) }, &[1_000_000, 10, 9, 1]);
    }

    #[test]
    fn negative_column_count_leaves_only_the_base_estimate() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(index) = fixture() else { return };
        let estimates = unsafe { index.add(ESTIMATES_OFFSET).cast::<u32>() };
        unsafe { index.add(INDEX_N_COLUMN_OFFSET).cast::<u32>().write((-1i32) as u32) };
        unsafe { index.add(INDEX_ROW_ESTIMATES_OFFSET).cast::<u32>().write(estimates as usize as u32) };
        unsafe { estimates.add(1).write(0xa5a5_a5a5) };

        unsafe { default_row_est(index) };

        assert_eq!(unsafe { estimates.read() }, DEFAULT_TABLE_ROWS);
        assert_eq!(unsafe { estimates.add(1).read() }, 0xa5a5_a5a5);
    }
}
