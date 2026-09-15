//! Fixed-pool UI entry construction.

use core::ptr;

use super::object_state::sequence_id_next;

/// ABI of the still-unported fixed-pool allocator at `0x0805de1c`.
pub type FixedPoolAcquire = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_fixed_pool_acquire(pool: *mut u8) -> *mut u8 {
    let acquire: FixedPoolAcquire = core::mem::transmute(0x0805_de1cusize);
    acquire(pool)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_fixed_pool_acquire(_pool: *mut u8) -> *mut u8 {
    ptr::null_mut()
}

/// Calls outside this one-function port.
///
/// Target builds dispatch to the unported fixed-pool allocator. Host tests
/// replace this boundary to observe both allocation outcomes.
#[derive(Clone, Copy)]
pub struct FixedPoolOps {
    pub acquire: FixedPoolAcquire,
}

pub const DEFAULT_FIXED_POOL_OPS: FixedPoolOps = FixedPoolOps {
    acquire: retail_fixed_pool_acquire,
};

/// Active fixed-pool allocation boundary.
pub static mut FIXED_POOL_OPS: FixedPoolOps = DEFAULT_FIXED_POOL_OPS;

#[inline(always)]
fn fixed_pool_ops() -> FixedPoolOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(FIXED_POOL_OPS)) }
}

/// ui_pool_entry_create — original: `FUN_0808e228` @ `0x0808e228` (52 bytes).
///
/// Raw ARM establishes the true extent as `0x0808e228..0x0808e25c`: the next
/// `push {r4,lr}` begins a separate function at `0x0808e25c`. It allocates an
/// entry from the fixed-pool descriptor at owner `+0x3c`. On success it stores
/// the owner target address at entry `+0x00`, stamps entry `+0x10` with the
/// pre-increment sequence identifier, and clears entry byte `+0x1c`; on
/// allocation failure it returns NULL without advancing that identifier.
///
/// Decoding every ARM B/BL word in `osos.dec` finds five direct callers: five
/// unconditional `bl` and zero predicated `bl` forms. The function itself has
/// two unconditional calls, to the unported fixed-pool allocator at
/// `0x0805de1c` and the ported `sequence_id_next` at `0x08055eb8`.
///
/// Deliberate deviation: `0x0805de1c` is not ported, so this uses the explicit
/// [`FIXED_POOL_OPS`] dispatch seam; target builds call the stock allocator.
/// Target addresses remain four-byte `u32` words even under 64-bit host tests.
///
/// # Safety
///
/// `owner` must be readable through `+0x3f`. If allocation succeeds, the
/// returned entry must be writable through `+0x1c`, exactly as required by the
/// original stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_pool_entry_create")]
#[inline(never)]
pub unsafe extern "C" fn ui_pool_entry_create(owner: *mut u8) -> *mut u8 {
    let pool = owner.add(0x3c).cast::<u32>().read() as usize as *mut u8;
    let entry = (fixed_pool_ops().acquire)(pool);
    if entry.is_null() {
        return ptr::null_mut();
    }

    entry.cast::<u32>().write(owner as usize as u32);
    entry.add(0x10).cast::<u32>().write(sequence_id_next());
    entry.add(0x1c).write(0);
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::{LazyLock, Mutex};

    const FIXTURE_BYTES: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_POOL_ENTRY_CREATE,
            FIXTURE_BYTES,
        )
        .map(|storage| storage as usize)
    });
    static mut ACQUIRE_POOL: usize = 0;
    static mut ACQUIRE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn record_acquire(pool: *mut u8) -> *mut u8 {
        ACQUIRE_POOL = pool as usize;
        ACQUIRE_RESULT
    }

    struct OpsReset(FixedPoolOps);

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { FIXED_POOL_OPS = self.0; }
        }
    }

    fn fixture() -> Option<*mut u8> {
        FIXTURE.map(|storage| storage as *mut u8)
    }

    fn seed_sequence_id(value: u32) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(super::super::object_state::SEQUENCE_ID), value); }
    }

    fn sequence_id() -> u32 {
        unsafe { ptr::read_volatile(ptr::addr_of!(super::super::object_state::SEQUENCE_ID)) }
    }

    #[test]
    fn initializes_entry_and_stamps_preincrement_sequence_id() {
        let _ops_guard = crate::testing::UI_POOL_ENTRY_CREATE_TEST_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _sequence_guard = crate::testing::SEQUENCE_ID_TEST_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(owner) = fixture() else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        let mut entry = [0xa5u8; 0x20];
        unsafe {
            owner.write_bytes(0x5a, FIXTURE_BYTES);
            owner.add(0x3c).cast::<u32>().write(0x1234_5000);
            ACQUIRE_RESULT = entry.as_mut_ptr();
            ACQUIRE_POOL = 0;
            let reset = OpsReset(FIXED_POOL_OPS);
            FIXED_POOL_OPS = FixedPoolOps { acquire: record_acquire };
            seed_sequence_id(0xffff_ffff);
            assert_eq!(ui_pool_entry_create(owner), entry.as_mut_ptr());
            assert_eq!(ACQUIRE_POOL, 0x1234_5000);
            assert_eq!(entry.as_ptr().cast::<u32>().read(), owner as usize as u32);
            assert_eq!(entry.as_ptr().add(0x10).cast::<u32>().read(), u32::MAX);
            assert_eq!(entry[0x1c], 0);
            assert_eq!(entry[0x1b], 0xa5);
            assert_eq!(entry[0x1d], 0xa5);
            assert_eq!(sequence_id(), 0);
            drop(reset);
        }
    }

    #[test]
    fn allocation_failure_preserves_sequence_and_owner_memory() {
        let _ops_guard = crate::testing::UI_POOL_ENTRY_CREATE_TEST_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _sequence_guard = crate::testing::SEQUENCE_ID_TEST_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(owner) = fixture() else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            owner.write_bytes(0x5a, FIXTURE_BYTES);
            owner.add(0x3c).cast::<u32>().write(0x8765_4000);
            ACQUIRE_RESULT = ptr::null_mut();
            ACQUIRE_POOL = 0;
            let reset = OpsReset(FIXED_POOL_OPS);
            FIXED_POOL_OPS = FixedPoolOps { acquire: record_acquire };
            seed_sequence_id(0x2468_ace0);
            assert!(ui_pool_entry_create(owner).is_null());
            assert_eq!(ACQUIRE_POOL, 0x8765_4000);
            assert_eq!(sequence_id(), 0x2468_ace0);
            assert_eq!(owner.add(0x3c).cast::<u32>().read(), 0x8765_4000);
            drop(reset);
        }
    }
}
