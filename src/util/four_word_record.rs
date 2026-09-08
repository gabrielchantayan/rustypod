//! Allocating the small four-word record used as an opaque payload carrier.

use crate::drivers::ata_cmd::traced_alloc;
use crate::kernel::diag_ring_record::diag_ring_record;

/// A 16-byte retailOS record. All fields are target words, including
/// [`FourWordRecord::payload`], which callers use for an opaque value or
/// target address.
#[repr(C)]
pub struct FourWordRecord {
    /// +0x00: initialized to zero.
    pub state: u32,
    /// +0x04: the constructor argument.
    pub payload: u32,
    /// +0x08: initialized to zero.
    pub reserved0: u32,
    /// +0x0c: initialized to zero.
    pub reserved1: u32,
}

/// four_word_record_create — original: `FUN_0803a488` @ **0x0803a488**
/// (80 bytes, `0x0803a488..0x0803a4d8`; the separately linked next function
/// begins at `0x0803a4d8`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies 20 direct inbound
/// call sites, all unconditional `bl`; there are no predicated BL forms or
/// direct tail branches. Allocates 16 bytes with `traced_alloc(16, 0, 0)`;
/// on success writes zero, `payload`, zero, zero in ascending word order and
/// returns the record. A NULL allocation records diagnostic
/// `(0x0d, 0x82, 0x41, 0, 0)` and returns NULL.
///
/// Deliberate deviations: none. Both callees (`traced_alloc` and
/// `diag_ring_record`) are ported, so this retains direct calls rather than
/// adding a dispatch seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn four_word_record_create(payload: u32) -> *mut FourWordRecord {
    let record = traced_alloc(16, 0, 0).cast::<FourWordRecord>();
    if record.is_null() {
        diag_ring_record(0x0d, 0x82, 0x41, 0, 0);
        return core::ptr::null_mut();
    }

    (*record).state = 0;
    (*record).payload = payload;
    (*record).reserved0 = 0;
    (*record).reserved1 = 0;
    record
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::MutexGuard;

    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_REQUEST: Option<(i32, u32, u32)> = None;
    static mut DIAG_RING: *mut DiagEventRing = core::ptr::null_mut();

    unsafe extern "C" fn recording_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_REQUEST = Some((size, tag1, tag2));
        ALLOC_RESULT
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        DIAG_RING
    }

    struct Fixture {
        _diag_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        storage: Box<[u32; 4]>,
        ring: Box<DiagEventRing>,
    }

    impl Fixture {
        fn new(allocation_succeeds: bool) -> Self {
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut storage = Box::new([0xa5a5_a5a5; 4]);
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_REQUEST = None;
                ALLOC_RESULT = if allocation_succeeds {
                    storage.as_mut_ptr().cast::<u8>()
                } else {
                    core::ptr::null_mut()
                };
                DIAG_RING = ring.as_mut();
                let saved_alloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_ring_getter = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: recording_alloc, trace: None },
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), Some(ring_getter));
                Self {
                    _diag_guard: diag_guard,
                    _alloc_guard: alloc_guard,
                    saved_alloc_hooks,
                    saved_ring_getter,
                    storage,
                    ring,
                }
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.saved_alloc_hooks);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER),
                    self.saved_ring_getter,
                );
                ALLOC_RESULT = core::ptr::null_mut();
                ALLOC_REQUEST = None;
                DIAG_RING = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn initializes_the_exact_four_word_record_after_a_successful_allocation() {
        let fixture = Fixture::new(true);
        let record = unsafe { four_word_record_create(0x1234_5678) };

        assert_eq!(record.cast::<u32>(), fixture.storage.as_ptr().cast_mut());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((16, 0, 0)));
        assert_eq!(*fixture.storage, [0, 0x1234_5678, 0, 0]);
        assert_eq!(fixture.ring.head, 0);
    }

    #[test]
    fn records_the_allocation_failure_triple_and_returns_null() {
        let fixture = Fixture::new(false);
        let record = unsafe { four_word_record_create(0xdead_beef) };

        assert!(record.is_null());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((16, 0, 0)));
        assert_eq!(fixture.ring.head, 1);
        assert_eq!(fixture.ring.tags[1], 0x0d08_2041);
        assert_eq!(fixture.ring.data0[1], 0);
        assert_eq!(fixture.ring.data1[1], 0);
    }
}
