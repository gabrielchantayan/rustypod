//! ASN.1 INTEGER storage used by the vendored OpenSSL object code.
//!
//! `Asn1Integer` is the target's three-word `ASN1_STRING` layout. The byte
//! payload is an owned, minimally sized big-endian signed integer encoding.

use crate::drivers::ata_cmd::{traced_alloc, traced_free};
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::iram_veneers::iram_memzero_veneer;

/// ASN.1 INTEGER tags used by the target's `ASN1_STRING` representation.
const ASN1_INTEGER: u32 = 2;
const ASN1_NEG_INTEGER: u32 = 0x102;
const INTEGER_STORAGE_SIZE: u32 = 5;

/// Target-layout `ASN1_INTEGER` / `ASN1_STRING` header.
///
/// `length` and `kind` are target words; `data` is naturally at +0x08 on both
/// ARM and the host under `repr(C)`.
#[repr(C)]
pub struct Asn1Integer {
    pub length: u32,
    pub kind: u32,
    pub data: *mut u8,
}

/// asn1_integer_set — original: `FUN_08039ff0` @ 0x08039ff0 (224 bytes,
/// including its final literal-pool word; Ghidra reports 220 code bytes; six
/// direct unconditional `bl` callers, binary-scanned).
///
/// Sets the `ASN1_INTEGER` tag and stores `value` as minimally-sized,
/// big-endian magnitude bytes. A header with an unsigned `length` below five
/// releases its old payload, allocates and clears exactly five bytes through
/// the IRAM memzero veneer, then writes the encoding. Negative values use tag
/// `0x102`; zero is represented by a zero payload length. Allocation failure
/// records diagnostic `(13, 0x76, 0x41, 0, 0)` and returns zero.
///
/// Deliberate deviation: the retail routine reaches memzero through the
/// `0x08037dc8 -> 0x220002d4` IRAM veneer; this port calls its already-ported
/// Rust veneer directly. The allocator, free, and diagnostic callees are also
/// direct ports, so no new dispatch seam is introduced.
///
/// # Safety
///
/// `integer` must point to an aligned, writable target-layout header. If its
/// unsigned `length` is below five, a non-NULL `data` must belong to the
/// `traced_free` allocation family.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn asn1_integer_set(integer: *mut Asn1Integer, value: i32) -> i32 {
    unsafe {
        core::ptr::addr_of_mut!((*integer).kind).write_volatile(ASN1_INTEGER);

        if core::ptr::addr_of!((*integer).length).read_volatile() < INTEGER_STORAGE_SIZE {
            let old_data = core::ptr::addr_of!((*integer).data).read_volatile();
            if !old_data.is_null() {
                traced_free(old_data);
            }

            let data = traced_alloc(INTEGER_STORAGE_SIZE as i32, 0, 0);
            core::ptr::addr_of_mut!((*integer).data).write_volatile(data);
            if data.is_null() {
                diag_ring_record(13, 0x76, 0x41, 0, 0);
                return 0;
            }
            iram_memzero_veneer(data, INTEGER_STORAGE_SIZE as usize);
        }

        let data = core::ptr::addr_of!((*integer).data).read_volatile();
        if data.is_null() {
            diag_ring_record(13, 0x76, 0x41, 0, 0);
            return 0;
        }

        let mut magnitude = value;
        if magnitude < 0 {
            magnitude = magnitude.wrapping_neg();
            core::ptr::addr_of_mut!((*integer).kind).write_volatile(ASN1_NEG_INTEGER);
        }

        let mut little_endian = [0u8; 4];
        let mut byte_count = 0usize;
        while magnitude != 0 && byte_count < little_endian.len() {
            little_endian[byte_count] = magnitude as u8;
            magnitude >>= 8;
            byte_count += 1;
        }

        for index in (0..byte_count).rev() {
            let data = core::ptr::addr_of!((*integer).data).read_volatile();
            data.add(byte_count - index - 1).write(little_endian[index]);
        }
        core::ptr::addr_of_mut!((*integer).length).write_volatile(byte_count as u32);
        1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK,
    };
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_REQUEST: Option<(i32, u32, u32)> = None;
    static mut FREED: *mut u8 = core::ptr::null_mut();
    static mut DIAG_RING: *mut DiagEventRing = core::ptr::null_mut();

    unsafe extern "C" fn recording_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        unsafe {
            ALLOC_REQUEST = Some((size, tag1, tag2));
            ALLOC_RESULT
        }
    }

    unsafe extern "C" fn recording_free(block: *mut u8) {
        unsafe { FREED = block };
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        unsafe { DIAG_RING }
    }

    struct Fixture {
        _test_guard: MutexGuard<'static, ()>,
        _diag_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        _free_guard: parking_lot::MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_free_hooks: TracedFreeHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        storage: Box<[u8; INTEGER_STORAGE_SIZE as usize]>,
        ring: Box<DiagEventRing>,
    }

    impl Fixture {
        fn new(allocation_succeeds: bool) -> Self {
            let test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let free_guard = TRACED_FREE_TEST_LOCK.lock();
            let mut storage = Box::new([0xa5; INTEGER_STORAGE_SIZE as usize]);
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_RESULT = if allocation_succeeds { storage.as_mut_ptr() } else { core::ptr::null_mut() };
                ALLOC_REQUEST = None;
                FREED = core::ptr::null_mut();
                DIAG_RING = ring.as_mut();
                let saved_alloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_free_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
                let saved_ring_getter = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: recording_alloc, trace: None },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                    TracedFreeHooks { free: recording_free, trace: None },
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), Some(ring_getter));
                Self {
                    _test_guard: test_guard,
                    _diag_guard: diag_guard,
                    _alloc_guard: alloc_guard,
                    _free_guard: free_guard,
                    saved_alloc_hooks,
                    saved_free_hooks,
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
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.saved_free_hooks);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), self.saved_ring_getter);
                ALLOC_RESULT = core::ptr::null_mut();
                ALLOC_REQUEST = None;
                FREED = core::ptr::null_mut();
                DIAG_RING = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn allocates_clears_and_serializes_a_positive_value_big_endian() {
        let fixture = Fixture::new(true);
        let mut integer = Asn1Integer { length: 0, kind: 0xffff_ffff, data: core::ptr::null_mut() };

        assert_eq!(unsafe { asn1_integer_set(&mut integer, 0x12_34_56) }, 1);
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((5, 0, 0)));
        assert_eq!(integer.kind, ASN1_INTEGER);
        assert_eq!(integer.length, 3);
        assert_eq!(integer.data, fixture.storage.as_ptr() as *mut u8);
        assert_eq!(&fixture.storage[..], &[0x12, 0x34, 0x56, 0, 0]);
    }

    #[test]
    fn negative_value_releases_short_payload_and_sets_negative_tag() {
        let fixture = Fixture::new(true);
        let mut old_storage = [0u8; INTEGER_STORAGE_SIZE as usize];
        let mut integer = Asn1Integer { length: 4, kind: 0, data: old_storage.as_mut_ptr() };

        assert_eq!(unsafe { asn1_integer_set(&mut integer, -0x1234) }, 1);
        assert_eq!(unsafe { FREED }, old_storage.as_mut_ptr());
        assert_eq!(integer.kind, ASN1_NEG_INTEGER);
        assert_eq!(integer.length, 2);
        assert_eq!(&fixture.storage[..], &[0x12, 0x34, 0, 0, 0]);
    }

    #[test]
    fn i32_min_uses_its_wrapping_four_byte_magnitude() {
        let _fixture = Fixture::new(true);
        let mut storage = [0xa5; INTEGER_STORAGE_SIZE as usize];
        let mut integer = Asn1Integer { length: 5, kind: 0, data: storage.as_mut_ptr() };

        assert_eq!(unsafe { asn1_integer_set(&mut integer, i32::MIN) }, 1);
        assert_eq!(integer.kind, ASN1_NEG_INTEGER);
        assert_eq!(integer.length, 4);
        assert_eq!(storage, [0x80, 0, 0, 0, 0xa5]);
    }

    #[test]
    fn zero_with_existing_five_byte_payload_preserves_its_bytes() {
        let _fixture = Fixture::new(true);
        let mut storage = [0xde, 0xad, 0xbe, 0xef, 0x55];
        let mut integer = Asn1Integer { length: 5, kind: ASN1_NEG_INTEGER, data: storage.as_mut_ptr() };

        assert_eq!(unsafe { asn1_integer_set(&mut integer, 0) }, 1);
        assert_eq!(unsafe { ALLOC_REQUEST }, None);
        assert_eq!(integer.kind, ASN1_INTEGER);
        assert_eq!(integer.length, 0);
        assert_eq!(storage, [0xde, 0xad, 0xbe, 0xef, 0x55]);
    }

    #[test]
    fn allocation_failure_records_the_retail_diagnostic() {
        let fixture = Fixture::new(false);
        let mut integer = Asn1Integer { length: 0, kind: 0, data: core::ptr::null_mut() };

        assert_eq!(unsafe { asn1_integer_set(&mut integer, 1) }, 0);
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((5, 0, 0)));
        assert!(integer.data.is_null());
        assert_eq!(fixture.ring.head, 1);
        assert_eq!(fixture.ring.tags[1], 0x0d07_6041);
        assert_eq!(fixture.ring.data0[1], 0);
        assert_eq!(fixture.ring.data1[1], 0);
    }
}
