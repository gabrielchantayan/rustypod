//! Zeroing buffer ownership and destruction.
//!
//! The target-layout [`ZeroingBuffer`] is a three-word owning record. Its
//! first word is retained without interpretation; destruction only consumes
//! the allocation and byte-count words.

use crate::drivers::ata_cmd::{traced_alloc, traced_free, traced_realloc};
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::iram_veneers::iram_memzero_veneer;
use crate::runtime::rt_div::__rt_sdiv;

/// Target-layout record whose owned payload is cleared before release.
///
/// `data` is at target offset `+0x04` and `byte_len` is at `+0x08`. The
/// pointer field has a host-width layout in host tests, but `repr(C)` gives
/// the retail layout on the 32-bit ARM target.
#[repr(C)]
pub struct ZeroingBuffer {
    pub state: u32,
    pub data: *mut u8,
    pub byte_len: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(ZeroingBuffer, data)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<ZeroingBuffer>()];
/// zeroing_buffer_create — original: `FUN_080421d4` @ `0x080421d4`
/// (76 bytes exactly, `0x080421d4..0x08042220`; the independently linked
/// successor begins with `push {r3,r4,r5,r6,r7,lr}` at `0x08042220`).
///
/// Decoding every ARM `B`/`BL` word in `osos.dec` finds seven direct inbound
/// calls, all unconditional `bl`: `0x0805fc0c`, `0x0806f620`, `0x0807bdc8`,
/// `0x0809d7c4`, `0x080a1258`, `0x080ec004`, and `0x080efd10`. There are no
/// predicated call forms or direct tail branches.
///
/// Allocates the three target-word [`ZeroingBuffer`] record through
/// `traced_alloc(12, 0, 0)`. Allocation failure records diagnostic
/// `(7, 0x65, 0x41, 0, 0)` and returns NULL. On success it clears
/// `{state, data, byte_len}` in the retail store order `state, byte_len,
/// data`, returning an empty owning buffer.
///
/// No deliberate deviations: both `traced_alloc` and `diag_ring_record` are
/// already ported direct callees.
#[cfg_attr(target_os = "none", link_section = ".text.zeroing_buffer_create")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn zeroing_buffer_create() -> *mut ZeroingBuffer {
    let buffer = traced_alloc(12, 0, 0).cast::<ZeroingBuffer>();
    if buffer.is_null() {
        diag_ring_record(7, 0x65, 0x41, 0, 0);
        return core::ptr::null_mut();
    }

    core::ptr::addr_of_mut!((*buffer).state).write_volatile(0);
    core::ptr::addr_of_mut!((*buffer).byte_len).write_volatile(0);
    core::ptr::addr_of_mut!((*buffer).data).write_volatile(core::ptr::null_mut());
    buffer
}

/// zeroing_buffer_resize — original: `FUN_08042114` @ `0x08042114`
/// (192 bytes exactly, `0x08042114..0x080421d4`; the independently linked
/// successor starts at `0x080421d4`).
///
/// Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly seven
/// direct inbound calls, all unconditional `bl`: `0x0805fcdc`, `0x0807b578`,
/// `0x080a12a4`, `0x080a13ac`, `0x080bfa30`, `0x080effe4`, and `0x080f4c90`.
/// There are no predicated forms, tail branches, or aligned image words equal
/// to the entry address.
///
/// Resizes the logical byte length. Shrinking clears the discarded suffix;
/// growing clears the newly exposed bytes. When the request exceeds capacity,
/// the payload grows through `traced_alloc` or `traced_realloc` to
/// `4 * trunc((requested + 3) / 3)` bytes, with the retail signed wrapping
/// arithmetic. An allocation failure records `(7, 100, 0x41, 0, 0)` and leaves
/// all record words unchanged.
///
/// No deliberate deviations: `traced_alloc`, `traced_realloc`, the diagnostic
/// recorder, and the IRAM memzero veneer are direct ports. The target's three
/// 32-bit words remain named fields, whose `repr(C)` layout is exact on ARM.
///
/// # Safety
///
/// `buffer` must point to writable [`ZeroingBuffer`] storage. Its `data` field
/// must be valid for every byte cleared by the requested resize; the retail
/// function performs no NULL or range checks before clearing.
#[cfg_attr(target_os = "none", link_section = ".text.zeroing_buffer_resize")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn zeroing_buffer_resize(buffer: *mut ZeroingBuffer, requested: i32) -> i32 {
    let current = core::ptr::addr_of!((*buffer).state).read_volatile() as i32;
    let mut data = core::ptr::addr_of!((*buffer).data).read_volatile();

    if current < requested {
        let capacity = core::ptr::addr_of!((*buffer).byte_len).read_volatile() as i32;
        if capacity < requested {
            let allocation_size = __rt_sdiv(requested.wrapping_add(3), 3).wrapping_shl(2);
            let replacement = if data.is_null() {
                traced_alloc(allocation_size, 0, 0)
            } else {
                traced_realloc(data, allocation_size, 0, 0)
            };
            if replacement.is_null() {
                diag_ring_record(7, 100, 0x41, 0, 0);
                return 0;
            }
            core::ptr::addr_of_mut!((*buffer).data).write_volatile(replacement);
            core::ptr::addr_of_mut!((*buffer).byte_len).write_volatile(allocation_size as u32);
            data = replacement;
        }
        iram_memzero_veneer(
            data.wrapping_offset(current as isize),
            requested.wrapping_sub(current) as u32 as usize,
        );
    } else {
        iram_memzero_veneer(
            data.wrapping_offset(requested as isize),
            current.wrapping_sub(requested) as u32 as usize,
        );
    }

    core::ptr::addr_of_mut!((*buffer).state).write_volatile(requested as u32);
    requested
}


/// zeroing_buffer_destroy — original: `FUN_0804202c` @ `0x0804202c`
/// (52 bytes exactly, `0x0804202c..0x08042060`; the independently linked
/// sibling starts with `push {r3,r4-r7,lr}` at `0x08042060`). Decoding every
/// ARM B/BL word in `osos.dec` finds nine direct inbound `bl` calls: four
/// unconditional (`0x0807c258`, `0x080a53f8`, `0x080ef850`, `0x080effb8`) and
/// five `blne` (`0x0803a8ac`, `0x0805fedc`, `0x0806f914`, `0x0807c230`,
/// `0x080a1410`); there are no tail branches or data words targeting it.
///
/// NULL is a no-op. Otherwise, a non-NULL `data` is cleared through the
/// ported IRAM memzero veneer (`0x08037dc8 -> 0x220002d4`) for `byte_len`
/// bytes, then released through [`traced_free`]. Finally the record itself is
/// released through `traced_free`. The five predicated callsites gate their
/// cleanup externally, but the `movs`/`popeq` in this body still makes a
/// direct NULL call a no-op; tests cover both paths.
///
/// No deliberate deviations: ARM release compilation retains the final tail
/// branch to `traced_free`, while its different prologue only saves the extra
/// registers LLVM uses to preserve the record across the payload release.
///
/// # Safety
///
/// `buffer` must be NULL or point to writable, aligned [`ZeroingBuffer`]
/// storage. A non-NULL `data` must name `byte_len` writable bytes and be
/// owned by the allocation family paired with [`traced_free`].
#[cfg_attr(target_os = "none", link_section = ".text.zeroing_buffer_destroy")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn zeroing_buffer_destroy(buffer: *mut ZeroingBuffer) {
    if buffer.is_null() {
        return;
    }

    let data = core::ptr::addr_of!((*buffer).data).read_volatile();
    if !data.is_null() {
        let byte_len = core::ptr::addr_of!((*buffer).byte_len).read_volatile() as usize;
        iram_memzero_veneer(data, byte_len);
        traced_free(data);
    }
    traced_free(buffer.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK};
    use parking_lot::{Mutex, MutexGuard};

    static FREE_EVENTS: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static INSPECTED_BYTES: Mutex<std::vec::Vec<u8>> = Mutex::new(std::vec::Vec::new());
    static mut INSPECTED_BLOCK: *mut u8 = core::ptr::null_mut();
    static mut INSPECTED_LEN: usize = 0;

    unsafe extern "C" fn record_free(block: *mut u8) {
        FREE_EVENTS.lock().push(block as usize);
        if block == INSPECTED_BLOCK {
            INSPECTED_BYTES.lock().extend_from_slice(core::slice::from_raw_parts(block, INSPECTED_LEN));
        }
    }

    struct FreeHooksReset {
        _guard: MutexGuard<'static, ()>,
        previous: TracedFreeHooks,
    }

    impl Drop for FreeHooksReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.previous);
                INSPECTED_BLOCK = core::ptr::null_mut();
                INSPECTED_LEN = 0;
            }
        }
    }

    fn destroy_and_record(buffer: *mut ZeroingBuffer, inspected: *mut u8, len: usize) -> (std::vec::Vec<usize>, std::vec::Vec<u8>) {
        let guard = TRACED_FREE_TEST_LOCK.lock();
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)) };
        let _reset = FreeHooksReset { _guard: guard, previous };
        FREE_EVENTS.lock().clear();
        INSPECTED_BYTES.lock().clear();
        unsafe {
            INSPECTED_BLOCK = inspected;
            INSPECTED_LEN = len;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                TracedFreeHooks { free: record_free, trace: None },
            );
            zeroing_buffer_destroy(buffer);
        }
        (FREE_EVENTS.lock().clone(), INSPECTED_BYTES.lock().clone())
    }

    #[test]
    fn null_buffer_does_not_reach_the_allocator() {
        let (freed, inspected) = destroy_and_record(core::ptr::null_mut(), core::ptr::null_mut(), 0);
        assert!(freed.is_empty());
        assert!(inspected.is_empty());
    }

    #[test]
    fn null_data_releases_only_the_record() {
        let mut buffer = ZeroingBuffer { state: 0xdead_beef, data: core::ptr::null_mut(), byte_len: 7 };
        let (freed, inspected) = destroy_and_record(&mut buffer, core::ptr::null_mut(), 0);
        assert_eq!(freed, [&mut buffer as *mut ZeroingBuffer as usize]);
        assert!(inspected.is_empty());
        assert_eq!(buffer.state, 0xdead_beef);
        assert_eq!(buffer.byte_len, 7);
    }

    #[test]
    fn data_is_zeroed_before_data_then_record_release() {
        let mut data = [0xa5, 0x00, 0x71, 0xfe, 0x5c];
        let mut buffer = ZeroingBuffer { state: 0x1357_9bdf, data: data.as_mut_ptr(), byte_len: 3 };
        let (freed, inspected) = destroy_and_record(&mut buffer, data.as_mut_ptr(), buffer.byte_len as usize);
        assert_eq!(inspected, [0, 0, 0], "the free hook observes the cleared payload");
        assert_eq!(data, [0, 0, 0, 0xfe, 0x5c], "only byte_len bytes are cleared");
        assert_eq!(
            freed,
            [data.as_mut_ptr() as usize, &mut buffer as *mut ZeroingBuffer as usize],
            "payload is released before its record",
        );
        assert_eq!(buffer.state, 0x1357_9bdf);
        assert_eq!(buffer.data, data.as_mut_ptr());
        assert_eq!(buffer.byte_len, 3);
    }

    #[test]
    fn zero_length_payload_is_still_released_without_writes() {
        let mut data = [0x44, 0x55];
        let mut buffer = ZeroingBuffer { state: 0, data: data.as_mut_ptr(), byte_len: 0 };
        let (freed, inspected) = destroy_and_record(&mut buffer, data.as_mut_ptr(), 0);
        assert!(inspected.is_empty());
        assert_eq!(data, [0x44, 0x55]);
        assert_eq!(freed, [data.as_mut_ptr() as usize, &mut buffer as *mut ZeroingBuffer as usize]);
    }
}

#[cfg(test)]
mod create_tests {
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

    struct CreateFixture {
        _diag_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        storage: Box<ZeroingBuffer>,
        ring: Box<DiagEventRing>,
    }

    impl CreateFixture {
        fn new(allocation_succeeds: bool) -> Self {
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let mut storage = Box::new(ZeroingBuffer {
                state: 0xa5a5_a5a5,
                data: 1usize as *mut u8,
                byte_len: 0xa5a5_a5a5,
            });
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_REQUEST = None;
                ALLOC_RESULT = if allocation_succeeds {
                    (storage.as_mut() as *mut ZeroingBuffer).cast::<u8>()
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

    impl Drop for CreateFixture {
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
    fn create_requests_three_words_and_clears_every_field() {
        let fixture = CreateFixture::new(true);
        let buffer = unsafe { zeroing_buffer_create() };

        assert_eq!(buffer, fixture.storage.as_ref() as *const ZeroingBuffer as *mut ZeroingBuffer);
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((12, 0, 0)));
        assert_eq!(unsafe { (*buffer).state }, 0);
        assert!(unsafe { (*buffer).data }.is_null());
        assert_eq!(unsafe { (*buffer).byte_len }, 0);
        assert_eq!(fixture.ring.head, 0, "success does not record a diagnostic");
    }

    #[test]
    fn create_failure_records_allocation_diagnostic() {
        let fixture = CreateFixture::new(false);
        let buffer = unsafe { zeroing_buffer_create() };

        assert!(buffer.is_null());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((12, 0, 0)));
        assert_eq!(fixture.ring.head, 1);
        assert_eq!(fixture.ring.tags[1], 0x0706_5041);
        assert_eq!(fixture.ring.data0[1], 0);
        assert_eq!(fixture.ring.data1[1], 0);
    }
}

#[cfg(test)]
mod resize_tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedReallocHooks, TRACED_ALLOC_HOOKS, TRACED_REALLOC_HOOKS,
        TRACED_REALLOC_TEST_LOCK,
    };
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static RESIZE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_REQUEST: Option<(i32, u32, u32)> = None;
    static mut REALLOC_REQUEST: Option<(*mut u8, i32, u32, u32)> = None;
    static mut DIAG_RING: *mut DiagEventRing = core::ptr::null_mut();

    unsafe extern "C" fn record_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_REQUEST = Some((size, tag1, tag2));
        ALLOC_RESULT
    }

    unsafe extern "C" fn record_realloc(
        block: *mut u8,
        size: i32,
        tag1: u32,
        tag2: u32,
    ) -> *mut u8 {
        REALLOC_REQUEST = Some((block, size, tag1, tag2));
        REALLOC_RESULT
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        DIAG_RING
    }

    struct ResizeFixture {
        _test_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        _realloc_guard: parking_lot::MutexGuard<'static, ()>,
        _diag_guard: MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_realloc_hooks: TracedReallocHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        ring: Box<DiagEventRing>,
    }

    impl ResizeFixture {
        fn new(alloc_result: *mut u8, realloc_result: *mut u8) -> Self {
            let test_guard = RESIZE_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let realloc_guard = TRACED_REALLOC_TEST_LOCK.lock();
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_RESULT = alloc_result;
                REALLOC_RESULT = realloc_result;
                ALLOC_REQUEST = None;
                REALLOC_REQUEST = None;
                DIAG_RING = ring.as_mut();
                let saved_alloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_realloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_REALLOC_HOOKS));
                let saved_ring_getter = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: record_alloc, trace: None },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_REALLOC_HOOKS),
                    TracedReallocHooks { realloc: record_realloc, trace: None },
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), Some(ring_getter));
                Self {
                    _test_guard: test_guard,
                    _alloc_guard: alloc_guard,
                    _realloc_guard: realloc_guard,
                    _diag_guard: diag_guard,
                    saved_alloc_hooks,
                    saved_realloc_hooks,
                    saved_ring_getter,
                    ring,
                }
            }
        }
    }

    impl Drop for ResizeFixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.saved_alloc_hooks);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_REALLOC_HOOKS),
                    self.saved_realloc_hooks,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER),
                    self.saved_ring_getter,
                );
                ALLOC_RESULT = core::ptr::null_mut();
                REALLOC_RESULT = core::ptr::null_mut();
                ALLOC_REQUEST = None;
                REALLOC_REQUEST = None;
                DIAG_RING = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn shrink_clears_only_the_discarded_suffix() {
        let mut data = [0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa];
        let _fixture = ResizeFixture::new(core::ptr::null_mut(), core::ptr::null_mut());
        let mut buffer = ZeroingBuffer { state: 5, data: data.as_mut_ptr(), byte_len: 6 };

        assert_eq!(unsafe { zeroing_buffer_resize(&mut buffer, 2) }, 2);
        assert_eq!(data, [0xa5, 0xb6, 0, 0, 0, 0xfa]);
        assert_eq!(buffer.state, 2);
        assert_eq!(buffer.byte_len, 6);
        assert!(unsafe { ALLOC_REQUEST }.is_none());
        assert!(unsafe { REALLOC_REQUEST }.is_none());
    }

    #[test]
    fn growth_within_capacity_clears_only_newly_exposed_bytes() {
        let mut data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let _fixture = ResizeFixture::new(core::ptr::null_mut(), core::ptr::null_mut());
        let mut buffer = ZeroingBuffer { state: 3, data: data.as_mut_ptr(), byte_len: 8 };

        assert_eq!(unsafe { zeroing_buffer_resize(&mut buffer, 6) }, 6);
        assert_eq!(data, [0x11, 0x22, 0x33, 0, 0, 0, 0x77, 0x88]);
        assert_eq!(buffer.state, 6);
        assert_eq!(buffer.byte_len, 8);
        assert!(unsafe { ALLOC_REQUEST }.is_none());
        assert!(unsafe { REALLOC_REQUEST }.is_none());
    }

    #[test]
    fn empty_buffer_allocates_rounded_capacity_before_clearing_growth() {
        let mut data = [0xa5; 12];
        let fixture = ResizeFixture::new(data.as_mut_ptr(), core::ptr::null_mut());
        let mut buffer = ZeroingBuffer { state: 0, data: core::ptr::null_mut(), byte_len: 0 };

        assert_eq!(unsafe { zeroing_buffer_resize(&mut buffer, 4) }, 4);
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((8, 0, 0)));
        assert!(unsafe { REALLOC_REQUEST }.is_none());
        assert_eq!(buffer.data, data.as_mut_ptr());
        assert_eq!(buffer.state, 4);
        assert_eq!(buffer.byte_len, 8);
        assert_eq!(&data[..5], &[0, 0, 0, 0, 0xa5]);
        assert_eq!(fixture.ring.head, 0);
    }

    #[test]
    fn reallocation_replaces_payload_and_clears_new_delta() {
        let mut old_data = [0x11; 4];
        let mut replacement = [0x5a; 12];
        let _fixture = ResizeFixture::new(core::ptr::null_mut(), replacement.as_mut_ptr());
        let mut buffer = ZeroingBuffer { state: 2, data: old_data.as_mut_ptr(), byte_len: 4 };

        assert_eq!(unsafe { zeroing_buffer_resize(&mut buffer, 7) }, 7);
        assert_eq!(
            unsafe { REALLOC_REQUEST },
            Some((old_data.as_mut_ptr(), 12, 0, 0)),
        );
        assert!(unsafe { ALLOC_REQUEST }.is_none());
        assert_eq!(buffer.data, replacement.as_mut_ptr());
        assert_eq!(buffer.state, 7);
        assert_eq!(buffer.byte_len, 12);
        assert_eq!(&replacement[..8], &[0x5a, 0x5a, 0, 0, 0, 0, 0, 0x5a]);
    }

    #[test]
    fn failed_growth_records_diagnostic_without_mutating_the_record() {
        let fixture = ResizeFixture::new(core::ptr::null_mut(), core::ptr::null_mut());
        let mut buffer = ZeroingBuffer { state: 0, data: core::ptr::null_mut(), byte_len: 0 };

        assert_eq!(unsafe { zeroing_buffer_resize(&mut buffer, 1) }, 0);
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((4, 0, 0)));
        assert!(unsafe { REALLOC_REQUEST }.is_none());
        assert!(buffer.data.is_null());
        assert_eq!(buffer.state, 0);
        assert_eq!(buffer.byte_len, 0);
        assert_eq!(fixture.ring.head, 1);
        assert_eq!(fixture.ring.tags[1], 0x0706_4041);
        assert_eq!(fixture.ring.data0[1], 0);
        assert_eq!(fixture.ring.data1[1], 0);
    }
}
