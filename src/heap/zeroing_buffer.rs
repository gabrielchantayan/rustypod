//! Zeroing buffer ownership and destruction.
//!
//! The target-layout [`ZeroingBuffer`] is a three-word owning record. Its
//! first word is retained without interpretation; destruction only consumes
//! the allocation and byte-count words.

use crate::drivers::ata_cmd::{traced_alloc, traced_free};
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::iram_veneers::iram_memzero_veneer;

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
