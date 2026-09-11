//! Zeroing buffer ownership and destruction.
//!
//! The target-layout [`ZeroingBuffer`] is a three-word owning record. Its
//! first word is retained without interpretation; destruction only consumes
//! the allocation and byte-count words.

use crate::drivers::ata_cmd::traced_free;
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
