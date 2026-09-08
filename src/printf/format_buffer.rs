//! Growable byte sink used by the legacy format-conversion family.
//!
//! Port:
//! - `format_buffer_append_char` — `FUN_08077bcc` @ 0x08077bcc (200 bytes,
//!   0x08077bcc..0x08077c94). Binary decoding finds exactly 20 inbound `bl`
//!   call sites, all unconditional (no predicated `bl` forms): 0x080e7b0c,
//!   0x080e7b6c, 0x080e7e9c, 0x080e817c, 0x080e819c, 0x080e81c0,
//!   0x080e81e4, 0x080e8204, 0x080e8238, 0x080e8258, 0x080e82b4,
//!   0x080e9124, 0x080e9148, 0x080e915c, 0x080e9188, 0x080e91a8,
//!   0x080e91c8, 0x080e9280, 0x080e92b8, and 0x080e92ec.
//!
//! The sink writes `value` at `length` when `length < capacity`, then advances
//! the length. With an optional heap-pointer slot, it first grows exhausted
//! storage: an absent heap buffer is allocated at the existing capacity (or
//! 0x400 when zero), copying the active inline buffer; an existing heap buffer
//! is reallocated after adding 0x400. The copy is the ported `__rt_memcpy`
//! reached by the stock IRAM veneer at 0x08037db0.
//!
//! Deliberate deviation: stock code attempts to copy or store through a NULL
//! result from allocation/reallocation. This port preserves the capacity and
//! heap-slot stores but returns before that invalid access; the default
//! reallocation seam therefore safely models an exhausted-buffer failure.

use crate::drivers::ata_cmd::traced_alloc;
use crate::libc::rt_memcpy::__rt_memcpy;

/// Unported `FUN_08043f3c`: traced reallocation of a formatter heap buffer.
pub type FormatBufferRealloc =
    unsafe extern "C" fn(block: *mut u8, new_size: u32, tag1: u32, tag2: u32) -> *mut u8;

unsafe extern "C" fn missing_format_buffer_realloc(
    _block: *mut u8,
    _new_size: u32,
    _tag1: u32,
    _tag2: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Reallocation dependency of [`format_buffer_append_char`].
///
/// `FUN_08043f3c` is not ported. Target integration must replace this with the
/// retail allocator; its default returns NULL, preserving the sink's
/// allocation-failure result without dereferencing the NULL address.
pub static mut FORMAT_BUFFER_REALLOC: FormatBufferRealloc = missing_format_buffer_realloc;

#[inline(always)]
unsafe fn format_buffer_realloc() -> FormatBufferRealloc {
    core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_BUFFER_REALLOC))
}

/// `format_buffer_append_char` — original: `FUN_08077bcc` @ 0x08077bcc
/// (200 bytes).
///
/// `inline_buffer`, `heap_buffer`, `length`, and `capacity` are independent
/// pointer slots, not a contiguous host struct. The low byte of `value` is
/// emitted. `heap_buffer` may be NULL to make this a fixed-capacity sink.
///
/// # Safety
///
/// All non-NULL slots must be naturally aligned and valid. When a byte is
/// emitted, the selected inline/heap buffer must cover `length`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn format_buffer_append_char(
    inline_buffer: *mut *mut u8,
    heap_buffer: *mut *mut u8,
    length: *mut u32,
    capacity: *mut u32,
    value: u32,
) {
    if !heap_buffer.is_null() {
        loop {
            let current_length = length.read();
            let current_capacity = capacity.read();
            if current_length < current_capacity {
                break;
            }

            let heap = heap_buffer.read();
            if heap.is_null() {
                if current_capacity == 0 {
                    capacity.write(0x400);
                }
                let replacement = traced_alloc(capacity.read() as i32, 0, 0);
                heap_buffer.write(replacement);

                if replacement.is_null() {
                    return;
                }
                if current_length != 0 {
                    __rt_memcpy(replacement, inline_buffer.read(), current_length as usize);
                }
                inline_buffer.write(core::ptr::null_mut());
            } else {
                let new_capacity = current_capacity.wrapping_add(0x400);
                capacity.write(new_capacity);
                let replacement = format_buffer_realloc()(heap, new_capacity, 0, 0);
                heap_buffer.write(replacement);

                if replacement.is_null() {
                    return;
                }
            }
        }
    }

    let current_length = length.read();
    if capacity.read() <= current_length {
        return;
    }

    let inline = inline_buffer.read();
    length.write(current_length.wrapping_add(1));
    let output = if inline.is_null() { heap_buffer.read() } else { inline };
    output.add(current_length as usize).write(value as u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::boxed::Box;
    use std::sync::MutexGuard;

    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_CALLS: u32 = 0;
    static mut ALLOC_SIZE: i32 = 0;
    static mut REALLOC_CALLS: u32 = 0;
    static mut REALLOC_SIZE: u32 = 0;

    unsafe extern "C" fn test_alloc(size: i32, _tag1: u32, _tag2: u32) -> *mut u8 {
        ALLOC_CALLS += 1;
        ALLOC_SIZE = size;
        ALLOC_RESULT
    }

    unsafe extern "C" fn test_realloc(
        _block: *mut u8,
        new_size: u32,
        _tag1: u32,
        _tag2: u32,
    ) -> *mut u8 {
        REALLOC_CALLS += 1;
        REALLOC_SIZE = new_size;
        REALLOC_RESULT
    }

    struct Fixture {
        storage: Box<[u8; 2048]>,
        _allocator_guard: MutexGuard<'static, ()>,
        old_alloc_hooks: TracedAllocHooks,
        old_realloc: FormatBufferRealloc,
    }

    impl Fixture {
        fn new() -> Self {
            let allocator_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut storage = Box::new([0u8; 2048]);
            let storage_ptr = storage.as_mut_ptr();
            unsafe {
                ALLOC_RESULT = storage_ptr;
                REALLOC_RESULT = storage_ptr;
                ALLOC_CALLS = 0;
                ALLOC_SIZE = 0;
                REALLOC_CALLS = 0;
                REALLOC_SIZE = 0;
                let old_alloc_hooks = core::ptr::read(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let old_realloc = core::ptr::read(core::ptr::addr_of!(FORMAT_BUFFER_REALLOC));
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = test_alloc;
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).trace = None;
                *core::ptr::addr_of_mut!(FORMAT_BUFFER_REALLOC) = test_realloc;
                Self { storage, _allocator_guard: allocator_guard, old_alloc_hooks, old_realloc }
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS) = self.old_alloc_hooks;
                *core::ptr::addr_of_mut!(FORMAT_BUFFER_REALLOC) = self.old_realloc;
                ALLOC_RESULT = core::ptr::null_mut();
                REALLOC_RESULT = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn fixed_capacity_sink_emits_low_byte_without_heap_slot() {
        let mut output = [0xa5u8; 3];
        let mut inline = output.as_mut_ptr();
        let mut length = 1;
        let mut capacity = 3;

        unsafe {
            format_buffer_append_char(&mut inline, core::ptr::null_mut(), &mut length, &mut capacity, 0x1234);
        }

        assert_eq!(output, [0xa5, 0x34, 0xa5]);
        assert_eq!(length, 2);
        assert_eq!(capacity, 3);
    }

    #[test]
    fn fixed_capacity_sink_drops_full_write() {
        let mut output = [0xa5u8; 2];
        let mut inline = output.as_mut_ptr();
        let mut length = 2;
        let mut capacity = 2;

        unsafe {
            format_buffer_append_char(&mut inline, core::ptr::null_mut(), &mut length, &mut capacity, b'!'.into());
        }

        assert_eq!(output, [0xa5; 2]);
        assert_eq!(length, 2);
    }

    #[test]
    fn initial_heap_growth_copies_inline_bytes_then_reallocates_before_emitting() {
        let fixture = Fixture::new();
        let mut inline_bytes = [b'a', b'b'];
        let mut inline = inline_bytes.as_mut_ptr();
        let mut heap = core::ptr::null_mut();
        let mut length = 2;
        let mut capacity = 2;

        unsafe {
            format_buffer_append_char(&mut inline, &mut heap, &mut length, &mut capacity, b'c'.into());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, 2);
            assert_eq!(REALLOC_CALLS, 1);
            assert_eq!(REALLOC_SIZE, 0x402);
        }
        assert_eq!(heap, fixture.storage.as_ptr() as *mut u8);
        assert!(inline.is_null());
        assert_eq!(length, 3);
        assert_eq!(capacity, 0x402);
        assert_eq!(&fixture.storage[..3], b"abc");
    }

    #[test]
    fn empty_heap_starts_at_0x400_bytes() {
        let fixture = Fixture::new();
        let mut inline = core::ptr::null_mut();
        let mut heap = core::ptr::null_mut();
        let mut length = 0;
        let mut capacity = 0;

        unsafe {
            format_buffer_append_char(&mut inline, &mut heap, &mut length, &mut capacity, b'x'.into());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, 0x400);
            assert_eq!(REALLOC_CALLS, 0);
        }
        assert_eq!(heap, fixture.storage.as_ptr() as *mut u8);
        assert_eq!(length, 1);
        assert_eq!(capacity, 0x400);
        assert_eq!(fixture.storage[0], b'x');
    }

    #[test]
    fn exhausted_heap_grows_by_0x400_before_emitting() {
        let fixture = Fixture::new();
        let mut inline = core::ptr::null_mut();
        let mut heap = fixture.storage.as_ptr() as *mut u8;
        let mut length = 2;
        let mut capacity = 2;

        unsafe {
            format_buffer_append_char(&mut inline, &mut heap, &mut length, &mut capacity, b'z'.into());
            assert_eq!(REALLOC_CALLS, 1);
            assert_eq!(REALLOC_SIZE, 0x402);
        }
        assert_eq!(heap, fixture.storage.as_ptr() as *mut u8);
        assert_eq!(length, 3);
        assert_eq!(capacity, 0x402);
        assert_eq!(fixture.storage[2], b'z');
    }

    #[test]
    fn failed_reallocation_keeps_length_and_skips_the_invalid_store() {
        let mut fixture = Fixture::new();
        let mut inline = core::ptr::null_mut();
        let mut heap = fixture.storage.as_ptr() as *mut u8;
        let mut length = 2;
        let mut capacity = 2;
        fixture.storage[2] = 0xa5;

        unsafe {
            REALLOC_RESULT = core::ptr::null_mut();
            format_buffer_append_char(&mut inline, &mut heap, &mut length, &mut capacity, b'z'.into());
            assert_eq!(REALLOC_CALLS, 1);
        }
        assert!(heap.is_null());
        assert_eq!(length, 2);
        assert_eq!(capacity, 0x402);
        assert_eq!(fixture.storage[2], 0xa5);
    }
}
