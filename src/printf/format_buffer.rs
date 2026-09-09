//! Growable byte sink used by the legacy format-conversion family.
//!
//! Ports:
//! - `format_buffer_append_char` — `FUN_08077bcc` @ 0x08077bcc (200 bytes,
//!   0x08077bcc..0x08077c94). Binary decoding finds exactly 20 inbound `bl`
//!   call sites, all unconditional (no predicated `bl` forms): 0x080e7b0c,
//!   0x080e7b6c, 0x080e7e9c, 0x080e817c, 0x080e819c, 0x080e81c0,
//!   0x080e81e4, 0x080e8204, 0x080e8238, 0x080e8258, 0x080e82b4,
//!   0x080e9124, 0x080e9148, 0x080e915c, 0x080e9188, 0x080e91a8,
//!   0x080e91c8, 0x080e9280, 0x080e92b8, and 0x080e92ec.
//! - `retail_sprintf` — `FUN_080edc2c` @ 0x080edc2c (28 bytes), the legacy
//!   family's `sprintf` veneer. Binary decoding finds exactly 15 inbound
//!   `bl` call sites, all unconditional (no predicated forms, no tail `b`):
//!   0x0806e0cc, 0x080beed8, 0x080d34d0, 0x08112234, 0x081125cc,
//!   0x08112850, 0x08116864, 0x081168bc, 0x0812bacc, 0x081cb0ac,
//!   0x081cb0f4, 0x081eb48c, 0x081ebb5c, 0x081ef4d0, and 0x0828b73c.
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
use crate::printf::printf_api::{vsprintf, VaList};

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

/// The legacy family's unbounded `vsprintf` veneer @ 0x080f3c24 —
/// `retail_sprintf`'s only callee. It is NOT ported: decoded from the raw
/// ARM it spills r2/r3, initializes a cursor at `buf`, calls conversion
/// core 0x08077c94 as `(sink descriptor 0x0807ca58, &cursor, 0xffffffff,
/// format, args)`, NUL-terminates at the final cursor, and returns the
/// core's count untouched. Same (buf, format, args) contract as the ported
/// [`vsprintf`] @ 0x0802f654, differing only in the conversion engine.
pub type RetailVsprintfFn =
    unsafe extern "C" fn(buf: *mut u8, format: *const u8, args: VaList) -> i32;

/// Active `retail_vsprintf` for [`retail_sprintf`]. The original callee @
/// 0x080f3c24 is unported, so the wired default is the ported [`vsprintf`]
/// @ 0x0802f654 — unbounded, NUL-terminating, count-returning, differing
/// only in the conversion engine (0x08034374 family instead of the
/// unported 0x08077c94 core). Host tests replace the seam to observe the
/// forwarding contract.
pub static mut RETAIL_VSPRINTF: RetailVsprintfFn = vsprintf;

#[inline(always)]
unsafe fn retail_vsprintf() -> RetailVsprintfFn {
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_VSPRINTF))
}

/// `retail_sprintf` — original: `FUN_080edc2c` @ 0x080edc2c (28 bytes,
/// 0x080edc2c..0x080edc48; the distinct next function begins at
/// 0x080edc48, confirming Ghidra's extent for once). 15 `bl` call sites,
/// binary-scanned (see the module docs).
///
/// The legacy format-conversion family's `sprintf`: an ADS variadic
/// adapter that captures the arguments after `format` into a va_list and
/// tail-dispatches the unbounded `vsprintf` veneer @ 0x080f3c24. Raw ARM:
///
/// ```text
/// push {r0, r1, r2, r3}   ; ADS variadic spill: buf, format, arg, arg
/// push {r4, lr}
/// ldr  r1, [sp, #12]      ; r1 = the spilled `format`
/// add  r2, sp, #16        ; r2 = &spilled arg 2 — the va_list
/// bl   0x080f3c24         ; retail_vsprintf(buf, format, va)
/// pop  {r4}
/// ldr  pc, [sp], #20      ; return, dropping the variadic spill
/// ```
///
/// r0 (`buf`) passes through untouched; the callee's count survives in r0
/// across the epilogue, so the veneer returns it unchanged. There is no
/// NULL guard on any argument — the original dereferences nothing itself
/// and neither does the port. Call sites pin the shape: @ 0x0806e0a4 the
/// format literal is `"%d.%d.%d"` formatting a packed word into four
/// version bytes (three register args, one stack arg — exactly what the
/// spill plus `sp + #16` va_list models).
///
/// Deviations:
/// - The variadic `...` becomes an explicit [`VaList`] (house convention,
///   see `printf/printf_api.rs`): stable Rust cannot define C-variadic
///   functions, and `args` IS the pointer the original's spill builds.
/// - The callee @ 0x080f3c24 is not ported; the call dispatches through
///   the [`RETAIL_VSPRINTF`] seam, whose wired default is the ported
///   [`vsprintf`] @ 0x0802f654 — same unbounded, NUL-terminating,
///   count-returning contract, differing only in the conversion engine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn retail_sprintf(buf: *mut u8, format: *const u8, args: VaList) -> i32 {
    retail_vsprintf()(buf, format, args)
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

    /// Serializes tests that swap the RETAIL_VSPRINTF seam.
    static VSPRINTF_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut RECORDED_BUF: *mut u8 = core::ptr::null_mut();
    static mut RECORDED_FORMAT: *const u8 = core::ptr::null();
    static mut RECORDED_ARGS: VaList = core::ptr::null();
    static mut RECORDED_CALLS: u32 = 0;

    unsafe extern "C" fn recording_vsprintf(
        buf: *mut u8,
        format: *const u8,
        args: VaList,
    ) -> i32 {
        RECORDED_BUF = buf;
        RECORDED_FORMAT = format;
        RECORDED_ARGS = args;
        RECORDED_CALLS += 1;
        -7
    }

    struct VsprintfSeam {
        _guard: MutexGuard<'static, ()>,
        old: RetailVsprintfFn,
    }

    impl VsprintfSeam {
        fn install(stub: RetailVsprintfFn) -> Self {
            let guard = VSPRINTF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                RECORDED_CALLS = 0;
                RECORDED_BUF = core::ptr::null_mut();
                RECORDED_FORMAT = core::ptr::null();
                RECORDED_ARGS = core::ptr::null();
                let old = core::ptr::read(core::ptr::addr_of!(RETAIL_VSPRINTF));
                *core::ptr::addr_of_mut!(RETAIL_VSPRINTF) = stub;
                Self { _guard: guard, old }
            }
        }
    }

    impl Drop for VsprintfSeam {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(RETAIL_VSPRINTF) = self.old;
            }
        }
    }

    #[test]
    fn forwards_arguments_verbatim_and_propagates_the_count() {
        let _seam = VsprintfSeam::install(recording_vsprintf);
        let mut buf = [0xa5u8; 4];
        let format = b"%d.%d.%d\0".as_ptr();
        let args = [9u32, 0, 35, 4];

        let count = unsafe { retail_sprintf(buf.as_mut_ptr(), format, args.as_ptr()) };

        assert_eq!(count, -7);
        unsafe {
            assert_eq!(RECORDED_CALLS, 1);
            assert_eq!(RECORDED_BUF, buf.as_mut_ptr());
            assert_eq!(RECORDED_FORMAT, format);
            assert_eq!(RECORDED_ARGS, args.as_ptr());
        }
        // The veneer writes nothing itself; emission is the callee's job.
        assert_eq!(buf, [0xa5; 4]);
    }

    #[test]
    fn null_arguments_pass_through_without_a_guard() {
        let _seam = VsprintfSeam::install(recording_vsprintf);

        let count = unsafe {
            retail_sprintf(core::ptr::null_mut(), core::ptr::null(), core::ptr::null())
        };

        assert_eq!(count, -7);
        unsafe {
            assert_eq!(RECORDED_CALLS, 1);
            assert!(RECORDED_BUF.is_null());
            assert!(RECORDED_FORMAT.is_null());
            assert!(RECORDED_ARGS.is_null());
        }
    }

    #[test]
    fn wired_default_is_the_ported_vsprintf() {
        let _guard = VSPRINTF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(
                core::ptr::read(core::ptr::addr_of!(RETAIL_VSPRINTF)) as usize,
                vsprintf as usize
            );
        }
    }
}
