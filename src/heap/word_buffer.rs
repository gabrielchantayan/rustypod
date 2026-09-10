//! `word_buffer_reserve` — reserve capacity for a growable u32 buffer.
//!
//! Original: `FUN_082b8174` @ 0x082b8174 (76 bytes exactly,
//! 0x082b8174..0x082b81c0; the next independent body starts immediately at
//! 0x082b81c0). All 27 direct callers are unconditional `bl` instructions;
//! a full decode of every ARM B/BL word in `osos.dec` found no predicated
//! `blne`/`bleq` calls.
//!
//! The three target words are `{data, len, capacity}`. When `capacity` is
//! smaller than the requested word count, the function calls the unported
//! grow/copy helper `FUN_080a7f2c`, which allocates `requested + 1` words,
//! preserves the existing `len` words, and zeroes the remainder. On success
//! it releases the old data through `traced_free`, then publishes the new
//! data word and requested capacity in that order. A failed grow leaves every
//! field untouched and returns NULL. A request no larger than capacity makes
//! no calls and returns the original object.
//!
//! Deliberate deviation: `FUN_080a7f2c` is not in `names.yaml` as ported, so
//! its direct call is an indirect, volatile hook. Firmware builds default it
//! to the stock address; host builds default to an allocation failure. The
//! old-data release is direct because `traced_free` @ 0x08043994 is ported.

use crate::drivers::ata_cmd::traced_free;

/// Target-layout header for the u32 buffer. `data` remains a target pointer
/// word rather than a host pointer so `len` and `capacity` stay at +0x04 and
/// +0x08 respectively on every build.
#[repr(C)]
pub struct WordBuffer {
    pub data: u32,
    pub len: u32,
    pub capacity: u32,
}

/// Target-layout word buffer with the adjacent marker reset by
/// [`word_buffer_reset_optional_singleton`]. All fields remain target words
/// so the layout is 16 bytes on both host and target.
#[repr(C)]
pub struct MarkedWordBuffer {
    pub data: u32,
    pub len: u32,
    pub capacity: u32,
    pub marker: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(MarkedWordBuffer, len)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(MarkedWordBuffer, capacity)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(MarkedWordBuffer, marker)];
const _: [u8; 0x10] = [0; core::mem::size_of::<MarkedWordBuffer>()];

/// The unported `FUN_080a7f2c` allocation/copy helper. It returns the new
/// data pointer as a target word pointer, or NULL without modifying `buffer`.
pub type WordBufferGrow = unsafe extern "C" fn(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_word_buffer_grow(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut u32 {
    let grow: WordBufferGrow = unsafe { core::mem::transmute(0x080a_7f2cusize) };
    unsafe { grow(buffer, requested_capacity) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_buffer_grow(
    _buffer: *mut WordBuffer,
    _requested_capacity: u32,
) -> *mut u32 {
    core::ptr::null_mut()
}

/// Hook for `FUN_080a7f2c`. It is volatile-read at the call site so LLVM
/// cannot fold the host failure stub into `word_buffer_reserve`.
#[cfg(target_os = "none")]
pub static mut WORD_BUFFER_GROW: WordBufferGrow = stock_word_buffer_grow;
#[cfg(not(target_os = "none"))]
pub static mut WORD_BUFFER_GROW: WordBufferGrow = missing_word_buffer_grow;

#[inline(always)]
unsafe fn word_buffer_grow() -> WordBufferGrow {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(WORD_BUFFER_GROW)) }
}

/// word_buffer_reserve — original: `FUN_082b8174` @ 0x082b8174 (76 bytes;
/// 27 unconditional `bl` call sites, no predicated direct calls).
///
/// Grows `buffer` to at least `requested_capacity` words. `buffer` must point
/// to the three aligned writable target words above; a nonzero `data` word
/// must be owned by the allocation family paired with `traced_free`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_buffer_reserve(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut WordBuffer {
    let capacity = unsafe { core::ptr::addr_of!((*buffer).capacity).read_volatile() };
    if capacity < requested_capacity {
        let data = unsafe { word_buffer_grow()(buffer, requested_capacity) };
        if data.is_null() {
            return core::ptr::null_mut();
        }

        let old_data = unsafe { core::ptr::addr_of!((*buffer).data).read_volatile() };
        if old_data != 0 {
            unsafe { traced_free(old_data as usize as *mut u8) };
        }
        unsafe {
            core::ptr::addr_of_mut!((*buffer).data).write_volatile(data as usize as u32);
            core::ptr::addr_of_mut!((*buffer).capacity).write_volatile(requested_capacity);
        }
    }
    buffer
}
/// marked_word_buffer_assign — original: `FUN_0803e6e8` @ 0x0803e6e8
/// (212 bytes exactly, 0x0803e6e8..0x0803e7bc; 12 direct call sites:
/// 10 unconditional `bl` and two `blne` at 0x08040330 and 0x08040a18).
///
/// Assigns the source's `len` target words and marker into `target`. It
/// returns `target` unchanged on self-assignment; otherwise, it reserves
/// source length through [`word_buffer_reserve`] when necessary, returning
/// NULL without mutation if that reserve fails. It copies full four-word
/// blocks then a one-to-three word tail, retains the target's capacity, stores
/// source length, clears the first target word for an empty source, and stores
/// the source marker. The two predicated calls are caller-side NE gates; this
/// body has no NULL guard after its pointer-equality fast path.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `target` and `source` must point to aligned, valid `MarkedWordBuffer`
/// headers. Their nonzero data words must be valid for `len` aligned u32
/// accesses. Source and target data ranges must not overlap incompatibly with
/// this forward copy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn marked_word_buffer_assign(
    target: *mut MarkedWordBuffer,
    source: *const MarkedWordBuffer,
) -> *mut MarkedWordBuffer {
    if core::ptr::eq(target, source.cast_mut()) {
        return target;
    }

    let requested_len = unsafe { core::ptr::addr_of!((*source).len).read_volatile() };
    let target_capacity = unsafe { core::ptr::addr_of!((*target).capacity).read_volatile() };
    if target_capacity < requested_len
        && unsafe { word_buffer_reserve(target.cast::<WordBuffer>(), requested_len) }.is_null()
    {
        return core::ptr::null_mut();
    }

    let source_data = unsafe { core::ptr::addr_of!((*source).data).read_volatile() as usize as *const u32 };
    let source_len = unsafe { core::ptr::addr_of!((*source).len).read_volatile() };
    let target_data = unsafe { core::ptr::addr_of!((*target).data).read_volatile() as usize as *mut u32 };
    let mut remaining_blocks = source_len >> 2;
    let mut source_words = source_data;
    let mut target_words = target_data;
    while remaining_blocks != 0 {
        unsafe {
            target_words.write_volatile(source_words.read_volatile());
            target_words.add(1).write_volatile(source_words.add(1).read_volatile());
            target_words.add(2).write_volatile(source_words.add(2).read_volatile());
            target_words.add(3).write_volatile(source_words.add(3).read_volatile());
            source_words = source_words.add(4);
            target_words = target_words.add(4);
        }
        remaining_blocks -= 1;
    }

    match source_len & 3 {
        3 => unsafe {
            target_words.add(2).write_volatile(source_words.add(2).read_volatile());
            target_words.add(1).write_volatile(source_words.add(1).read_volatile());
            target_words.write_volatile(source_words.read_volatile());
        },
        2 => unsafe {
            target_words.add(1).write_volatile(source_words.add(1).read_volatile());
            target_words.write_volatile(source_words.read_volatile());
        },
        1 => unsafe { target_words.write_volatile(source_words.read_volatile()) },
        _ => {}
    }

    unsafe {
        core::ptr::addr_of_mut!((*target).len).write_volatile(source_len);
        if source_len == 0 && !target_data.is_null() {
            target_data.write_volatile(0);
        }
        let source_marker = core::ptr::addr_of!((*source).marker).read_volatile();
        core::ptr::addr_of_mut!((*target).marker).write_volatile(source_marker);
    }
    target
}


/// word_buffer_reset_optional_singleton — original: `FUN_0804082c` @
/// 0x0804082c (88 bytes exactly; 18 unconditional `bl` plus one `blne`
/// caller).
///
/// Resets `buffer` to either an empty buffer (`value == 0`) or a one-word
/// buffer whose first data word is `value`. If the current capacity is zero,
/// it reserves two words through [`word_buffer_reserve`]; allocation failure
/// leaves all four words unchanged and returns zero. On success it clears the
/// adjacent marker, sets `len` to zero, writes the first data word, then sets
/// `len` to one only for a nonzero value. The raw body has no NULL guard; the
/// lone predicated caller at 0x0803e9e8 gates its call with `ne`.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `buffer` must point to four aligned writable target words. Its nonzero
/// `data` word must be a valid writable `u32` target pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_buffer_reset_optional_singleton(
    buffer: *mut MarkedWordBuffer,
    value: u32,
) -> u32 {
    let capacity = unsafe { core::ptr::addr_of!((*buffer).capacity).read_volatile() };
    let reserved = if capacity >= 1 {
        buffer.cast::<WordBuffer>()
    } else {
        unsafe { word_buffer_reserve(buffer.cast::<WordBuffer>(), 2) }
    };
    if reserved.is_null() {
        return 0;
    }

    unsafe {
        core::ptr::addr_of_mut!((*buffer).marker).write_volatile(0);
        core::ptr::addr_of_mut!((*buffer).len).write_volatile(0);
        let data = core::ptr::addr_of!((*buffer).data).read_volatile() as usize as *mut u32;
        data.write_volatile(value);
        if value != 0 {
            core::ptr::addr_of_mut!((*buffer).len).write_volatile(1);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GROW_RESULT: *mut u32 = core::ptr::null_mut();
    static mut GROW_ARGS: (*mut WordBuffer, u32) = (core::ptr::null_mut(), 0);
    static mut FREED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn grow(buffer: *mut WordBuffer, requested_capacity: u32) -> *mut u32 {
        unsafe {
            GROW_ARGS = (buffer, requested_capacity);
            GROW_RESULT
        }
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        unsafe { FREED = block }
    }

    fn install() -> (MutexGuard<'static, ()>, WordBufferGrow, TracedFreeHooks) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old_grow = core::ptr::read_volatile(core::ptr::addr_of!(WORD_BUFFER_GROW));
            let old_free = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            WORD_BUFFER_GROW = grow;
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_free, trace: None };
            GROW_RESULT = core::ptr::null_mut();
            GROW_ARGS = (core::ptr::null_mut(), 0);
            FREED = core::ptr::null_mut();
            (guard, old_grow, old_free)
        }
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>, old_grow: WordBufferGrow, old_free: TracedFreeHooks) {
        unsafe {
            WORD_BUFFER_GROW = old_grow;
            TRACED_FREE_HOOKS = old_free;
        }
        drop(guard);
    }

    #[test]
    fn reserve_skips_growth_at_capacity_and_preserves_every_word() {
        let (guard, old_grow, old_free) = install();
        let mut buffer = WordBuffer { data: 0x1111_0000, len: 3, capacity: 3 };

        let result = unsafe { word_buffer_reserve(&mut buffer, 3) };

        assert_eq!(result, &mut buffer as *mut WordBuffer);
        assert_eq!((buffer.data, buffer.len, buffer.capacity), (0x1111_0000, 3, 3));
        unsafe {
            assert_eq!(GROW_ARGS, (core::ptr::null_mut(), 0));
            assert!(FREED.is_null());
            restore(guard, old_grow, old_free);
        }
    }

    #[test]
    fn reserve_failed_growth_returns_null_without_releasing_or_mutating() {
        let (guard, old_grow, old_free) = install();
        let mut buffer = WordBuffer { data: 0x2222_0000, len: 4, capacity: 4 };

        let result = unsafe { word_buffer_reserve(&mut buffer, 7) };

        assert!(result.is_null());
        assert_eq!(unsafe { GROW_ARGS }, (&mut buffer as *mut WordBuffer, 7));
        assert_eq!((buffer.data, buffer.len, buffer.capacity), (0x2222_0000, 4, 4));
        unsafe {
            assert!(FREED.is_null());
            restore(guard, old_grow, old_free);
        }
    }

    #[test]
    fn reserve_releases_old_data_then_publishes_new_data_and_capacity() {
        let (guard, old_grow, old_free) = install();
        let mut replacement = [0u32; 8];
        let mut buffer = WordBuffer { data: 0x3333_0000, len: 2, capacity: 2 };
        unsafe { GROW_RESULT = replacement.as_mut_ptr() };

        let result = unsafe { word_buffer_reserve(&mut buffer, 8) };

        assert_eq!(result, &mut buffer as *mut WordBuffer);
        assert_eq!(unsafe { GROW_ARGS }, (&mut buffer as *mut WordBuffer, 8));
        assert_eq!(unsafe { FREED }, 0x3333_0000usize as *mut u8);
        assert_eq!(buffer.data, replacement.as_mut_ptr() as usize as u32);
        assert_eq!((buffer.len, buffer.capacity), (2, 8));
        unsafe { restore(guard, old_grow, old_free) };
    }

    #[test]
    fn assign_preserves_self_capacity_and_failed_growth_then_copies_after_growth() {
        let (guard, old_grow, old_free) = install();
        let Some(slab) = try_map_u32_slab(hints::MARKED_WORD_BUFFER_ASSIGN, 0x100) else {
            unsafe { restore(guard, old_grow, old_free) };
            assert!(note_missing_u32_fixture("heap::word_buffer::marked_word_buffer_assign"));
            return;
        };
        let source_data = slab.cast::<u32>();
        let destination_data = unsafe { source_data.add(16) };
        let grown_data = unsafe { source_data.add(32) };

        unsafe {
            for (index, value) in [0x11, 0x22, 0x33, 0x44, 0x55].iter().enumerate() {
                source_data.add(index).write(*value);
            }
            destination_data.write(0xaaaa_aaaa);
            let mut source = MarkedWordBuffer {
                data: source_data as usize as u32,
                len: 5,
                capacity: 9,
                marker: 0x1234_5678,
            };
            let mut destination = MarkedWordBuffer {
                data: destination_data as usize as u32,
                len: 4,
                capacity: 5,
                marker: 0xfeed_face,
            };

            let destination_ptr = &mut destination as *mut MarkedWordBuffer;
            let self_before = (destination.data, destination.len, destination.capacity, destination.marker);
            assert_eq!(marked_word_buffer_assign(destination_ptr, destination_ptr), destination_ptr);
            assert_eq!(
                (destination.data, destination.len, destination.capacity, destination.marker),
                self_before,
            );

            assert_eq!(marked_word_buffer_assign(destination_ptr, &source), destination_ptr);
            assert_eq!(
                [
                    destination_data.read(),
                    destination_data.add(1).read(),
                    destination_data.add(2).read(),
                    destination_data.add(3).read(),
                    destination_data.add(4).read(),
                ],
                [0x11, 0x22, 0x33, 0x44, 0x55],
            );
            assert_eq!((destination.len, destination.capacity, destination.marker), (5, 5, 0x1234_5678));

            source.len = 0;
            source.marker = 0xcafe_babe;
            destination_data.write(0xffff_ffff);
            assert_eq!(marked_word_buffer_assign(destination_ptr, &source), destination_ptr);
            assert_eq!(destination_data.read(), 0);
            assert_eq!((destination.len, destination.capacity, destination.marker), (0, 5, 0xcafe_babe));

            source.len = 5;
            destination.capacity = 2;
            let failed_before = (destination.data, destination.len, destination.capacity, destination.marker);
            assert!(marked_word_buffer_assign(destination_ptr, &source).is_null());
            assert_eq!(GROW_ARGS, (destination_ptr.cast::<WordBuffer>(), 5));
            assert_eq!(
                (destination.data, destination.len, destination.capacity, destination.marker),
                failed_before,
            );

            GROW_RESULT = grown_data;
            assert_eq!(marked_word_buffer_assign(destination_ptr, &source), destination_ptr);
            assert_eq!(FREED, destination_data.cast::<u8>());
            assert_eq!(destination.data, grown_data as usize as u32);
            assert_eq!(
                [
                    grown_data.read(),
                    grown_data.add(1).read(),
                    grown_data.add(2).read(),
                    grown_data.add(3).read(),
                    grown_data.add(4).read(),
                ],
                [0x11, 0x22, 0x33, 0x44, 0x55],
            );
            assert_eq!((destination.len, destination.capacity, destination.marker), (5, 5, 0xcafe_babe));
            restore(guard, old_grow, old_free);
        }
    }

    #[test]
    fn reset_optional_singleton_preserves_failure_and_replaces_empty_or_present_value() {
        let (guard, old_grow, old_free) = install();
        let mut insufficient = MarkedWordBuffer {
            data: 0x4444_0000,
            len: 7,
            capacity: 0,
            marker: 0xfeed_face,
        };

        assert_eq!(unsafe { word_buffer_reset_optional_singleton(&mut insufficient, 0x55) }, 0);
        assert_eq!(
            unsafe { GROW_ARGS },
            ((&mut insufficient as *mut MarkedWordBuffer).cast::<WordBuffer>(), 2),
        );
        assert_eq!(
            (insufficient.data, insufficient.len, insufficient.capacity, insufficient.marker),
            (0x4444_0000, 7, 0, 0xfeed_face),
        );
        unsafe { restore(guard, old_grow, old_free) };

        let Some(data) = try_map_u32_slab(hints::WORD_BUFFER_RESET_OPTIONAL_SINGLETON, 0x100) else {
            assert!(note_missing_u32_fixture("heap::word_buffer::reset_optional_singleton"));
            return;
        };
        let data = data.cast::<u32>();
        unsafe {
            data.write(0xaaaa_aaaa);
            let mut buffer = MarkedWordBuffer {
                data: data as usize as u32,
                len: 8,
                capacity: 1,
                marker: 0xdead_beef,
            };

            assert_eq!(word_buffer_reset_optional_singleton(&mut buffer, 0), 1);
            assert_eq!(data.read(), 0);
            assert_eq!((buffer.len, buffer.capacity, buffer.marker), (0, 1, 0));

            data.write(0xbbbb_bbbb);
            buffer.len = 3;
            buffer.marker = 0xcafe_babe;
            assert_eq!(word_buffer_reset_optional_singleton(&mut buffer, 0x1234_5678), 1);
            assert_eq!(data.read(), 0x1234_5678);
            assert_eq!((buffer.len, buffer.capacity, buffer.marker), (1, 1, 0));
        }
    }
}
