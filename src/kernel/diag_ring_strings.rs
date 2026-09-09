//! Build an owned diagnostic string from a C varargs list and attach it to
//! the current diagnostic-ring event.
//!
//! `diag_ring_attach_strings` — original: `FUN_080495d0` @ 0x080495d0
//! (192 bytes, 0x080495d0..0x08049690; next function starts at
//! 0x08049690). Binary decoding of every ARM B/BL word in `osos.dec`
//! finds **14 direct `bl` callers**, all unconditional: zero `blne`/
//! `bleq` forms. The callers use two through six string arguments; the
//! wrapper therefore preserves the original ARM varargs ABI instead of
//! imposing a fixed Rust arity.
//!
//! Algorithm:
//!
//! 1. Allocate an 81-byte (`capacity = 80`, terminator included) buffer
//!    through ported [`traced_alloc`]. Allocation failure returns silently.
//! 2. Walk exactly `count` pointers from the ARM varargs home area. NULL
//!    strings are skipped; otherwise add their unguarded [`strlen`] to the
//!    signed running length.
//! 3. When that length exceeds the signed capacity, set capacity to
//!    `length + 20`, then call the unported traced realloc
//!    `FUN_08043f3c` @ 0x08043f3c with `capacity + 1`. A NULL result frees
//!    the original buffer through ported [`traced_free`] and returns.
//! 4. Append every accepted string with the bounded `strlcat` algorithm of
//!    `FUN_0804228c` @ 0x0804228c, then hand the completed owned buffer to
//!    `FUN_08049bbc` @ 0x08049bbc with flag word 3.
//!
//! Deliberate deviations:
//!
//! - Rust cannot expose this ARM C-varargs ABI directly. The target-only
//!   assembly export spills r1-r3 beside the caller's stack arguments and
//!   calls the typed implementation; host tests pass that contiguous
//!   pointer list explicitly. This is ABI-equivalent for all arities.
//! - The realloc and attachment callees are unported and dispatch through
//!   [`DIAG_RING_STRING_OPS`]. Their defaults reproduce the useful failure
//!   behavior: realloc fails and attachment is inert. The bounded strlcat
//!   call is reproduced locally because its return value is discarded.

use crate::drivers::ata_cmd::{traced_alloc, traced_free};
use crate::libc::strlen::strlen;

// Target ABI entry point for the C-varargs original. Saving only r1-r3
// first is intentional: the word immediately after saved r3 is the first
// caller-stack argument. Saving lr after them keeps that sequence intact
// and restores 8-byte stack alignment before the `bl`.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .arm
    .section .text.diag_ring_attach_strings, "ax", %progbits
    .global diag_ring_attach_strings
    .type diag_ring_attach_strings, %function
diag_ring_attach_strings:
    push {{r1, r2, r3}}
    push {{lr}}
    add r1, sp, #4
    bl diag_ring_attach_strings_impl
    pop {{lr}}
    add sp, sp, #12
    bx lr
    .size diag_ring_attach_strings, .-diag_ring_attach_strings
"#,
);

/// Host-side typed façade for the target varargs entry point. `strings`
/// denotes the same contiguous sequence the target wrapper synthesizes:
/// r1, r2, r3, then the caller's stacked arguments.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn diag_ring_attach_strings(count: i32, strings: *const *const u8) {
    diag_ring_attach_strings_impl(count, strings);
}

/// Unported `FUN_08043f3c` @ 0x08043f3c: reallocates `block` to `size`,
/// passing the two trace tags through unchanged.
pub type DiagStringRealloc = unsafe extern "C" fn(
    block: *mut u8,
    size: i32,
    tag1: u32,
    tag2: u32,
) -> *mut u8;

/// Unported `FUN_08049bbc` @ 0x08049bbc: attaches an owned string to the
/// current diagnostic-ring slot with `flags` describing its ownership.
pub type DiagStringAttach = unsafe extern "C" fn(block: *mut u8, flags: u32);

/// Dispatches for the two unported services reached by this function.
#[derive(Copy, Clone)]
pub struct DiagRingStringOps {
    pub realloc: DiagStringRealloc,
    pub attach: DiagStringAttach,
}

unsafe extern "C" fn missing_realloc(
    _block: *mut u8,
    _size: i32,
    _tag1: u32,
    _tag2: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn missing_attach(_block: *mut u8, _flags: u32) {}

/// Active models of the two unported callees. Volatile reads preserve the
/// mutable firmware-service slots instead of letting LLVM fold the defaults.
pub static mut DIAG_RING_STRING_OPS: DiagRingStringOps = DiagRingStringOps {
    realloc: missing_realloc,
    attach: missing_attach,
};

#[inline(always)]
fn string_ops() -> DiagRingStringOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_STRING_OPS)) }
}

/// Reproduce the side effects of `FUN_0804228c`'s `strlcat(dst, src, size)`
/// call. Its length return is discarded by the original, so this helper only
/// needs the bounded destination scan, byte append, and conditional NUL.
#[inline(always)]
unsafe fn append_strlcat(mut dst: *mut u8, mut src: *const u8, mut size: u32) {
    while size != 0 && dst.read_volatile() != 0 {
        dst = dst.add(1);
        size = size.wrapping_sub(1);
    }

    while size > 1 {
        let byte = src.read_volatile();
        if byte == 0 {
            break;
        }
        dst.write_volatile(byte);
        dst = dst.add(1);
        src = src.add(1);
        size = size.wrapping_sub(1);
    }

    if size != 0 {
        dst.write_volatile(0);
    }
}

/// Typed body of [`diag_ring_attach_strings`]. It receives the string-pointer
/// sequence after `count`, directly matching the saved r1-r3/caller-stack
/// sequence traversed by the original's `ldr r9,[r7],#4` loop.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn diag_ring_attach_strings_impl(count: i32, strings: *const *const u8) {
    let mut capacity = 0x50i32;
    let mut buffer = traced_alloc(0x51, 0, 0);
    if buffer.is_null() {
        return;
    }

    buffer.write_volatile(0);
    let mut total_len = 0i32;
    let mut index = 0i32;
    while index < count {
        let string = strings.add(index as usize).read();
        if !string.is_null() {
            total_len = total_len.wrapping_add(strlen(string) as u32 as i32);
            if total_len > capacity {
                capacity = total_len.wrapping_add(0x14);
                let resized = (string_ops().realloc)(buffer, capacity.wrapping_add(1), 0, 0);
                if resized.is_null() {
                    traced_free(buffer);
                    return;
                }
                buffer = resized;
            }
            append_strlcat(buffer, string, capacity.wrapping_add(1) as u32);
        }
        index = index.wrapping_add(1);
    }

    (string_ops().attach)(buffer, 3);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
    };
    use crate::testing::{DIAG_RING_STRING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::MutexGuard as StdMutexGuard;
    use std::vec::Vec;

    static BLOCKS: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());
    static REALLOC_SIZES: Mutex<Vec<i32>> = Mutex::new(Vec::new());
    static ATTACHES: Mutex<Vec<(Vec<u8>, u32)>> = Mutex::new(Vec::new());
    static FAIL_REALLOC: Mutex<bool> = Mutex::new(false);

    unsafe extern "C" fn test_alloc(size: i32, _tag1: u32, _tag2: u32) -> *mut u8 {
        if size <= 0 {
            return core::ptr::null_mut();
        }
        let mut block = std::vec![0; size as usize].into_boxed_slice();
        let ptr = block.as_mut_ptr();
        BLOCKS.lock().push(block);
        ptr
    }

    unsafe extern "C" fn test_free(block: *mut u8) {
        let mut blocks = BLOCKS.lock();
        let index = blocks
            .iter()
            .position(|candidate| candidate.as_ptr() == block)
            .expect("traced_free must receive a live test allocation");
        blocks.remove(index);
    }

    unsafe extern "C" fn test_realloc(
        block: *mut u8,
        size: i32,
        _tag1: u32,
        _tag2: u32,
    ) -> *mut u8 {
        REALLOC_SIZES.lock().push(size);
        if *FAIL_REALLOC.lock() || size <= 0 {
            return core::ptr::null_mut();
        }

        let mut blocks = BLOCKS.lock();
        let index = blocks
            .iter()
            .position(|candidate| candidate.as_ptr() == block)
            .expect("traced realloc must receive the live allocation");
        let mut resized = std::vec![0; size as usize].into_boxed_slice();
        let copied = core::cmp::min(blocks[index].len(), resized.len());
        core::ptr::copy_nonoverlapping(blocks[index].as_ptr(), resized.as_mut_ptr(), copied);
        let ptr = resized.as_mut_ptr();
        blocks[index] = resized;
        ptr
    }

    unsafe extern "C" fn test_attach(block: *mut u8, flags: u32) {
        let mut bytes = Vec::new();
        let mut p = block;
        loop {
            let byte = p.read_volatile();
            bytes.push(byte);
            if byte == 0 {
                break;
            }
            p = p.add(1);
        }
        ATTACHES.lock().push((bytes, flags));
    }

    /// Installs a real byte-backed allocator plus recorder seams and restores
    /// every shared process-global slot on drop.
    struct Fixture {
        _string_guard: MutexGuard<'static, ()>,
        _alloc_guard: StdMutexGuard<'static, ()>,
        saved_alloc: TracedAllocHooks,
        saved_free: TracedFreeHooks,
        saved_ops: DiagRingStringOps,
    }

    impl Fixture {
        fn new() -> Self {
            let string_guard = DIAG_RING_STRING_TEST_LOCK.lock();
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            BLOCKS.lock().clear();
            REALLOC_SIZES.lock().clear();
            ATTACHES.lock().clear();
            *FAIL_REALLOC.lock() = false;

            let (saved_alloc, saved_free, saved_ops) = unsafe {
                let saved_alloc = core::ptr::read(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_free = core::ptr::read(core::ptr::addr_of!(TRACED_FREE_HOOKS));
                let saved_ops = core::ptr::read(core::ptr::addr_of!(DIAG_RING_STRING_OPS));
                core::ptr::write(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: test_alloc, trace: None },
                );
                core::ptr::write(
                    core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                    TracedFreeHooks { free: test_free, trace: None },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_STRING_OPS),
                    DiagRingStringOps { realloc: test_realloc, attach: test_attach },
                );
                (saved_alloc, saved_free, saved_ops)
            };
            Fixture { _string_guard: string_guard, _alloc_guard: alloc_guard, saved_alloc, saved_free, saved_ops }
        }

        fn attachments(&self) -> Vec<(Vec<u8>, u32)> {
            ATTACHES.lock().clone()
        }

        fn realloc_sizes(&self) -> Vec<i32> {
            REALLOC_SIZES.lock().clone()
        }

        fn live_blocks(&self) -> usize {
            BLOCKS.lock().len()
        }

        fn fail_realloc(&self) {
            *FAIL_REALLOC.lock() = true;
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    self.saved_alloc,
                );
                core::ptr::write(
                    core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                    self.saved_free,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_STRING_OPS),
                    self.saved_ops,
                );
            }
            BLOCKS.lock().clear();
        }
    }

    #[test]
    fn joins_four_spilled_strings_and_skips_nulls() {
        let fixture = Fixture::new();
        let args = [
            b"section\0".as_ptr(),
            core::ptr::null(),
            b"name\0".as_ptr(),
            b"value\0".as_ptr(),
        ];
        unsafe { diag_ring_attach_strings(4, args.as_ptr()) };

        assert_eq!(fixture.attachments(), std::vec![(b"sectionnamevalue\0".to_vec(), 3)]);
        assert!(fixture.realloc_sizes().is_empty(), "short join keeps the initial 80-byte capacity");
        assert_eq!(fixture.live_blocks(), 1, "attachment takes ownership of the allocation");
    }

    #[test]
    fn grows_at_the_strictly_greater_than_capacity_boundary() {
        let fixture = Fixture::new();
        let mut first = std::vec![b'a'; 50];
        first.push(0);
        let mut second = std::vec![b'b'; 31];
        second.push(0);
        let args = [first.as_ptr(), second.as_ptr()];
        unsafe { diag_ring_attach_strings(2, args.as_ptr()) };

        let mut expected = std::vec![b'a'; 50];
        expected.extend_from_slice(&second[..31]);
        expected.push(0);
        assert_eq!(fixture.realloc_sizes(), std::vec![102], "81 bytes of text grows capacity to 101 plus NUL");
        assert_eq!(fixture.attachments(), std::vec![(expected, 3)]);
    }

    #[test]
    fn realloc_failure_releases_the_original_buffer_without_attachment() {
        let fixture = Fixture::new();
        fixture.fail_realloc();
        let mut too_long = std::vec![b'x'; 81];
        too_long.push(0);
        let args = [too_long.as_ptr()];
        unsafe { diag_ring_attach_strings(1, args.as_ptr()) };

        assert_eq!(fixture.realloc_sizes(), std::vec![102]);
        assert!(fixture.attachments().is_empty(), "failed resize never attaches a partial string");
        assert_eq!(fixture.live_blocks(), 0, "the initial allocation is freed on resize failure");
    }

    #[test]
    fn negative_count_does_not_dereference_the_varargs_pointer() {
        let fixture = Fixture::new();
        unsafe { diag_ring_attach_strings(-1, core::ptr::null()) };

        assert_eq!(fixture.attachments(), std::vec![(b"\0".to_vec(), 3)]);
        assert!(fixture.realloc_sizes().is_empty());
    }

    #[test]
    fn allocation_failure_has_no_realloc_or_attachment_side_effect() {
        let fixture = Fixture::new();
        unsafe {
            (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = crate::drivers::ata_cmd::missing_allocator;
            diag_ring_attach_strings(0, core::ptr::null());
        }

        assert!(fixture.realloc_sizes().is_empty());
        assert!(fixture.attachments().is_empty());
        assert_eq!(fixture.live_blocks(), 0);
    }
}
