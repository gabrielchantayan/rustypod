//! Owned-buffer allocation, assignment, and destruction.
//!
//! The target-layout [`OwnedBuffer`] is shared by the sibling factory
//! `four_word_record_create` @ 0x0803a488. It owns an optional NUL-terminated
//! byte allocation at +0x08, while its other three target words are retained
//! for the callers that use this small four-word record.

use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;

use crate::drivers::ata_cmd::traced_free;
use crate::drivers::ata_cmd::traced_alloc;

/// Target-layout owner allocated by the sibling factory @ 0x0803a488.
///
/// Only `data` is consumed here. The other words retain the target layout:
/// sibling code initializes word 0 to zero, stores its constructor argument
/// in word 1, and later writes word 3 after growing/copying the data.
#[repr(C)]
pub struct OwnedBuffer {
    pub length: u32,
    pub source: u32,
    pub data: *mut u8,
    pub context: u32,
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(OwnedBuffer, data)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::size_of::<OwnedBuffer>()];

/// `FUN_08043f3c` (unported): traced reallocation over the same allocator
/// family as [`traced_alloc`]. This caller passes the existing allocation,
/// `requested_length + 1` with u32 wraparound, and two zero tags.
pub type OwnedBufferRealloc =
    unsafe extern "C" fn(block: *mut u8, new_size: u32, tag1: u32, tag2: u32) -> *mut u8;

/// Fails a grow request, matching retailOS allocation failure until target
/// integration installs the still-unported `FUN_08043f3c`.
unsafe extern "C" fn missing_owned_buffer_realloc(
    _block: *mut u8,
    _new_size: u32,
    _tag1: u32,
    _tag2: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// RetailOS reallocation dependency of [`owned_buffer_assign`].
///
/// A volatile load keeps the target hook mutable and lets host tests install
/// the real grow path without adding a second implementation of the unported
/// allocator front-end.
pub static mut OWNED_BUFFER_REALLOC: OwnedBufferRealloc = missing_owned_buffer_realloc;

#[inline(always)]
unsafe fn owned_buffer_realloc() -> OwnedBufferRealloc {
    core::ptr::read_volatile(core::ptr::addr_of!(OWNED_BUFFER_REALLOC))
}

/// owned_buffer_destroy — original: `FUN_0803a2ec` @ 0x0803a2ec (36 bytes;
/// 15 `bl` + 1 `blne` direct call sites, plus one tail `b`).
///
/// Releases `owner.data` when it is non-NULL, then releases `owner`. The
/// pointer must be NULL or name a writable, aligned [`OwnedBuffer`] whose
/// non-NULL `data` is a live allocation from `traced_free`'s allocator
/// family. Neither pointer is cleared: matching the original, repeated calls
/// release the same allocations again.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_buffer_destroy(owner: *mut OwnedBuffer) {
    if owner.is_null() {
        return;
    }

    let data = (*owner).data;
    if !data.is_null() {
        traced_free(data);
    }
    traced_free(owner.cast());
}

/// owned_buffer_assign — original: `FUN_0803a3cc` @ 0x0803a3cc (188 bytes,
/// exactly 0x0803a3cc..0x0803a488; the next independently linked body starts
/// at 0x0803a488).
///
/// Raw decoding of every ARM B/BL word in `osos.dec` finds 12 direct inbound
/// calls, all unconditional `bl` (at 0x0803a2c8, 0x0805fd68, 0x0805fdf4,
/// 0x08060254, 0x08065ad0, 0x08078964, 0x0808a248, 0x0808a974, 0x080a96ac,
/// 0x082b4f54, 0x08396bf4, and 0x08396d50). A separate unconditional tail
/// `b` at 0x0803a258 is the `thunk_FUN_0803a3cc` entry. There are no
/// predicated inbound forms.
///
/// A negative `requested_length` measures the non-NULL source through the
/// unguarded retailOS `strlen`. If the signed current length is too small, or
/// the data pointer is NULL, allocates/reallocates `length + 1`; allocation
/// failure preserves the old data word and length. Success stores the new
/// length, then a non-NULL source is copied verbatim and followed by a NUL.
/// A NULL source deliberately skips both copy and terminator store.
///
/// Deliberate deviation: the still-unported traced realloc `FUN_08043f3c`
/// dispatches through [`OWNED_BUFFER_REALLOC`]; its default failure is the
/// original allocation-failure result. The port directly calls already ported
/// `traced_alloc`, `strlen`, and `__rt_memcpy`.
///
/// # Safety
/// `owner` must point to a writable, aligned [`OwnedBuffer`]. A non-NULL
/// `source` must be readable for `requested_length` bytes (or NUL-terminated
/// when that length is negative). Its copied range must not overlap the owned
/// destination. Any non-NULL old `data` must belong to the traced allocator
/// family.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_buffer_assign(
    owner: *mut OwnedBuffer,
    source: *const u8,
    requested_length: i32,
) -> u32 {
    let length = if requested_length < 0 {
        if source.is_null() {
            return 0;
        }
        strlen(source) as i32
    } else {
        requested_length
    };

    let old_data = (*owner).data;
    if ((*owner).length as i32) < length || old_data.is_null() {
        let data = if old_data.is_null() {
            traced_alloc(length.wrapping_add(1), 0, 0)
        } else {
            owned_buffer_realloc()(old_data, length.wrapping_add(1) as u32, 0, 0)
        };
        (*owner).data = data;
        if data.is_null() {
            (*owner).data = old_data;
            return 0;
        }
    }

    (*owner).length = length as u32;
    if !source.is_null() {
        __rt_memcpy((*owner).data, source, length as usize);
        (*owner).data.add(length as usize).write(0);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK,
    };
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::MutexGuard as StdMutexGuard;
    static FREED: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    static ASSIGN_TEST_LOCK: Mutex<()> = Mutex::new(());
    static ALLOC_CALLS: Mutex<std::vec::Vec<(i32, u32, u32)>> = Mutex::new(std::vec::Vec::new());
    static REALLOC_CALLS: Mutex<std::vec::Vec<(usize, u32, u32, u32)>> = Mutex::new(std::vec::Vec::new());
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_CALLS.lock().push((size, tag1, tag2));
        ALLOC_RESULT
    }

    unsafe extern "C" fn record_realloc(
        block: *mut u8,
        new_size: u32,
        tag1: u32,
        tag2: u32,
    ) -> *mut u8 {
        REALLOC_CALLS.lock().push((block as usize, new_size, tag1, tag2));
        REALLOC_RESULT
    }

    struct AssignHooksReset {
        _assign_guard: MutexGuard<'static, ()>,
        _alloc_guard: StdMutexGuard<'static, ()>,
        old_alloc: TracedAllocHooks,
        old_realloc: OwnedBufferRealloc,
    }

    impl Drop for AssignHooksReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.old_alloc);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(OWNED_BUFFER_REALLOC), self.old_realloc);
                ALLOC_RESULT = core::ptr::null_mut();
                REALLOC_RESULT = core::ptr::null_mut();
            }
        }
    }

    fn install_assign_hooks(alloc_result: *mut u8, realloc_result: *mut u8) -> AssignHooksReset {
        let assign_guard = ASSIGN_TEST_LOCK.lock();
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let old_alloc = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
            let old_realloc = core::ptr::read_volatile(core::ptr::addr_of!(OWNED_BUFFER_REALLOC));
            ALLOC_CALLS.lock().clear();
            REALLOC_CALLS.lock().clear();
            ALLOC_RESULT = alloc_result;
            REALLOC_RESULT = realloc_result;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                TracedAllocHooks { alloc: record_alloc, trace: None },
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!(OWNED_BUFFER_REALLOC), record_realloc);
            AssignHooksReset { _assign_guard: assign_guard, _alloc_guard: alloc_guard, old_alloc, old_realloc }
        }
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        FREED.lock().push(block as usize);
    }

    struct FreeHooksReset(TracedFreeHooks);

    impl Drop for FreeHooksReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.0);
            }
        }
    }

    fn destroy_and_record(owner: *mut OwnedBuffer) -> std::vec::Vec<usize> {
        let _global_free_guard = TRACED_FREE_TEST_LOCK.lock();
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)) };
        let _reset = FreeHooksReset(previous);
        FREED.lock().clear();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                TracedFreeHooks { free: record_free, trace: None },
            );
            owned_buffer_destroy(owner);
        }
        FREED.lock().clone()
    }

    #[test]
    fn null_owner_does_not_reach_the_allocator() {
        assert!(destroy_and_record(core::ptr::null_mut()).is_empty());
    }

    #[test]
    fn null_data_releases_only_the_owner() {
        let mut owner = OwnedBuffer { length: 0, source: 0, data: core::ptr::null_mut(), context: 0 };
        assert_eq!(destroy_and_record(&mut owner), [&mut owner as *mut OwnedBuffer as usize]);
    }

    #[test]
    fn data_is_released_before_its_owner() {
        let mut data = 0u8;
        let mut owner = OwnedBuffer { length: 17, source: 0xfeed_cafe, data: &mut data, context: 0x1234_5678 };
        assert_eq!(
            destroy_and_record(&mut owner),
            [&mut data as *mut u8 as usize, &mut owner as *mut OwnedBuffer as usize],
        );
    }

    #[test]
    fn negative_length_measures_then_allocates_copies_and_terminates() {
        let mut storage = [0xa5u8; 8];
        let _hooks = install_assign_hooks(storage.as_mut_ptr(), core::ptr::null_mut());
        let mut owner = OwnedBuffer { length: 99, source: 0, data: core::ptr::null_mut(), context: 0 };
        let source = b"cat\0ignored";

        assert_eq!(unsafe { owned_buffer_assign(&mut owner, source.as_ptr(), -1) }, 1);
        assert_eq!(*ALLOC_CALLS.lock(), [(4, 0, 0)]);
        assert!(REALLOC_CALLS.lock().is_empty());
        assert_eq!(owner.length, 3);
        assert_eq!(owner.data, storage.as_mut_ptr());
        assert_eq!(&storage[..4], b"cat\0");
    }

    #[test]
    fn negative_length_with_null_source_fails_without_touching_owner() {
        let mut data = [0x5au8; 2];
        let _hooks = install_assign_hooks(core::ptr::null_mut(), core::ptr::null_mut());
        let mut owner = OwnedBuffer {
            length: 7,
            source: 0xfeed_cafe,
            data: data.as_mut_ptr(),
            context: 0x1234_5678,
        };

        assert_eq!(unsafe { owned_buffer_assign(&mut owner, core::ptr::null(), -1) }, 0);
        assert!(ALLOC_CALLS.lock().is_empty());
        assert!(REALLOC_CALLS.lock().is_empty());
        assert_eq!(owner.length, 7);
        assert_eq!(owner.data, data.as_mut_ptr());
        assert_eq!(owner.source, 0xfeed_cafe);
        assert_eq!(owner.context, 0x1234_5678);
    }

    #[test]
    fn failed_realloc_preserves_the_old_data_word_and_length() {
        let mut old_data = [0x5au8; 3];
        let _hooks = install_assign_hooks(core::ptr::null_mut(), core::ptr::null_mut());
        let mut owner = OwnedBuffer { length: 2, source: 0, data: old_data.as_mut_ptr(), context: 0 };

        assert_eq!(unsafe { owned_buffer_assign(&mut owner, b"four".as_ptr(), 4) }, 0);
        assert!(ALLOC_CALLS.lock().is_empty());
        assert_eq!(*REALLOC_CALLS.lock(), [(old_data.as_mut_ptr() as usize, 5, 0, 0)]);
        assert_eq!(owner.length, 2);
        assert_eq!(owner.data, old_data.as_mut_ptr());
        assert_eq!(old_data, [0x5a; 3]);
    }

    #[test]
    fn high_bit_length_forces_signed_realloc_and_null_source_leaves_bytes_untouched() {
        let mut old_data = [0x7au8; 1];
        let mut replacement = [0x5au8; 1];
        let _hooks = install_assign_hooks(core::ptr::null_mut(), replacement.as_mut_ptr());
        let mut owner = OwnedBuffer {
            length: 0x8000_0000,
            source: 0,
            data: old_data.as_mut_ptr(),
            context: 0,
        };

        assert_eq!(unsafe { owned_buffer_assign(&mut owner, core::ptr::null(), 0) }, 1);
        assert!(ALLOC_CALLS.lock().is_empty());
        assert_eq!(*REALLOC_CALLS.lock(), [(old_data.as_mut_ptr() as usize, 1, 0, 0)]);
        assert_eq!(owner.length, 0);
        assert_eq!(owner.data, replacement.as_mut_ptr());
        assert_eq!(replacement, [0x5a], "NULL source skips the NUL store too");
    }
}
