//! Grows a FreeType-backed MSB-first bit buffer's allocated byte capacity.
//!
//! `bit_buffer_ensure_capacity` — retailOS `FUN_0808ab4c` @ 0x0808ab4c.
//!
//! Raw `osos.dec` establishes the 112-byte extent from 0x0808ab4c through
//! `pop {r1-r5,pc}` at 0x0808abb8; 0x0808abbc begins the next function.
//! The body has one plain `bl`, to [`crate::ft::memory::ft_mem_realloc`] at
//! 0x082cfc3c, and no predicated `bl` calls. Three incoming plain `bl` calls
//! are verified by whole-image A32 decoding; there are no predicated incoming
//! `bl` calls.
//!
//! Algorithm: compare the requested and logical bit lengths rounded up to
//! bytes. If growth is needed, call FreeType's one-byte-item realloc with the
//! new byte capacity rounded up to eight bytes. On success store both the new
//! allocation pointer and logical bit capacity. Deliberate deviation: the host
//! signature uses `*mut FtMemory` rather than target-width `u32`; ARM ABI
//! layout remains identical.

use crate::ft::memory::{ft_mem_realloc, FtMemory};

/// Ensures `buffer` has storage for `required_bits` MSB-first bits.
///
/// `buffer[1]` is the logical capacity in bits and `buffer[2]` is its
/// target-width byte-storage pointer.
///
/// # Safety
///
/// `buffer` must point to at least three ARM words. `memory` and any storage
/// pointer in `buffer[2]` must satisfy [`ft_mem_realloc`]'s requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_buffer_ensure_capacity(
    buffer: *mut u32,
    required_bits: u32,
    memory: *mut FtMemory,
) -> i32 {
    let current_bytes = unsafe { buffer.add(1).read().wrapping_add(7) >> 3 };
    let required_bytes = required_bits.wrapping_add(7) >> 3;
    if required_bytes <= current_bytes {
        return 0;
    }

    let allocation_bytes = required_bytes.wrapping_add(7) & !7;
    let mut error = 0;
    let block = unsafe {
        ft_mem_realloc(
            memory,
            1,
            current_bytes as i32,
            allocation_bytes as i32,
            buffer.add(2).read() as usize as *mut u8,
            &mut error,
        )
    };
    unsafe { buffer.add(2).write(block as usize as u32); }
    if error == 0 {
        unsafe { buffer.add(1).write(allocation_bytes << 3); }
    }
    error
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ft::memory::{FtAllocFunc, FtFreeFunc, FtReallocFunc};
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATION: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_FAILS: bool = false;
    static mut ALLOC_SIZE: i32 = 0;

    unsafe extern "C" fn alloc(_memory: *mut FtMemory, size: i32) -> *mut u8 {
        unsafe { ALLOC_SIZE = size; if ALLOC_FAILS { core::ptr::null_mut() } else { ALLOCATION } }
    }
    unsafe extern "C" fn free(_memory: *mut FtMemory, _block: *mut u8) {}
    unsafe extern "C" fn realloc(_memory: *mut FtMemory, _old: i32, size: i32, _block: *mut u8) -> *mut u8 {
        unsafe { ALLOC_SIZE = size; if ALLOC_FAILS { core::ptr::null_mut() } else { ALLOCATION } }
    }

    fn memory() -> FtMemory {
        FtMemory { user: core::ptr::null_mut(), alloc: alloc as FtAllocFunc, free: free as FtFreeFunc, realloc: realloc as FtReallocFunc }
    }

    #[test]
    fn grows_to_an_eight_byte_boundary_and_updates_bit_capacity() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(storage) = crate::testing::try_map_u32_slab(hints::BIT_BUFFER_ENSURE_CAPACITY, 0x1000) else { return };
        unsafe {
            ALLOCATION = storage;
            ALLOC_FAILS = false;
            ALLOC_SIZE = 0;
            let mut allocator = memory();
            let mut buffer = [0, 8, storage as usize as u32];
            assert_eq!(bit_buffer_ensure_capacity(buffer.as_mut_ptr(), 65, &mut allocator), 0);
            assert_eq!(ALLOC_SIZE, 16);
            assert_eq!(buffer[1], 128);
            assert_eq!(buffer[2], storage as usize as u32);
        }
    }

    #[test]
    fn does_not_allocate_when_rounded_byte_length_already_fits() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            ALLOC_SIZE = -1;
            let mut allocator = memory();
            let mut buffer = [0, 9, 0];
            assert_eq!(bit_buffer_ensure_capacity(buffer.as_mut_ptr(), 16, &mut allocator), 0);
            assert_eq!(ALLOC_SIZE, -1);
            assert_eq!(buffer[1], 9);
        }
    }

    #[test]
    fn allocation_failure_keeps_logical_capacity_and_records_null_block() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            ALLOCATION = core::ptr::null_mut();
            ALLOC_FAILS = true;
            let mut allocator = memory();
            let mut buffer = [0, 8, 0x1234_5678];
            assert_eq!(bit_buffer_ensure_capacity(buffer.as_mut_ptr(), 9, &mut allocator), 0x40);
            assert_eq!(buffer[1], 8);
            assert_eq!(buffer[2], 0);
        }
    }
}
