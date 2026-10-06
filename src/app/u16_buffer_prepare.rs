//! Locked u16-buffer preparation, `FUN_0816f388` @ 0x0816f388.
//! Raw A32 extent [0x0816f388, 0x0816f3d0): 72 bytes; the next word
//! starts a distinct push prologue. Two inbound plain BLs (0x081319f4,
//! 0x08132810), four outbound plain BLs, zero predicated BLs, and one
//! tail B to mutex_unlock_counted. Lock owner+0x5c, clear the vector at
//! owner+0x68, reserve total / (width << 1) u16 elements, then unlock.
//! The shift wraps at 32 bits; division uses the existing ADS divide port.
//! Resident vector helpers are clear @ 0x083e6cd0 and reserve @ 0x083e6d24,
//! verified from raw words, not Ghidra's misleading clear-loop rendering.
//!
//! Deliberate deviations: repr(C) native pointers keep fields disjoint on
//! hosts; target offsets remain 0x5c and 0x68. Host vector operations are
//! explicitly supplied; target operations call the resident helpers.

use crate::kernel::sync_mutex::{CountedMutex, mutex_lock_counted, mutex_unlock_counted};
use crate::runtime::rt_div::__rt_udiv;

#[repr(C)]
pub struct U16Buffer {
    pub begin: *mut u16,
    pub end: *mut u16,
    pub capacity_end: *mut u16,
}

#[repr(C)]
pub struct U16BufferOwner {
    pub prefix: [u32; 23],
    pub lock: CountedMutex,
    pub buffer: U16Buffer,
}

#[derive(Clone, Copy)]
pub struct U16BufferOps {
    pub clear: unsafe extern "C" fn(*mut U16Buffer),
    pub reserve: unsafe extern "C" fn(*mut U16Buffer, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clear(_: *mut U16Buffer) { panic!("install u16 vector clear operation") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reserve(_: *mut U16Buffer, _: u32) { panic!("install u16 vector reserve operation") }
#[cfg(not(target_os = "none"))]
pub static mut U16_BUFFER_OPS: U16BufferOps = U16BufferOps {
    clear: missing_clear, reserve: missing_reserve,
};

/// Clear and reserve the embedded vector under its counted mutex.
///
/// # Safety
/// Owner must contain a live mutex and a valid resident u16 vector. Host
/// callers must install vector operations and serialize their replacement.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn u16_buffer_prepare(owner: *mut U16BufferOwner, total: u32, width: u32) {
    #[cfg(target_os = "none")]
    let ops = U16BufferOps {
        clear: core::mem::transmute(0x083e_6cd0usize),
        reserve: core::mem::transmute(0x083e_6d24usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(U16_BUFFER_OPS).read();
    prepare(owner, total, width, ops);
}

unsafe fn prepare(owner: *mut U16BufferOwner, total: u32, width: u32, ops: U16BufferOps) {
    let lock = core::ptr::addr_of_mut!((*owner).lock);
    let buffer = core::ptr::addr_of_mut!((*owner).buffer);
    mutex_lock_counted(lock);
    (ops.clear)(buffer);
    let capacity = __rt_udiv(total, width.wrapping_shl(1));
    (ops.reserve)(buffer, capacity);
    mutex_unlock_counted(lock);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    // Host model of clear/reserve, with a preallocated 64-element arena.
    // Clear must precede reserve: otherwise the growth floor is old_len+32.
    unsafe extern "C" fn clear(buffer: *mut U16Buffer) {
        (*buffer).end = (*buffer).begin;
    }
    unsafe extern "C" fn reserve(buffer: *mut U16Buffer, requested: u32) {
        let b = &mut *buffer;
        let capacity = b.capacity_end.offset_from(b.begin) as u32;
        if capacity < requested {
            let len = b.end.offset_from(b.begin) as u32;
            let grown = (len + 32).max(len + (len >> 1) + (len >> 3)).max(requested);
            assert!(grown <= 64);
            b.capacity_end = b.begin.add(grown as usize);
        }
    }

    #[test]
    fn clears_before_growth_and_preserves_existing_capacity_and_contents() {
        for (total, width, expected) in [(0, 1, 8), (15, 1, 8), (19, 1, 32),
            (129, 2, 32), (130, 2, 32), (256, 2, 64),
            (u32::MAX, u32::MAX, 8), (19, 0x8000_0001, 32)] {
            let mut storage = [0x1234u16; 64];
            let begin = storage.as_mut_ptr();
            let mut owner = U16BufferOwner {
                prefix: [0xa5a5_a5a5; 23],
                lock: CountedMutex { mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
                    hold_count: u32::MAX },
                buffer: U16Buffer { begin, end: unsafe { begin.add(7) },
                    capacity_end: unsafe { begin.add(8) } },
            };
            unsafe { prepare(&mut owner, total, width, U16BufferOps { clear, reserve }) };
            assert_eq!(owner.buffer.end, begin);
            assert_eq!(unsafe { owner.buffer.capacity_end.offset_from(begin) }, expected);
            assert_eq!(owner.lock.hold_count, u32::MAX);
            assert_eq!(owner.prefix, [0xa5a5_a5a5; 23]);
            assert_eq!(storage, [0x1234; 64]);
        }
    }
}
