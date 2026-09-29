//! `volume_table_release_buffer` — original: `FUN_082e04fc` @ **0x082e04fc**
//! (**36 bytes**, `0x082e04fc..0x082e051f`; `0x082e0520` begins the next
//! independently entered function). Raw ARM decoding finds **2 incoming plain
//! `bl` call sites** (0x082e5e3c and 0x082e6690) and no predicated incoming
//! `bl`; the body contains one unconditional `bl` to `free` @ 0x0802edc8.
//!
//! Algorithm: if the mounted-volume table slot's owned buffer at `+0x20` is
//! non-NULL, free it and clear the slot afterwards. Deliberate deviation: the
//! Rust port calls the existing `free` port rather than the original direct
//! BL, preserving its NULL guard and host heap seam.

use crate::runtime::malloc_rt::free;

const BUFFER_OFFSET: usize = 0x20;

/// Releases and clears a mounted-volume table slot's owned buffer.
///
/// # Safety
/// `volume_slot` must be NULL or point to a retail mounted-volume table slot
/// whose `+0x20` word is an owned allocation accepted by [`free`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_table_release_buffer(volume_slot: *mut u8) {
    if volume_slot.is_null() {
        return;
    }
    let buffer = (volume_slot.add(BUFFER_OFFSET) as *const *mut u8).read();
    if !buffer.is_null() {
        free(buffer);
        (volume_slot.add(BUFFER_OFFSET) as *mut *mut u8).write(core::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::malloc_rt::{HeapOps, DEFAULT_MALLOC_RT_OPS, HEAP_OPS};
    use parking_lot::Mutex;
    use core::ptr::addr_of_mut;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static LOCK: Mutex<()> = Mutex::new(());
    static OBSERVED: Mutex<(usize, usize)> = Mutex::new((0, 0));
    static SLOT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_free(pointer: *mut u8) {
        let mut observed = OBSERVED.lock();
        observed.0 = pointer as usize;
        observed.1 = ((SLOT.load(Ordering::Relaxed) + BUFFER_OFFSET) as *const *mut u8).read() as usize;
    }

    #[test]
    fn non_null_buffer_is_freed_before_its_slot_is_cleared() {
        let _lock = LOCK.lock();
        let mut slot = [0u8; 0x24];
        let buffer = 0x1234_5678usize as *mut u8;
        unsafe {
            *OBSERVED.lock() = (0, 0);
            SLOT.store(slot.as_mut_ptr() as usize, Ordering::Relaxed);
            let mut ops: HeapOps = DEFAULT_MALLOC_RT_OPS;
            ops.free = record_free;
            addr_of_mut!(HEAP_OPS).write(ops);
            (slot.as_mut_ptr().add(BUFFER_OFFSET) as *mut *mut u8).write(buffer);
            volume_table_release_buffer(slot.as_mut_ptr());
            addr_of_mut!(HEAP_OPS).write(DEFAULT_MALLOC_RT_OPS);
        }
        assert_eq!(*OBSERVED.lock(), (buffer as usize, buffer as usize));
        assert!((unsafe { (slot.as_ptr().add(BUFFER_OFFSET) as *const *mut u8).read() }).is_null());
    }

    #[test]
    fn null_slot_and_null_buffer_do_not_free() {
        let _lock = LOCK.lock();
        let mut slot = [0u8; 0x24];
        unsafe {
            *OBSERVED.lock() = (0, 0);
            let mut ops: HeapOps = DEFAULT_MALLOC_RT_OPS;
            ops.free = record_free;
            addr_of_mut!(HEAP_OPS).write(ops);
            volume_table_release_buffer(core::ptr::null_mut());
            volume_table_release_buffer(slot.as_mut_ptr());
            addr_of_mut!(HEAP_OPS).write(DEFAULT_MALLOC_RT_OPS);
        }
        assert_eq!(*OBSERVED.lock(), (0, 0));
    }
}
