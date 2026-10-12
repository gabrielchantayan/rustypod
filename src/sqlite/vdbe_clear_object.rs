//! Clear a VDBE's owned execution state.
//!
//! RetailOS `FUN_08044c78` @ `0x08044c78`, 196 bytes, extent
//! `[0x08044c78,0x08044d3c)`; the successor has an independent PUSH prologue.
//! Whole-image raw ARM decoding finds two inbound plain BLs (0x08386d38,
//! 0x0838cbdc), six outbound plain BLs, and no predicated BLs in either set.
//! Close cursors, replace the low five flag bits of registers 1..=nMem with
//! MEM_Null, release their resources, clear the main and per-context pending
//! frame lists, free the context array and error message, then clear their
//! ownership fields. Counts are signed and reread at loop boundaries.
//! Deliberate deviations: target-width pointer words preserve retail offsets
//! on hosts; host-only free interception permits low-address fixtures without
//! allocator headers. Target builds call the verified tracked_free port.

use super::vdbe::Vdbe;
use super::vdbe_close_all_cursors::vdbe_close_all_cursors;
use super::release_mem_array::release_mem_array;
use super::vdbe_frame_list_clear::vdbe_frame_list_clear;
use crate::heap::tracked::tracked_free;

#[cfg(not(target_os = "none"))]
static mut CLEAR_OBJECT_FREE: unsafe extern "C" fn(*mut u8) = tracked_free;

#[inline(always)]
unsafe fn pointer(base: *mut u8, offset: usize) -> *mut u8 {
    base.add(offset).cast::<u32>().read() as usize as *mut u8
}

#[inline(always)]
unsafe fn free_owned(payload: *mut u8) {
    #[cfg(target_os = "none")]
    tracked_free(payload);
    #[cfg(not(target_os = "none"))]
    (core::ptr::read_volatile(core::ptr::addr_of!(CLEAR_OBJECT_FREE)))(payload);
}

/// Clear execution resources; `freebuffer` is the reset caller's ABI word.
///
/// # Safety
/// `statement` must have the retail layout and own valid cursor, Mem, frame,
/// context, and error-message storage accepted by the corresponding callees.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_clear_object(statement: *mut Vdbe, freebuffer: *mut u8) {
    let base = statement.cast::<u8>();
    vdbe_close_all_cursors(statement);
    let mut register = 1i32;
    while register <= base.add(0x48).cast::<i32>().read() {
        let flags = pointer(base, 0x4c).add(register as usize * 0x28 + 0x1c).cast::<u16>();
        flags.write((flags.read() & !0x1f) | 1);
        register = register.wrapping_add(1);
    }
    release_mem_array(pointer(base, 0x4c).wrapping_add(0x28),
        base.add(0x48).cast::<i32>().read(), freebuffer as usize as i32);
    vdbe_frame_list_clear(base.add(0x58));
    if !pointer(base, 0x6c).is_null() {
        let mut context = 0i32;
        while context < base.add(0x64).cast::<i32>().read() {
            vdbe_frame_list_clear(pointer(base, 0x6c).add(context as usize * 0x18 + 0x0c));
            context = context.wrapping_add(1);
        }
        free_owned(pointer(base, 0x6c));
    }
    base.add(0x6c).cast::<u32>().write(0);
    base.add(0x68).cast::<u32>().write(0);
    base.add(0x64).cast::<u32>().write(0);
    free_owned(pointer(base, 0xf4));
    base.add(0xf4).cast::<u32>().write(0);
    base.add(0xf8).cast::<u32>().write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<usize> = LazyLock::new(||
        try_map_u32_slab(hints::VDBE_CLEAR_OBJECT, 0x1000).expect("VDBE fixture") as usize);
    static FREED: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_free(payload: *mut u8) {
        let base = *SLAB as *mut u8;
        if payload == base.add(0x800) {
            // Every context descriptor must be cleared before array release.
            for i in 0..2 {
                for word in 0..3 {
                    assert_eq!(base.add(0x800 + i * 0x18 + 0xc + word * 4).cast::<u32>().read(), 0);
                }
            }
            assert_eq!(base.add(0x64).cast::<i32>().read(), 2);
        } else {
            assert_eq!(base.add(0x6c).cast::<u32>().read(), 0);
            assert_eq!(base.add(0x64).cast::<u32>().read(), 0);
        }
        FREED.lock().push(payload as usize);
    }

    #[test]
    fn clears_registers_and_contexts_without_touching_sentinels() {
        let _guard = LOCK.lock();
        unsafe {
            let base = *SLAB as *mut u8;
            for count in [0i32, -1, 1, 3] {
                base.write_bytes(0, 0x1000);
                let mem = base.add(0x200);
                let db = base.add(0x600);
                for i in 0..5 {
                    mem.add(i * 40 + 0x10).cast::<*mut u8>().write(db);
                    mem.add(i * 40 + 0x1c).cast::<u16>().write(0x81e);
                }
                base.add(0x48).cast::<i32>().write(count);
                base.add(0x4c).cast::<u32>().write(mem as usize as u32);
                base.add(0x58).cast::<u32>().write(0x1234);
                base.add(0x60).cast::<u32>().write(0x5678);
                base.add(0x64).cast::<i32>().write(2);
                base.add(0x68).cast::<u32>().write(7);
                base.add(0x6c).cast::<u32>().write(base.add(0x800) as usize as u32);
                for i in 0..2 {
                    base.add(0x800 + i * 24).cast::<u32>().write(0xfeed);
                    base.add(0x800 + i * 24 + 12).cast::<u32>().write(9);
                    base.add(0x800 + i * 24 + 20).cast::<u32>().write(11);
                }
                base.add(0xf4).cast::<u32>().write(base.add(0x900) as usize as u32);
                base.add(0xf8).cast::<u32>().write(0xdead);
                FREED.lock().clear();
                CLEAR_OBJECT_FREE = record_free;
                vdbe_clear_object(base.cast(), core::ptr::null_mut());
                CLEAR_OBJECT_FREE = tracked_free;
                assert_eq!(*FREED.lock(), std::vec![base.add(0x800) as usize, base.add(0x900) as usize]);
                for i in 0..5 {
                    assert_eq!(mem.add(i * 40 + 0x1c).cast::<u16>().read(),
                        if i > 0 && i <= count.max(0) as usize { 1 } else { 0x81e });
                }
                for offset in [0x58, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0xf4, 0xf8] {
                    assert_eq!(base.add(offset).cast::<u32>().read(), 0);
                }
                assert_eq!(base.add(0x48).cast::<i32>().read(), count);
                assert_eq!(base.add(0x800).cast::<u32>().read(), 0xfeed);
                assert_eq!(base.add(0x818).cast::<u32>().read(), 0xfeed);
            }
            // NULL context array ignores a positive count; NULL error is freed.
            base.write_bytes(0, 0x1000);
            base.add(0x64).cast::<i32>().write(99);
            FREED.lock().clear();
            CLEAR_OBJECT_FREE = record_free;
            vdbe_clear_object(base.cast(), 1usize as *mut u8);
            CLEAR_OBJECT_FREE = tracked_free;
            assert_eq!(*FREED.lock(), std::vec![0]);
            assert_eq!(base.add(0x64).cast::<i32>().read(), 0);
        }
    }
}
