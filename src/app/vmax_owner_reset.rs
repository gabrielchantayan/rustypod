//! Reset the owner receiving the `VMax` message family.
//!
//! Original FUN_081b12d0 @ 0x081b12d0: true extent 160 bytes, comprising
//! 140 instruction bytes and 20 literal bytes; next function is 0x081b1370.
//! Raw A32 scan: two inbound plain BLs (0x081b141c, 0x081b1ab4), no
//! predicated BLs. Body: two plain BLs, no predicated BLs, three virtual BLXs,
//! and a tail B to 0x081b19ec. Set byte 0x089cfd64 to one; dispatch vtable
//! +0x58 with (0x564d6178, 0x6d0d/0x6d0e/0x6d08), reloading the vtable
//! each time; dispose then clear the embedded container at +0x58; reset
//! +0x84 and byte +0x88, then the five fields written by the tail target.
//!
//! Deviations: inline the verified five-store tail target (not yet registered
//! in names.yaml), rather than invent a callee seam. Host operations model
//! firmware dispatch/global storage without truncating native pointers.

#[cfg(target_os = "none")]
extern "C" {
    fn observable_array_clear(this: *mut crate::cxx::observable_array::ObservableArray);
}

#[cfg(not(target_os = "none"))]
pub struct VmaxOwnerResetOps {
    pub flag: *mut u8,
    pub dispatch: unsafe fn(*mut u32, u32, u32),
    pub dispose: unsafe fn(*mut u8),
    pub clear: unsafe fn(*mut u8),
}

/// # Safety
/// `owner` must be writable word-aligned storage through +0xa3 with valid
/// virtual message and embedded-container methods. Host operations must model
/// those methods and supply writable flag storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vmax_owner_reset(
    owner: *mut u32,
    #[cfg(not(target_os = "none"))] ops: &VmaxOwnerResetOps,
) {
    #[cfg(target_os = "none")]
    (0x089c_fd64 as *mut u8).write_volatile(1);
    #[cfg(not(target_os = "none"))]
    ops.flag.write_volatile(1);

    for message in [0x6d0d, 0x6d0e, 0x6d08] {
        #[cfg(target_os = "none")]
        {
            let vtable = owner.read_volatile() as *const u32;
            let dispatch: unsafe extern "C" fn(*mut u32, u32, u32) =
                core::mem::transmute(vtable.add(0x58 / 4).read_volatile());
            dispatch(owner, 0x564d_6178, message);
        }
        #[cfg(not(target_os = "none"))]
        (ops.dispatch)(owner, 0x564d_6178, message);
    }
    let array = owner.add(0x58 / 4).cast::<u8>();
    #[cfg(target_os = "none")]
    {
        crate::cxx::container_dispose_elements::container_dispose_elements(array);
        observable_array_clear(array.cast());
    }
    #[cfg(not(target_os = "none"))]
    {
        (ops.dispose)(array);
        (ops.clear)(array);
    }
    owner.add(0x84 / 4).write_volatile(0);
    owner.cast::<u8>().add(0x88).write_volatile(0);
    owner.add(0x8c / 4).write_volatile(u32::MAX);
    owner.add(0x90 / 4).write_volatile(0);
    owner.add(0x9c / 4).write_volatile(u32::MAX);
    owner.add(0x98 / 4).write_volatile(0);
    owner.add(0xa0 / 4).write_volatile(u32::MAX);
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe fn dispatch(owner: *mut u32, family: u32, message: u32) {
        assert_eq!(family, 0x564d_6178);
        // Message handling changes the state observed by the next dispatch.
        let stage = owner.add(1).read();
        assert_eq!(message, [0x6d0d, 0x6d0e, 0x6d08][stage as usize]);
        owner.add(1).write(stage + 1);
    }
    unsafe fn dispose(array: *mut u8) {
        let owner = array.cast::<u32>().sub(0x58 / 4);
        assert_eq!(owner.add(1).read(), 3);
        assert_eq!(owner.add(0x84 / 4).read(), 0xa5a5_a5a5);
        // Model releasing the two owned values, without clearing the length.
        assert_eq!(array.cast::<u32>().add(1).read(), 2);
        array.cast::<u32>().add(2).write(0);
        array.cast::<u32>().add(3).write(0);
    }
    unsafe fn clear(array: *mut u8) {
        assert_eq!(array.cast::<u32>().add(2).read(), 0);
        assert_eq!(array.cast::<u32>().add(3).read(), 0);
        array.cast::<u32>().add(1).write(0);
        // Reset must happen after the clear callback, not before it.
        array.cast::<u32>().sub(0x58 / 4).add(0x8c / 4).write(123);
    }
    #[test]
    fn releases_before_clear_and_preserves_unwritten_bytes() {
        let mut words = [0xa5a5_a5a5; 42];
        words[1] = 0;
        words[0x5c / 4] = 2;
        let mut flag = 0x7f;
        let ops = VmaxOwnerResetOps { flag: &mut flag, dispatch, dispose, clear };
        unsafe { vmax_owner_reset(words.as_mut_ptr(), &ops) };
        assert_eq!(flag, 1);
        let mut expected = [0xa5a5_a5a5; 42];
        expected[1] = 3;
        for offset in [0x5c, 0x60, 0x64, 0x84, 0x90, 0x98] {
            expected[offset / 4] = 0;
        }
        expected[0x88 / 4] = u32::from_ne_bytes({
            let mut bytes = 0xa5a5_a5a5u32.to_ne_bytes(); bytes[0] = 0; bytes
        });
        for offset in [0x8c, 0x9c, 0xa0] { expected[offset / 4] = u32::MAX; }
        assert_eq!(words, expected);
        words[1] = 0;
        words[0x5c / 4] = 2;
        words[0x84 / 4] = 0xa5a5_a5a5;
        unsafe { vmax_owner_reset(words.as_mut_ptr(), &ops) };
        assert_eq!(words, expected);
    }
}
