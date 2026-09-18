//! `u32_window_reader` — original: `FUN_081c3960` @ `0x081c3960`.
//!
//! Raw `osos.dec` establishes the exact 136-byte extent
//! `0x081c3960..0x081c39e7`; `0x081c39e8` begins the next function with its
//! own push prologue. Whole-image A32 decoding finds four incoming plain `bl`
//! calls and no predicated `bl` calls. The body contains one direct plain `bl`
//! (to the unnamed byte-swap helper at `0x080743b8`) and two indirect `blx`
//! virtual calls.
//!
//! The receiver stored at `owner + 8` first receives its unknown vtable slot
//! `+0x14` with the caller's output and 64-bit source offset. If it returns
//! zero, slot `+0x10` reads `word_count * 4` bytes in mode 2. A successful read
//! byte-swaps every output word; either virtual failure returns retailOS status
//! 3. Deliberate deviation: `0x080743b8` has no established `names.yaml`
//! identity, so Rust uses `u32::swap_bytes` rather than creating a seam.

/// Target object whose `+0x08` word is the window reader receiver.
#[repr(C)]
pub struct U32WindowReadOwner {
    pub unresolved_00_to_07: [u32; 2],
    pub reader: *mut U32WindowReader,
}

/// ABI shared by the two unrecovered reader vtable slots.
pub type U32WindowReadSlot = unsafe extern "C" fn(*mut U32WindowReader, *mut u32, u32, u32, u32) -> u32;

/// Vtable fields used by [`u32_window_reader`].
///
/// On the target the slots are at `+0x10` and `+0x14`. Native pointers are
/// wider, so this host representation names slots rather than asserting their
/// host byte offsets.
#[repr(C)]
pub struct U32WindowReaderVtable {
    pub unresolved_00_to_0f: [u32; 4],
    pub read_slot_10: U32WindowReadSlot,
    pub prepare_slot_14: U32WindowReadSlot,
}

/// Reader receiver stored through [`U32WindowReadOwner::reader`].
#[repr(C)]
pub struct U32WindowReader {
    pub vtable: *const U32WindowReaderVtable,
}

/// Reads a window of big-endian words through the receiver at `owner + 8`.
///
/// # Safety
/// `owner` must contain a valid reader at `+0x08`; `output` must have at least
/// `word_count` writable words and both vtable slots must accept the recovered
/// five-argument ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_window_reader(
    owner: *mut U32WindowReadOwner,
    output: *mut u32,
    source_offset_lo: u32,
    source_offset_hi: u32,
    word_count: u32,
) -> u32 {
    let reader = unsafe { (*owner).reader };
    let vtable = unsafe { &*(*reader).vtable };
    if unsafe { (vtable.prepare_slot_14)(reader, output, source_offset_lo, source_offset_hi, 0) } != 0 {
        return 3;
    }
    if unsafe { (vtable.read_slot_10)(reader, output, word_count.wrapping_mul(4), 2, 0) } == 0 {
        for index in 0..word_count as usize {
            unsafe { *output.add(index) = (*output.add(index)).swap_bytes() };
        }
        0
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PREPARE: Option<(u32, u32, u32, u32)> = None;
    static mut READ: Option<(u32, u32, u32, u32)> = None;
    static mut PREPARE_RESULT: u32 = 0;
    static mut READ_RESULT: u32 = 0;

    unsafe extern "C" fn prepare(_reader: *mut U32WindowReader, output: *mut u32, lo: u32, hi: u32, zero: u32) -> u32 {
        unsafe { PREPARE = Some((output as usize as u32, lo, hi, zero)); PREPARE_RESULT }
    }

    unsafe extern "C" fn read(_reader: *mut U32WindowReader, output: *mut u32, bytes: u32, mode: u32, zero: u32) -> u32 {
        unsafe { READ = Some((output as usize as u32, bytes, mode, zero)); READ_RESULT }
    }

    fn vtable() -> U32WindowReaderVtable {
        U32WindowReaderVtable { unresolved_00_to_0f: [0; 4], read_slot_10: read, prepare_slot_14: prepare }
    }

    #[test]
    fn swaps_words_only_after_both_slots_succeed() {
        let _guard = LOCK.lock();
        unsafe { PREPARE = None; READ = None; PREPARE_RESULT = 0; READ_RESULT = 0 };
        let vtable = vtable();
        let mut reader = U32WindowReader { vtable: &vtable };
        let mut owner = U32WindowReadOwner { unresolved_00_to_07: [0; 2], reader: &mut reader };
        let mut words = [0x4433_2211, 0x0000_0000, 0xddcc_bbaa];
        assert_eq!(unsafe { u32_window_reader(&mut owner, words.as_mut_ptr(), 0x1234, 7, 3) }, 0);
        assert_eq!(unsafe { PREPARE.map(|(_, lo, hi, zero)| (lo, hi, zero)) }, Some((0x1234, 7, 0)));
        assert_eq!(unsafe { READ.map(|(_, bytes, mode, zero)| (bytes, mode, zero)) }, Some((12, 2, 0)));
        assert_eq!(words, [0x1122_3344, 0, 0xaabb_ccdd]);
    }

    #[test]
    fn failure_skips_read_or_swap() {
        let _guard = LOCK.lock();
        let vtable = vtable();
        let mut reader = U32WindowReader { vtable: &vtable };
        let mut owner = U32WindowReadOwner { unresolved_00_to_07: [0; 2], reader: &mut reader };
        let mut words = [0x4433_2211];
        unsafe { PREPARE = None; READ = None; PREPARE_RESULT = 1; READ_RESULT = 0 };
        assert_eq!(unsafe { u32_window_reader(&mut owner, words.as_mut_ptr(), 0, 0, 1) }, 3);
        assert_eq!(unsafe { READ }, None);
        assert_eq!(words, [0x4433_2211]);
        unsafe { PREPARE_RESULT = 0; READ_RESULT = 1; READ = None };
        assert_eq!(unsafe { u32_window_reader(&mut owner, words.as_mut_ptr(), 0, 0, 1) }, 3);
        assert!(unsafe { READ.is_some() });
        assert_eq!(words, [0x4433_2211]);
    }
}
