//! Record descriptor packing for the retailOS record query engine.
//!
//! `record_descriptor_pack` — original: `FUN_080433b0` @ 0x080433b0 (148
//! bytes, 0x080433b0..0x08043444; the next separately linked function
//! begins at 0x08043444 with `stmdb sp!,{r4-r8,lr}`). Raw ARM has four
//! plain internal `bl` instructions and no predicated `bl`; decoding every
//! inbound ARM branch word finds five plain `bl` callers (0x080472d4,
//! 0x0804844c, 0x08051784, 0x0805c104, 0x0805c178) and no predicated
//! forms.
//!
//! Writes a descriptor record at `dst`: a two-byte total-length field
//! (u16 in wide mode, a u8/u8 zero pair in byte mode), the unaligned LE
//! u32 `id` at `+2` through the ported
//! [`crate::libc::rt_unaligned::__rt_uwrite4`] (0x08031160), then a zeroed
//! counted-string slot at `+6`. When `name` is non-NULL the counted name
//! string is copied into `+6` and its payload length is folded into the
//! total: wide mode (chosen by callers when the object tag at `+2` is
//! 0x482b) copies a u16-counted UTF-16 string via the unported
//! 0x08045fb0 and adds `2 * count`; byte mode copies a u8-counted string
//! clamped to 31 via the unported 0x0806c520 and adds the copied count
//! stored at `dst + 6`.
//!
//! Deliberate deviations: both counted-string copiers stay in retailOS
//! behind volatile host-test seams (ARM builds call the fixed firmware
//! load addresses, producing `blx` through the seam pointer instead of
//! the original's direct `bl`). The u16 total-length updates use aligned
//! halfword accesses exactly like the original's `ldrh`/`strh` (an odd
//! `dst` would fault on the target, as stock).

use crate::libc::rt_unaligned::__rt_uwrite4;

/// Unported counted UTF-16 string copy @ 0x08045fb0: with a nonzero third
/// argument (always the case here) it copies `(count + 1) * 2` bytes,
/// where `count` is the u16 at `src`, i.e. the count word plus that many
/// u16 elements.
type CountedWideCopy = unsafe extern "C" fn(src: *const u8, dst: *mut u8, wide: i32);

/// Unported counted byte string copy @ 0x0806c520: stores the u8 count at
/// `src` clamped to 31 at `dst`, then copies that many bytes from
/// `src + 1` to `dst + 1`.
type CountedByteCopy = unsafe extern "C" fn(src: *const u8, dst: *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn counted_wide_copy(src: *const u8, dst: *mut u8, wide: i32) {
    let function: CountedWideCopy = unsafe { core::mem::transmute(0x0804_5fb0usize) };
    unsafe { function(src, dst, wide) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn counted_byte_copy(src: *const u8, dst: *mut u8) {
    let function: CountedByteCopy = unsafe { core::mem::transmute(0x0806_c520usize) };
    unsafe { function(src, dst) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_counted_wide_copy(_src: *const u8, _dst: *mut u8, _wide: i32) {
    panic!("record_descriptor_pack requires the 0x08045fb0 counted wide copy")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_counted_byte_copy(_src: *const u8, _dst: *mut u8) {
    panic!("record_descriptor_pack requires the 0x0806c520 counted byte copy")
}

#[cfg(not(target_os = "none"))]
pub static mut COUNTED_WIDE_COPY: CountedWideCopy = missing_counted_wide_copy;

#[cfg(not(target_os = "none"))]
pub static mut COUNTED_BYTE_COPY: CountedByteCopy = missing_counted_byte_copy;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn counted_wide_copy(src: *const u8, dst: *mut u8, wide: i32) {
    let function = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COUNTED_WIDE_COPY)) };
    unsafe { function(src, dst, wide) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn counted_byte_copy(src: *const u8, dst: *mut u8) {
    let function = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COUNTED_BYTE_COPY)) };
    unsafe { function(src, dst) }
}

/// record_descriptor_pack — original: `FUN_080433b0` @ 0x080433b0.
///
/// `wide` selects the payload encoding: nonzero packs a u16-counted
/// UTF-16 name, zero packs a u8-counted byte name. `name == NULL` emits
/// just the six-byte header with the counted slot left zero.
///
/// # Safety
///
/// `dst` must be writable for at least 8 bytes (header plus the counted
/// slot) and halfword-aligned, as on target; with a non-NULL `name` the
/// stock copiers additionally read the counted source and write its full
/// payload at `dst + 6`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_descriptor_pack(
    id: u32,
    name: *const u8,
    wide: i32,
    dst: *mut u8,
) {
    if wide != 0 {
        unsafe { (dst as *mut u16).write(6) };
        unsafe { __rt_uwrite4(dst.add(2), id) };
        unsafe { (dst.add(6) as *mut u16).write(0) };
        if name.is_null() {
            return;
        }
        unsafe { counted_wide_copy(name, dst.add(6), wide) };
        let total = unsafe { (dst as *mut u16).read() };
        let count = unsafe { (name as *const u16).read() };
        unsafe { (dst as *mut u16).write(total.wrapping_add(count.wrapping_mul(2))) };
    } else {
        unsafe { *dst = 6 };
        unsafe { *dst.add(1) = 0 };
        unsafe { __rt_uwrite4(dst.add(2), id) };
        unsafe { *dst.add(6) = 0 };
        if name.is_null() {
            return;
        }
        unsafe { counted_byte_copy(name, dst.add(6)) };
        unsafe { *dst = (*dst).wrapping_add(*dst.add(6)) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct CopyCall {
        src: usize,
        dst: usize,
        wide: i32,
    }

    static mut WIDE_CALLS: Vec<CopyCall> = Vec::new();
    static mut BYTE_CALLS: Vec<CopyCall> = Vec::new();

    /// Faithful model of the unported 0x08045fb0 (nonzero-wide path):
    /// copies the u16 count word plus that many u16 elements.
    unsafe extern "C" fn model_counted_wide_copy(src: *const u8, dst: *mut u8, wide: i32) {
        let log = &mut *core::ptr::addr_of_mut!(WIDE_CALLS);
        log.push(CopyCall {
            src: src as usize,
            dst: dst as usize,
            wide,
        });
        let count = (src as *const u16).read_unaligned() as usize;
        core::ptr::copy_nonoverlapping(src, dst, (count + 1) * 2);
    }

    /// Faithful model of the unported 0x0806c520: stores the clamped
    /// count, then copies the payload bytes.
    unsafe extern "C" fn model_counted_byte_copy(src: *const u8, dst: *mut u8) {
        let log = &mut *core::ptr::addr_of_mut!(BYTE_CALLS);
        log.push(CopyCall {
            src: src as usize,
            dst: dst as usize,
            wide: 0,
        });
        let mut count = *src as usize;
        if count > 31 {
            count = 31;
        }
        *dst = count as u8;
        core::ptr::copy_nonoverlapping(src.add(1), dst.add(1), count);
    }

    /// Restores the stock-call boundaries before another test uses them.
    struct SeamReset;

    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(COUNTED_WIDE_COPY).write(missing_counted_wide_copy);
                core::ptr::addr_of_mut!(COUNTED_BYTE_COPY).write(missing_counted_byte_copy);
            }
        }
    }

    struct SeamMocks {
        _guard: MutexGuard<'static, ()>,
        _reset: SeamReset,
    }

    fn install_seam_mocks() -> SeamMocks {
        let guard = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(WIDE_CALLS)).clear();
            (*core::ptr::addr_of_mut!(BYTE_CALLS)).clear();
            core::ptr::addr_of_mut!(COUNTED_WIDE_COPY).write(model_counted_wide_copy);
            core::ptr::addr_of_mut!(COUNTED_BYTE_COPY).write(model_counted_byte_copy);
        }
        SeamMocks {
            _guard: guard,
            _reset: SeamReset,
        }
    }

    fn wide_calls() -> Vec<CopyCall> {
        unsafe { (*core::ptr::addr_of!(WIDE_CALLS)).clone() }
    }

    fn byte_calls() -> Vec<CopyCall> {
        unsafe { (*core::ptr::addr_of!(BYTE_CALLS)).clone() }
    }

    /// Builds a u16-counted wide name: count word plus `count` u16s.
    fn wide_name(values: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(values.len() as u16).to_le_bytes());
        for &value in values {
            v.extend_from_slice(&value.to_le_bytes());
        }
        v
    }

    #[test]
    fn wide_pack_folds_doubled_count_into_total() {
        let _mocks = install_seam_mocks();
        let name = wide_name(&[0x41, 0x42, 0x43]);
        let mut dst = [0xeeu8; 32];
        unsafe { record_descriptor_pack(0xdead_beef, name.as_ptr(), 1, dst.as_mut_ptr()) };
        assert_eq!(
            u16::from_le_bytes([dst[0], dst[1]]),
            6 + 3 * 2,
            "total = 6 + 2 * u16 count"
        );
        assert_eq!(&dst[2..6], &0xdead_beefu32.to_le_bytes(), "unaligned id at +2");
        assert_eq!(
            &dst[6..6 + (3 + 1) * 2],
            &name[..],
            "counted wide payload lands at +6"
        );
        let calls = wide_calls();
        assert_eq!(
            calls,
            [CopyCall {
                src: name.as_ptr() as usize,
                dst: dst.as_mut_ptr() as usize + 6,
                wide: 1,
            }],
            "the wide copier sees (name, dst + 6, wide)"
        );
        assert!(byte_calls().is_empty(), "the byte copier is not called");
    }

    #[test]
    fn wide_pack_null_name_emits_header_only() {
        let _mocks = install_seam_mocks();
        let mut dst = [0xeeu8; 16];
        unsafe { record_descriptor_pack(7, core::ptr::null(), 1, dst.as_mut_ptr()) };
        assert_eq!(u16::from_le_bytes([dst[0], dst[1]]), 6, "total stays at the header size");
        assert_eq!(&dst[2..6], &7u32.to_le_bytes());
        assert_eq!(&dst[6..8], &[0, 0], "the counted slot is zeroed");
        assert!(wide_calls().is_empty(), "no copy happens for a NULL name");
    }

    #[test]
    fn byte_pack_folds_copied_count_into_total() {
        let _mocks = install_seam_mocks();
        let name: Vec<u8> = std::iter::once(5u8).chain(0x61..=0x65).collect();
        let mut dst = [0xeeu8; 32];
        unsafe { record_descriptor_pack(0x1122_3344, name.as_ptr(), 0, dst.as_mut_ptr()) };
        assert_eq!(dst[0], 6 + 5, "total = 6 + copied count");
        assert_eq!(dst[1], 0, "the second header byte stays zero");
        assert_eq!(&dst[2..6], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&dst[6..12], &name[..], "clamped counted byte payload lands at +6");
        assert_eq!(byte_calls().len(), 1);
        assert!(wide_calls().is_empty(), "the wide copier is not called");
    }

    #[test]
    fn byte_pack_clamps_long_names_to_31() {
        let _mocks = install_seam_mocks();
        let name: Vec<u8> = std::iter::once(0x7fu8).chain((0..40).map(|i| i as u8)).collect();
        let mut dst = [0xeeu8; 64];
        unsafe { record_descriptor_pack(0, name.as_ptr(), 0, dst.as_mut_ptr()) };
        assert_eq!(dst[6], 31, "the stock copier clamps the count to 31");
        assert_eq!(dst[0], 6 + 31, "the fold uses the clamped count stored at +6");
        assert_eq!(&dst[7..7 + 31], &name[1..32]);
    }

    #[test]
    fn byte_pack_null_name_emits_header_only() {
        let _mocks = install_seam_mocks();
        let mut dst = [0xeeu8; 16];
        unsafe { record_descriptor_pack(9, core::ptr::null(), 0, dst.as_mut_ptr()) };
        assert_eq!(&dst[0..2], &[6, 0]);
        assert_eq!(&dst[2..6], &9u32.to_le_bytes());
        assert_eq!(dst[6], 0);
        assert!(byte_calls().is_empty(), "no copy happens for a NULL name");
    }

    #[test]
    fn wide_total_wraps_as_u16() {
        let _mocks = install_seam_mocks();
        // 0x8000 u16 elements: 6 + 2 * 0x8000 wraps to 6 in the u16 field.
        let mut name = std::vec![0u8; 2 + 0x8000 * 2];
        name[0..2].copy_from_slice(&0x8000u16.to_le_bytes());
        let mut dst = [0u8; 6 + 2 + 0x8000 * 2];
        unsafe { record_descriptor_pack(0, name.as_ptr(), 1, dst.as_mut_ptr()) };
        assert_eq!(u16::from_le_bytes([dst[0], dst[1]]), 6, "the fold is u16 arithmetic");
    }
}
