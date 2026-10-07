//! Buffered text owner construction — `FUN_08152374` @ `0x08152374`.
//!
//! True extent [0x08152374, 0x081523b4): 64 bytes, comprising 60 bytes
//! of instructions and the fallback-buffer literal 0x089cc96c. The next
//! independently entered function is `bx lr` at 0x081523b4. Whole-image
//! aligned A32 decoding finds two incoming plain BLs (0x080fe0f4,
//! 0x08293550), zero predicated incoming BLs; two outgoing plain BLs,
//! zero predicated outgoing BLs.
//!
//! Initialize owned storage with capacity 0x3500 (or the retail fallback),
//! construct the embedded text buffer at +12 from storage words +4/+8,
//! then clear bytes +0x27b, +0x28f, +0x3e6 and +0x3e7 on the owner
//! returned by that constructor. Return that owner, not void. Ghidra's
//! offsets are relative to the embedded buffer and are not owner offsets.
//! No target behavioral deviations. Unported storage initialization
//! (0x08150238) and text construction (0x08123cb4) remain verified retail
//! calls. Host production calls are unsupported; tests inject reference
//! callees without changing the four-byte ARM word layout.

pub(crate) type StorageInitialize = unsafe extern "C" fn(*mut u8, u32, *mut u8) -> *mut u8;
pub(crate) type TextConstruct = unsafe extern "C" fn(*mut u8, u32, u32, u8) -> *mut u8;

#[inline(always)]
pub(crate) unsafe fn construct_with(
    owner: *mut u8, storage_initialize: StorageInitialize, text_construct: TextConstruct,
) -> *mut u8 {
    let storage = storage_initialize(owner, 0x3500, 0x089c_c96cusize as *mut u8);
    let words = storage.cast::<u32>();
    let buffer = words.add(1).read();
    let capacity = words.add(2).read();
    let owner = text_construct(storage.add(12), buffer, capacity, 0).sub(12);
    owner.add(0x27b).write(0);
    owner.add(0x28f).write(0);
    owner.add(0x3e6).write(0);
    owner.add(0x3e7).write(0);
    owner
}

/// Requires a writable aligned retail owner of at least 1000 bytes, plus
/// the firmware allocator and text-buffer runtime. NULL is not accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_text_owner_construct(owner: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        construct_with(owner, core::mem::transmute(0x0815_0238usize),
                       core::mem::transmute(0x0812_3cb4usize))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = owner;
        panic!("retail buffered text construction is unavailable on host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn initialize(owner: *mut u8, capacity: u32, fallback: *mut u8) -> *mut u8 {
        // Model the allocation-failure result, retaining ARM-width fields.
        owner.write(0);
        owner.cast::<u32>().add(1).write(fallback as usize as u32);
        owner.cast::<u32>().add(2).write(capacity);
        owner
    }

    unsafe extern "C" fn construct(text: *mut u8, buffer: u32, capacity: u32, mode: u8) -> *mut u8 {
        let words = text.cast::<u32>();
        words.write(0x0898_2fd8);
        words.add(1).write(buffer);
        words.add(2).write(capacity);
        words.add(3).write(0);
        words.add(4).write(0);
        text.add(20).write(mode);
        text
    }

    unsafe extern "C" fn construct_next(text: *mut u8, buffer: u32, capacity: u32, mode: u8) -> *mut u8 {
        construct(text.add(1000), buffer, capacity, mode)
    }

    #[test]
    fn clears_exact_owner_bytes_and_preserves_adjacent_state() {
        for seed in [0x01u8, 0xa5, 0xff] {
            let mut slab = [u32::from_ne_bytes([seed; 4]); 501];
            let base = slab.as_mut_ptr().cast::<u8>();
            let mut expected = [seed; 2004];
            expected[0] = 0;
            expected[4..8].copy_from_slice(&0x089c_c96cu32.to_ne_bytes());
            expected[8..12].copy_from_slice(&0x3500u32.to_ne_bytes());
            expected[12..16].copy_from_slice(&0x0898_2fd8u32.to_ne_bytes());
            expected[16..20].copy_from_slice(&0x089c_c96cu32.to_ne_bytes());
            expected[20..24].copy_from_slice(&0x3500u32.to_ne_bytes());
            expected[24..33].fill(0);
            for offset in [0x27b, 0x28f, 0x3e6, 0x3e7] { expected[offset] = 0; }
            unsafe {
                assert_eq!(construct_with(base, initialize, construct), base);
                assert_eq!(core::slice::from_raw_parts(base, 2004), &expected);
            }
        }
    }

    #[test]
    fn clears_and_returns_owner_selected_by_text_constructor() {
        let mut slab = [0xa5a5_a5a5u32; 501];
        let base = slab.as_mut_ptr().cast::<u8>();
        unsafe {
            let returned = construct_with(base, initialize, construct_next);
            assert_eq!(returned, base.add(1000));
            for offset in [0x27b, 0x28f, 0x3e6, 0x3e7] {
                assert_eq!(base.add(offset).read(), 0xa5);
                assert_eq!(returned.add(offset).read(), 0);
                assert_eq!(returned.add(offset - 1).read(), if offset == 0x3e7 { 0 } else { 0xa5 });
                assert_eq!(returned.add(offset + 1).read(), if offset == 0x3e6 { 0 } else { 0xa5 });
            }
        }
    }
}
