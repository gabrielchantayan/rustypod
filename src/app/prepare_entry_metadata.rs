//! Prepare an entry's metadata and extract its two result words.
//!
//! - `prepare_entry_metadata` — original: `FUN_080fe480` @ 0x080fe480
//!   (68 bytes; 3 direct `bl` call sites, 0 predicated BL, 0 plain-`b`
//!   tail callers, verified by decoding every B/BL word in `osos.dec`).

const TARGET_OFFSET: usize = 0x14;
const RETAIL_PREPARE_METADATA: usize = 0x0805_1470;
const RETAIL_EXTRACT_METADATA: usize = 0x0805_1420;

type PrepareMetadata = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;
type ExtractMetadata = unsafe extern "C" fn(*mut u8, *mut u32, *mut u32) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn prepare_metadata(metadata: *mut u8, scratch: *mut u8) -> i32 {
    unsafe { core::mem::transmute::<usize, PrepareMetadata>(RETAIL_PREPARE_METADATA)(metadata, scratch) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn extract_metadata(metadata: *mut u8, first: *mut u32, second: *mut u32) -> i32 {
    unsafe { core::mem::transmute::<usize, ExtractMetadata>(RETAIL_EXTRACT_METADATA)(metadata, first, second) }
}

#[cfg(all(not(target_os = "none"), test))]
static mut PREPARE_METADATA: Option<PrepareMetadata> = None;
#[cfg(all(not(target_os = "none"), test))]
static mut EXTRACT_METADATA: Option<ExtractMetadata> = None;

#[cfg(all(not(target_os = "none"), test))]
#[inline(always)]
unsafe fn prepare_metadata(metadata: *mut u8, scratch: *mut u8) -> i32 {
    unsafe { PREPARE_METADATA.expect("test prepare seam")(metadata, scratch) }
}

#[cfg(all(not(target_os = "none"), test))]
#[inline(always)]
unsafe fn extract_metadata(metadata: *mut u8, first: *mut u32, second: *mut u32) -> i32 {
    unsafe { EXTRACT_METADATA.expect("test extract seam")(metadata, first, second) }
}

/// prepare_entry_metadata — original: `FUN_080fe480` @ 0x080fe480 (68 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x080fe480..0x080fe4c4`;
/// `ldr r0,[r0,#4]; bx lr` at `0x080fe4c4` begins the next function. The
/// function saves its three non-self arguments, calls retailOS `0x08051470`
/// with the self object's +0x14 metadata pointer and `scratch`, then—only on
/// success—calls retailOS `0x08051420` with that pointer and the two output
/// pointers.
///
/// Algorithm: return one exactly when both operations return zero; otherwise
/// return zero. Call sites: 3 unconditional `bl` (0x0821097c, 0x082115f0,
/// 0x082c8094), zero predicated `bl`. Deliberate deviations: the two verified
/// retailOS callees remain direct ARM-target seams because neither is ported.
///
/// # Safety
///
/// `owner` must be readable through +0x17 and contain a valid metadata
/// pointer at +0x14. `scratch`, `first`, and `second` have the contracts of
/// the respective retailOS callees.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.prepare_entry_metadata")]
pub unsafe extern "C" fn prepare_entry_metadata(
    owner: *const u8,
    first: *mut u32,
    scratch: *mut u8,
    second: *mut u32,
) -> u32 {
    let metadata = unsafe { owner.add(TARGET_OFFSET).cast::<*mut u8>().read() };
    if unsafe { prepare_metadata(metadata, scratch) } != 0 {
        return 0;
    }
    (unsafe { extract_metadata(metadata, first, second) } == 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PREPARE_STATUS: i32 = 0;
    static mut EXTRACT_STATUS: i32 = 0;
    static mut CALLS: [usize; 5] = [0; 5];

    unsafe extern "C" fn prepare(metadata: *mut u8, scratch: *mut u8) -> i32 {
        unsafe {
            CALLS[0] += 1;
            CALLS[1] = metadata as usize;
            CALLS[2] = scratch as usize;
            PREPARE_STATUS
        }
    }

    unsafe extern "C" fn extract(metadata: *mut u8, first: *mut u32, second: *mut u32) -> i32 {
        unsafe {
            CALLS[3] = metadata as usize;
            CALLS[4] += 1;
            assert_eq!(first as usize, 0x1111_2222);
            assert_eq!(second as usize, 0x3333_4444);
            EXTRACT_STATUS
        }
    }

    fn reset(prepare_status: i32, extract_status: i32) {
        unsafe {
            PREPARE_METADATA = Some(prepare);
            EXTRACT_METADATA = Some(extract);
            PREPARE_STATUS = prepare_status;
            EXTRACT_STATUS = extract_status;
            CALLS = [0; 5];
        }
    }

    #[test]
    fn only_succeeds_when_both_metadata_operations_succeed() {
        let _guard = TEST_LOCK.lock();
        let mut owner = [0u32; 6];
        owner[TARGET_OFFSET / 4] = 0x5566_7788;

        for (prepare_status, extract_status, expected) in [(0, 0, 1), (-1, 0, 0), (0, 1, 0)] {
            reset(prepare_status, extract_status);
            assert_eq!(unsafe {
                prepare_entry_metadata(
                    owner.as_ptr().cast(),
                    0x1111_2222usize as *mut u32,
                    0x99aa_bbccusize as *mut u8,
                    0x3333_4444usize as *mut u32,
                )
            }, expected);
            unsafe {
                assert_eq!(CALLS[0], 1);
                assert_eq!(CALLS[1], 0x5566_7788);
                assert_eq!(CALLS[2], 0x99aa_bbcc);
                assert_eq!(CALLS[3], if prepare_status == 0 { 0x5566_7788 } else { 0 });
                assert_eq!(CALLS[4], if prepare_status == 0 { 1 } else { 0 });
            }
        }
    }
}
