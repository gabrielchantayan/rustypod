//! Refreshing clipping state for the three displayed carousel items.

use core::ptr;

const FIRST_ITEM_INDEX: usize = 1;
const ITEM_COUNT: usize = 3;
const ITEM_HANDLE_WORD: usize = 0x38 / core::mem::size_of::<u32>();
const ITEM_HORIZONTAL_WORD: usize = 0x4c / core::mem::size_of::<u32>();
const ITEM_VERTICAL_WORD: usize = 0x60 / core::mem::size_of::<u32>();
const ITEM_EXTENT: i32 = 0xb4;

/// ABI of the unported per-item clipping helper at `0x08144568`.
type RefreshItemClip = unsafe extern "C" fn(*mut u8, u32, u32, i32, i32, i32, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_refresh_item_clip(
    owner: *mut u8,
    item: u32,
    index: u32,
    horizontal: i32,
    vertical: i32,
    width: i32,
    height: i32,
) {
    let refresh: RefreshItemClip = core::mem::transmute(0x0814_4568usize);
    refresh(owner, item, index, horizontal, vertical, width, height);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh_item_clip(
    _owner: *mut u8,
    _item: u32,
    _index: u32,
    _horizontal: i32,
    _vertical: i32,
    _width: i32,
    _height: i32,
) {
    panic!("ui_refresh_three_item_clips requires item clipping helper 0x08144568")
}

#[cfg(target_os = "none")]
static mut REFRESH_ITEM_CLIP: RefreshItemClip = firmware_refresh_item_clip;
#[cfg(not(target_os = "none"))]
static mut REFRESH_ITEM_CLIP: RefreshItemClip = missing_refresh_item_clip;

#[inline(always)]
unsafe fn refresh_item_clip() -> RefreshItemClip {
    ptr::read_volatile(ptr::addr_of!(REFRESH_ITEM_CLIP))
}

/// `ui_refresh_three_item_clips` — original: `FUN_08144cb4` @ `0x08144cb4`
/// (68 bytes, exactly `0x08144cb4..0x08144cf8`; the distinct next function
/// starts at `0x08144cf8`). Six direct call sites are verified by decoding
/// every ARM B/BL word in `osos.dec`: `0x08145030`, `0x0814595c`,
/// `0x08145be4`, `0x08145f3c`, `0x08145fc0`, and `0x08146210`. All six are
/// unconditional `bl`; there are no predicated calls.
///
/// The function visits item slots 1, 2, and 3. For each, it reads the item
/// handle at `+0x38 + index*4`, horizontal coordinate at `+0x4c + index*4`,
/// and vertical coordinate at `+0x60 + index*4`, then asks the clipping helper
/// to refresh that item with its index and a fixed 180-by-180 extent.
///
/// # Deliberate deviations
///
/// The stock body issues a direct `bl 0x08144568`; Rust uses a volatile
/// dispatch seam. On firmware the seam calls that unported helper, while host
/// tests record the exact seven-argument calls.
///
/// # Safety
///
/// `owner` must point to readable, naturally aligned target-width words
/// through word 27. As in retailOS, no pointer or bounds check is performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_refresh_three_item_clips")]
#[inline(never)]
pub unsafe extern "C" fn ui_refresh_three_item_clips(owner: *mut u8) {
    let words = owner.cast::<u32>();
    for index in FIRST_ITEM_INDEX..FIRST_ITEM_INDEX + ITEM_COUNT {
        let item = words.add(ITEM_HANDLE_WORD + index).read();
        let horizontal = (words.add(ITEM_HORIZONTAL_WORD + index) as *const i32).read();
        let vertical = (words.add(ITEM_VERTICAL_WORD + index) as *const i32).read();
        refresh_item_clip()(
            owner,
            item,
            index as u32,
            horizontal,
            vertical,
            ITEM_EXTENT,
            ITEM_EXTENT,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32, i32, i32, i32, i32); ITEM_COUNT] = [(0, 0, 0, 0, 0, 0); ITEM_COUNT];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn recording_refresh(
        _owner: *mut u8,
        item: u32,
        index: u32,
        horizontal: i32,
        vertical: i32,
        width: i32,
        height: i32,
    ) {
        CALLS[CALL_COUNT] = (item, index, horizontal, vertical, width, height);
        CALL_COUNT += 1;
    }

    unsafe fn prepare() {
        REFRESH_ITEM_CLIP = recording_refresh;
        CALLS = [(0, 0, 0, 0, 0, 0); ITEM_COUNT];
        CALL_COUNT = 0;
    }

    #[test]
    fn refreshes_each_item_slot_in_ascending_order() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut owner = [0u32; 28];
        owner[ITEM_HANDLE_WORD + 1] = 0x1111_1111;
        owner[ITEM_HANDLE_WORD + 2] = 0x2222_2222;
        owner[ITEM_HANDLE_WORD + 3] = 0x3333_3333;
        owner[ITEM_HORIZONTAL_WORD + 1] = (-40i32) as u32;
        owner[ITEM_HORIZONTAL_WORD + 2] = 160;
        owner[ITEM_HORIZONTAL_WORD + 3] = 360;
        owner[ITEM_VERTICAL_WORD + 1] = 122;
        owner[ITEM_VERTICAL_WORD + 2] = 123;
        owner[ITEM_VERTICAL_WORD + 3] = 124;

        unsafe {
            prepare();
            ui_refresh_three_item_clips(owner.as_mut_ptr().cast());
            assert_eq!(CALL_COUNT, ITEM_COUNT);
            assert_eq!(CALLS, [
                (0x1111_1111, 1, -40, 122, 180, 180),
                (0x2222_2222, 2, 160, 123, 180, 180),
                (0x3333_3333, 3, 360, 124, 180, 180),
            ]);
        }
    }

    #[test]
    fn preserves_signed_coordinates_and_opaque_handle_bits() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut owner = [0u32; 28];
        owner[ITEM_HANDLE_WORD + 1] = u32::MAX;
        owner[ITEM_HANDLE_WORD + 2] = 0x8000_0000;
        owner[ITEM_HANDLE_WORD + 3] = 0;
        owner[ITEM_HORIZONTAL_WORD + 1] = i32::MIN as u32;
        owner[ITEM_HORIZONTAL_WORD + 2] = (-1i32) as u32;
        owner[ITEM_HORIZONTAL_WORD + 3] = i32::MAX as u32;
        owner[ITEM_VERTICAL_WORD + 1] = i32::MAX as u32;
        owner[ITEM_VERTICAL_WORD + 2] = (-1i32) as u32;
        owner[ITEM_VERTICAL_WORD + 3] = i32::MIN as u32;

        unsafe {
            prepare();
            ui_refresh_three_item_clips(owner.as_mut_ptr().cast());
            assert_eq!(CALLS, [
                (u32::MAX, 1, i32::MIN, i32::MAX, 180, 180),
                (0x8000_0000, 2, -1, -1, 180, 180),
                (0, 3, i32::MAX, i32::MIN, 180, 180),
            ]);
        }
    }
}
