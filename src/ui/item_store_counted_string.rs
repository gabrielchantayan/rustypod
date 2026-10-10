//! Item counted-string replacement — FUN_08067c70 @ 0x08067c70.
//! True extent [0x08067c70, 0x08067c9c): 44 bytes, no literals; the next
//! function begins with strb r1,[r0,#0xe3c]. Whole-image aligned A32 decoding
//! finds two incoming plain BLs (0x080462b8, 0x08067c50), zero predicated
//! incoming BLs, two outgoing plain BLs, and zero predicated outgoing BLs.
//! Store in the owner's pool at +0xc0, replacing the item's id at +0x28;
//! refresh item flag bit 3 at +0x15 unconditionally, then return store status.
//! Deviations: use the existing Rust counted-string wrapper; the unported
//! flag refresh at 0x080444d4 uses a volatile seam with its real target address.
//! repr(C) widens the owner pointer on hosts; ARM retains all retail offsets.

use core::ptr;
use crate::util::string_pool::{string_pool_store_counted, StringPool};

/// Retail item prefix, through the string-pool entry id.
#[repr(C)]
pub struct CountedStringItem {
    pub owner: *mut u8,
    pub state: [u32; 9],
    pub string_id: i32,
}

type RefreshStringFlag = unsafe extern "C" fn(*mut CountedStringItem);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_refresh_string_flag(item: *mut CountedStringItem) {
    let refresh: RefreshStringFlag = core::mem::transmute(0x0804_44d4usize);
    refresh(item)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_refresh_string_flag(_: *mut CountedStringItem) {
    panic!("item flag refresh requires retail 0x080444d4")
}

/// Refresh reads the stored string and replaces flag bit 3 at item +0x15.
/// Raw code calls 0x080d6e50, halves its byte length, then scans with 0x1d
/// via 0x08059c68. No stronger identity for that scan is assumed.
pub static mut ITEM_REFRESH_STRING_FLAG: RefreshStringFlag = retail_refresh_string_flag;

/// Replace the counted string, refreshing derived state even on store failure.
///
/// # Safety
/// `item` must be writable through its id field and have a valid owner pool
/// at +0xc0. `counted` is NULL (clear) or a readable u16 length and payload.
/// The item and owner must also satisfy retail flag-refresh requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_store_counted_string(item: *mut CountedStringItem, counted: *const u16) -> i32 {
    let status = string_pool_store_counted(
        (*item).owner.add(0xc0).cast::<StringPool>(),
        counted,
        ptr::addr_of_mut!((*item).string_id),
    );
    let refresh = ptr::read_volatile(ptr::addr_of!(ITEM_REFRESH_STRING_FLAG));
    refresh(item);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::string_pool::{STRING_POOL_SEAM_LOCK, STRING_POOL_STORE};

    static mut STATUS: i32 = 0;
    static mut REFRESHES: u32 = 0;

    unsafe extern "C" fn replace(_: *mut StringPool, data: *const u8, len: u32, id: *mut i32) -> i32 {
        // Model a replacement/clear, including a failing store that leaves a
        // changed id: refresh must observe post-store state on every path.
        assert_eq!(len, if data.is_null() { 0 } else { 4 });
        id.write(if data.is_null() { 0 } else { 27 });
        STATUS
    }

    unsafe extern "C" fn refresh(item: *mut CountedStringItem) {
        (*item).state[0] = (*item).string_id as u32;
        (*item).string_id = -99;
        REFRESHES += 1;
    }

    #[test]
    fn replacement_and_clear_refresh_post_store_state_and_preserve_status() {
        let _lock = STRING_POOL_SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut owner = [0u32; 64];
        let mut item = CountedStringItem { owner: owner.as_mut_ptr().cast(), state: [0; 9], string_id: 9 };
        let counted = [2u16, 0x61, 0x62];
        unsafe {
            let old_store = STRING_POOL_STORE;
            let old_refresh = ITEM_REFRESH_STRING_FLAG;
            STRING_POOL_STORE = replace;
            ITEM_REFRESH_STRING_FLAG = refresh;
            REFRESHES = 0;
            for status in [0, -50, i32::MIN, i32::MAX] {
                STATUS = status;
                assert_eq!(item_store_counted_string(&mut item, counted.as_ptr()), status);
                assert_eq!(item.state[0], 27);
                assert_eq!(item.string_id, -99);
                assert_eq!(item_store_counted_string(&mut item, ptr::null()), status);
                assert_eq!(item.state[0], 0);
                assert_eq!(item.string_id, -99);
            }
            let refreshes = REFRESHES;
            assert_eq!(refreshes, 8);
            STRING_POOL_STORE = old_store;
            ITEM_REFRESH_STRING_FLAG = old_refresh;
        }
    }
}
