//! Item count through a linked 'plst' UI element.
//!
//! - `ui_plst_linked_item_count` — original: `FUN_08054214` @ 0x08054214
//!   (24 bytes; 11 direct `bl` call sites, all unconditional, verified by
//!   decoding every ARM B/BL word in osos.dec).

/// Owner offset of the linked 'plst' element (`ldr r0,[r0,#0xf50]`).
const PLST_ELEMENT_LINK_OFFSET: usize = 0x0f50;
/// 'plst' element offset of its collection header (`ldrne r0,[r0,#0x40]`).
const COLLECTION_LINK_OFFSET: usize = 0x40;
/// Collection-header offset of the zero-extended item count (`ldrhne r0,[r0,#0x2e]`).
const ITEM_COUNT_OFFSET: usize = 0x2e;

/// ui_plst_linked_item_count — original: `FUN_08054214` @ 0x08054214 (24 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x08054214..0x0805422c`;
/// the sibling function starts with `push {r3,r4,r5,lr}` at `0x0805422c`, so
/// Ghidra's 24-byte extent is exact:
///
/// ```text
/// 08054214  ldr r0,[r0,#0xf50]    ; linked 'plst' element
/// 08054218  cmp r0,#0
/// 0805421c  ldrne r0,[r0,#0x40]   ; collection header
/// 08054220  ldrhne r0,[r0,#0x2e]  ; u16 item count
/// 08054224  moveq r0,#0
/// 08054228  bx lr
/// ```
///
/// Algorithm: read the linked 'plst' UI element from `owner+0xf50`. A null
/// link returns zero; otherwise, return the zero-extended u16 item count at
/// `element+0x40+0x2e`. The same element/header pair feeds
/// `ui_plst_slot_item_at` (0x08052728), which range-checks indexed slot reads
/// against this count. Decoding every ARM B/BL word in osos.dec finds 11
/// direct call sites, all plain unconditional `bl`; callers rely on this
/// link-null guard rather than predicating the call.
///
/// Deliberate deviations: none. As in ARM, the `owner` argument itself is
/// not NULL-guarded, and a non-NULL linked element's header pointer is
/// dereferenced without a second NULL check. Loads are aligned `u32`/`u16`
/// reads, matching `ldr`/`ldrh`.
///
/// # Safety
///
/// `owner` must be non-NULL and readable through `+0xf53`. If its linked
/// element word is nonzero, it must be readable through `+0x43`, and its
/// collection-header word must identify readable memory through `+0x2f`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_linked_item_count")]
pub unsafe extern "C" fn ui_plst_linked_item_count(owner: *const u8) -> u32 {
    let element = owner
        .add(PLST_ELEMENT_LINK_OFFSET)
        .cast::<u32>()
        .read() as usize as *const u8;
    if element.is_null() {
        return 0;
    }
    let header = element
        .add(COLLECTION_LINK_OFFSET)
        .cast::<u32>()
        .read() as usize as *const u8;
    header.add(ITEM_COUNT_OFFSET).cast::<u16>().read() as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    // The firmware stores both links as u32 target pointers. Map a single
    // below-4-GiB slab so they survive host truncation.
    const OWNER_OFFSET: usize = 0x0000;
    const ELEMENT_OFFSET: usize = 0x1000;
    const HEADER_OFFSET: usize = 0x2000;
    const SLAB_BYTES: usize = 0x3000;

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::PLST_LINKED_ITEM_COUNT,
                SLAB_BYTES,
            )
            .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn owner() -> *mut u8 {
        slab().add(OWNER_OFFSET)
    }

    unsafe fn element() -> *mut u8 {
        slab().add(ELEMENT_OFFSET)
    }

    unsafe fn header() -> *mut u8 {
        slab().add(HEADER_OFFSET)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(item_count: u16) {
        write_word(owner(), PLST_ELEMENT_LINK_OFFSET, element() as u32);
        write_word(element(), COLLECTION_LINK_OFFSET, header() as u32);
        header().add(ITEM_COUNT_OFFSET).cast::<u16>().write(item_count);
    }

    #[test]
    fn null_linked_element_returns_zero_without_header_access() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::plst_linked_item_count");
            return;
        }
        unsafe {
            // A poisoned element/header word proves the first NULL gate stops
            // before either follow-on dereference.
            write_word(owner(), PLST_ELEMENT_LINK_OFFSET, 0);
            assert_eq!(ui_plst_linked_item_count(owner()), 0);
        }
    }

    #[test]
    fn linked_item_count_is_zero_extended_halfword() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::plst_linked_item_count");
            return;
        }
        unsafe {
            prepare(0xbeef);
            assert_eq!(ui_plst_linked_item_count(owner()), 0x0000_beef);
        }
    }

    #[test]
    fn linked_item_count_preserves_zero_and_u16_max_boundaries() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::plst_linked_item_count");
            return;
        }
        unsafe {
            prepare(0);
            assert_eq!(ui_plst_linked_item_count(owner()), 0);
            prepare(u16::MAX);
            assert_eq!(ui_plst_linked_item_count(owner()), u16::MAX as u32);
        }
    }
}
