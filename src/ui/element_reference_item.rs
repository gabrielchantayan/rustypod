//! Resolve-gated indexed item lookup on a UI element reference.
//!
//! - `ui_element_reference_item_at` — original: `FUN_082a60a8` @
//!   0x082a60a8 (80 bytes; 7 direct `bl` call sites, all unconditional).

use crate::ui::plst_slot_item::ui_plst_slot_item_at;

/// Vtable resolve method offset (`ldr r1,[r0,#0xc]`).
const VTABLE_RESOLVE_OFFSET: usize = 0x0c;
/// Target element word in the reference (`ldr r0,[r4,#4]`).
const TARGET_OFFSET: usize = 0x04;
/// Target flag that selects slot 1 or 2 (`ldrb r1,[r0,#0x18c]`).
const SELECTOR_FLAG_OFFSET: usize = 0x18c;
/// Target bit 2, forwarded as the reverse-index flag (`ldrb r1,[r0,#0x18d]`).
const REVERSE_FLAG_OFFSET: usize = 0x18d;

/// Vtable slot 3 returns nonzero when the reference resolves.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_item_at — original: `FUN_082a60a8` @ 0x082a60a8
/// (80 bytes, exact: the next separately linked function begins with
/// `push {r4,r5,r6,lr}` at 0x082a60f8).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x082a60a8..0x082a60f8`:
///
/// ```text
/// 082a60a8  push    {r4,r5,r6,lr}
/// 082a60ac  mov     r4,r0
/// 082a60b0  ldr     r0,[r0]
/// 082a60b4  mov     r5,r1
/// 082a60b8  ldr     r1,[r0,#0xc]
/// 082a60bc  mov     r0,r4
/// 082a60c0  blx     r1
/// 082a60c4  cmp     r0,#0
/// 082a60c8  popeq   {r4,r5,r6,pc}
/// 082a60cc  ldr     r0,[r4,#4]
/// 082a60d0  mov     r3,r5
/// 082a60d4  ldrb    r1,[r0,#0x18d]
/// 082a60d8  lsl     r1,r1,#29
/// 082a60dc  lsr     r2,r1,#31
/// 082a60e0  ldrb    r1,[r0,#0x18c]
/// 082a60e4  pop     {r4,r5,r6,lr}
/// 082a60e8  tst     r1,#1
/// 082a60ec  moveq   r1,#1
/// 082a60f0  movne   r1,#2
/// 082a60f4  b       0x08052728 ; ui_plst_slot_item_at
/// ```
///
/// Calls vtable slot +0x0c with `reference`; a zero result returns zero
/// before loading the target. A successful resolution loads the target's
/// +0x18c bit 0 as selector 1 (clear) or 2 (set), and forwards target +0x18d
/// bit 2 as `ui_plst_slot_item_at`'s reverse-index flag with the requested
/// index. Decoding every ARM B/BL word in `osos.dec` finds 7 direct callers:
/// all are unconditional `bl`; the non-call `b` at 0x0817bb30 is a tail
/// transfer and is excluded from that count.
///
/// Deliberate host deviation: vtable function pointers occupy eight bytes
/// while firmware vtable entries are four, so only that function-pointer read
/// is unaligned. The source calls the existing Rust port normally; ARM LLVM
/// lowers that final call to the same register-restoring tail transfer.
///
/// # Safety
///
/// `reference` must be readable through +0x04 and its vtable through +0x0c.
/// When the resolve slot returns nonzero, its target word must name a readable
/// 'plst' element through +0x18d; the original has no target NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_element_reference_item_at")]
pub unsafe extern "C" fn ui_element_reference_item_at(reference: *const u8, index: u32) -> u32 {
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    #[cfg(target_os = "none")]
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    #[cfg(not(target_os = "none"))]
    let resolve: ResolveSlot = vtable
        .add(VTABLE_RESOLVE_OFFSET)
        .cast::<ResolveSlot>()
        .read_unaligned();

    if resolve(reference) == 0 {
        return 0;
    }

    let element = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *mut u8;
    let reverse_flag = (element.add(REVERSE_FLAG_OFFSET).read() >> 2) & 1;
    let selector = if element.add(SELECTOR_FLAG_OFFSET).read() & 1 == 0 {
        1
    } else {
        2
    };
    ui_plst_slot_item_at(element, selector, reverse_flag as u32, index)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut RESOLVE_REFERENCE: *const u8 = ptr::null();
    static mut RESOLVE_CALLS: u32 = 0;

    const SLAB_BYTES: usize = 0x6000;
    const VTABLE_OFFSET: usize = 0x0100;
    const HEADER_OFFSET: usize = 0x0800;
    const ELEMENT_OFFSET: usize = 0x1000;
    const FIRST_SLOT_OFFSET: usize = 0x3000;
    const SECOND_SLOT_OFFSET: usize = 0x4000;
    const SLOT_TABLE_OFFSET: usize = 0x3ac;
    const SLOT_ITEMS_OFFSET: usize = 0x10;
    const PLST_TAG: u32 = 0x706c7374;

    unsafe extern "C" fn resolve_stub(reference: *const u8) -> u32 {
        RESOLVE_REFERENCE = reference;
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_ITEM,
                SLAB_BYTES,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(resolve_result: u32) {
        let reference = slab();
        let vtable = reference.add(VTABLE_OFFSET);
        let header = reference.add(HEADER_OFFSET);
        let element = reference.add(ELEMENT_OFFSET);
        let first_slot = reference.add(FIRST_SLOT_OFFSET);
        let second_slot = reference.add(SECOND_SLOT_OFFSET);

        RESOLVE_RESULT = resolve_result;
        RESOLVE_REFERENCE = ptr::null();
        RESOLVE_CALLS = 0;
        core::ptr::write_bytes(reference, 0, SLAB_BYTES);
        write_word(reference, 0, vtable as u32);
        write_word(reference, TARGET_OFFSET, element as u32);
        vtable
            .add(VTABLE_RESOLVE_OFFSET)
            .cast::<ResolveSlot>()
            .write_unaligned(resolve_stub);

        write_word(element, 4, PLST_TAG);
        write_word(element, 0x40, header as u32);
        header.add(0x2e).cast::<u16>().write(3);
        write_word(element, SLOT_TABLE_OFFSET + 4, first_slot as u32);
        write_word(element, SLOT_TABLE_OFFSET + 8, second_slot as u32);
        write_word(first_slot, SLOT_ITEMS_OFFSET, 0x1111_0000);
        write_word(first_slot, SLOT_ITEMS_OFFSET + 4, 0x1111_0001);
        write_word(first_slot, SLOT_ITEMS_OFFSET + 8, 0x1111_0002);
        write_word(second_slot, SLOT_ITEMS_OFFSET, 0x2222_0000);
        write_word(second_slot, SLOT_ITEMS_OFFSET + 4, 0x2222_0001);
        write_word(second_slot, SLOT_ITEMS_OFFSET + 8, 0x2222_0002);
    }

    #[test]
    fn failed_resolve_returns_zero_without_loading_target() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item");
            return;
        }
        unsafe {
            prepare(0);
            write_word(slab(), TARGET_OFFSET, 1);

            assert_eq!(ui_element_reference_item_at(slab(), 0), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, slab());
        }
    }

    #[test]
    fn selector_flag_selects_slot_one_or_two() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item");
            return;
        }
        unsafe {
            prepare(1);
            let element = slab().add(ELEMENT_OFFSET);

            assert_eq!(ui_element_reference_item_at(slab(), 1), 0x1111_0001);
            element.add(SELECTOR_FLAG_OFFSET).write(1);
            assert_eq!(ui_element_reference_item_at(slab(), 1), 0x2222_0001);
            assert_eq!(RESOLVE_CALLS, 2);
        }
    }

    #[test]
    fn reverse_bit_uses_last_item_for_zero_index() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item");
            return;
        }
        unsafe {
            prepare(1);
            let element = slab().add(ELEMENT_OFFSET);
            element.add(REVERSE_FLAG_OFFSET).write(0x04);

            assert_eq!(ui_element_reference_item_at(slab(), 0), 0x1111_0002);
            assert_eq!(RESOLVE_CALLS, 1);
        }
    }
}
