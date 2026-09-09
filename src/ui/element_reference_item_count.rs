//! Resolve-gated item-count reader on a UI element reference.
//!
//! - `ui_element_reference_target_item_count` — original: `FUN_082a5e48` @
//!   0x082a5e48 (52 bytes; 16 direct `bl` call sites, all unconditional).
//!
//! The reference is the same vtable-headed record used by
//! [`crate::ui::element_reference_cookie`]: its target is the 32-bit word at
//! +0x04 and vtable slot +0x0c decides whether that target resolves.

/// Byte offset of the resolve method inside the reference's vtable
/// (`ldr r1,[r0,#0xc]` — slot 3).
const VTABLE_RESOLVE_OFFSET: usize = 0x0c;

/// Byte offset of the reference's target pointer (`ldrne r0,[r4,#4]`).
const TARGET_OFFSET: usize = 0x04;

/// Byte offset of the target's nested collection pointer
/// (`ldrne r0,[r0,#0x40]`).
const TARGET_COLLECTION_OFFSET: usize = 0x40;

/// Byte offset of the collection's item count (`ldrhne r0,[r0,#0x2e]`).
const COLLECTION_ITEM_COUNT_OFFSET: usize = 0x2e;

/// Vtable slot 3 signature: takes the reference, returning nonzero when it
/// currently resolves.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_item_count — original: `FUN_082a5e48` @
/// 0x082a5e48 (52 bytes, exact: 0x082a5e7c starts the next separately linked
/// function's `push {r4,r5,lr}` prologue; **16 direct `bl` call sites**, all
/// plain unconditional `bl`, verified by decoding every ARM B/BL word in
/// `osos.dec`).
///
/// ```text
/// 082a5e48  push    {r4,lr}
/// 082a5e4c  mov     r4,r0
/// 082a5e50  ldr     r0,[r0]
/// 082a5e54  ldr     r1,[r0,#0xc]
/// 082a5e58  mov     r0,r4
/// 082a5e5c  blx     r1
/// 082a5e60  cmp     r0,#0
/// 082a5e64  ldrne   r0,[r4,#4]
/// 082a5e68  cmpne   r0,#0
/// 082a5e6c  ldrne   r0,[r0,#0x40]
/// 082a5e70  moveq   r0,#0
/// 082a5e74  ldrhne  r0,[r0,#0x2e]
/// 082a5e78  pop     {r4,pc}
/// ```
///
/// Calls vtable slot +0x0c with `reference`. A zero result short-circuits to
/// zero without reading the target. A nonzero result with a NULL target also
/// returns zero. Otherwise it follows `target + 0x40` without a NULL guard and
/// returns the zero-extended halfword at that nested record's +0x2e. The
/// item-count name is call-site grounded: 0x0816ebe0 accepts an index only
/// when it is smaller than this result before resolving that index, while
/// 0x0816ecd8 and 0x0816eefc compare selection positions against it.
///
/// Decoding every ARM B/BL word also finds one non-call `bne` tail transfer at
/// 0x0812c718: its NULL-guarding wrapper passes a reference at +0x14 here, or
/// returns zero itself. It is not part of the 16 `bl` call count. The static
/// descriptor 0x089a6600's slot +0x0c word is 0x0826acd8, a
/// selector/implementation data pair rather than a decodable function entry;
/// as with sibling property readers, this port preserves the raw vtable
/// dispatch and deliberately does not invent a callee identity.
///
/// Deliberate host deviation: test fixtures store the vtable slot as a native
/// function pointer (8 bytes on this host, 4 on ARM), while the reference and
/// target pointers remain target `u32` words.
///
/// # Safety
///
/// `reference` must be readable through +0x04 and its vtable through +0x0c.
/// If its resolve slot returns nonzero and the target is non-NULL, `target +
/// 0x40` must name a non-NULL record readable through +0x30 with 2-byte
/// alignment; the original does not guard that nested pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_item_count(reference: *const u8) -> u32 {
    // ldr r0,[r0]; ldr r1,[r0,#0xc]; mov r0,r4; blx r1 — resolve through
    // vtable slot 3.
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    #[cfg(target_os = "none")]
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    #[cfg(not(target_os = "none"))]
    let resolve: ResolveSlot = vtable
        .add(VTABLE_RESOLVE_OFFSET)
        .cast::<ResolveSlot>()
        .read_unaligned();
    // cmp r0,#0; ldrne r0,[r4,#4]; cmpne r0,#0; moveq r0,#0 — failed
    // resolution and a NULL target both avoid the target dereference.
    let target = if resolve(reference) != 0 {
        reference.add(TARGET_OFFSET).cast::<u32>().read()
    } else {
        0
    };
    if target == 0 {
        return 0;
    }
    // ldrne r0,[r0,#0x40]; ldrhne r0,[r0,#0x2e] — the collection pointer
    // itself has no NULL guard in the original.
    let collection = (target as usize as *const u8)
        .add(TARGET_COLLECTION_OFFSET)
        .cast::<u32>()
        .read() as usize as *const u8;
    collection
        .add(COLLECTION_ITEM_COUNT_OFFSET)
        .cast::<u16>()
        .read() as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    /// The shared slab fixture is global, so the tests serialize on one lock.
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut RESOLVE_REFERENCE: *const u8 = ptr::null();
    static mut RESOLVE_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn resolve_stub(reference: *const u8) -> u32 {
        RESOLVE_REFERENCE = reference;
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    /// Installed in every vtable slot except +0xc: any call through it proves
    /// the port selected the wrong slot.
    unsafe extern "C" fn wrong_slot_stub(_reference: *const u8) -> u32 {
        WRONG_SLOT_CALLS += 1;
        1
    }

    /// Maps the fixture slab once per process. The port widens `u32`
    /// vtable/target words into host pointers and dereferences them, so every
    /// fixture record must live below 4 GiB; `None` means this host cannot
    /// supply such a mapping and the tests skip rather than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_ITEM_COUNT,
                0x2000,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn reference() -> *mut u8 {
        slab()
    }

    unsafe fn vtable() -> *mut u8 {
        slab().add(0x100)
    }

    unsafe fn target() -> *mut u8 {
        slab().add(0x400)
    }

    unsafe fn collection() -> *mut u8 {
        slab().add(0x800)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    /// Resets every word the port can observe and installs the resolver stub.
    unsafe fn prepare(resolve_result: u32) {
        RESOLVE_RESULT = resolve_result;
        RESOLVE_REFERENCE = ptr::null();
        RESOLVE_CALLS = 0;
        WRONG_SLOT_CALLS = 0;

        write_word(reference(), 0x0, vtable() as u32);
        write_word(reference(), TARGET_OFFSET, target() as u32);
        let slot_end = VTABLE_RESOLVE_OFFSET + core::mem::size_of::<ResolveSlot>();
        for slot in 0..8usize {
            let offset = slot * 4;
            if !(VTABLE_RESOLVE_OFFSET..slot_end).contains(&offset) {
                write_word(vtable(), offset, wrong_slot_stub as u32);
            }
        }
        vtable()
            .add(VTABLE_RESOLVE_OFFSET)
            .cast::<ResolveSlot>()
            .write_unaligned(resolve_stub);
        write_word(target(), TARGET_COLLECTION_OFFSET, collection() as u32);
        collection()
            .add(COLLECTION_ITEM_COUNT_OFFSET)
            .cast::<u16>()
            .write(0);
    }

    #[test]
    fn failed_resolve_short_circuits_before_target_load() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item_count");
            return;
        }
        unsafe {
            prepare(0);
            // A poisoned target word proves the failed resolve does not load it.
            write_word(reference(), TARGET_OFFSET, 1);

            assert_eq!(ui_element_reference_target_item_count(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_null_target_returns_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item_count");
            return;
        }
        unsafe {
            prepare(1);
            write_word(reference(), TARGET_OFFSET, 0);

            assert_eq!(ui_element_reference_target_item_count(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_item_count_is_zero_extended_halfword() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item_count");
            return;
        }
        unsafe {
            prepare(1);
            collection()
                .add(COLLECTION_ITEM_COUNT_OFFSET)
                .cast::<u16>()
                .write(0xbeef);

            assert_eq!(ui_element_reference_target_item_count(reference()), 0x0000_beef);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn any_nonzero_resolve_result_opens_item_count_gate() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_item_count");
            return;
        }
        unsafe {
            prepare(u32::MAX);
            collection()
                .add(COLLECTION_ITEM_COUNT_OFFSET)
                .cast::<u16>()
                .write(u16::MAX);

            assert_eq!(ui_element_reference_target_item_count(reference()), u16::MAX as u32);
            assert_eq!(RESOLVE_CALLS, 1);
        }
    }
}
