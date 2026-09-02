//! The 'plst' UI element's indexed slot-item fetch.
//!
//! - `ui_plst_slot_item_at` — original: `FUN_08052728` @ 0x08052728
//!   (172 bytes; 23 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in osos.dec).
//!
//! A 'plst' element carries a header link at +0x40 whose u16 at +0x2e is
//! the item count, and a 49-word slot table at +0x3ac. Each non-NULL slot
//! points at a block whose u32 array at +0x10 holds one word per item
//! (callers such as 0x080aa498 treat that word as a sub-element pointer).
//! This function validates the class and range, lets the stock selector
//! normalizer rewrite the selector word and the reverse flag, optionally
//! reverse-indexes, lazily materializes a NULL slot, and returns the
//! indexed word.

use crate::ui::plst_class_check::ui_element_is_plst_class;

/// Element offset of the header link (`ldr r0, [r4, #0x40]`).
const HEADER_LINK_OFFSET: usize = 0x40;
/// Header offset of the u16 item count (`ldrh r6, [r0, #0x2e]`).
const HEADER_ITEM_COUNT_OFFSET: usize = 0x2e;
/// Element offset of the 49-word slot table (`ldr r0, [r0, #0x3ac]`).
const SLOT_TABLE_OFFSET: usize = 0x3ac;
/// Slot-block offset of the per-item u32 array (`ldr r0, [r0, #0x10]`).
const SLOT_ITEMS_OFFSET: usize = 0x10;

/// Stock selector normalizer @ 0x080b48dc (unported, 200 bytes).
/// Rewrites `*selector` for the special selectors 0x33..0x37 (0x34/0x37
/// become 4; 0x33/0x35/0x36 consult element bytes +0x18c/+0x18d and word
/// +0xc8) and may force `*reverse_flag` to 0. Identity for selectors
/// below 0x33.
#[cfg(target_os = "none")]
static NORMALIZE_SELECTOR_ADDRESS: usize = 0x080b_48dc;

/// Stock slot materializer @ 0x080df1b8 (unported). Called with
/// (element, selector) when the slot word is NULL; fills the slot on
/// success, returns 0 or an error (~0x31 when selector >= 49). The
/// original caller discards the return value and re-reads the slot.
#[cfg(target_os = "none")]
static MATERIALIZE_SLOT_ADDRESS: usize = 0x080d_f1b8;

/// ABI of the selector normalizer at 0x080b48dc.
pub type PlstNormalizeSelector =
    unsafe extern "C" fn(element: *mut u8, selector: *mut u32, reverse_flag: *mut u8);
/// ABI of the slot materializer at 0x080df1b8.
pub type PlstMaterializeSlot = unsafe extern "C" fn(element: *mut u8, selector: u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_normalize_selector(
    element: *mut u8,
    selector: *mut u32,
    reverse_flag: *mut u8,
) {
    let normalize: PlstNormalizeSelector = core::mem::transmute(NORMALIZE_SELECTOR_ADDRESS);
    normalize(element, selector, reverse_flag);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_materialize_slot(element: *mut u8, selector: u32) -> u32 {
    let materialize: PlstMaterializeSlot = core::mem::transmute(MATERIALIZE_SLOT_ADDRESS);
    materialize(element, selector)
}

/// Host default: the stock normalizer is the identity for every selector
/// below 0x33, which is all a fixture needs unless it installs a mock.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_normalize_selector(
    _element: *mut u8,
    _selector: *mut u32,
    _reverse_flag: *mut u8,
) {
}

/// Host default: nothing materializes; the slot stays NULL and the fetch
/// returns 0. `0xffff_ffce` mirrors the stock `mvn r0, #0x31` error word.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_materialize_slot(_element: *mut u8, _selector: u32) -> u32 {
    0xffff_ffce
}

/// Calls outside this one-function port.
///
/// `normalize_selector` preserves the stock boundary at 0x080b48dc;
/// `materialize_slot` the one at 0x080df1b8. Both are unported retailOS
/// code; host tests replace them with mocks.
#[derive(Clone, Copy)]
pub struct PlstSlotItemOps {
    pub normalize_selector: PlstNormalizeSelector,
    pub materialize_slot: PlstMaterializeSlot,
}

/// Default target/host call boundary.
pub const DEFAULT_PLST_SLOT_ITEM_OPS: PlstSlotItemOps = PlstSlotItemOps {
    #[cfg(target_os = "none")]
    normalize_selector: firmware_normalize_selector,
    #[cfg(not(target_os = "none"))]
    normalize_selector: host_normalize_selector,
    #[cfg(target_os = "none")]
    materialize_slot: firmware_materialize_slot,
    #[cfg(not(target_os = "none"))]
    materialize_slot: host_materialize_slot,
};

/// Active call boundary. Target builds call the retailOS functions; host
/// tests swap in recording mocks.
pub static mut PLST_SLOT_ITEM_OPS: PlstSlotItemOps = DEFAULT_PLST_SLOT_ITEM_OPS;

#[inline(always)]
fn slot_item_ops() -> PlstSlotItemOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PLST_SLOT_ITEM_OPS)) }
}

/// Reads the slot-table word for `selector` (`ldr r0, [r4 + r1*4 + #0x3ac]`)
/// and widens the u32 target pointer.
#[inline(always)]
unsafe fn read_slot(element: *mut u8, selector: u32) -> *mut u8 {
    element
        .add(SLOT_TABLE_OFFSET)
        .cast::<u32>()
        .add(selector as usize)
        .read() as usize as *mut u8
}

/// ui_plst_slot_item_at — original: `FUN_08052728` @ 0x08052728 (172 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x08052728..0x080527d4`
/// (the sibling function's `stmdb` prologue starts at 0x080527d4, so
/// Ghidra's 172-byte extent is exact for once):
///
/// ```text
/// 08052728  push {r0,r1,r2,r3,r4,r5,r6,lr}
/// 0805272c  mov r5, r3              ; index
/// 08052730  mov r4, r0              ; element
/// 08052734  bl 0x80613e0            ; ui_element_is_plst_class
/// 08052738  cmp r0, #0
/// 0805273c  ldrne r0, [sp, #4]      ; selector
/// 08052740  cmpne r0, #0
/// 08052744  beq 0x80527cc           ; -> return 0
/// 08052748  cmp r4, #0
/// 0805274c  ldrne r0, [r4, #0x40]   ; header link
/// 08052750  moveq r6, #0
/// 08052754  ldrhne r6, [r0, #0x2e]  ; item count
/// 08052758  cmp r5, r6
/// 0805275c  bcs 0x80527cc           ; index >= count -> return 0
/// 08052760  add r2, sp, #8          ; &reverse_flag word
/// 08052764  add r1, sp, #4          ; &selector
/// 08052768  mov r0, r4
/// 0805276c  bl 0x80b48dc            ; normalize selector (may clear flag)
/// 08052770  ldrb r0, [sp, #8]       ; flag low byte
/// 08052774  ldr r1, [sp, #4]        ; normalized selector
/// 08052778  cmp r0, #0
/// 0805277c  subne r0, r6, r5
/// 08052780  subne r5, r0, #1        ; reverse: index = count-index-1
/// 08052784  add r0, r4, r1, lsl #2
/// 08052788  ldr r0, [r0, #0x3ac]    ; slot = element->slots[selector]
/// 0805278c  cmp r0, #0
/// 08052790  bne 0x80527b0
/// 08052794  mov r0, r4
/// 08052798  bl 0x80df1b8            ; materialize(element, selector)
/// 0805279c  ldr r0, [sp, #4]
/// 080527a0  add r0, r4, r0, lsl #2
/// 080527a4  ldr r0, [r0, #0x3ac]    ; re-read slot
/// 080527a8  cmp r0, #0
/// 080527ac  beq 0x80527cc           ; still NULL -> return 0
/// 080527b0  ldr r0, [sp, #4]
/// 080527b4  add r0, r4, r0, lsl #2
/// 080527b8  ldr r0, [r0, #0x3ac]
/// 080527bc  add r0, r0, r5, lsl #2
/// 080527c0  ldr r0, [r0, #0x10]     ; slot->items[index]
/// 080527c4  add sp, sp, #16
/// 080527c8  pop {r4,r5,r6,pc}
/// 080527cc  mov r0, #0
/// 080527d0  b 0x80527c4
/// ```
///
/// Algorithm: fetch item word `index` from the per-selector slot of a
/// 'plst' UI element. Returns 0 unless the element passes
/// [`ui_element_is_plst_class`] AND `selector != 0` (both guards are
/// internal — all 23 call sites are unconditional `bl`). The item count
/// is the u16 at header(+0x40)+0x2e; `index >= count` returns 0 (the
/// `cmp r4,#0 / moveq r6,#0` pair makes a NULL element count 0, though
/// that path is unreachable after the class check). The selector and the
/// low byte of the reverse-flag word then pass through the stock
/// normalizer at 0x080b48dc by pointer, so both may be rewritten. A
/// nonzero flag byte reverse-indexes (`count - index - 1`). A NULL slot
/// is materialized lazily via 0x80df1b8; if it is still NULL afterwards
/// the fetch returns 0. Otherwise the word at slot+0x10+index*4 is
/// returned verbatim.
///
/// Deviations: the two unported callees sit behind
/// [`PLST_SLOT_ITEM_OPS`]; on target they are the stock addresses, on
/// host the defaults are identity-normalize / never-materialize. The
/// original passes `sp+8` (the saved r2 word) as the flag pointer and the
/// normalizer writes it with `strb`; the port narrows to the low byte
/// before the call, which is bit-identical because only `strb`/`ldrb`
/// ever touch that slot. The materializer's error return is discarded
/// exactly like the original (result clobbered by the slot re-read).
/// All loads are aligned word/halfword loads like the original's
/// `ldr`/`ldrh`; no `read_unaligned` anywhere.
///
/// # Safety
///
/// `element` may be NULL (guarded by the class check, like the original).
/// When non-NULL it must be a readable 'plst' element: the header link at
/// +0x40 must point at a readable block of at least 0x30 bytes, and the
/// slot table at +0x3ac must be readable through the post-normalization
/// selector. Any non-NULL slot must be readable through
/// +0x10+index*4+3.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_slot_item_at")]
pub unsafe extern "C" fn ui_plst_slot_item_at(
    element: *mut u8,
    selector: u32,
    reverse_flag: u32,
    index: u32,
) -> u32 {
    if ui_element_is_plst_class(element) == 0 || selector == 0 {
        return 0;
    }
    let mut count: u32 = 0;
    if !element.is_null() {
        let header = element.add(HEADER_LINK_OFFSET).cast::<u32>().read() as usize as *const u8;
        count = u32::from(header.add(HEADER_ITEM_COUNT_OFFSET).cast::<u16>().read());
    }
    let mut index = index;
    if index >= count {
        return 0;
    }
    let mut selector = selector;
    let mut reverse_flag = reverse_flag as u8;
    let ops = slot_item_ops();
    (ops.normalize_selector)(element, &mut selector, &mut reverse_flag);
    if reverse_flag != 0 {
        index = count - index - 1;
    }
    let mut slot = read_slot(element, selector);
    if slot.is_null() {
        (ops.materialize_slot)(element, selector);
        slot = read_slot(element, selector);
        if slot.is_null() {
            return 0;
        }
    }
    slot.add(SLOT_ITEMS_OFFSET)
        .cast::<u32>()
        .add(index as usize)
        .read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // Slab layout: header @ +0x0000, element @ +0x1000, slot blocks from
    // +0x2000 in 0x400 strides. Each slot block holds up to 16 item words
    // at +0x10.
    const HEADER_OFF: usize = 0x0000;
    const ELEMENT_OFF: usize = 0x1000;
    const SLOT_REGION: usize = 0x2000;
    const SLOT_STRIDE: usize = 0x400;
    const ELEMENT_BYTES: usize = SLOT_TABLE_OFFSET + 49 * 4;
    const SLAB_BYTES: usize = 0x10000;
    const MAX_ITEMS: usize = 16;

    const PLST_TAG: u32 = 0x706c7374;

    static mut NORMALIZE_CALLS: u32 = 0;
    static mut MATERIALIZE_CALLS: u32 = 0;
    static mut LAST_MATERIALIZE_ELEMENT: *mut u8 = core::ptr::null_mut();
    static mut LAST_MATERIALIZE_SELECTOR: u32 = u32::MAX;

    unsafe fn base() -> *mut u8 {
        match testing::try_map_u32_slab(testing::hints::PLST_SLOT_ITEM, SLAB_BYTES) {
            Some(p) => p,
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn element(base: *mut u8) -> *mut u8 {
        base.add(ELEMENT_OFF)
    }

    unsafe fn write_word(addr: *mut u8, value: u32) {
        addr.cast::<u32>().write(value);
    }

    /// Builds a 'plst' element with the given item count in the slab.
    unsafe fn make_element(base: *mut u8, count: u16) {
        let header = base.add(HEADER_OFF);
        let element = element(base);
        core::ptr::write_bytes(element, 0, ELEMENT_BYTES);
        write_word(element.add(0x4), PLST_TAG);
        write_word(element.add(HEADER_LINK_OFFSET), header as u32);
        header
            .add(HEADER_ITEM_COUNT_OFFSET)
            .cast::<u16>()
            .write(count);
    }

    /// Allocates slot block `n` (0..) and fills its item array.
    unsafe fn make_slot(base: *mut u8, n: usize, items: &[u32]) -> *mut u8 {
        assert!(items.len() <= MAX_ITEMS);
        let slot = base.add(SLOT_REGION + n * SLOT_STRIDE);
        for (i, item) in items.iter().enumerate() {
            write_word(slot.add(SLOT_ITEMS_OFFSET + i * 4), *item);
        }
        slot
    }

    unsafe fn set_slot(base: *mut u8, selector: u32, slot: *mut u8) {
        write_word(
            element(base).add(SLOT_TABLE_OFFSET + selector as usize * 4),
            slot as u32,
        );
    }

    unsafe extern "C" fn mock_normalize_passthrough(
        _element: *mut u8,
        _selector: *mut u32,
        _reverse_flag: *mut u8,
    ) {
        NORMALIZE_CALLS += 1;
    }

    /// Mimics the stock 0x34/0x37 -> 4 remap and, like the 0x33 path,
    /// forces the reverse flag to 0.
    unsafe extern "C" fn mock_normalize_remap(
        _element: *mut u8,
        selector: *mut u32,
        reverse_flag: *mut u8,
    ) {
        NORMALIZE_CALLS += 1;
        if *selector == 0x34 || *selector == 0x37 {
            *selector = 4;
            *reverse_flag = 0;
        }
    }

    unsafe extern "C" fn mock_materialize_leave_null(element: *mut u8, selector: u32) -> u32 {
        MATERIALIZE_CALLS += 1;
        LAST_MATERIALIZE_ELEMENT = element;
        LAST_MATERIALIZE_SELECTOR = selector;
        0xffff_ffce
    }

    unsafe extern "C" fn mock_materialize_populate(element: *mut u8, selector: u32) -> u32 {
        MATERIALIZE_CALLS += 1;
        LAST_MATERIALIZE_ELEMENT = element;
        LAST_MATERIALIZE_SELECTOR = selector;
        // The element fixture lives at +0x1000 within the slab.
        let slot = element.cast::<u8>().sub(ELEMENT_OFF).add(SLOT_REGION + 8 * SLOT_STRIDE);
        write_word(
            element.add(SLOT_TABLE_OFFSET + selector as usize * 4),
            slot as u32,
        );
        0
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: PlstSlotItemOps,
        base: *mut u8,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                PLST_SLOT_ITEM_OPS = self.previous_ops;
            }
        }
    }

    fn bench(ops: PlstSlotItemOps) -> Option<Bench> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = unsafe { base() };
        if base.is_null() {
            testing::note_missing_u32_fixture("ui::plst_slot_item");
            return None;
        }
        let previous_ops = unsafe { PLST_SLOT_ITEM_OPS };
        unsafe {
            NORMALIZE_CALLS = 0;
            MATERIALIZE_CALLS = 0;
            LAST_MATERIALIZE_ELEMENT = core::ptr::null_mut();
            LAST_MATERIALIZE_SELECTOR = u32::MAX;
            PLST_SLOT_ITEM_OPS = ops;
        }
        Some(Bench {
            _lock: lock,
            previous_ops,
            base,
        })
    }

    fn passthrough_ops() -> PlstSlotItemOps {
        PlstSlotItemOps {
            normalize_selector: mock_normalize_passthrough,
            materialize_slot: mock_materialize_leave_null,
        }
    }

    #[test]
    fn null_element_returns_zero_without_touching_seams() {
        let Some(_bench) = bench(passthrough_ops()) else {
            return;
        };
        assert_eq!(unsafe { ui_plst_slot_item_at(core::ptr::null_mut(), 5, 0, 0) }, 0);
        assert_eq!(unsafe { (NORMALIZE_CALLS, MATERIALIZE_CALLS) }, (0, 0));
    }

    #[test]
    fn wrong_class_tag_returns_zero() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            write_word(element(bench.base).add(0x4), 0x74646174); // 'tdat'
            assert_eq!(ui_plst_slot_item_at(element(bench.base), 5, 0, 0), 0);
            assert_eq!((NORMALIZE_CALLS, MATERIALIZE_CALLS), (0, 0));
        }
    }

    #[test]
    fn zero_selector_returns_zero() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            set_slot(bench.base, 1, make_slot(bench.base, 0, &[0xaa]));
            assert_eq!(ui_plst_slot_item_at(element(bench.base), 0, 0, 0), 0);
            assert_eq!((NORMALIZE_CALLS, MATERIALIZE_CALLS), (0, 0));
        }
    }

    #[test]
    fn index_at_or_past_count_returns_zero() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            set_slot(bench.base, 5, make_slot(bench.base, 0, &[1, 2, 3]));
            for index in [3u32, 4, u32::MAX] {
                assert_eq!(ui_plst_slot_item_at(element(bench.base), 5, 0, index), 0);
            }
            // The range check precedes the normalizer.
            assert_eq!((NORMALIZE_CALLS, MATERIALIZE_CALLS), (0, 0));
        }
    }

    #[test]
    fn zero_count_rejects_every_index() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 0);
            assert_eq!(ui_plst_slot_item_at(element(bench.base), 5, 1, 0), 0);
        }
    }

    #[test]
    fn forward_indexing_returns_item_word_verbatim() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            set_slot(bench.base, 5, make_slot(bench.base, 0, &[0x1111_0001, 0xdead_beef, 0x2222_0003]));
            let element = element(bench.base);
            assert_eq!(ui_plst_slot_item_at(element, 5, 0, 0), 0x1111_0001);
            assert_eq!(ui_plst_slot_item_at(element, 5, 0, 1), 0xdead_beef);
            assert_eq!(ui_plst_slot_item_at(element, 5, 0, 2), 0x2222_0003);
            assert_eq!(NORMALIZE_CALLS, 3);
            assert_eq!(MATERIALIZE_CALLS, 0);
        }
    }

    #[test]
    fn reverse_flag_indexes_from_the_end() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            set_slot(bench.base, 5, make_slot(bench.base, 0, &[10, 20, 30]));
            let element = element(bench.base);
            assert_eq!(ui_plst_slot_item_at(element, 5, 1, 0), 30);
            assert_eq!(ui_plst_slot_item_at(element, 5, 1, 1), 20);
            assert_eq!(ui_plst_slot_item_at(element, 5, 1, 2), 10);
        }
    }

    #[test]
    fn only_the_low_byte_of_the_flag_word_is_read() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 2);
            set_slot(bench.base, 5, make_slot(bench.base, 0, &[10, 20]));
            let element = element(bench.base);
            // 0x100 has a zero low byte: the original's ldrb sees forward.
            assert_eq!(ui_plst_slot_item_at(element, 5, 0x100, 1), 20);
            // 0x1ff has a nonzero low byte: reverse.
            assert_eq!(ui_plst_slot_item_at(element, 5, 0x1ff, 1), 10);
        }
    }

    #[test]
    fn null_slot_materialize_failure_returns_zero() {
        let Some(bench) = bench(passthrough_ops()) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            let element = element(bench.base);
            assert_eq!(ui_plst_slot_item_at(element, 7, 0, 1), 0);
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(LAST_MATERIALIZE_ELEMENT, element);
            assert_eq!(LAST_MATERIALIZE_SELECTOR, 7);
        }
    }

    #[test]
    fn null_slot_materialize_populate_returns_item() {
        let Some(bench) = bench(PlstSlotItemOps {
            normalize_selector: mock_normalize_passthrough,
            materialize_slot: mock_materialize_populate,
        }) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            let slot = make_slot(bench.base, 8, &[0xf0, 0xf1, 0xf2]);
            assert!(!slot.is_null());
            let element = element(bench.base);
            assert_eq!(ui_plst_slot_item_at(element, 7, 0, 2), 0xf2);
            assert_eq!(MATERIALIZE_CALLS, 1);
            // A second fetch finds the slot already filled.
            assert_eq!(ui_plst_slot_item_at(element, 7, 0, 0), 0xf0);
            assert_eq!(MATERIALIZE_CALLS, 1);
        }
    }

    #[test]
    fn normalizer_rewrites_selector_and_clears_reverse_flag() {
        let Some(bench) = bench(PlstSlotItemOps {
            normalize_selector: mock_normalize_remap,
            materialize_slot: mock_materialize_leave_null,
        }) else {
            return;
        };
        unsafe {
            make_element(bench.base, 3);
            set_slot(bench.base, 4, make_slot(bench.base, 0, &[40, 41, 42]));
            let element = element(bench.base);
            // Selector 0x34 remaps to slot 4; the cleared flag makes the
            // fetch forward despite reverse_flag = 1.
            assert_eq!(ui_plst_slot_item_at(element, 0x34, 1, 0), 40);
            assert_eq!(ui_plst_slot_item_at(element, 0x37, 1, 2), 42);
        }
    }
}
