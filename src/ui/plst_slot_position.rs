//! The 'plst' UI element's reverse slot lookup: position of an item
//! handle within a per-selector slot.
//!
//! - `ui_plst_slot_item_position` — original: `FUN_08054664` @ 0x08054664
//!   (172 bytes; 13 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in osos.dec).
//!
//! The handle is a two-word object: the owning element at +0x0 and a peer
//! pointer at +0x4 that is only NULL-gated, never dereferenced. The
//! element carries the same 49-word slot table at +0x3ac that
//! [`crate::ui::plst_slot_item`] reads, plus a parallel 49-word cache
//! table at +0x470 (0x3ac + 49*4) holding one sorted key->index map per
//! selector. Where `ui_plst_slot_item_at` maps (selector, index) to an
//! item word, this function maps (selector, item word) back to its index:
//! it lazily builds the sorted map for a selector with the unported
//! snapshot/sort helper 0x080ca00c, caches it at +0x470+selector*4, and
//! binary-searches the handle itself through the unported index-of helper
//! 0x080daad4 (which reverse-adjusts a found index when the flag byte is
//! nonzero). All failure paths return -1.

use crate::ui::plst_slot_item::{PlstMaterializeSlot, PlstNormalizeSelector};

/// Element offset of the 49-word slot table (`ldr r0, [r5, #0x3ac]`).
const SLOT_TABLE_OFFSET: usize = 0x3ac;
/// Element offset of the 49-word sorted-map cache table
/// (`ldr r0, [r0, #0x470]`), immediately after the slot table.
const POSITION_MAP_TABLE_OFFSET: usize = 0x470;
/// Number of per-selector slots (`cmpne r5, #0x31; bcs` skips >= 49).
const SLOT_COUNT: u32 = 49;

/// Stock selector normalizer @ 0x080b48dc (unported, shared with
/// `ui/plst_slot_item`). Rewrites `*selector` for the special selectors
/// 0x33..0x37 and may force `*reverse_flag` to 0. Identity for selectors
/// below 0x33.
#[cfg(target_os = "none")]
static NORMALIZE_SELECTOR_ADDRESS: usize = 0x080b_48dc;

/// Stock slot materializer @ 0x080df1b8 (unported). Called with
/// (element, selector) when the cached map is NULL and the normalized
/// selector is in 1..49; fills the +0x3ac slot on success and returns 0,
/// otherwise an error word (~0x31 when selector >= 49). Unlike
/// `ui/plst_slot_item`, this caller CHECKS the return: the map builder
/// only runs when it returns 0.
#[cfg(target_os = "none")]
static MATERIALIZE_SLOT_ADDRESS: usize = 0x080d_f1b8;

/// Stock sorted-map builder @ 0x080ca00c (unported). Reads the u32 count
/// at slot+0xc, allocates 16+count*8 bytes (via 0x805d1d4), copies the
/// per-item words at slot+0x10 into {key = item word, value = original
/// index} pairs at map+8, stores the count at map+4, and sorts by key
/// (0x8061ecc) when count > 1. Returns the map, NULL on allocation
/// failure.
#[cfg(target_os = "none")]
static BUILD_POSITION_MAP_ADDRESS: usize = 0x080c_a00c;

/// Stock index-of helper @ 0x080daad4 (unported, 172 bytes). Binary
/// search for `key` among the sorted {key, value} pairs at map+8 (count
/// at map+4), with a linear-scan fallback over the untested remainder;
/// returns the value (original index) or -1. When `reverse_flag` is
/// nonzero and the key was found, the result is reverse-adjusted to
/// count-index-1 — the same convention `ui/plst_slot_item` applies to a
/// forward fetch.
#[cfg(target_os = "none")]
static SLOT_INDEX_OF_ADDRESS: usize = 0x080d_aad4;

/// ABI of the sorted-map builder at 0x080ca00c.
pub type PlstBuildPositionMap = unsafe extern "C" fn(slot: *mut u8) -> *mut u8;
/// ABI of the index-of helper at 0x080daad4. `reverse_flag` travels in
/// r2; the original only ever produces it with `ldrb`, so only the low
/// byte is meaningful.
pub type PlstSlotIndexOf =
    unsafe extern "C" fn(key: *mut u8, map: *mut u8, reverse_flag: u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_normalize_selector(
    element: *mut u8,
    selector: *mut u32,
    reverse_flag: *mut u8,
) {
    let normalize: PlstNormalizeSelector = core::mem::transmute(NORMALIZE_SELECTOR_ADDRESS);
    normalize(element, selector, reverse_flag)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_materialize_slot(element: *mut u8, selector: u32) -> u32 {
    let materialize: PlstMaterializeSlot = core::mem::transmute(MATERIALIZE_SLOT_ADDRESS);
    materialize(element, selector)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_build_position_map(slot: *mut u8) -> *mut u8 {
    let build: PlstBuildPositionMap = core::mem::transmute(BUILD_POSITION_MAP_ADDRESS);
    build(slot)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_slot_index_of(
    key: *mut u8,
    map: *mut u8,
    reverse_flag: u32,
) -> u32 {
    let index_of: PlstSlotIndexOf = core::mem::transmute(SLOT_INDEX_OF_ADDRESS);
    index_of(key, map, reverse_flag)
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

/// Host default: nothing materializes; the cache stays NULL and the
/// lookup returns -1. `0xffff_ffce` mirrors the stock `mvn r0, #0x31`
/// error word.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_materialize_slot(_element: *mut u8, _selector: u32) -> u32 {
    0xffff_ffce
}

/// Host default: unreachable with the never-materialize default (the
/// original only calls the builder after a SUCCESSFUL materialize), so a
/// call here means a test installed half a mock chain.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_build_position_map(_slot: *mut u8) -> *mut u8 {
    panic!("ui_plst_slot_item_position requires builder 0x080ca00c")
}

/// Host default: unreachable with the never-materialize default (the
/// cache stays NULL), so a call here means a test fixture installed a
/// cache word without installing the search mock.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_slot_index_of(_key: *mut u8, _map: *mut u8, _reverse_flag: u32) -> u32 {
    panic!("ui_plst_slot_item_position requires index-of 0x080daad4")
}

/// Calls outside this one-function port.
///
/// `normalize_selector` preserves the stock boundary at 0x080b48dc,
/// `materialize_slot` the one at 0x080df1b8, `build_position_map` the one
/// at 0x080ca00c, and `slot_index_of` the one at 0x080daad4. All four are
/// unported retailOS code; host tests replace them with mocks.
#[derive(Clone, Copy)]
pub struct PlstSlotPositionOps {
    pub normalize_selector: PlstNormalizeSelector,
    pub materialize_slot: PlstMaterializeSlot,
    pub build_position_map: PlstBuildPositionMap,
    pub slot_index_of: PlstSlotIndexOf,
}

/// Default target/host call boundary.
pub const DEFAULT_PLST_SLOT_POSITION_OPS: PlstSlotPositionOps = PlstSlotPositionOps {
    #[cfg(target_os = "none")]
    normalize_selector: firmware_normalize_selector,
    #[cfg(not(target_os = "none"))]
    normalize_selector: host_normalize_selector,
    #[cfg(target_os = "none")]
    materialize_slot: firmware_materialize_slot,
    #[cfg(not(target_os = "none"))]
    materialize_slot: host_materialize_slot,
    #[cfg(target_os = "none")]
    build_position_map: firmware_build_position_map,
    #[cfg(not(target_os = "none"))]
    build_position_map: host_build_position_map,
    #[cfg(target_os = "none")]
    slot_index_of: firmware_slot_index_of,
    #[cfg(not(target_os = "none"))]
    slot_index_of: host_slot_index_of,
};

/// Active call boundary. Target builds call the retailOS functions; host
/// tests swap in recording mocks.
pub static mut PLST_SLOT_POSITION_OPS: PlstSlotPositionOps = DEFAULT_PLST_SLOT_POSITION_OPS;

#[inline(always)]
fn slot_position_ops() -> PlstSlotPositionOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PLST_SLOT_POSITION_OPS)) }
}

/// Reads a word of the per-selector table at `table` (`ldr r0, [r4 +
/// r5*4 + #off]`) and widens the u32 target pointer.
#[inline(always)]
unsafe fn read_table_word(element: *mut u8, table: usize, selector: u32) -> *mut u8 {
    element
        .add(table)
        .cast::<u32>()
        .add(selector as usize)
        .read() as usize as *mut u8
}

/// ui_plst_slot_item_position — original: `FUN_08054664` @ 0x08054664
/// (172 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x08054664..0x08054710`
/// (the next function's `ldrb` body starts at 0x08054710, so Ghidra's
/// 172-byte extent is exact):
///
/// ```text
/// 08054664  push {r0,r1,r2,r4,r5,r6,r7,lr}
/// 08054668  movs r6, r0             ; handle
/// 0805466c  ldrne r4, [r6]          ; element = handle->element
/// 08054670  cmpne r4, #0
/// 08054674  ldrne r0, [r6, #4]      ; handle->peer (gate only)
/// 08054678  cmpne r0, #0
/// 0805467c  ldrne r0, [sp, #4]      ; selector
/// 08054680  cmpne r0, #0
/// 08054684  mvneq r0, #0
/// 08054688  beq 0x805470c           ; -> return -1
/// 0805468c  mvn r7, #0              ; result = -1
/// 08054690  add r2, sp, #8          ; &flag word
/// 08054694  add r1, sp, #4          ; &selector
/// 08054698  mov r0, r4
/// 0805469c  bl 0x80b48dc            ; normalize selector (may clear flag)
/// 080546a0  ldr r5, [sp, #4]        ; normalized selector
/// 080546a4  add r0, r4, r5, lsl #2
/// 080546a8  ldr r0, [r0, #0x470]    ; cached = element->maps[selector]
/// 080546ac  cmp r0, #0
/// 080546b0  bne 0x80546e4
/// 080546b4  cmp r5, #0
/// 080546b8  cmpne r5, #0x31         ; 49
/// 080546bc  bcs 0x80546e4           ; sel==0 || sel>=49 -> skip
/// 080546c0  mov r1, r5
/// 080546c4  mov r0, r4
/// 080546c8  bl 0x80df1b8            ; materialize(element, selector)
/// 080546cc  cmp r0, #0
/// 080546d0  bne 0x80546e4           ; error -> skip
/// 080546d4  add r5, r4, r5, lsl #2
/// 080546d8  ldr r0, [r5, #0x3ac]    ; slot = element->slots[selector]
/// 080546dc  bl 0x80ca00c            ; build sorted key->index map
/// 080546e0  str r0, [r5, #0x470]    ; cache it
/// 080546e4  ldr r0, [sp, #4]
/// 080546e8  add r0, r4, r0, lsl #2
/// 080546ec  ldr r1, [r0, #0x470]    ; re-read cached map
/// 080546f0  cmp r1, #0
/// 080546f4  beq 0x8054708           ; -> return -1
/// 080546f8  ldrb r2, [sp, #8]       ; flag low byte
/// 080546fc  mov r0, r6              ; key = handle
/// 08054700  bl 0x80daad4            ; index_of(handle, map, flag)
/// 08054704  mov r7, r0
/// 08054708  mov r0, r7
/// 0805470c  pop {r1,r2,r3,r4,r5,r6,r7,pc}
/// ```
///
/// Algorithm: reverse-lookup the position of `handle` among the item
/// words of one selector's slot of a 'plst' element. Returns -1
/// (0xffffffff) unless `handle`, `handle->element` (+0x0),
/// `handle->peer` (+0x4) and `selector` are ALL non-NULL — the internal
/// guard chain is what all 13 unconditional `bl` call sites rely on (0
/// predicated, verified by decoding every B/BL word in osos.dec). The
/// selector and the low byte of the flag word then pass through the stock
/// normalizer at 0x080b48dc by pointer, so both may be rewritten. The
/// cached sorted map at element+0x470+selector*4 is consulted; when it is
/// NULL and the normalized selector is in 1..=48 the slot is materialized
/// via 0x80df1b8 and, ONLY when that returns 0, the map is built from the
/// +0x3ac slot via 0x80ca00c and cached. The map word is then re-read
/// (`0x080546e4`), and when non-NULL the handle itself is searched
/// through 0x80daad4 with the flag's low byte; its result (index or -1)
/// is returned verbatim. A still-NULL map returns the pre-seeded -1.
///
/// Deviations: the four unported callees sit behind
/// [`PLST_SLOT_POSITION_OPS`]; on target they are the stock addresses, on
/// host the defaults are identity-normalize / never-materialize /
/// panic-on-reach. The normalize-selector and materialize-slot fn
/// pointer types are reused from [`crate::ui::plst_slot_item`], which
/// shares both stock boundaries. The original passes `sp+8` (the saved r2
/// word) as the flag pointer and the normalizer writes it with `strb`;
/// the port narrows to the low byte before the call, bit-identical
/// because only `strb`/`ldrb` ever touch that slot. All table loads are
/// aligned word loads like the original's `ldr`; no `read_unaligned`
/// anywhere.
///
/// # Safety
///
/// `handle` may be NULL (guarded, like the original). When non-NULL it
/// must be readable through +0x4, and a non-NULL element at +0x0 must be
/// readable through the slot table at +0x3ac and the map cache at +0x470
/// through the post-normalization selector. Any non-NULL slot word must
/// be readable by the map builder (slot+0xc count, slot+0x10 items).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_slot_item_position")]
pub unsafe extern "C" fn ui_plst_slot_item_position(
    handle: *mut u8,
    selector: u32,
    reverse_flag: u32,
) -> u32 {
    if handle.is_null() || selector == 0 {
        return u32::MAX;
    }
    // Pointer fields are 32-bit target words: read u32 and widen.
    let element = handle.cast::<u32>().read() as usize as *mut u8;
    let peer = handle.add(4).cast::<u32>().read() as usize as *mut u8;
    if element.is_null() || peer.is_null() {
        return u32::MAX;
    }
    let mut selector = selector;
    let mut reverse_flag = reverse_flag as u8;
    let ops = slot_position_ops();
    (ops.normalize_selector)(element, &mut selector, &mut reverse_flag);
    let mut map = read_table_word(element, POSITION_MAP_TABLE_OFFSET, selector);
    if map.is_null() && selector != 0 && selector < SLOT_COUNT {
        if (ops.materialize_slot)(element, selector) == 0 {
            let slot = read_table_word(element, SLOT_TABLE_OFFSET, selector);
            map = (ops.build_position_map)(slot);
            element
                .add(POSITION_MAP_TABLE_OFFSET)
                .cast::<u32>()
                .add(selector as usize)
                .write(map as u32);
        }
        map = read_table_word(element, POSITION_MAP_TABLE_OFFSET, selector);
    }
    if map.is_null() {
        return u32::MAX;
    }
    (ops.slot_index_of)(handle, map, u32::from(reverse_flag))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // Slab layout: handle @ +0x0000, element @ +0x1000, slot block @
    // +0x2000, canned sorted map @ +0x2400.
    const HANDLE_OFF: usize = 0x0000;
    const ELEMENT_OFF: usize = 0x1000;
    const SLOT_OFF: usize = 0x2000;
    const MAP_OFF: usize = 0x2400;
    const SLAB_BYTES: usize = 0x8000;

    static mut NORMALIZE_CALLS: u32 = 0;
    static mut MATERIALIZE_CALLS: u32 = 0;
    static mut BUILD_CALLS: u32 = 0;
    static mut INDEX_OF_CALLS: u32 = 0;
    static mut LAST_MATERIALIZE_ELEMENT: *mut u8 = core::ptr::null_mut();
    static mut LAST_MATERIALIZE_SELECTOR: u32 = u32::MAX;
    static mut LAST_BUILD_SLOT: *mut u8 = core::ptr::null_mut();
    static mut LAST_INDEX_OF_KEY: *mut u8 = core::ptr::null_mut();
    static mut LAST_INDEX_OF_MAP: *mut u8 = core::ptr::null_mut();
    static mut LAST_INDEX_OF_FLAG: u32 = u32::MAX;
    static mut INDEX_OF_RESULT: u32 = 0;

    unsafe fn base() -> *mut u8 {
        match testing::try_map_u32_slab(testing::hints::PLST_SLOT_POSITION, SLAB_BYTES) {
            Some(p) => p,
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn write_word(addr: *mut u8, value: u32) {
        addr.cast::<u32>().write(value);
    }

    unsafe fn handle(base: *mut u8) -> *mut u8 {
        base.add(HANDLE_OFF)
    }

    unsafe fn element(base: *mut u8) -> *mut u8 {
        base.add(ELEMENT_OFF)
    }

    /// Builds a handle {element, peer} and a zeroed element. The whole
    /// slab is zeroed so the out-of-table word a selector >= 49 reads
    /// (the original checks the bound only AFTER the cache load) is a
    /// deterministic NULL.
    unsafe fn make_handle(base: *mut u8) {
        core::ptr::write_bytes(base, 0, SLAB_BYTES);
        let element = element(base);
        write_word(handle(base), element as u32);
        // Peer pointer: any non-NULL word; the function never reads it.
        write_word(handle(base).add(4), base.add(SLOT_OFF) as u32);
    }

    unsafe fn set_map(base: *mut u8, selector: u32, map: *mut u8) {
        write_word(
            element(base).add(POSITION_MAP_TABLE_OFFSET + selector as usize * 4),
            map as u32,
        );
    }

    unsafe fn canned_map(base: *mut u8) -> *mut u8 {
        base.add(MAP_OFF)
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

    unsafe extern "C" fn mock_materialize_fail(element: *mut u8, selector: u32) -> u32 {
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
        let slot = element.sub(ELEMENT_OFF).add(SLOT_OFF);
        write_word(
            element.add(SLOT_TABLE_OFFSET + selector as usize * 4),
            slot as u32,
        );
        0
    }

    unsafe extern "C" fn mock_build_canned_map(slot: *mut u8) -> *mut u8 {
        BUILD_CALLS += 1;
        LAST_BUILD_SLOT = slot;
        // The slot fixture lives at +0x2000 within the slab.
        slot.sub(SLOT_OFF).add(MAP_OFF)
    }

    unsafe extern "C" fn mock_index_of(key: *mut u8, map: *mut u8, reverse_flag: u32) -> u32 {
        INDEX_OF_CALLS += 1;
        LAST_INDEX_OF_KEY = key;
        LAST_INDEX_OF_MAP = map;
        LAST_INDEX_OF_FLAG = reverse_flag;
        INDEX_OF_RESULT
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: PlstSlotPositionOps,
        base: *mut u8,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                PLST_SLOT_POSITION_OPS = self.previous_ops;
            }
        }
    }

    fn bench(ops: PlstSlotPositionOps) -> Option<Bench> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = unsafe { base() };
        if base.is_null() {
            testing::note_missing_u32_fixture("ui::plst_slot_position");
            return None;
        }
        let previous_ops = unsafe { PLST_SLOT_POSITION_OPS };
        unsafe {
            NORMALIZE_CALLS = 0;
            MATERIALIZE_CALLS = 0;
            BUILD_CALLS = 0;
            INDEX_OF_CALLS = 0;
            LAST_MATERIALIZE_ELEMENT = core::ptr::null_mut();
            LAST_MATERIALIZE_SELECTOR = u32::MAX;
            LAST_BUILD_SLOT = core::ptr::null_mut();
            LAST_INDEX_OF_KEY = core::ptr::null_mut();
            LAST_INDEX_OF_MAP = core::ptr::null_mut();
            LAST_INDEX_OF_FLAG = u32::MAX;
            INDEX_OF_RESULT = 0;
            PLST_SLOT_POSITION_OPS = ops;
        }
        Some(Bench {
            _lock: lock,
            previous_ops,
            base,
        })
    }

    fn failing_ops() -> PlstSlotPositionOps {
        PlstSlotPositionOps {
            normalize_selector: mock_normalize_passthrough,
            materialize_slot: mock_materialize_fail,
            build_position_map: mock_build_canned_map,
            slot_index_of: mock_index_of,
        }
    }

    #[test]
    fn null_handle_returns_minus_one_without_touching_seams() {
        let Some(_bench) = bench(failing_ops()) else {
            return;
        };
        assert_eq!(
            unsafe { ui_plst_slot_item_position(core::ptr::null_mut(), 5, 0) },
            u32::MAX
        );
        assert_eq!(
            unsafe { (NORMALIZE_CALLS, MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS) },
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn null_element_returns_minus_one() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            write_word(handle(bench.base), 0);
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 5, 0), u32::MAX);
            assert_eq!(NORMALIZE_CALLS, 0);
        }
    }

    #[test]
    fn null_peer_returns_minus_one() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            write_word(handle(bench.base).add(4), 0);
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 5, 0), u32::MAX);
            assert_eq!(NORMALIZE_CALLS, 0);
        }
    }

    #[test]
    fn zero_selector_returns_minus_one() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            set_map(bench.base, 1, canned_map(bench.base));
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 0, 0), u32::MAX);
            assert_eq!(
                (NORMALIZE_CALLS, MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS),
                (0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn cached_map_searches_handle_and_returns_index_verbatim() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            let map = canned_map(bench.base);
            set_map(bench.base, 5, map);
            INDEX_OF_RESULT = 7;
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 5, 0), 7);
            assert_eq!(LAST_INDEX_OF_KEY, handle(bench.base));
            assert_eq!(LAST_INDEX_OF_MAP, map);
            assert_eq!(LAST_INDEX_OF_FLAG, 0);
            // A not-found -1 from the search passes through unchanged.
            INDEX_OF_RESULT = u32::MAX;
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 5, 0), u32::MAX);
            assert_eq!(INDEX_OF_CALLS, 2);
            assert_eq!((MATERIALIZE_CALLS, BUILD_CALLS), (0, 0));
        }
    }

    #[test]
    fn only_the_low_byte_of_the_flag_word_reaches_the_search() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            set_map(bench.base, 5, canned_map(bench.base));
            ui_plst_slot_item_position(handle(bench.base), 5, 0x1ff);
            assert_eq!(LAST_INDEX_OF_FLAG, 0xff);
            ui_plst_slot_item_position(handle(bench.base), 5, 0x100);
            assert_eq!(LAST_INDEX_OF_FLAG, 0);
        }
    }

    #[test]
    fn materialize_failure_returns_minus_one_without_building() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            let element = element(bench.base);
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 7, 0), u32::MAX);
            assert_eq!((MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS), (1, 0, 0));
            assert_eq!(LAST_MATERIALIZE_ELEMENT, element);
            assert_eq!(LAST_MATERIALIZE_SELECTOR, 7);
        }
    }

    #[test]
    fn out_of_range_selector_skips_materialize() {
        let Some(bench) = bench(failing_ops()) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            // Selector 49 hits the post-normalization `cmpne r5, #0x31;
            // bcs` bound: the cache load still happens (it precedes the
            // bound check in the original) but no materialize/build does.
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 49, 0), u32::MAX);
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 60, 0), u32::MAX);
            assert_eq!((NORMALIZE_CALLS, MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS), (2, 0, 0, 0));
        }
    }

    #[test]
    fn successful_materialize_builds_caches_and_searches() {
        let Some(bench) = bench(PlstSlotPositionOps {
            normalize_selector: mock_normalize_passthrough,
            materialize_slot: mock_materialize_populate,
            build_position_map: mock_build_canned_map,
            slot_index_of: mock_index_of,
        }) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            let element = element(bench.base);
            let slot = bench.base.add(SLOT_OFF);
            let map = canned_map(bench.base);
            INDEX_OF_RESULT = 3;
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 7, 0), 3);
            assert_eq!((MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS), (1, 1, 1));
            assert_eq!(LAST_BUILD_SLOT, slot);
            assert_eq!(LAST_INDEX_OF_MAP, map);
            // The built map is cached at element+0x470+selector*4.
            assert_eq!(
                element
                    .add(POSITION_MAP_TABLE_OFFSET + 7 * 4)
                    .cast::<u32>()
                    .read(),
                map as u32
            );
            // A second lookup hits the cache: no new materialize/build.
            INDEX_OF_RESULT = 9;
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 7, 0), 9);
            assert_eq!((MATERIALIZE_CALLS, BUILD_CALLS, INDEX_OF_CALLS), (1, 1, 2));
        }
    }

    #[test]
    fn normalizer_rewrites_selector_and_clears_flag() {
        let Some(bench) = bench(PlstSlotPositionOps {
            normalize_selector: mock_normalize_remap,
            ..failing_ops()
        }) else {
            return;
        };
        unsafe {
            make_handle(bench.base);
            set_map(bench.base, 4, canned_map(bench.base));
            INDEX_OF_RESULT = 2;
            // Selector 0x34 remaps to slot 4; the cleared flag reaches
            // the search as 0 despite reverse_flag = 1.
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 0x34, 1), 2);
            assert_eq!(LAST_INDEX_OF_FLAG, 0);
            assert_eq!(ui_plst_slot_item_position(handle(bench.base), 0x37, 1), 2);
        }
    }
}
