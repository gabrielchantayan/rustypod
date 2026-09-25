//! Selects the first flag-0x20 'plst' element attached to a UI context.
//!
//! - `ui_tdat_flagged_plst` — original: `FUN_080561b4` @ 0x080561b4
//!   (76 bytes; 3 direct `bl` call sites, 0 predicated, verified from
//!   `osos.dec`).

use crate::ui::plst_next::ui_plst_next;
use crate::ui::tdat_first_plst::ui_tdat_first_plst;

/// Cached selected element (`ldr r1,[r0,#0xf48]`).
const CACHED_PLST_OFFSET: usize = 0xf48;
/// 'tdat' element whose linked 'plst' sequence is searched (`ldr r0,[r0,#0xf60]`).
const TDAT_ELEMENT_OFFSET: usize = 0xf60;
/// Flag byte which marks the selected 'plst' element (`tst r1,#0x20`).
const SELECTED_FLAG_OFFSET: usize = 0x1ac;
const SELECTED_FLAG: u8 = 0x20;

/// ui_tdat_flagged_plst — original: `FUN_080561b4` @ `0x080561b4` (76 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x080561b4..0x08056200`; the next separately linked function begins with
/// `ldr r1,[pc,#...]` at `0x08056200`, confirming the 76-byte extent:
///
/// ```text
/// 080561b4  push {r4,lr}
/// 080561b8  ldr r1,[r0,#0xf48]
/// 080561bc  cmp r1,#0
/// 080561c0  movne r0,r1
/// 080561c4  popne {r4,pc}
/// 080561c8  ldr r0,[r0,#0xf60]
/// 080561cc  bl 0x080522d4         ; ui_tdat_first_plst
/// 080561d0  b 0x080561e4
/// 080561d4  ldrb r1,[r0,#0x1ac]
/// 080561d8  tst r1,#0x20
/// 080561dc  bne 0x080561f0
/// 080561e0  bl 0x08053bd0         ; ui_plst_next
/// 080561e4  cmp r0,#0
/// 080561e8  bne 0x080561d4
/// 080561ec  b 0x080561f8
/// 080561f0  cmp r0,#0
/// 080561f4  popne {r4,pc}
/// 080561f8  mov r0,#0
/// 080561fc  pop {r4,pc}
/// ```
///
/// Algorithm: return the cached element word at `context + 0xf48` when it is
/// nonzero. Otherwise obtain the first linked 'plst' element from the 'tdat'
/// element word at `context + 0xf60`, follow `ui_plst_next`, and return the
/// first nonzero element whose byte at +0x1ac has bit 0x20 set; return zero
/// when the sequence is empty or no element is marked.
///
/// Inbound call count, independently decoded from ARM `bl` words in
/// `osos.dec`: 3 unconditional sites (0x080537c0, 0x0809dfa0, 0x0811369c),
/// zero predicated sites. Deliberate deviations: none. The two ported selector
/// seams replace branches to their retailOS addresses; target-width pointer
/// words, aligned word loads, and byte flag loads retain the original layout.
///
/// # Safety
///
/// `context` must be non-NULL and readable through +0xf63. If its cached word
/// is zero, the `context + 0xf60` word must name a valid 'tdat' element and
/// every traversed 'plst' element must satisfy `ui_plst_next`'s safety
/// requirements and be readable through +0x1ac.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_tdat_flagged_plst(context: *const u8) -> u32 {
    let cached = unsafe { context.add(CACHED_PLST_OFFSET).cast::<u32>().read() };
    if cached != 0 {
        return cached;
    }

    let tdat = unsafe { context.add(TDAT_ELEMENT_OFFSET).cast::<u32>().read() };
    let mut element = unsafe { ui_tdat_first_plst(tdat as *const u8) };
    while element != 0 {
        let element_ptr = element as *const u8;
        if unsafe { element_ptr.add(SELECTED_FLAG_OFFSET).read() } & SELECTED_FLAG != 0 {
            return element;
        }
        element = unsafe { ui_plst_next(element_ptr) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const SLAB_BYTES: usize = 0x4000;
    const TDAT_OFFSET: usize = 0x1000;
    const FIRST_PLST_OFFSET: usize = 0x2000;
    const SECOND_PLST_OFFSET: usize = 0x3000;
    const TDAT_TAG: u32 = 0x7464_6174;
    const PLST_TAG: u32 = 0x706c_7374;

    static FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::TDAT_FLAGGED_PLST, SLAB_BYTES)
            .map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<*mut u8> {
        (*FIXTURE).map(|pointer| pointer as *mut u8)
    }

    unsafe fn word(object: *mut u8, offset: usize, value: u32) {
        object.add(offset).cast::<u32>().write(value);
    }

    unsafe fn setup() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = fixture()?;
        core::ptr::write_bytes(base, 0, SLAB_BYTES);
        let context = base;
        let tdat = base.add(TDAT_OFFSET);
        let first = base.add(FIRST_PLST_OFFSET);
        let second = base.add(SECOND_PLST_OFFSET);
        word(tdat, 4, TDAT_TAG);
        word(first, 4, PLST_TAG);
        word(second, 4, PLST_TAG);
        word(context, TDAT_ELEMENT_OFFSET, tdat as usize as u32);
        word(tdat, 0x34, first as usize as u32);
        Some((context, tdat, first, second))
    }

    macro_rules! locked_fixture {
        () => {{
            let guard = FIXTURE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(objects) = (unsafe { setup() }) else {
                assert!(crate::testing::note_missing_u32_fixture(module_path!()));
                return;
            };
            (guard, objects)
        }};
    }

    #[test]
    fn nonzero_cached_element_bypasses_the_sequence() {
        let (_guard, (context, tdat, _first, _second)) = locked_fixture!();
        unsafe {
            word(context, CACHED_PLST_OFFSET, 0xdead_beef);
            word(tdat, 4, 0);
            assert_eq!(ui_tdat_flagged_plst(context), 0xdead_beef);
        }
    }

    #[test]
    fn finds_the_first_marked_element_after_unmarked_predecessors() {
        let (_guard, (context, _tdat, first, second)) = locked_fixture!();
        unsafe {
            word(first, 0x24, second as usize as u32);
            first.add(SELECTED_FLAG_OFFSET).write(0x9f);
            second.add(SELECTED_FLAG_OFFSET).write(SELECTED_FLAG | 0x04);
            assert_eq!(ui_tdat_flagged_plst(context), second as usize as u32);
        }
    }

    #[test]
    fn returns_zero_when_no_linked_element_is_marked() {
        let (_guard, (context, _tdat, first, second)) = locked_fixture!();
        unsafe {
            word(first, 0x24, second as usize as u32);
            first.add(SELECTED_FLAG_OFFSET).write(0x1f);
            second.add(SELECTED_FLAG_OFFSET).write(0xdf);
            assert_eq!(ui_tdat_flagged_plst(context), 0);
        }
    }

    #[test]
    fn invalid_tdat_element_has_no_sequence() {
        let (_guard, (context, tdat, _first, _second)) = locked_fixture!();
        unsafe {
            word(tdat, 4, PLST_TAG);
            assert_eq!(ui_tdat_flagged_plst(context), 0);
        }
    }
}
