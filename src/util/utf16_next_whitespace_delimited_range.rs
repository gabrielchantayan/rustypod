//! utf16_next_whitespace_delimited_range — retailOS `FUN_081ee278` @
//! 0x081ee278 (116 bytes).
//!
//! Raw decoding establishes the 29-instruction body from 0x081ee278 through
//! 0x081ee2e8; the next distinct function starts at 0x081ee2ec. It has four
//! direct `bl` call sites, all unconditional (zero predicated `bl` sites):
//! `FUN_081ee250`, `FUN_081ee228`, and the shared two-word range store/copy
//! leaves at 0x081bb69c and 0x081bb6a4.
//!
//! Algorithm: when the cursor at state +0x08 is non-NULL and lies below the
//! UTF-16 end pointer at +0x04, skip U+0020 and U+0009, then return the next
//! non-whitespace span and advance the cursor to its end. An exhausted or
//! invalid cursor returns the empty range without changing state.
//!
//! Deliberate deviation: the three tiny direct callees are inlined. Their raw
//! bodies are simple scans and two-word stores, so a dispatch seam would add
//! no observable behavior.

/// Target-width `{begin, end}` UTF-16 range.
#[repr(C)]
pub struct Utf16Range {
    pub begin: u32,
    pub end: u32,
}

/// Target-width state consumed by [`utf16_next_whitespace_delimited_range`].
#[repr(C)]
pub struct Utf16TokenCursor {
    pub reserved: u32,
    pub end: u32,
    pub cursor: u32,
}

/// Return the next space/tab-delimited UTF-16 range and advance `state`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn utf16_next_whitespace_delimited_range(
    out: *mut Utf16Range,
    state: *mut Utf16TokenCursor,
) {
    let end = (*state).end;
    let mut cursor = (*state).cursor;

    if cursor != 0 && cursor < end {
        while cursor < end && matches!(*(cursor as *const u16), 0x20 | 9) {
            cursor += 2;
        }
        let token_begin = cursor;
        while cursor < end && !matches!(*(cursor as *const u16), 0x20 | 9) {
            cursor += 2;
        }
        (*out).begin = token_begin;
        (*out).end = cursor;
        (*state).cursor = cursor;
    } else {
        (*out).begin = 0;
        (*out).end = 0;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const STATE_OFFSET: usize = 0x20;
    const OUT_OFFSET: usize = 0x40;
    const TEXT_OFFSET: usize = 0x100;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::UTF16_NEXT_WHITESPACE_DELIMITED_RANGE, SLAB_LEN)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut Utf16TokenCursor, *mut Utf16Range, *mut u16)> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        Some((
            base.add(STATE_OFFSET).cast(),
            base.add(OUT_OFFSET).cast(),
            base.add(TEXT_OFFSET).cast(),
        ))
    }

    #[test]
    fn skips_leading_space_and_tab_then_stops_at_space() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, out, text)) = (unsafe { fixture() }) else { return; };
        unsafe {
            text.copy_from_nonoverlapping([0x20, 9, b'a' as u16, b'b' as u16, 0x20].as_ptr(), 5);
            (*state).end = text.add(5) as usize as u32;
            (*state).cursor = text as usize as u32;
            utf16_next_whitespace_delimited_range(out, state);
            assert_eq!(((*out).begin, (*out).end), (text.add(2) as usize as u32, text.add(4) as usize as u32));
            assert_eq!((*state).cursor, text.add(4) as usize as u32);
        }
    }

    #[test]
    fn returns_empty_and_preserves_an_exhausted_cursor() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, out, text)) = (unsafe { fixture() }) else { return; };
        unsafe {
            (*state).end = text.add(2) as usize as u32;
            (*state).cursor = text.add(2) as usize as u32;
            (*out).begin = u32::MAX;
            (*out).end = u32::MAX;
            utf16_next_whitespace_delimited_range(out, state);
            assert_eq!(((*out).begin, (*out).end), (0, 0));
            assert_eq!((*state).cursor, text.add(2) as usize as u32);
        }
    }

    #[test]
    fn returns_empty_for_a_null_cursor() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, out, _)) = (unsafe { fixture() }) else { return; };
        unsafe {
            (*state).end = u32::MAX;
            (*state).cursor = 0;
            utf16_next_whitespace_delimited_range(out, state);
            assert_eq!(((*out).begin, (*out).end, (*state).cursor), (0, 0, 0));
        }
    }
}
