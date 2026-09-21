//! context_index_matches_context_field_f40 — original: `FUN_082982e4` @
//! **0x082982e4** (12 bytes; **3 plain unconditional inbound `bl` call
//! sites**, zero predicated forms, verified by decoding every A32 branch word
//! in `osos.dec`: 0x08111990, 0x08114648, and 0x081151f4).
//!
//! Raw ARM is `ldr r0,[r0,#0x30]; add r1,r1,#1; b 0x08059c08` at
//! `0x082982e4..0x082982ef`; `0x082982f0` begins the next real function with
//! `push {lr}`. The tail target loads the opaque context's word at +0xf64 as
//! an index-table pointer, loads the context word at +0xf40, and returns 1
//! exactly when table[index + 1] equals that word.
//!
//! Deliberate deviation: the unnamed, unported tail target at `0x08059c08` is
//! inlined rather than introduced as a speculative Rust seam. The pointer
//! fields remain target-width u32 words, preserving their four-byte offsets
//! on both ARM and 64-bit host tests.

const OBJECT_CONTEXT_OFFSET: usize = 0x30;
const CONTEXT_SELECTED_WORD_OFFSET: usize = 0x0f40;
const CONTEXT_INDEX_TABLE_OFFSET: usize = 0x0f64;

/// Compares the context's selected word with its one-based index-table entry.
///
/// # Safety
///
/// `object` must be non-NULL, four-byte aligned, and readable through +0x30.
/// Its target-width context pointer must designate a readable context through
/// +0xf64, whose target-width table pointer must designate a readable u32 at
/// `index + 1`. These are the exact unchecked A32 load preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_index_matches_context_field_f40(
    object: *const u8,
    index: u32,
) -> u32 {
    let context = unsafe { object.add(OBJECT_CONTEXT_OFFSET).cast::<u32>().read() as usize as *const u8 };
    let index_table = unsafe {
        context
            .add(CONTEXT_INDEX_TABLE_OFFSET)
            .cast::<u32>()
            .read() as usize as *const u32
    };
    let selected = unsafe { context.add(CONTEXT_SELECTED_WORD_OFFSET).cast::<u32>().read() };
    u32::from(unsafe { index_table.add(index as usize + 1).read() } == selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x2000;
    const CONTEXT_OFFSET: usize = 0x100;
    const TABLE_OFFSET: usize = 0x1100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTEXT_INDEX_MATCHES_CONTEXT_FIELD_F40, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn compares_the_one_based_index_entry_against_the_context_word() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture(
                "app::context_index_matches_context_field_f40"
            ));
            return;
        };
        let base = base as *mut u8;
        let mut object = [0u32; (OBJECT_CONTEXT_OFFSET / 4) + 1];
        let context = unsafe { base.add(CONTEXT_OFFSET) };
        let table = unsafe { base.add(TABLE_OFFSET).cast::<u32>() };

        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            object[OBJECT_CONTEXT_OFFSET / 4] = context as usize as u32;
            context.add(CONTEXT_SELECTED_WORD_OFFSET).cast::<u32>().write(0x7a5c_1122);
            context.add(CONTEXT_INDEX_TABLE_OFFSET).cast::<u32>().write(table as usize as u32);
            table.add(0).write(0x7a5c_1122);
            table.add(1).write(0);
            table.add(2).write(0x7a5c_1122);
            table.add(3).write(0x7a5c_1123);

            assert_eq!(
                context_index_matches_context_field_f40(object.as_ptr().cast(), 0),
                0,
                "index zero selects table[1], not table[0]"
            );
            assert_eq!(context_index_matches_context_field_f40(object.as_ptr().cast(), 1), 1);
            assert_eq!(context_index_matches_context_field_f40(object.as_ptr().cast(), 2), 0);
        }
    }
}
