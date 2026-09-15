//! `opaque_record_source_entry_count` — original: `FUN_0827b308` @ `0x0827b308`
//! (20 bytes, `0x0827b308..0x0827b31c`).
//!
//! Raw ARM establishes the next real function boundary at `0x0827b31c`:
//!
//! ```text
//! 0827b308  ldr   r0, [r0, #4]
//! 0827b30c  cmp   r0, #0
//! 0827b310  moveq r0, #0
//! 0827b314  bne   0x081c1cdc
//! 0827b318  bx    lr
//! ```
//!
//! A whole-image ARM immediate-branch scan finds five inbound direct `bl` call
//! sites, all plain unconditional (`0x081a1948`, `0x081a19c0`, `0x081a1a64`,
//! `0x081a1a78`, and `0x0827b4d4`); there are no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Return `-1` when the record source's provider word at `+0x04` is null.
//! Otherwise tail-transfer to the unported `FUN_081c1cdc`, which raw code and
//! its decompilation establish as loading the signed entry count from
//! `provider[0x1c] + 4`.
//!
//! # Deliberate deviations
//!
//! The target tail branch is represented by its verified three-load result
//! rather than inventing a Rust seam for the still-unnamed `FUN_081c1cdc`.

const PROVIDER_OFFSET: usize = 0x04;
const PROVIDER_COUNT_STATE_OFFSET: usize = 0x1c;
const COUNT_OFFSET: usize = 0x04;

/// Returns a record source's signed entry count, or `-1` with no provider.
///
/// # Safety
///
/// `source` must identify readable, aligned target storage through `+0x04`.
/// When that word is nonzero, it and its `+0x1c` state word must identify
/// readable, aligned target storage through the count at `+0x04`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_source_entry_count")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_source_entry_count(source: *const u8) -> i32 {
    let provider = unsafe { source.add(PROVIDER_OFFSET).cast::<u32>().read() };
    if provider == 0 {
        return -1;
    }

    let count_state = unsafe {
        ((provider as usize).wrapping_add(PROVIDER_COUNT_STATE_OFFSET) as *const u8)
            .cast::<u32>()
            .read()
    };
    unsafe {
        ((count_state as usize).wrapping_add(COUNT_OFFSET) as *const u8)
            .cast::<i32>()
            .read()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const PROVIDER_OFFSET_IN_FIXTURE: usize = 0x100;
    const STATE_OFFSET_IN_FIXTURE: usize = 0x200;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_RECORD_SOURCE_ENTRY_COUNT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        let source = base;
        let provider = unsafe { base.add(PROVIDER_OFFSET_IN_FIXTURE) };
        let state = unsafe { base.add(STATE_OFFSET_IN_FIXTURE) };
        Some((source, provider, state, guard))
    }

    #[test]
    fn null_provider_returns_negative_one() {
        let Some((source, _, _, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_record_source_entry_count"));
            return;
        };

        assert_eq!(unsafe { opaque_record_source_entry_count(source) }, -1);
    }

    #[test]
    fn returns_signed_count_from_provider_state() {
        let Some((source, provider, state, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_record_source_entry_count"));
            return;
        };
        unsafe {
            source.add(PROVIDER_OFFSET).cast::<u32>().write(provider as usize as u32);
            provider
                .add(PROVIDER_COUNT_STATE_OFFSET)
                .cast::<u32>()
                .write(state as usize as u32);
            state.add(COUNT_OFFSET).cast::<i32>().write(-2);
        }

        assert_eq!(unsafe { opaque_record_source_entry_count(source) }, -2);
    }
}
