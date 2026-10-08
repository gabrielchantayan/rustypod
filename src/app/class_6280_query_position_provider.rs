//! `class_6280_query_position_provider` — `FUN_0811b95c` @ **0x0811b95c**.
//! True size: 16 bytes, ending at the next function's push at 0x0811b96c.
//! Raw firmware scan: two plain inbound BLs (0x0811b840, 0x0828e7dc),
//! zero predicated inbound BLs. Body: zero BLs, one indirect tail BX.
//! Loads the class-0x6280 position provider at +0x88, loads its vtable,
//! and tail-dispatches slot +0x20 with the provider as receiver. Both callers
//! consume r0, despite Ghidra declaring void. Preserve the full result word;
//! its units and the concrete virtual method identity remain unidentified.
//! Deviations: host vtable pointers widen with usize; opaque source words
//! remain u32. No target semantic deviations or invented callee seam.

pub type PositionProviderQuery = unsafe extern "C" fn(*mut PositionProvider) -> u32;

#[repr(C)]
pub struct PositionProviderVtable {
    pub unresolved_slots: [usize; 8],
    pub query: PositionProviderQuery,
}

#[repr(C)]
pub struct PositionProvider {
    pub vtable: *const PositionProviderVtable,
}

#[repr(C)]
pub struct Class6280ProviderSource {
    pub opaque_00_84: [u32; 34],
    pub provider: *mut PositionProvider,
}

const _: [u8; 0x88] = [0; core::mem::offset_of!(Class6280ProviderSource, provider)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(PositionProviderVtable, query)];

/// Queries the current provider, preserving its full return word.
///
/// # Safety
/// `source`, its provider and vtable must be valid and aligned. Slot +0x20
/// must accept the provider as its sole argument and return a word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6280_query_position_provider(
    source: *mut Class6280ProviderSource,
) -> u32 {
    let provider = (*source).provider;
    ((*(*provider).vtable).query)(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct ProviderState {
        base: PositionProvider,
        result: u32,
        queries: u32,
    }

    unsafe extern "C" fn query(provider: *mut PositionProvider) -> u32 {
        let state = &mut *provider.cast::<ProviderState>();
        state.queries += 1;
        state.result
    }

    #[test]
    fn preserves_zero_and_full_word_results_with_provider_side_effects() {
        let table = PositionProviderVtable { unresolved_slots: [0; 8], query };
        let mut state = ProviderState {
            base: PositionProvider { vtable: &table }, result: 0, queries: 0,
        };
        let mut source = Class6280ProviderSource {
            opaque_00_84: [0xa5a5_a5a5; 34], provider: &mut state.base,
        };
        for (i, result) in [0, 1, 0x8000_0000, u32::MAX].into_iter().enumerate() {
            state.result = result;
            assert_eq!(unsafe { class_6280_query_position_provider(&mut source) }, result);
            assert_eq!(state.queries, i as u32 + 1);
            assert_eq!(source.opaque_00_84, [0xa5a5_a5a5; 34]);
        }
    }

    #[test]
    fn reloads_provider_after_replacement() {
        let table = PositionProviderVtable { unresolved_slots: [0; 8], query };
        let mut first = ProviderState {
            base: PositionProvider { vtable: &table }, result: 17, queries: 0,
        };
        let mut second = ProviderState {
            base: PositionProvider { vtable: &table }, result: 93, queries: 0,
        };
        let mut source = Class6280ProviderSource {
            opaque_00_84: [0; 34], provider: &mut first.base,
        };
        assert_eq!(unsafe { class_6280_query_position_provider(&mut source) }, 17);
        source.provider = &mut second.base;
        assert_eq!(unsafe { class_6280_query_position_provider(&mut source) }, 93);
        assert_eq!((first.queries, second.queries), (1, 1));
    }
}
