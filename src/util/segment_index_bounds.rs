//! Segment index bounds — `FUN_081bac38` @ load address `0x081bac38`.
//!
//! Raw `osos.dec` words establish the exact 80-byte A32 extent
//! `0x081bac38..0x081bac84`; the next real function starts at `0x081bac88`.
//! A full-image aligned A32 decode finds three inbound plain `bl` sites
//! (`0x081babf4`, `0x081bad34`, and `0x081bafa8`), no predicated `bl` forms,
//! and two outbound plain `bl` calls to `0x081bad78`.
//!
//! Algorithm: copy the four-word default bounds at provider +0x80 into
//! `bounds`; when context +0x1e4 is at least two, replace words zero and two
//! with the offsets for `index` and `index + 1`.
//!
//! Deliberate deviation: the hidden r3 fallback of the now-ported resolver is
//! passed explicitly from the provider's third default bounds word. The raw
//! caller keeps that word in r3 across both resolver calls.

/// Returns the bounds for `index` from `context`.
///
/// # Safety
///
/// `bounds` must point to four writable words. `context` must expose target-layout
/// words at +0xec and +0x1e4; the provider named by +0xec must expose four readable
/// words at +0x80. When context +0x1e4 is at least two, its embedded observable
/// array and offset fields must satisfy segment_index_offset's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.segment_index_bounds")]
pub unsafe extern "C" fn segment_index_bounds(bounds: *mut u32, context: *mut u8, index: u32) {
    let provider = unsafe { core::ptr::read(context.add(0xec).cast::<u32>()) as usize as *mut u8 };
    unsafe { core::ptr::copy_nonoverlapping(provider.add(0x80).cast::<u32>(), bounds, 4) };
    if unsafe { core::ptr::read(context.add(0x1e4).cast::<u32>()) } >= 2 {
        let fallback = unsafe { core::ptr::read(bounds.add(2)) };
        unsafe { core::ptr::write(bounds, super::segment_index_offset::segment_index_offset(context, index, 0, fallback)) };
        unsafe { core::ptr::write(bounds.add(2), super::segment_index_offset::segment_index_offset(context, index.wrapping_add(1), 0, fallback)) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const PROVIDER_OFFSET: usize = 0x400;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SEGMENT_INDEX_BOUNDS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, *mut u8)> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((base, base.add(PROVIDER_OFFSET)))
        }
    }

    #[test]
    fn copies_default_bounds_without_resolving_single_segment_context() {
        let _lock = LOCK.lock();
        let Some((context, provider)) = fixture() else { return; };
        unsafe {
            provider.add(0x80).cast::<[u32; 4]>().write([11, 22, 33, 44]);
            context.add(0xec).cast::<u32>().write(provider as usize as u32);
            context.add(0x1e4).cast::<u32>().write(1);
            let mut bounds = [0; 4];
            segment_index_bounds(bounds.as_mut_ptr(), context, 19);
            assert_eq!(bounds, [11, 22, 33, 44]);
        }
    }

    #[test]
    fn resolves_first_and_third_bounds_for_multi_segment_context() {
        let _lock = LOCK.lock();
        let Some((context, provider)) = fixture() else { return; };
        unsafe {
            provider.add(0x80).cast::<[u32; 4]>().write([11, 22, 33, 44]);
            context.add(0xec).cast::<u32>().write(provider as usize as u32);
            context.add(0x1e4).cast::<u32>().write(2);
            use crate::cxx::observable_array::{ObservableArray, ObservableArrayReadHost, ObservableArrayReadVtable};
            unsafe extern "C" fn read(_: *mut ObservableArray, index: i32, output: *mut u8) -> u32 {
                output.cast::<u32>().write([7, 17][index as usize]);
                0
            }
            let vtable = ObservableArrayReadVtable { unresolved_00_a0: [0; 41], read_element: read };
            context.add(0x1e0).cast::<ObservableArrayReadHost>().write(
                ObservableArrayReadHost { vtable: &vtable, len: 2 },
            );
            context.add(0x100).cast::<u32>().write(u32::MAX);
            context.add(0x80).cast::<u32>().write(100);
            let mut bounds = [0; 4];
            segment_index_bounds(bounds.as_mut_ptr(), context, u32::MAX);
            assert_eq!(bounds, [107, 22, 117, 44]);
        }
    }
}
