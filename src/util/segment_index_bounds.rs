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
//! Deliberate deviations: the unported `0x081bad78` offset resolver is an
//! explicit address-named seam. On ARM it calls retailOS directly; host tests
//! replace it.

/// ABI of the unported segment offset resolver at `0x081bad78`.
pub type ResolveSegmentIndexOffset = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unresolved_segment_index_offset(_context: *mut u8, _index: u32) -> u32 { 0 }

/// Host boundary for the retailOS resolver at `0x081bad78`.
#[cfg(not(target_arch = "arm"))]
pub static mut RESOLVE_SEGMENT_INDEX_OFFSET: ResolveSegmentIndexOffset = unresolved_segment_index_offset;

#[cfg(target_arch = "arm")]
unsafe fn resolve_segment_index_offset(context: *mut u8, index: u32) -> u32 {
    let resolver: ResolveSegmentIndexOffset = unsafe { core::mem::transmute(0x081b_ad78usize) };
    unsafe { resolver(context, index) }
}

#[cfg(not(target_arch = "arm"))]
unsafe fn resolve_segment_index_offset(context: *mut u8, index: u32) -> u32 {
    unsafe { RESOLVE_SEGMENT_INDEX_OFFSET(context, index) }
}

/// Returns the bounds for `index` from `context`.
///
/// # Safety
///
/// `bounds` must point to four writable words. `context` must expose target-layout
/// words at +0xec and +0x1e4; the provider named by +0xec must expose four readable
/// words at +0x80. When context +0x1e4 is at least two, it must be valid for the
/// selected resolver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.segment_index_bounds")]
pub unsafe extern "C" fn segment_index_bounds(bounds: *mut u32, context: *mut u8, index: u32) {
    let provider = unsafe { core::ptr::read(context.add(0xec).cast::<u32>()) as usize as *mut u8 };
    unsafe { core::ptr::copy_nonoverlapping(provider.add(0x80).cast::<u32>(), bounds, 4) };
    if unsafe { core::ptr::read(context.add(0x1e4).cast::<u32>()) } >= 2 {
        unsafe { core::ptr::write(bounds, resolve_segment_index_offset(context, index)) };
        unsafe { core::ptr::write(bounds.add(2), resolve_segment_index_offset(context, index.wrapping_add(1))) };
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
    static mut CALLS: [(u32, u32); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_offset(context: *mut u8, index: u32) -> u32 {
        unsafe {
            CALLS[CALL_COUNT] = (context as usize as u32, index);
            CALL_COUNT += 1;
        }
        index.wrapping_mul(10).wrapping_add(7)
    }

    struct ResolverGuard(ResolveSegmentIndexOffset);

    impl Drop for ResolverGuard {
        fn drop(&mut self) {
            unsafe { RESOLVE_SEGMENT_INDEX_OFFSET = self.0 };
        }
    }

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
            CALL_COUNT = 0;
            let mut bounds = [0; 4];
            segment_index_bounds(bounds.as_mut_ptr(), context, 19);
            assert_eq!(bounds, [11, 22, 33, 44]);
            assert_eq!(CALL_COUNT, 0);
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
            CALL_COUNT = 0;
            let old = RESOLVE_SEGMENT_INDEX_OFFSET;
            RESOLVE_SEGMENT_INDEX_OFFSET = record_offset;
            let _restore = ResolverGuard(old);
            let mut bounds = [0; 4];
            segment_index_bounds(bounds.as_mut_ptr(), context, u32::MAX);
            assert_eq!(bounds, [4_294_967_293, 22, 7, 44]);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS, [(context as usize as u32, u32::MAX), (context as usize as u32, 0)]);
        }
    }
}
