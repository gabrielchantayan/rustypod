//! Segment cursor snapshot — `FUN_082974cc` @ load address `0x082974cc`.
//!
//! Raw `osos.dec` words establish the exact 104-byte A32 extent
//! `0x082974cc..0x08297530`; the next function starts at `0x08297534` with
//! `ldr ip, [pc, #8]`. Complete A32 branch decoding finds three inbound plain
//! `bl` calls (0x0814a454, 0x0814a558, and 0x083d37e0) and no predicated
//! `bl` calls. The body itself calls the unrecovered payload resolver at
//! `0x082142ec`, dynamically calls vtable slot +0x38 when `available` is
//! requested, and conditionally calls the cursor advance helper at
//! `0x08297588`.
//!
//! Algorithm: resolve the cursor's current payload (+0x0c), return that
//! resolver result and the current segment's +0x08 byte count, optionally
//! return the source's reported position less the cursor's +0x08 offset, then
//! optionally advance to the next segment. It always returns one.
//!
//! Deliberate deviations: the two unported direct callees are explicit
//! address-named seams. On ARM their defaults call the retailOS addresses;
//! host tests replace them. The dynamic vtable dispatch is likewise a host
//! seam because target vtable words are four bytes while host function
//! pointers are wider; ARM performs the literal +0x38 dispatch.

/// ABI of the unrecovered payload resolver at `0x082142ec`.
pub type ResolveSegmentPayload = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// ABI of the cursor advance helper at `0x08297588`.
pub type AdvanceSegmentCursor = unsafe extern "C" fn(*mut u8);

/// ABI of the source method at vtable slot +0x38.
pub type SourcePosition = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unresolved_segment_payload(_segment: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unresolved_cursor_advance(_cursor: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unresolved_source_position(_source: *mut u8) -> u32 { 0 }

/// Host boundary for the unported resolver at `0x082142ec`.
#[cfg(not(target_arch = "arm"))]
pub static mut RESOLVE_SEGMENT_PAYLOAD: ResolveSegmentPayload = unresolved_segment_payload;

/// Host boundary for the unported advance helper at `0x08297588`.
#[cfg(not(target_arch = "arm"))]
pub static mut ADVANCE_SEGMENT_CURSOR: AdvanceSegmentCursor = unresolved_cursor_advance;

/// Host boundary for the target's source vtable slot +0x38 dispatch.
#[cfg(not(target_arch = "arm"))]
pub static mut SOURCE_POSITION: SourcePosition = unresolved_source_position;

#[cfg(test)]
pub(crate) static SEGMENT_CURSOR_SNAPSHOT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(target_arch = "arm")]
unsafe fn resolve_segment_payload(segment: *mut u8) -> *mut u8 {
    let resolver: ResolveSegmentPayload = unsafe { core::mem::transmute(0x0821_42ecusize) };
    unsafe { resolver(segment) }
}

#[cfg(not(target_arch = "arm"))]
unsafe fn resolve_segment_payload(segment: *mut u8) -> *mut u8 {
    unsafe { RESOLVE_SEGMENT_PAYLOAD(segment) }
}

#[cfg(target_arch = "arm")]
unsafe fn source_position(source: *mut u8) -> u32 {
    let vtable = unsafe { core::ptr::read(source.cast::<*const u8>()) };
    let method: SourcePosition = unsafe { core::ptr::read(vtable.add(0x38).cast::<SourcePosition>()) };
    unsafe { method(source) }
}

#[cfg(not(target_arch = "arm"))]
unsafe fn source_position(source: *mut u8) -> u32 {
    unsafe { SOURCE_POSITION(source) }
}

#[cfg(target_arch = "arm")]
unsafe fn advance_segment_cursor(cursor: *mut u8) {
    let advance: AdvanceSegmentCursor = unsafe { core::mem::transmute(0x0829_7588usize) };
    unsafe { advance(cursor) }
}

#[cfg(not(target_arch = "arm"))]
unsafe fn advance_segment_cursor(cursor: *mut u8) {
    unsafe { ADVANCE_SEGMENT_CURSOR(cursor) }
}

/// Snapshots the current payload and byte count of `cursor`, optionally its
/// source availability, then optionally advances to the next segment.
///
/// # Safety
///
/// `cursor`, `payload`, and `byte_count` must be valid pointers. `cursor`
/// must expose readable target-layout words at +0x04/+0x08/+0x0c; its current
/// segment and source object must satisfy the selected resolver and vtable
/// method. When non-null, `available` must be writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.segment_cursor_snapshot")]
pub unsafe extern "C" fn segment_cursor_snapshot(
    cursor: *mut u8,
    payload: *mut *mut u8,
    byte_count: *mut u32,
    advance: u32,
    available: *mut u32,
) -> u32 {
    let segment = unsafe { core::ptr::read(cursor.add(0x0c).cast::<u32>()) as usize as *mut u8 };
    unsafe { core::ptr::write(payload, resolve_segment_payload(segment)) };
    unsafe { core::ptr::write(byte_count, core::ptr::read(segment.add(8).cast::<u32>())) };
    if !available.is_null() {
        let source = unsafe { core::ptr::read(cursor.add(4).cast::<u32>()) as usize as *mut u8 };
        let position = unsafe { source_position(source) };
        let offset = unsafe { core::ptr::read(cursor.add(8).cast::<u32>()) };
        unsafe { core::ptr::write(available, position.wrapping_sub(offset)) };
    }
    if advance != 0 {
        unsafe { advance_segment_cursor(cursor) };
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static FIXTURE_BASE: LazyLock<usize> = LazyLock::new(|| {
        try_map_u32_slab(hints::SEGMENT_CURSOR_SNAPSHOT, 48).map_or(0, |p| p as usize)
    });
    static mut RESOLVED_SEGMENT: usize = 0;
    static mut SEEN_SOURCE: usize = 0;
    static mut ADVANCED_CURSOR: usize = 0;
    static mut SOURCE_RESULT: u32 = 0;

    unsafe extern "C" fn resolve(segment: *mut u8) -> *mut u8 {
        unsafe { RESOLVED_SEGMENT = segment as usize };
        unsafe { segment.add(4) }
    }

    unsafe extern "C" fn position(source: *mut u8) -> u32 {
        unsafe { SEEN_SOURCE = source as usize };
        unsafe { SOURCE_RESULT }
    }

    unsafe extern "C" fn advance(cursor: *mut u8) {
        unsafe { ADVANCED_CURSOR = cursor as usize };
    }

    fn fixture() -> Option<(*mut u8, *mut u8, *mut u8)> {
        let base = *FIXTURE_BASE;
        if base == 0 {
            return None;
        }
        let cursor = base as *mut u8;
        let source = unsafe { cursor.add(16) };
        let segment = unsafe { cursor.add(32) };
        unsafe { core::ptr::write_bytes(cursor, 0, 48) };
        unsafe { core::ptr::write(segment.add(8).cast::<u32>(), 0x31) };
        unsafe { core::ptr::write(cursor.add(4).cast::<u32>(), source as usize as u32) };
        unsafe { core::ptr::write(cursor.add(8).cast::<u32>(), 0x11) };
        unsafe { core::ptr::write(cursor.add(12).cast::<u32>(), segment as usize as u32) };
        Some((cursor, source, segment))
    }

    #[test]
    fn snapshots_payload_and_count_without_optional_calls() {
        let _lock = SEGMENT_CURSOR_SNAPSHOT_TEST_LOCK.lock();
        let Some((cursor, _source, segment)) = fixture() else {
            note_missing_u32_fixture("util/segment_cursor_snapshot");
            return;
        };
        unsafe {
            RESOLVE_SEGMENT_PAYLOAD = resolve;
            SOURCE_POSITION = position;
            ADVANCE_SEGMENT_CURSOR = advance;
            RESOLVED_SEGMENT = 0;
            SEEN_SOURCE = 0;
            ADVANCED_CURSOR = 0;
        }
        let mut payload = core::ptr::null_mut();
        let mut count = 0;
        assert_eq!(unsafe { segment_cursor_snapshot(cursor, &mut payload, &mut count, 0, core::ptr::null_mut()) }, 1);
        assert_eq!(payload, unsafe { segment.add(4) });
        assert_eq!(count, 0x31);
        assert_eq!(unsafe { RESOLVED_SEGMENT }, segment as usize);
        assert_eq!(unsafe { SEEN_SOURCE }, 0);
        assert_eq!(unsafe { ADVANCED_CURSOR }, 0);
    }

    #[test]
    fn reports_wrapping_availability_then_advances() {
        let _lock = SEGMENT_CURSOR_SNAPSHOT_TEST_LOCK.lock();
        let Some((cursor, source, _segment)) = fixture() else {
            note_missing_u32_fixture("util/segment_cursor_snapshot");
            return;
        };
        unsafe {
            RESOLVE_SEGMENT_PAYLOAD = resolve;
            SOURCE_POSITION = position;
            ADVANCE_SEGMENT_CURSOR = advance;
            SOURCE_RESULT = 3;
            SEEN_SOURCE = 0;
            ADVANCED_CURSOR = 0;
        }
        let mut payload = core::ptr::null_mut();
        let mut count = 0;
        let mut available = 0;
        assert_eq!(unsafe { segment_cursor_snapshot(cursor, &mut payload, &mut count, 1, &mut available) }, 1);
        assert_eq!(available, 3u32.wrapping_sub(0x11));
        assert_eq!(unsafe { SEEN_SOURCE }, source as usize);
        assert_eq!(unsafe { ADVANCED_CURSOR }, cursor as usize);
    }
}
