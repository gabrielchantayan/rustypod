//! strided_buffer_entry_at — original: `FUN_08209768` @ `0x08209768` (**32
//! bytes**, `0x08209768..0x08209788`; the next separately linked function
//! begins with `push {r4, r5, r6, lr}` at `0x08209788`). **14 direct `bl`
//! call sites, all unconditional; no predicated `bl` or direct tail-branch**,
//! binary-scanned by decoding every ARM B/BL word in
//! `work/firmware/osos.dec`. No aligned DATA word names this entry.
//!
//! The table keeps its entry-buffer base at `+0x04` and a layout object at
//! `+0x0c`. The layout's vtable slot `+0x2c` yields the entry stride. This
//! accessor dispatches that slot with the layout object, then returns
//! `base + (index + 1) * stride`; the leading stride is the table header and
//! all arithmetic wraps at 32 bits, exactly as the ARM `add` / `mla` pair.
//!
//! `FUN_081d8614` is ported below as [`strided_buffer_entry_size`]. Both
//! routines dispatch the same dynamic vtable slot directly; no seam is added
//! because the target is a per-layout virtual method rather than a fixed
//! firmware callee. No deliberate deviations.

/// A layout vtable's recovered entry-stride selector (`+0x2c` on target).
pub type StridedBufferEntrySize = unsafe extern "C" fn(*const StridedBufferLayout) -> u32;

/// strided_buffer_entry_size — original: `FUN_081d8614` @ `0x081d8614` (16
/// bytes; true extent `0x081d8614..0x081d8624`; 4 plain `bl` callers and no
/// predicated `bl` callers, binary-scanned).
///
/// Loads the table's layout, then selects its vtable's `+0x2c` entry-size
/// method and tail-dispatches it with that layout pointer. The target is
/// dynamic, so this directly calls the recovered function pointer rather than
/// inventing a fixed-callee seam. No deliberate deviations.
///
/// # Safety
///
/// `table` must identify readable [`StridedBuffer`] storage whose `layout`
/// word identifies a readable [`StridedBufferLayout`] and vtable whose `+0x2c`
/// entry accepts that layout pointer. As in retailOS, neither pointer is
/// NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_buffer_entry_size(
    table: *const StridedBuffer,
) -> u32 {
    let layout = (*table).layout as usize as *const StridedBufferLayout;
    ((*(*layout).vtable).entry_size)(layout)
}

/// The table portion this accessor reads. Every field is a target-width word,
/// keeping the `+0x04` base and `+0x0c` layout link exact on 64-bit hosts.
#[repr(C)]
pub struct StridedBuffer {
    /// +0x00: unexamined by this accessor.
    pub opaque_00: u32,
    /// +0x04: first byte of the table's header.
    pub entry_buffer: u32,
    /// +0x08: unexamined by this accessor.
    pub opaque_08: u32,
    /// +0x0c: pointer to a vtable-bearing entry layout.
    pub layout: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(StridedBuffer, opaque_00)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(StridedBuffer, entry_buffer)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(StridedBuffer, layout)];
const _: [u8; 0x10] = [0; core::mem::size_of::<StridedBuffer>()];

/// The one-word layout object reached through [`StridedBuffer::layout`].
#[repr(C)]
pub struct StridedBufferLayout {
    /// +0x00: dynamic layout vtable.
    pub vtable: *const StridedBufferLayoutVtable,
}

/// The recovered portion of a strided-buffer layout vtable.
#[repr(C)]
pub struct StridedBufferLayoutVtable {
    /// Slots `+0x00..+0x28`, not decoded by this accessor.
    pub unresolved_00_28: [usize; 11],
    /// +0x2c: returns the byte stride of each entry.
    pub entry_size: StridedBufferEntrySize,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x2c] = [0; core::mem::offset_of!(StridedBufferLayoutVtable, entry_size)];

/// strided_buffer_entry_at — original: `FUN_08209768` @ `0x08209768` (32
/// bytes; 14 unconditional direct `bl` call sites, binary-scanned).
///
/// Returns the entry at `index` after the table header. Both the increment and
/// multiply follow the original's modulo-$2^{32}$ word arithmetic.
///
/// # Safety
///
/// `table` must point to readable [`StridedBuffer`] storage; its `layout` word
/// must identify a readable [`StridedBufferLayout`] and vtable whose `+0x2c`
/// entry accepts that layout pointer. As in retailOS, none of these pointers
/// is NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_buffer_entry_at(
    table: *const StridedBuffer,
    index: u32,
) -> u32 {
    let layout = (*table).layout as usize as *const StridedBufferLayout;
    let vtable = (*layout).vtable;
    let entry_size = ((*vtable).entry_size)(layout);

    (*table)
        .entry_buffer
        .wrapping_add(index.wrapping_add(1).wrapping_mul(entry_size))
}

/// The buffer vtable's recovered extent selector (`+0x08` on target).
#[repr(C)]
pub struct StridedBufferVtable {
    pub unresolved_00_04: [usize; 2],
    pub entry_count: unsafe extern "C" fn(*const StridedBuffer) -> u32,
}

/// strided_buffer_clear — original: `FUN_081d86d0` @ `0x081d86d0` (52
/// bytes; true extent `0x081d86d0..0x081d8704`). Raw whole-image ARM decoding
/// finds two incoming plain BLs (`0x08209664`, `0x08209804`), no predicated
/// BLs. Outbound: one BLX to vtable slot +8, one plain BL to entry_size,
/// and a tail B to the IRAM memzero veneer; no predicated calls.
///
/// Dispatches the buffer's entry-count method, obtains its layout's entry
/// size, and clears exactly their 32-bit wrapping product at entry_buffer.
/// Both selectors execute even for a zero product; the buffer pointer is
/// loaded only after both calls. No NULL checks. No behavioral deviations:
/// the known IRAM veneer and entry-size helper use their existing Rust ports.
/// The caller-visible API is void, as in Ghidra and both raw callers.
///
/// # Safety
///
/// `table` and its target-width vtable/layout links must be valid for the
/// recovered dispatches. The selected buffer must be writable for the
/// wrapped byte count. Callbacks must obey these same object invariants.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_buffer_clear(table: *const StridedBuffer) {
    let vtable = (*table).opaque_00 as usize as *const StridedBufferVtable;
    let count = ((*vtable).entry_count)(table);
    let size = strided_buffer_entry_size(table);
    let buffer = (*table).entry_buffer as usize as *mut u8;
    crate::libc::iram_veneers::iram_memzero_veneer(buffer, count.wrapping_mul(size) as usize);
}

/// strided_buffer_ensure_allocated — original: `FUN_081d8624` @
/// `0x081d8624` (104 bytes, true extent `0x081d8624..0x081d868c`).
/// Whole-image ARM decoding finds two incoming plain BLs at `0x081f4cb4`
/// and `0x081f4d1c`, zero predicated BLs. Outbound: three plain BLs
/// (operator_new, entry_size, aligned_buffer_init), zero predicated BLs,
/// and one virtual BLX through the buffer's vtable slot +8.
///
/// Returns zero immediately when the entry buffer is already installed.
/// Otherwise queries the entry count, allocates an eight-byte aligned-buffer
/// owner, queries the stride, and initializes the owner with their wrapping
/// u32 product. Stores the owner at +8 before copying its data word to +4.
/// Returns 25 if that word is zero, retaining the owner even on failure.
/// No deliberate deviations; all fixed callees use existing ports.
///
/// # Safety
///
/// `table` must be writable and its vtable/layout links valid for the
/// recovered selectors. The tag-2 owner allocation must succeed: retailOS
/// does not NULL-check it. Callbacks must preserve the object invariants.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_buffer_ensure_allocated(table: *mut StridedBuffer) -> u32 {
    if (*table).entry_buffer != 0 {
        return 0;
    }
    let vtable = (*table).opaque_00 as usize as *const StridedBufferVtable;
    let count = ((*vtable).entry_count)(table);
    let owner = crate::heap::veneers::operator_new(8);
    let stride = strided_buffer_entry_size(table);
    let owner = crate::heap::aligned_buffer::aligned_buffer_init(
        owner, count.wrapping_mul(stride) as usize,
    );
    (*table).opaque_08 = owner as u32;
    let data = owner.cast::<u32>().read_volatile();
    (*table).entry_buffer = data;
    if data == 0 { 25 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{strided_buffer_entry_at, strided_buffer_entry_size, StridedBuffer, StridedBufferLayout, StridedBufferLayoutVtable};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const LAYOUT_OFFSET: usize = 0x100;
    const BUFFER_OFFSET: usize = 0x400;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STRIDED_BUFFER_ENTRY, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static ENTRY_SIZE: AtomicU32 = AtomicU32::new(0);
    static SEEN_LAYOUT: AtomicUsize = AtomicUsize::new(0);
    static ENTRY_SIZE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn entry_size(layout: *const StridedBufferLayout) -> u32 {
        SEEN_LAYOUT.store(layout as usize, Ordering::SeqCst);
        ENTRY_SIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        ENTRY_SIZE.load(Ordering::SeqCst)
    }

    static VTABLE: StridedBufferLayoutVtable = StridedBufferLayoutVtable {
        unresolved_00_28: [0; 11],
        entry_size,
    };

    fn fixture() -> Option<(*mut StridedBuffer, *mut StridedBufferLayout, u32)> {
        let base = *SLAB.as_ref()? as *mut u8;
        let layout = unsafe { base.add(LAYOUT_OFFSET).cast::<StridedBufferLayout>() };
        let buffer = unsafe { base.add(BUFFER_OFFSET) };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            layout.write(StridedBufferLayout { vtable: &VTABLE });
            base.cast::<StridedBuffer>().write(StridedBuffer {
                opaque_00: 0x1122_3344,
                entry_buffer: buffer as u32,
                opaque_08: 0x5566_7788,
                layout: layout as u32,
            });
        }
        Some((base.cast(), layout, buffer as u32))
    }

    static COUNT: AtomicU32 = AtomicU32::new(0);
    static OWNER: AtomicUsize = AtomicUsize::new(0);
    static DATA: AtomicUsize = AtomicUsize::new(0);
    static REQUEST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn allocation_entry_count(_: *const StridedBuffer) -> u32 {
        COUNT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn allocate(
        _: *mut crate::heap::types::HeapDescriptorDescriptor, size: usize, tag: usize,
    ) -> *mut u8 {
        if tag == 2 {
            assert_eq!(size, 8);
            OWNER.load(Ordering::SeqCst) as *mut u8
        } else {
            assert_eq!(tag, 3);
            REQUEST.store(size, Ordering::SeqCst);
            DATA.load(Ordering::SeqCst) as *mut u8
        }
    }

    struct RestoreHeap(crate::heap::veneers::HeapVeneerOps);
    impl Drop for RestoreHeap {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write(self.0); }
        }
    }

    #[test]
    fn allocation_caches_success_wraps_sizes_and_retains_failed_owner() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some((table, _, _)) = fixture() else {
            note_missing_u32_fixture("app::strided_buffer_entry");
            return;
        };
        unsafe {
            let _restore = RestoreHeap(core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read());
            (*core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS)).alloc = allocate;
            let vtable = (table as *mut u8).add(0x200).cast::<super::StridedBufferVtable>();
            vtable.write(super::StridedBufferVtable { unresolved_00_04: [0; 2], entry_count: allocation_entry_count });
            (*table).opaque_00 = vtable as u32;
            let owner = (table as *mut u8).add(0x300);
            OWNER.store(owner as usize, Ordering::SeqCst);
            let raw = (table as *mut u8).add(0x501);
            for (count, stride, data) in [
                (3u32, 12u32, raw as usize),
                (0, 17, raw as usize),
                (0x8000_0001, 2, raw as usize),
                (5, 8, 0),
            ] {
                (*table).entry_buffer = 0;
                COUNT.store(count, Ordering::SeqCst);
                ENTRY_SIZE.store(stride, Ordering::SeqCst);
                DATA.store(data, Ordering::SeqCst);
                let status = super::strided_buffer_ensure_allocated(table);
                let expected = if data == 0 { 0 } else { (data as u32 + 31) & !31 };
                assert_eq!(status, if data == 0 { 25 } else { 0 });
                assert_eq!((*table).entry_buffer, expected);
                assert_eq!((*table).opaque_08, owner as u32);
                assert_eq!(owner.cast::<u32>().read(), expected);
                assert_eq!(owner.cast::<u32>().add(1).read(), data as u32);
                assert_eq!(REQUEST.load(Ordering::SeqCst), count.wrapping_mul(stride) as usize + 32);
                if data != 0 {
                    // Invalid dispatch links prove the cached path does not call selectors.
                    let saved = (*table).opaque_00;
                    (*table).opaque_00 = 0;
                    assert_eq!(super::strided_buffer_ensure_allocated(table), 0);
                    assert_eq!((*table).entry_buffer, expected);
                    assert_eq!((*table).opaque_08, owner as u32);
                    (*table).opaque_00 = saved;
                }
            }
            DATA.store(raw as usize, Ordering::SeqCst);
            assert_eq!(super::strided_buffer_ensure_allocated(table), 0);
            assert_ne!((*table).entry_buffer, 0, "failure remains retryable");
        }
    }

    #[test]
    fn dispatches_the_layout_entry_size_method_with_the_original_pointer() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((table, layout, _)) = fixture() else {
            note_missing_u32_fixture("app::strided_buffer_entry");
            return;
        };
        ENTRY_SIZE.store(0, Ordering::SeqCst);
        SEEN_LAYOUT.store(0, Ordering::SeqCst);
        ENTRY_SIZE_CALLS.store(0, Ordering::SeqCst);

        unsafe {
            assert_eq!(strided_buffer_entry_size(table), 0);
            ENTRY_SIZE.store(u32::MAX, Ordering::SeqCst);
            assert_eq!(strided_buffer_entry_size(table), u32::MAX);
        }
        assert_eq!(SEEN_LAYOUT.load(Ordering::SeqCst), layout as usize);
        assert_eq!(ENTRY_SIZE_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dispatches_layout_stride_and_uses_header_relative_wrapping_address() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((table, layout, buffer)) = fixture() else {
            note_missing_u32_fixture("app::strided_buffer_entry");
            return;
        };
        ENTRY_SIZE.store(0x38, Ordering::SeqCst);
        SEEN_LAYOUT.store(0, Ordering::SeqCst);
        ENTRY_SIZE_CALLS.store(0, Ordering::SeqCst);

        unsafe {
            assert_eq!(strided_buffer_entry_at(table, 0), buffer.wrapping_add(0x38));
            assert_eq!(strided_buffer_entry_at(table, 2), buffer.wrapping_add(0xa8));
            assert_eq!(strided_buffer_entry_at(table, u32::MAX), buffer);
        }
        assert_eq!(SEEN_LAYOUT.load(Ordering::SeqCst), layout as usize);
        assert_eq!(ENTRY_SIZE_CALLS.load(Ordering::SeqCst), 3);
    }

    unsafe extern "C" fn entry_count(table: *const StridedBuffer) -> u32 {
        (*table).opaque_08
    }

    #[test]
    fn clear_preserves_boundaries_for_zero_unaligned_and_wrapped_extents() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((table, _, buffer)) = fixture() else {
            note_missing_u32_fixture("app::strided_buffer_clear");
            return;
        };
        unsafe {
            let vtable = (table as *mut u8).add(0x200).cast::<super::StridedBufferVtable>();
            vtable.write(super::StridedBufferVtable {
                unresolved_00_04: [0; 2],
                entry_count,
            });
            (*table).opaque_00 = vtable as u32;
            for offset in 0..4u32 {
                for (count, size, len) in [
                    (0, 17, 0usize), (7, 0, 0), (1, 1, 1), (3, 11, 33),
                    (8, 8, 64), (0x8000_0000, 2, 0), (0x8000_0001, 2, 2),
                ] {
                    let storage = buffer as usize as *mut u8;
                    ptr::write_bytes(storage, 0xa5, 80);
                    (*table).entry_buffer = buffer + 4 + offset;
                    (*table).opaque_08 = count;
                    ENTRY_SIZE.store(size, Ordering::SeqCst);
                    super::strided_buffer_clear(table);
                    for index in 0..80usize {
                        let start = 4 + offset as usize;
                        let expected = if (start..start + len).contains(&index) { 0 } else { 0xa5 };
                        assert_eq!(*storage.add(index), expected,
                            "offset={offset} count={count} size={size} index={index}");
                    }
                }
            }
        }
    }
}
