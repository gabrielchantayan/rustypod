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
//! `FUN_081d8614` is not separately ported. It is only three loads followed
//! by `bx` through this same layout vtable slot, so this port performs the
//! decoded dispatch directly rather than adding a second dispatch seam or
//! inventing an identity for the dynamic slot. No deliberate deviations.

/// A layout vtable's recovered entry-stride selector (`+0x2c` on target).
pub type StridedBufferEntrySize = unsafe extern "C" fn(*const StridedBufferLayout) -> u32;

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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{strided_buffer_entry_at, StridedBuffer, StridedBufferLayout, StridedBufferLayoutVtable};
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
}
