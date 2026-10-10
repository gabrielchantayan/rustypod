//! Release the auto-hinter's glyph workspace.

use super::memory::{ft_mem_free, FtMemory};

/// Seven target words per axis; the final word survives cleanup.
#[repr(C)]
pub struct AfAxisHints {
    pub segment_count: u32,
    pub segment_capacity: u32,
    pub segments: *mut u8,
    pub edge_count: u32,
    pub edge_capacity: u32,
    pub edges: *mut u8,
    pub untouched: u32,
}

/// Owned glyph-hints fields, covering the 0x68-byte target prefix.
/// The caller at 0x080dd054 supplies a larger, 0x74-byte record.
#[repr(C)]
pub struct AfGlyphHints {
    pub memory: *mut FtMemory,
    pub untouched: [u32; 5],
    pub point_capacity: u32,
    pub point_count: u32,
    pub points: *mut u8,
    pub contour_capacity: u32,
    pub contour_count: u32,
    pub contours: *mut u8,
    pub axes: [AfAxisHints; 2],
}

/// Original FUN_080ad52c at load address 0x080ad52c; true extent
/// [0x080ad52c, 0x080ad5c8), 156 bytes, ending before a fresh push prologue.
/// Raw A32 verifies four plain BL sites (0x080ad564, 0x080ad57c,
/// 0x080ad598, 0x080ad5b0), all to ft_mem_free at 0x082cfae8;
/// zero predicated BLs. Raw scanning finds two plain incoming BLs at
/// 0x080dd294 and 0x082b32a0, zero predicated incoming BLs.
/// Null hints or null memory returns without writes. Snapshot memory, clear
/// each axis's segment counters, free segments, clear its pointer and edge
/// counters, free edges and clear their pointer. Then free contours and points,
/// clearing their pointers/counters, and finally clear memory. Other words
/// survive. Deliberate deviation: repr(C) native pointers widen on hosts;
/// target fields retain four-byte spacing. No algorithmic deviations or seams.
///
/// # Safety
/// Non-null hints must be readable and, when memory is non-null, writable.
/// Allocations must belong to memory; callbacks must keep the record alive.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn af_glyph_hints_done(hints: *mut AfGlyphHints) {
    if hints.is_null() { return; }
    let memory = (*hints).memory;
    if memory.is_null() { return; }
    for index in 0..2 {
        let axis = core::ptr::addr_of_mut!((*hints).axes[index]);
        (*axis).segment_count = 0;
        (*axis).segment_capacity = 0;
        ft_mem_free(memory, (*axis).segments);
        (*axis).segments = core::ptr::null_mut();
        (*axis).edge_count = 0;
        (*axis).edge_capacity = 0;
        ft_mem_free(memory, (*axis).edges);
        (*axis).edges = core::ptr::null_mut();
    }
    ft_mem_free(memory, (*hints).contours);
    (*hints).contours = core::ptr::null_mut();
    (*hints).contour_capacity = 0;
    (*hints).contour_count = 0;
    ft_mem_free(memory, (*hints).points);
    (*hints).points = core::ptr::null_mut();
    (*hints).point_count = 0;
    (*hints).point_capacity = 0;
    (*hints).memory = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct Recorder {
        hints: *mut AfGlyphHints,
        calls: std::vec::Vec<(usize, [usize; 26])>,
    }
    unsafe fn snapshot(h: *mut AfGlyphHints) -> [usize; 26] {
        let mut words = [0; 26];
        words[0] = (*h).memory as usize;
        for i in 0..5 { words[i + 1] = (*h).untouched[i] as usize; }
        words[6..12].copy_from_slice(&[(*h).point_capacity as usize,
            (*h).point_count as usize, (*h).points as usize,
            (*h).contour_capacity as usize, (*h).contour_count as usize,
            (*h).contours as usize]);
        for i in 0..2 {
            let a = &(*h).axes[i];
            words[12 + i * 7..19 + i * 7].copy_from_slice(&[
                a.segment_count as usize, a.segment_capacity as usize,
                a.segments as usize, a.edge_count as usize, a.edge_capacity as usize,
                a.edges as usize, a.untouched as usize]);
        }
        words
    }
    unsafe extern "C" fn free(memory: *mut FtMemory, block: *mut u8) {
        let r = &mut *((*memory).user as *mut Recorder);
        r.calls.push((block as usize, snapshot(r.hints)));
    }
    unsafe extern "C" fn alloc(_: *mut FtMemory, _: i32) -> *mut u8 { panic!("unexpected allocation") }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 { panic!("unexpected reallocation") }

    #[test]
    fn every_partial_allocation_preserves_callback_state_and_unowned_words() {
        #[repr(C)]
        struct Fixture { hints: AfGlyphHints, trailing: [u32; 3] }
        for mask in 0..64 {
            let mut buffers = [[0u8; 16]; 6];
            let mut pointers = [core::ptr::null_mut(); 6];
            for i in 0..6 {
                if mask & (1 << i) != 0 { pointers[i] = buffers[i].as_mut_ptr(); }
            }
            let mut fixture = Fixture {
                hints: AfGlyphHints { memory: core::ptr::null_mut(), untouched: [71; 5],
                    point_capacity: 13, point_count: 11, points: pointers[5],
                    contour_capacity: 9, contour_count: 7, contours: pointers[4],
                    axes: core::array::from_fn(|i| AfAxisHints {
                        segment_count: 3, segment_capacity: 5, segments: pointers[i * 2],
                        edge_count: 7, edge_capacity: 9, edges: pointers[i * 2 + 1], untouched: 73,
                    }),
                }, trailing: [79; 3],
            };
            let h = &mut fixture.hints as *mut AfGlyphHints;
            let mut r = Recorder { hints: h, calls: std::vec::Vec::new() };
            let mut memory = FtMemory { user: (&mut r as *mut Recorder).cast(), alloc, free, realloc };
            fixture.hints.memory = &mut memory;
            unsafe {
                let mut state = snapshot(h);
                let mut expected = std::vec::Vec::new();
                for (pointer, before, after) in [
                    (14, [12, 13], [14, 15, 16]), (17, [15, 16], [17, 17, 17]),
                    (21, [19, 20], [21, 22, 23]), (24, [22, 23], [24, 24, 24]),
                    (11, [9, 10], [11, 9, 10]), (8, [6, 7], [8, 7, 6]),
                ] {
                    // Axis counters clear before free; glyph counters clear after.
                    if pointer != 11 && pointer != 8 { for field in before { state[field] = 0; } }
                    if state[pointer] != 0 { expected.push((state[pointer], state)); }
                    for field in after { state[field] = 0; }
                }
                state[0] = 0;
                af_glyph_hints_done(h);
                assert_eq!(r.calls, expected, "mask {mask}");
                assert_eq!(snapshot(h), state);
                assert_eq!(fixture.trailing, [79; 3]);
                r.calls.clear();
                af_glyph_hints_done(h);
                assert!(r.calls.is_empty());
                assert_eq!(snapshot(h), state);
            }
        }
    }

    #[test]
    fn null_memory_leaves_even_stale_allocations_untouched() {
        let mut buffer = [0u8; 16];
        let mut h = AfGlyphHints { memory: core::ptr::null_mut(), untouched: [17; 5],
            point_capacity: 3, point_count: 2, points: buffer.as_mut_ptr(),
            contour_capacity: 5, contour_count: 4, contours: buffer.as_mut_ptr(),
            axes: core::array::from_fn(|_| AfAxisHints { segment_count: 7, segment_capacity: 8,
                segments: buffer.as_mut_ptr(), edge_count: 9, edge_capacity: 10,
                edges: buffer.as_mut_ptr(), untouched: 11 }),
        };
        unsafe {
            let before = snapshot(&mut h);
            af_glyph_hints_done(core::ptr::null_mut());
            af_glyph_hints_done(&mut h);
            assert_eq!(snapshot(&mut h), before);
        }
    }
}
