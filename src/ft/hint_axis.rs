//! Cleanup of the per-axis hint workspace used by the retailOS outline hinter.

use crate::ft::memory::{ft_mem_free, FtMemory};

/// Eight-word owned prefix; the caller's two following words are not cleared.
/// The producer at 0x080b0dd4 allocates 28-byte hints, a split index array,
/// and a 16-byte-element work buffer. Pointers have native width on hosts.
#[repr(C)]
pub struct HintAxis {
    pub hint_count: u32,
    pub selected_count: u32,
    pub hints: *mut u8,
    pub indices: *mut u32,
    pub selected_indices: *mut u32,
    pub work_count: u32,
    pub work_buffer: *mut u8,
    pub work_cursor: u32,
}

/// Release an outline hinter's axis workspace — FUN_080b0d7c @ 0x080b0d7c.
/// True extent [0x080b0d7c, 0x080b0dd4): 88 bytes, three plain BLs to
/// ft_mem_free @ 0x082cfae8, zero predicated BLs. The next word is a fresh
/// function prologue. Free the work buffer, split index allocation, and
/// hints in that order, clearing each associated field after its free.
/// Callback-visible sequencing and the untouched trailing words match stock.
/// Deliberate deviation: repr(C) native pointers permit host testing; ARM
/// offsets remain +0x08, +0x0c, +0x10, and +0x18. No new callee seams.
///
/// # Safety
/// `axis` is writable and each non-null allocation belongs to `memory`.
/// Free callbacks must leave the axis record alive until this call returns.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn hint_axis_done(axis: *mut HintAxis, memory: *mut FtMemory) {
    ft_mem_free(memory, (*axis).work_buffer);
    (*axis).work_buffer = core::ptr::null_mut();
    (*axis).work_count = 0;
    (*axis).work_cursor = 0;
    ft_mem_free(memory, (*axis).indices.cast());
    (*axis).indices = core::ptr::null_mut();
    ft_mem_free(memory, (*axis).hints);
    (*axis).hints = core::ptr::null_mut();
    (*axis).selected_count = 0;
    (*axis).hint_count = 0;
    (*axis).selected_indices = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct Recorder {
        axis: *mut HintAxis,
        calls: std::vec::Vec<(usize, [usize; 8])>,
    }

    unsafe fn snapshot(axis: *mut HintAxis) -> [usize; 8] {
        [(*axis).hint_count as usize, (*axis).selected_count as usize,
         (*axis).hints as usize, (*axis).indices as usize,
         (*axis).selected_indices as usize, (*axis).work_count as usize,
         (*axis).work_buffer as usize, (*axis).work_cursor as usize]
    }

    unsafe extern "C" fn free(memory: *mut FtMemory, block: *mut u8) {
        let recorder = &mut *((*memory).user as *mut Recorder);
        recorder.calls.push((block as usize, snapshot(recorder.axis)));
    }
    unsafe extern "C" fn alloc(_: *mut FtMemory, _: i32) -> *mut u8 {
        panic!("cleanup must not allocate")
    }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        panic!("cleanup must not reallocate")
    }

    #[test]
    fn partial_allocations_preserve_free_order_and_intermediate_state() {
        #[repr(C)]
        struct Fixture { axis: HintAxis, trailing: [u32; 2] }
        for mask in 0..8 {
            let mut hints = [0u8; 28];
            let mut indices = [0u32; 2];
            let mut work = [0u8; 48];
            let mut fixture = Fixture {
                axis: HintAxis {
                    hint_count: 7, selected_count: 3,
                    hints: if mask & 1 != 0 { hints.as_mut_ptr() } else { core::ptr::null_mut() },
                    indices: if mask & 2 != 0 { indices.as_mut_ptr() } else { core::ptr::null_mut() },
                    selected_indices: unsafe { indices.as_mut_ptr().add(1) },
                    work_count: 9,
                    work_buffer: if mask & 4 != 0 { work.as_mut_ptr() } else { core::ptr::null_mut() },
                    work_cursor: 11,
                },
                trailing: [0x12345678, 0xabcdef01],
            };
            let axis = &mut fixture.axis as *mut HintAxis;
            let mut recorder = Recorder { axis, calls: std::vec::Vec::new() };
            let mut memory = FtMemory {
                user: (&mut recorder as *mut Recorder).cast(), alloc, free, realloc,
            };
            unsafe {
                let mut state = snapshot(axis);
                let mut expected = std::vec::Vec::new();
                for field in [6, 3, 2] {
                    if state[field] != 0 { expected.push((state[field], state)); }
                    state[field] = 0;
                    if field == 6 { state[5] = 0; state[7] = 0; }
                }
                hint_axis_done(axis, &mut memory);
                assert_eq!(recorder.calls, expected, "allocation mask {mask}");
                assert_eq!(snapshot(axis), [0; 8]);
                assert_eq!(fixture.trailing, [0x12345678, 0xabcdef01]);
                recorder.calls.clear();
                hint_axis_done(axis, core::ptr::null_mut());
                assert!(recorder.calls.is_empty());
                assert_eq!(snapshot(axis), [0; 8]);
            }
        }
    }
}
