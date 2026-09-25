//! Strided plane copy — original: `FUN_080394c4` @ `0x080394c4` (208 bytes,
//! `0x080394c4..0x08039594`; the next function begins at `0x08039594`).
//!
//! Verified call count: three inbound unconditional `bl` sites (`0x080395d0`,
//! `0x080396ec`, and `0x08039748`), no predicated inbound calls. The body has
//! two unconditional outbound `bl` calls and no predicated calls.
//!
//! Looks up a source span selected by the descriptor, computes its word offset
//! from the source-index record, then copies it into the descriptor's output
//! plane. Kind zero with target mode one copies paired words into 16-byte
//! destination strides; nonzero kind with `short_mode` copies low halfwords;
//! every other case copies contiguous words. Deliberate deviation: the
//! resident span lookup at `0x080b64fc` remains a target address and a volatile
//! host seam; the trivial contiguous-copy callee at `0x080a9fc4` is inlined.

use core::ptr;

#[repr(C)]
pub struct PlaneCopyDescriptor {
    pub kind: u8,
    pub _unknown_01_03: [u8; 3],
    pub source_position: u32,
    pub _unknown_08_0b: [u8; 4],
    pub output_offset: u32,
    pub byte_len: u32,
    pub source_selector: u8,
    pub short_mode: u8,
}

pub type SourceSpanLookup = unsafe extern "C" fn(u32, u8, *mut u32) -> u32;

#[derive(Clone, Copy)]
pub struct StridedPlaneCopyOps { pub source_span_lookup: SourceSpanLookup }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_source_span_lookup(_: u32, _: u8, out: *mut u32) -> u32 {
    unsafe { out.write(0); out.add(1).write(0); }
    0
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRIDED_PLANE_COPY_OPS: StridedPlaneCopyOps = StridedPlaneCopyOps { source_span_lookup: missing_source_span_lookup };
#[cfg(not(target_os = "none"))]
pub static mut STRIDED_PLANE_COPY_OPS: StridedPlaneCopyOps = DEFAULT_STRIDED_PLANE_COPY_OPS;

#[inline(always)]
unsafe fn source_span_lookup(context: u32, selector: u8, out: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let lookup: SourceSpanLookup = unsafe { core::mem::transmute(0x080b_64fcusize) };
        unsafe { lookup(context, selector, out); }
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = ptr::read_volatile(ptr::addr_of!(STRIDED_PLANE_COPY_OPS));
        (ops.source_span_lookup)(context, selector, out);
    }
}

/// Copy the descriptor-selected source plane to its output layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strided_plane_copy(
    context: u32, source_index: *const u32, descriptor: *const PlaneCopyDescriptor,
    position: u32, target: *const u8,
) {
    let mut span = [0u32; 2];
    unsafe { source_span_lookup(context, (*descriptor).source_selector, span.as_mut_ptr()); }
    let source_word = unsafe {
        source_index.add(3).read().wrapping_add(((*descriptor).source_position.wrapping_sub(position).wrapping_sub(source_index.read())) << 2)
    } as *const u32;
    let output = unsafe { (span[0] as *mut u8).add((*descriptor).output_offset as usize) };
    if unsafe { (*descriptor).kind == 0 } && unsafe { target.add(5).read() == 1 } {
        for i in 0..(unsafe { (*descriptor).byte_len } >> 3) {
            unsafe {
                let src = source_word.add(i as usize * 2);
                output.add(i as usize * 16).cast::<u32>().write(src.read());
                output.add(i as usize * 16 + 4).cast::<u32>().write(src.add(1).read());
            }
        }
    } else if unsafe { (*descriptor).kind != 0 && (*descriptor).short_mode == 1 } {
        for i in 0..(unsafe { (*descriptor).byte_len } >> 1) { unsafe { output.add(i as usize * 2).cast::<u16>().write(source_word.add(i as usize).read() as u16); } }
    } else {
        for i in 0..(unsafe { (*descriptor).byte_len } >> 2) { unsafe { output.cast::<u32>().add(i as usize).write(source_word.add(i as usize).read()); } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::system::TEST_OPS_LOCK;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of_mut, null};

    static mut OUTPUT: u32 = 0;
    unsafe extern "C" fn lookup(_: u32, _: u8, out: *mut u32) -> u32 { unsafe { out.write(OUTPUT); out.add(1).write(0); } 0 }
    fn descriptor(kind: u8, short_mode: u8, bytes: u32) -> PlaneCopyDescriptor { PlaneCopyDescriptor { kind, _unknown_01_03: [0; 3], source_position: 0, _unknown_08_0b: [0; 4], output_offset: 0, byte_len: bytes, source_selector: 3, short_mode } }

    #[test]
    fn copies_interleaved_words_and_short_or_contiguous_layouts() {
        let _guard = TEST_OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::STRIDED_PLANE_COPY, 0x1000) else { note_missing_u32_fixture("h264::strided_plane_copy"); return; };
        unsafe {
            addr_of_mut!(OUTPUT).write(slab.add(0x200).addr() as u32);
            addr_of_mut!(STRIDED_PLANE_COPY_OPS).write(StridedPlaneCopyOps { source_span_lookup: lookup });
            let source = slab.cast::<u32>();
            for (i, word) in [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888].iter().enumerate() { source.add(i).write(*word); }
            let index = [0, 0, 0, slab.addr() as u32];
            let mut target = [0u8; 6]; target[5] = 1;
            strided_plane_copy(9, index.as_ptr(), &descriptor(0, 0, 16), 0, target.as_ptr());
            assert_eq!((slab.add(0x200).cast::<u32>()).read(), 0x1111_2222);
            assert_eq!((slab.add(0x204).cast::<u32>()).read(), 0x3333_4444);
            assert_eq!((slab.add(0x210).cast::<u32>()).read(), 0x5555_6666);
            assert_eq!((slab.add(0x214).cast::<u32>()).read(), 0x7777_8888);
            strided_plane_copy(9, index.as_ptr(), &descriptor(1, 1, 8), 0, null());
            assert_eq!((slab.add(0x200).cast::<u16>()).read(), 0x2222);
            assert_eq!((slab.add(0x202).cast::<u16>()).read(), 0x4444);
            strided_plane_copy(9, index.as_ptr(), &descriptor(0, 0, 12), 0, [0u8; 6].as_ptr());
            assert_eq!((slab.add(0x200).cast::<u32>()).read(), 0x1111_2222);
            assert_eq!((slab.add(0x204).cast::<u32>()).read(), 0x3333_4444);
            assert_eq!((slab.add(0x208).cast::<u32>()).read(), 0x5555_6666);
        }
    }
}
