//! Segment index offset — `FUN_081bad78` @ `0x081bad78`.
//!
//! True extent: 44 bytes, 0x081bad78..0x081bada4 (exclusive); the next
//! function begins with push {r4,r5,r6,lr}. Whole-image aligned raw decoding
//! finds two incoming plain BL sites (0x081bac6c, 0x081bac7c), zero predicated
//! BL sites. The body has one plain BL to observable_array_read_at at
//! 0x082a4d10 and no predicated BL or indirect calls.
//!
//! Subtract context +0x100 from the index with word wrapping, read a word
//! through the observable array at +0x1e0, ignore its success flag, and add
//! context +0x80 with word wrapping. A rejected read retains incoming r3.
//! The caller loads r3 from its provider's third default bounds word.
//!
//! Deliberate deviations: ARM assembly preserves the hidden r3 input exactly;
//! host Rust exposes it as a fourth argument (r2 is unused) and uses the
//! existing widened observable-array vtable. No concrete virtual callee is
//! invented. The base offset is loaded after dispatch, as in the raw code.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.segment_index_offset,"ax",%progbits
    .global segment_index_offset
    .type segment_index_offset,%function
segment_index_offset:
    push {{r3,r4,r5,lr}}
    mov r4,r0
    ldr r0,[r0,#0x100]
    mov r2,sp
    sub r1,r1,r0
    add r0,r4,#0x1e0
    bl observable_array_read_at
    ldr r0,[r4,#0x80]
    ldr r1,[sp]
    add r0,r0,r1
    pop {{r3,r4,r5,pc}}
    .size segment_index_offset, .-segment_index_offset
"#
);

#[cfg(target_os = "none")]
extern "C" {
    pub fn segment_index_offset(context: *mut u8, index: u32, unused: u32, fallback: u32) -> u32;
}

/// Resolve an absolute segment index into a base-relative offset.
///
/// # Safety
/// Context must contain aligned words at +0x80 and +0x100 and an array
/// at +0x1e0 valid for observable_array_read_at and its word-output callback.
#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn segment_index_offset(
    context: *mut u8, index: u32, _unused: u32, fallback: u32,
) -> u32 {
    let first = context.add(0x100).cast::<u32>().read();
    let mut offset = fallback;
    crate::cxx::observable_array::observable_array_read_at(
        context.add(0x1e0).cast(), index.wrapping_sub(first) as i32,
        core::ptr::addr_of_mut!(offset).cast(),
    );
    context.add(0x80).cast::<u32>().read().wrapping_add(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{ObservableArray, ObservableArrayReadHost, ObservableArrayReadVtable};

    #[repr(C)]
    struct Context {
        words: [u32; 0x1e0 / 4],
        array: ObservableArrayReadHost,
    }

    #[test]
    fn relative_indices_sentinel_rejection_and_wrapping_offsets() {
        unsafe extern "C" fn read(_: *mut ObservableArray, index: i32, output: *mut u8) -> u32 {
            output.cast::<u32>().write([5, 9, u32::MAX][index as usize]);
            0
        }
        let vtable = ObservableArrayReadVtable { unresolved_00_a0: [0; 41], read_element: read };
        let mut context = Context {
            words: [0; 0x1e0 / 4],
            array: ObservableArrayReadHost { vtable: &vtable, len: 3 },
        };
        for (first, index, base, fallback, expected) in [
            (10, 10, 100, 77, 105),
            (10, 11, 100, 77, 109),
            (10, 9, 100, 77, 177),
            (10, 13, 100, 77, 177),
            (0, i32::MAX as u32, 2, 77, 1),
            (u32::MAX, 0, u32::MAX, 77, 8),
            (0, 0x8000_0000, u32::MAX, 2, 1),
        ] {
            context.words[0x100 / 4] = first;
            context.words[0x80 / 4] = base;
            assert_eq!(unsafe { segment_index_offset((&mut context as *mut Context).cast(), index, 0, fallback) }, expected);
        }
        context.array.len = 0;
        context.words[0x100 / 4] = 0;
        context.words[0x80 / 4] = 4;
        assert_eq!(unsafe { segment_index_offset((&mut context as *mut Context).cast(), i32::MAX as u32, 0, 8) }, 12);
    }
}
