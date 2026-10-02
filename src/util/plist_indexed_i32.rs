//! Indexed plist integer access — `FUN_0829c188` @ 0x0829c188.
//!
//! True extent: 124 bytes, ending at the next function, 0x0829c204.
//! Raw words verify two incoming plain BLs (0x080ab200, 0x080ab410),
//! zero predicated BLs, two outgoing plain BLs to plist_node_child_count,
//! and a tail branch to the conversion wrapper at 0x0802f87c.
//! Return the fallback for a NULL node, inactive view, or an index greater
//! than the unsigned child count. Dictionary views (kind 2) transform the
//! index to 2*index+1 with wrapping arithmetic and check the count again.
//! Read the selected 40-byte child's text at +0x10 and convert with base 0.
//!
//! Deliberate deviations: LLVM chooses the frame and tail-call shape.
//! ARM retains the retail conversion wrapper: the existing Rust strtol
//! clamps instead of wrapping and omits errno. Host execution uses the
//! existing unsigned parser (cast to i32), preserving the return bits but
//! not the retail errno/locale side effects. Target pointer fields remain
//! aligned u32 words, including on 64-bit hosts. Equality at the count
//! boundary is intentionally accepted; callers must provide readable storage.

use crate::fp::fp_misc::plist_node_child_count;

#[inline(never)]
unsafe fn convert_integer(text: *const u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        let convert: unsafe extern "C" fn(*const u8, *mut *mut u8, i32) -> i32 =
            core::mem::transmute(0x0802_f87cusize);
        convert(text, core::ptr::null_mut(), 0)
    }
    #[cfg(not(target_os = "none"))]
    {
        crate::strto::strtoul::strtoul(text, core::ptr::null_mut(), 0) as i32
    }
}

/// `view` holds a node address at word 0 and a kind byte at +4.
/// All reached nodes, children, and NUL-terminated text must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plist_indexed_i32(view: *const u32, mut index: u32, fallback: i32) -> i32 {
    let node = view.read() as usize as *const u8;
    if node.is_null() { return fallback; }
    let kind = view.cast::<u8>().add(4).read();
    if kind == 0 || (plist_node_child_count(node) as u32) < index { return fallback; }
    if kind == 2 { index = index.wrapping_mul(2).wrapping_add(1); }
    if (plist_node_child_count(node) as u32) < index { return fallback; }
    let children = node.cast::<u32>().add(5).read();
    let child = children.wrapping_add(index.wrapping_mul(40)) as usize as *const u32;
    let text = child.add(4).read() as usize as *const u8;
    convert_integer(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_values_preserve_retail_boundaries_and_conversion_bits() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::PLIST_INDEXED_I32, 4096,
            ) else { return; };
            let view = slab.cast::<u32>();
            let node = slab.add(32).cast::<u32>();
            let children = slab.add(128).cast::<u32>();
            view.write(node as u32);
            view.add(1).write(1);
            node.add(5).write(children as u32);
            node.add(6).write((children as u32).wrapping_add(3 * 40));
            let strings: [&[u8]; 4] = [b"17\0", b" -0x80000001\0", b"077\0", b"4294967295\0"];
            for (i, text) in strings.iter().enumerate() {
                let dst = slab.add(512 + i * 64);
                core::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
                children.add(i * 10 + 4).write(dst as u32);
            }
            assert_eq!(plist_indexed_i32(view, 0, -99), 17);
            assert_eq!(plist_indexed_i32(view, 1, -99), 0x7fff_ffff);
            assert_eq!(plist_indexed_i32(view, 2, -99), 63);
            assert_eq!(plist_indexed_i32(view, 3, -99), -1); // equality is accepted
            assert_eq!(plist_indexed_i32(view, 4, -99), -99);
            assert_eq!(plist_indexed_i32(view, u32::MAX, -99), -99);
            view.add(1).write(2);
            assert_eq!(plist_indexed_i32(view, 0, -99), 0x7fff_ffff);
            assert_eq!(plist_indexed_i32(view, 1, -99), -1);
            assert_eq!(plist_indexed_i32(view, 2, -99), -99); // second bounds check
            view.add(1).write(0);
            assert_eq!(plist_indexed_i32(view, 0, -99), -99);
            view.write(0);
            view.add(1).write(1);
            assert_eq!(plist_indexed_i32(view, 0, -99), -99);
        }
    }
}
