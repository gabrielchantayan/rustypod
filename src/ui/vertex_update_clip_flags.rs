//! Homogeneous vertex clip classification for the retailOS polygon clipper.

/// Original: `FUN_0824c7c0` @ `0x0824c7c0`, 136 bytes through
/// `0x0824c848` (next real function). Verified raw A32 call counts: two
/// inbound plain BLs at 0x0824fd58 and 0x0824ff14, zero predicated BLs,
/// and zero outgoing BLs.
///
/// Compare signed x/y/z words at +0x10/+0x14/+0x18 with -w and w at
/// +0x1c. Replace bits 2..7 of the +0x90 flag word with the six strict
/// outside-plane predicates, preserving every other bit. Negation wraps
/// like ARM RSB, even for i32::MIN; negative w is not normalized.
/// Deliberate deviations: no semantic changes; LLVM may omit the leaf's
/// original LR spill. Word indices retain the target layout on hosts.
///
/// # Safety
/// `vertex` must be aligned and readable for 37 u32 words, with word 36
/// writable. No null or range checks are performed, matching firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vertex_update_clip_flags(vertex: *mut u32) {
    let w = unsafe { vertex.add(7).read() } as i32;
    let lower = w.wrapping_neg();
    let x = unsafe { vertex.add(4).read() } as i32;
    let y = unsafe { vertex.add(5).read() } as i32;
    let z = unsafe { vertex.add(6).read() } as i32;
    let clip = ((x < lower) as u32) << 2
        | ((x > w) as u32) << 3
        | ((y < lower) as u32) << 4
        | ((y > w) as u32) << 5
        | ((z < lower) as u32) << 6
        | ((z > w) as u32) << 7;
    let flags = unsafe { vertex.add(36).read() };
    unsafe { vertex.add(36).write((flags & !0xfc) | clip) };
}

#[cfg(test)]
mod tests {
    use super::vertex_update_clip_flags;

    fn check(coords: [i32; 3], w: i32, old_flags: u32, expected_clip: u32) {
        let mut words = [0x5a5a_a5a5; 39];
        for axis in 0..3 {
            words[axis + 5] = coords[axis] as u32;
        }
        words[8] = w as u32;
        words[37] = old_flags;
        let before = words;
        unsafe { vertex_update_clip_flags(words.as_mut_ptr().add(1)) };
        assert_eq!(words[37], (old_flags & !0xfc) | expected_clip);
        for i in 0..words.len() {
            if i != 37 { assert_eq!(words[i], before[i], "word {i} changed"); }
        }
    }

    #[test]
    fn strict_planes_and_all_outcode_combinations() {
        // Equalities lie inside; the three possibilities per axis exercise
        // every combination of independent negative/positive outside bits.
        let samples = [(-11, 1), (-10, 0), (0, 0), (10, 0), (11, 2)];
        for (x, xcode) in samples {
            for (y, ycode) in samples {
                for (z, zcode) in samples {
                    for flags in [0, u32::MAX, 0xa5a5_5a5a] {
                        check([x, y, z], 10, flags,
                            (xcode << 2) | (ycode << 4) | (zcode << 6));
                    }
                }
            }
        }
    }

    #[test]
    fn zero_negative_and_extreme_w_preserve_signed_arm_semantics() {
        check([-1, 0, 1], 0, u32::MAX, 0x84);
        check([0, -1, 1], -1, 0, 0x9c);
        check([i32::MIN, 0, i32::MAX], i32::MIN, 3, 0xa0);
        check([i32::MIN, -i32::MAX, i32::MAX], i32::MAX, 0xffff_fffc, 4);
    }
}
