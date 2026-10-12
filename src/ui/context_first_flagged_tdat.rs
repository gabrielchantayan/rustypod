//! Find the first context-linked 'tdat' element with flag bit 0 set.

#[cfg(target_os = "none")]
unsafe fn retail_context_tdat_head(context: *const u8) -> u32 {
    let call: unsafe extern "C" fn(*const u8) -> u32 = core::mem::transmute(0x0805_22ecusize);
    call(context)
}

#[cfg(not(target_os = "none"))]
unsafe fn retail_context_tdat_head(context: *const u8) -> u32 {
    if context.is_null() { 0 } else { context.add(0xb98).cast::<u32>().read() }
}

#[cfg(target_os = "none")]
unsafe fn retail_tdat_next(element: *const u8) -> u32 {
    let call: unsafe extern "C" fn(*const u8) -> u32 = core::mem::transmute(0x0805_3d3cusize);
    call(element)
}

#[cfg(not(target_os = "none"))]
unsafe fn retail_tdat_next(element: *const u8) -> u32 {
    if super::tdat_class_check::ui_element_is_tdat_class(element) != 0 {
        element.cast::<u32>().read()
    } else {
        0
    }
}

/// ui_context_first_flagged_tdat — original: FUN_08050c14 @ 0x08050c14.
/// True extent: 52 bytes, [0x08050c14,0x08050c48); the next real function
/// starts with push {r4,r5,r6,lr}. Raw aligned A32 decoding finds two plain
/// incoming BLs (0x08050acc, 0x0805865c), zero predicated; the body has two
/// plain outgoing BLs (0x08050c20, 0x08050c34), zero predicated.
///
/// Reject NULL context; obtain its chain head from +0xb98 via 0x080522ec.
/// Return the first nonzero element whose byte at +0x20 has bit 0 set.
/// Otherwise advance via 0x08053d3c, which returns the word at element+0
/// only if the existing 'tdat' class predicate accepts it. A wrong-class
/// element with the flag set still succeeds; an unflagged one ends the scan.
/// Caller 0x08050ac8 reads result+0x3c; 0x08058590 stores it at +0xf60.
/// The flag's higher-level meaning is not established.
///
/// Deliberate deviations: neither direct callee is registered in names.yaml;
/// ARM retains their verified stock addresses. Host-only boundary bodies
/// reproduce the decoded aligned word loads and use the existing Rust class
/// predicate, not mocks. Pointer fields remain u32 on every target. No added
/// class validation, cycle detection, or bounds checks.
///
/// # Safety
/// A non-NULL context must be aligned and readable through +0xb9b. Each
/// visited nonzero element must be readable through +0x20; an unflagged
/// element must also permit aligned word reads at +4 and, if 'tdat', +0.
/// An unflagged valid-class chain must terminate or eventually reach a match.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_context_first_flagged_tdat(context: *const u8) -> u32 {
    if context.is_null() {
        return 0;
    }
    let mut element = retail_context_tdat_head(context);
    while element != 0 {
        let pointer = element as usize as *const u8;
        if pointer.add(0x20).read() & 1 != 0 {
            return element;
        }
        element = retail_tdat_next(pointer);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_empty_context() {
        let context = [0u32; 0xb9c / 4];
        unsafe {
            assert_eq!(ui_context_first_flagged_tdat(core::ptr::null()), 0);
            assert_eq!(ui_context_first_flagged_tdat(context.as_ptr().cast()), 0);
        }
    }

    #[test]
    fn first_match_bit_mask_and_class_gated_termination() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTEXT_FIRST_FLAGGED_TDAT, 4096,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let mut context = [0u32; 0xb9c / 4];
        let addresses = [base as usize as u32, unsafe { base.add(0x40) } as usize as u32,
            unsafe { base.add(0x80) } as usize as u32];
        context[0xb98 / 4] = addresses[0];
        // Exhaust all flag bytes on the head, match positions (including no
        // match), and class rejection positions. The oracle uses indices,
        // independent of target pointer arithmetic and retail boundaries.
        for flags in 0..=255u8 {
            for match_index in 1..=3 {
                for rejected_index in 0..=3 {
                    let node_flags = [flags, if match_index == 1 { 1 } else { 0x80 },
                        if match_index == 2 { 0xff } else { 0xfe }];
                    unsafe {
                        for index in 0..3 {
                            let node = base.add(index * 0x40);
                            node.cast::<u32>().write(if index == 2 { 0 } else { addresses[index + 1] });
                            node.add(4).cast::<u32>().write(if index == rejected_index { 0x706c_7374 } else { 0x7464_6174 });
                            node.add(0x20).write(node_flags[index]);
                        }
                        let mut expected = 0;
                        for index in 0..3 {
                            if node_flags[index] & 1 != 0 {
                                expected = addresses[index];
                                break;
                            }
                            if index == rejected_index { break; }
                        }
                        assert_eq!(ui_context_first_flagged_tdat(context.as_ptr().cast()), expected,
                            "flags={flags:#x}, match={match_index}, rejected={rejected_index}");
                    }
                }
            }
        }
        // Success must not advance through the head's poisoned next pointer.
        unsafe {
            base.cast::<u32>().write(1);
            base.add(4).cast::<u32>().write(0);
            base.add(0x20).write(1);
            assert_eq!(ui_context_first_flagged_tdat(context.as_ptr().cast()), addresses[0]);
        }
    }
}
