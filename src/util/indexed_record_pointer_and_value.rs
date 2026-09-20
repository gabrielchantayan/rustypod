//! An indexed record pointer-and-value helper.

/// indexed_record_pointer_and_value — retailOS `FUN_083d20f0` @
/// 0x083d20f0 (36 bytes).
///
/// Raw osos.dec words establish the exact extent 0x083d20f0..0x083d2113:
/// `push {r0,r1,r2,r3,lr}; add r1,r1,#16; ldmib r1,{r1,r2};
/// ldr r2,[r1,r2,lsl #2]!; stm r0,{r1,r2}; pop {r1,r2,r3,r12,pc}`.
/// The next independently entered function starts at 0x083d2114. Whole-image
/// call analysis finds three inbound plain `bl` calls and no predicated `bl`
/// calls; this leaf has no outbound calls. It loads the base and index from
/// target-width input words +20 and +24, derives `base + index * 4`, and
/// stores that record address plus its first word to `output`.
///
/// Deliberate deviations: volatile aligned word accesses retain the retail
/// load/store ordering against LLVM transformations. The input and output are
/// represented as `u32` words so host pointer width cannot change target
/// offsets.
///
/// # Safety
/// `input` must be valid for seven aligned `u32` reads. The base word at
/// `input[5]`, interpreted as a target address, must be valid for an aligned
/// `u32` read at index `input[6]`; `output` must be valid for two aligned
/// `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.indexed_record_pointer_and_value")]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_pointer_and_value(
    output: *mut u32,
    input: *const u32,
) {
    let base = input.add(5).read_volatile() as *const u32;
    let record = base.add(input.add(6).read_volatile() as usize);
    output.write_volatile(record as u32);
    output.add(1).write_volatile(record.read_volatile());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::indexed_record_pointer_and_value;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn stores_selected_record_address_and_first_word() {
        let Some(records) = try_map_u32_slab(hints::INDEXED_RECORD_POINTER_AND_VALUE_FIRST, 12) else {
            assert!(note_missing_u32_fixture("util/indexed_record_pointer_and_value"));
            return;
        };
        let records = records.cast::<u32>();
        unsafe {
            records.write(0x1000_0001);
            records.add(1).write(0x2000_0002);
            records.add(2).write(0x3000_0003);
        }
        let mut input = [0u32; 7];
        input[5] = records as u32;
        input[6] = 2;
        let mut output = [0xdead_beef, 0xcafe_babe];

        unsafe { indexed_record_pointer_and_value(output.as_mut_ptr(), input.as_ptr()) };

        assert_eq!(output, [unsafe { records.add(2) as u32 }, 0x3000_0003]);
    }

    #[test]
    fn uses_target_width_word_offsets_not_host_pointer_layout() {
        let Some(slab) = try_map_u32_slab(hints::INDEXED_RECORD_POINTER_AND_VALUE_SECOND, 32) else {
            assert!(note_missing_u32_fixture("util/indexed_record_pointer_and_value"));
            return;
        };
        let slab = slab.cast::<u32>();
        unsafe {
            slab.add(4).write(0xaaaa_aaaa);
            slab.add(5).write(0xbbbb_bbbb);
            slab.add(6).write(0xcccc_cccc);
        }
        let mut input = [0u32; 7];
        input[5] = slab as u32;
        input[6] = 5;
        let mut output = [0; 2];

        unsafe { indexed_record_pointer_and_value(output.as_mut_ptr(), input.as_ptr()) };

        assert_eq!(output, [unsafe { slab.add(5) as u32 }, 0xbbbb_bbbb]);
    }
}
