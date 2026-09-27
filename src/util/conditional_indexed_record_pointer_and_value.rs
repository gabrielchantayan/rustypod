//! A conditional indexed record pointer-and-value helper.

/// conditional_indexed_record_pointer_and_value — retailOS `FUN_083d2114` @
/// 0x083d2114 (52 bytes).
///
/// Raw osos.dec words establish the exact extent 0x083d2114..0x083d2147:
/// `push {r0,r1,r2,r3,lr}; add r1,r1,#16; ldr r2,[r1,#16]; cmp r2,#0;
/// ldreq r0,[r1,#24]; addeq r1,r1,r0,lsl #2; ldrne r1,[r1,#12]; ldr r2,[r1];
/// stm r0,{r1,r2}; pop {r1,r2,r3,r12,pc}`. The next independently entered
/// function starts at 0x083d2148. Whole-image ARM B/BL decoding finds two
/// inbound plain `bl` sites (0x08268f48 and 0x0826a6c4) and no predicated
/// sites; this leaf has no outbound calls. It tests input word +32: when zero,
/// it selects entry `input[4] + input[10] * 4`; otherwise it selects the
/// pointer at input word +28. It writes the selected address and its first
/// word to `output`.
///
/// Deliberate deviations: volatile aligned word accesses retain the retail
/// load/store ordering against LLVM transformations. The input and output are
/// represented as `u32` words so host pointer width cannot change target
/// offsets.
///
/// # Safety
/// `input` must be valid for eleven aligned `u32` reads. The selected target
/// address must be valid for an aligned `u32` read; `output` must be valid for
/// two aligned `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.conditional_indexed_record_pointer_and_value")]
#[inline(never)]
pub unsafe extern "C" fn conditional_indexed_record_pointer_and_value(
    output: *mut u32,
    input: *const u32,
) {
    let record = if input.add(8).read_volatile() == 0 {
        (input.add(4).read_volatile() as *const u32).add(input.add(10).read_volatile() as usize)
    } else {
        input.add(7).read_volatile() as *const u32
    };
    output.write_volatile(record as u32);
    output.add(1).write_volatile(record.read_volatile());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::conditional_indexed_record_pointer_and_value;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn selects_indexed_record_when_selector_is_zero() {
        let Some(records) = try_map_u32_slab(hints::CONDITIONAL_INDEXED_RECORD_POINTER_AND_VALUE_INDEXED, 4) else {
            assert!(note_missing_u32_fixture("util/conditional_indexed_record_pointer_and_value"));
            return;
        };
        let records = records.cast::<u32>();
        unsafe {
            records.write(0x1111_1111);
            records.add(1).write(0x2222_2222);
            records.add(2).write(0x3333_3333);
        }
        let mut input = [0u32; 11];
        input[4] = records as u32;
        input[8] = 0;
        input[10] = 2;
        let mut output = [0xdead_beef, 0xcafe_babe];

        unsafe { conditional_indexed_record_pointer_and_value(output.as_mut_ptr(), input.as_ptr()) };

        assert_eq!(output, [unsafe { records.add(2) as u32 }, 0x3333_3333]);
    }

    #[test]
    fn selects_direct_record_when_selector_is_nonzero() {
        let Some(records) = try_map_u32_slab(hints::CONDITIONAL_INDEXED_RECORD_POINTER_AND_VALUE_DIRECT, 4) else {
            assert!(note_missing_u32_fixture("util/conditional_indexed_record_pointer_and_value"));
            return;
        };
        let records = records.cast::<u32>();
        unsafe {
            records.write(0x4444_4444);
            records.add(1).write(0x5555_5555);
        }
        let mut input = [0u32; 11];
        input[4] = records as u32;
        input[7] = unsafe { records.add(1) as u32 };
        input[8] = 1;
        input[10] = 0;
        let mut output = [0; 2];

        unsafe { conditional_indexed_record_pointer_and_value(output.as_mut_ptr(), input.as_ptr()) };

        assert_eq!(output, [unsafe { records.add(1) as u32 }, 0x5555_5555]);
    }
}
