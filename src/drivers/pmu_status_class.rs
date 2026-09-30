//! Priority classification of the three retail PMU status queries.

const STORE_REGISTER_4B_BIT2: usize = 0x080b_fbd4;
const STORE_BOARD_STATUS_BIT: usize = 0x080c_8890;
const QUERY_CACHED_REGISTER_18_INVERTED_BIT0: usize = 0x082e_540c;

// These retail calls expose caller-saved r3 on failed transfers. Capture the
// actual r1-r3 outputs rather than forwarding their original incoming values.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_query(address: usize, r0: usize, scratch: &mut [u32; 3]) -> u32 {
    let result: u32;
    core::arch::asm!(
        "blx {callee}",
        callee = in(reg) address,
        inlateout("r0") r0 => result,
        inlateout("r1") scratch[0],
        inlateout("r2") scratch[1],
        inlateout("r3") scratch[2],
        clobber_abi("C"),
    );
    result
}

#[cfg(not(target_os = "none"))]
type RetailQuery = unsafe fn(usize, usize, &mut [u32; 3]) -> u32;

#[cfg(not(target_os = "none"))]
unsafe fn missing_retail_query(_: usize, _: usize, _: &mut [u32; 3]) -> u32 {
    panic!("pmu_status_class requires retail PMU query seams")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_QUERY: RetailQuery = missing_retail_query;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_query(address: usize, r0: usize, scratch: &mut [u32; 3]) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_QUERY))(address, r0, scratch)
}

/// Original `FUN_082bc5b8` @ `0x082bc5b8`: 72 bytes, next real function
/// starts at `0x082bc600`. Raw words contain 3 plain BL and 0 predicated BL;
/// incoming references contain 2 plain BL and 0 predicated BL.
///
/// Returns 2 if PMU register 0x4b bit 2 is set, otherwise 3 if the board's
/// selected status bit is set, otherwise the normalized nonzero result of
/// the locked, cached inverted register-0x18 bit-0 query. Queries short-circuit.
///
/// Deliberate deviations: expose incoming r0-r3 explicitly and use indirect
/// retail calls (including the already-ported first callee) so caller-saved
/// words flow exactly between calls, including failed-transfer scratch data.
/// The final dead stack store is omitted. No hardware identity beyond the
/// verified register/bit behavior is assumed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_status_class(
    _incoming_r0: u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    let mut scratch = [incoming_r1, incoming_r2, incoming_r3];
    let mut status = incoming_r3;
    retail_query(STORE_REGISTER_4B_BIT2, &mut status as *mut u32 as usize, &mut scratch);
    if status != 0 {
        return 2;
    }
    retail_query(STORE_BOARD_STATUS_BIT, &mut status as *mut u32 as usize, &mut scratch);
    if status != 0 {
        return 3;
    }
    (retail_query(QUERY_CACHED_REGISTER_18_INVERTED_BIT0, 0, &mut scratch) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    use parking_lot::Mutex;
    static mut SAMPLES: [u32; 3] = [0; 3];
    static LOCK: Mutex<()> = Mutex::new(());
    static mut STEP: usize = 0;

    unsafe fn query(address: usize, r0: usize, scratch: &mut [u32; 3]) -> u32 {
        let step = STEP;
        assert_eq!(address, [STORE_REGISTER_4B_BIT2, STORE_BOARD_STATUS_BIT,
            QUERY_CACHED_REGISTER_18_INVERTED_BIT0][step]);
        assert_eq!(*scratch, [11 + step as u32, 22 + step as u32, 33 + step as u32]);
        *scratch = [12 + step as u32, 23 + step as u32, 34 + step as u32];
        STEP += 1;
        if step < 2 {
            *(r0 as *mut u32) = SAMPLES[step];
            0
        } else {
            assert_eq!(r0, 0);
            SAMPLES[step]
        }
    }

    #[test]
    fn priority_short_circuit_and_nonzero_normalization() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = RETAIL_QUERY;
            RETAIL_QUERY = query;
            for (samples, expected, calls) in [
                ([4, 1, 1], 2, 1),
                ([0, 0x8000_0000, 1], 3, 2),
                ([0, 0, 0], 0, 3),
                ([0, 0, 1], 1, 3),
                ([0, 0, u32::MAX], 1, 3),
            ] {
                SAMPLES = samples;
                STEP = 0;
                assert_eq!(pmu_status_class(99, 11, 22, 33), expected);
                assert_eq!(STEP, calls);
            }
            RETAIL_QUERY = previous;
        }
    }
}
