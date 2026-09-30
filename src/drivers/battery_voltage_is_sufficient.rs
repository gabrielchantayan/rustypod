//! Battery-voltage threshold predicate, original `FUN_082bc4b8` @ `0x082bc4b8`.
//! True instruction size: 64 bytes (`0x082bc4b8..0x082bc4f7`), followed by
//! the 3400-mV literal at `0x082bc4f8`; next real function: `0x082bc4fc`.
//! Full-image decoding finds 2 inbound plain BL sites (0x082bcd48, 0x082bcd84)
//! and 0 predicated BL sites; the body has 3 plain BL and 0 predicated BL.
//!
//! Query the PMU status class, then obtain the battery ADC sample through
//! pmu_operation_retry. On success convert it to millivolts and compare using
//! signed GE against 3400 for class 1, otherwise 3600. A failed read returns 0.
//! The saved incoming r3 initializes the sample, including if a successful
//! operation leaves it unchanged. Deliberate deviations: incoming r0-r3 are
//! explicit ABI arguments; host tests substitute the two hardware queries.
//! Target calls reuse all three existing Rust ports; no target algorithm changes.

use crate::util::battery_adc_code_to_millivolts::battery_adc_code_to_millivolts;

#[cfg(target_os = "none")]
use crate::drivers::{pmu_operation_retry::pmu_operation_retry, pmu_status_class::pmu_status_class};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_status_class(_: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("battery_voltage_is_sufficient requires a PMU status query")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sample(_: *mut u32) -> u32 {
    panic!("battery_voltage_is_sufficient requires a PMU sample query")
}
#[cfg(not(target_os = "none"))]
static mut STATUS_CLASS: unsafe extern "C" fn(u32, u32, u32, u32) -> u32 = missing_status_class;
#[cfg(not(target_os = "none"))]
static mut SAMPLE: unsafe extern "C" fn(*mut u32) -> u32 = missing_sample;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn battery_voltage_is_sufficient(
    incoming_r0: u32, incoming_r1: u32, incoming_r2: u32, incoming_r3: u32,
) -> u32 {
    let mut adc_code = incoming_r3;
    #[cfg(target_os = "none")]
    let class = pmu_status_class(incoming_r0, incoming_r1, incoming_r2, incoming_r3);
    #[cfg(not(target_os = "none"))]
    let class = core::ptr::read_volatile(core::ptr::addr_of!(STATUS_CLASS))(
        incoming_r0, incoming_r1, incoming_r2, incoming_r3);
    let threshold = if class == 1 { 3400 } else { 3600 };
    #[cfg(target_os = "none")]
    let status = pmu_operation_retry(&mut adc_code);
    #[cfg(not(target_os = "none"))]
    let status = core::ptr::read_volatile(core::ptr::addr_of!(SAMPLE))(&mut adc_code);
    if status != 0 {
        return 0;
    }
    ((battery_adc_code_to_millivolts(adc_code) as i32) >= threshold) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CLASS: u32 = 0;
    static mut STATUS: u32 = 0;
    static mut CODE: Option<u32> = None;

    unsafe extern "C" fn classify(_: u32, _: u32, _: u32, _: u32) -> u32 { CLASS }
    unsafe extern "C" fn sample(code: *mut u32) -> u32 {
        if let Some(value) = CODE { code.write(value); }
        STATUS
    }

    #[test]
    fn thresholds_failures_and_retained_sample() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = (STATUS_CLASS, SAMPLE);
            STATUS_CLASS = classify;
            SAMPLE = sample;
            for (class, status, code, incoming, expected) in [
                (1, 0, Some(588), 0, 0), // 3399 mV
                (1, 0, Some(589), 0, 1), // 3401 mV
                (0, 0, Some(690), 0, 0), // 3598 mV
                (0, 0, Some(691), 0, 1), // 3600 mV, inclusive
                (2, 0, Some(690), 0, 0),
                (3, 0, Some(691), 0, 1),
                (u32::MAX, 0, Some(690), 0, 0),
                (1, 1, Some(1023), 0, 0),
                (0, u32::MAX, Some(1023), 0, 0),
                (1, 0, None, 589, 1),
                (0, 0, None, 690, 0),
                (1, 0, Some(0), 1023, 0),
                (0, 0, Some(u32::MAX), 0, 1),
            ] {
                CLASS = class;
                STATUS = status;
                CODE = code;
                assert_eq!(battery_voltage_is_sufficient(0, 0, 0, incoming), expected,
                    "class={class} status={status} code={code:?} incoming={incoming}");
            }
            (STATUS_CLASS, SAMPLE) = previous;
        }
    }
}
