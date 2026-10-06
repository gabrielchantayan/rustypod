//! Panel transition — `FUN_0816a580` @ 0x0816a580.
//!
//! True code size: 164 bytes (through 0x0816a620), followed by two literal
//! words; the next real function starts at 0x0816a62c. Raw decoding verifies
//! seven plain outbound BLs, no predicated BLs, and one virtual BLX. There
//! are two plain inbound BLs (0x081d8da0, 0x081d9164), no predicated ones.
//! Sets the format selector, enables and configures the panel, applies the
//! global scale flag, invokes vtable slot 8, marks the panel active, enables
//! its IRQ binding, resets the LCD state, and finally applies the transition.
//! All callee statuses are ignored; returns zero, even for invalid modes.
//! The third argument is unused. Deliberate deviations: named existing Rust
//! scale/IRQ ports replace their stock entries; unnamed dependencies retain
//! exact firmware addresses. A private inline dispatcher allows isolated host
//! tests without hardware. Pointer indexing accommodates native host width.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step { Enable, Configure, SelectPath, Scale, VirtualEnable, EnableIrq, ResetLcd, Transition }

#[inline(always)]
unsafe fn transition_with(
    panel: *mut u8, mode: u32, transition: u32, state: *mut u8,
    scale_flag: *const u8, mut call: impl FnMut(Step, *mut u8, u32),
) -> u32 {
    state.add(7).write_volatile(if transition == 2 { 3 } else { 0 });
    call(Step::Enable, panel, 1);
    call(Step::Configure, panel, mode);
    call(Step::SelectPath, panel, u32::from(transition != 2));
    call(Step::Scale, panel, u32::from(scale_flag.read_volatile() != 0));
    call(Step::VirtualEnable, panel, 1);
    state.add(8).write_volatile(1);
    let binding = state.add(0x30).cast::<u32>().read_volatile();
    call(Step::EnableIrq, binding as usize as *mut u8, 0);
    call(Step::ResetLcd, core::ptr::null_mut(), 0);
    call(Step::Transition, panel, transition);
    0
}

/// # Safety
/// Requires a live retail panel, its vtable, the shared firmware globals and
/// all hardware dependencies. There are no NULL guards or mode validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn panel_apply_transition(
    panel: *mut u8, mode: u32, _reserved: u32, transition: u32,
) -> u32 {
    transition_with(panel, mode, transition, 0x089c_c9b4 as *mut u8,
        0x089c_af7e as *const u8, |step, object, value| {
            match step {
                Step::Scale => { super::panel_scale_mode::panel_set_scale_mode(object, value); }
                Step::EnableIrq => crate::kernel::irq_binding::irq_binding_enable(object.cast()),
                Step::VirtualEnable => {
                    let table = object.cast::<*const unsafe extern "C" fn(*mut u8, u32)>().read();
                    (table.add(8).read())(object, value);
                }
                Step::ResetLcd => {
                    let reset: unsafe extern "C" fn() = core::mem::transmute(0x080b_e760usize);
                    reset();
                }
                _ => {
                    let address = match step {
                        Step::Enable => 0x0816_8ebcusize,
                        Step::Configure => 0x0816_a2b0,
                        Step::SelectPath => 0x0816_a370,
                        Step::Transition => 0x0816_a3fc,
                        _ => unreachable!(),
                    };
                    let original: unsafe extern "C" fn(*mut u8, u32) -> i32 = core::mem::transmute(address);
                    original(object, value);
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_modes_preserve_full_words_and_ordered_state() {
        for mode in [0, 1, 2, 0xffff_ffff] {
            for transition in [0, 1, 2, 3, 0xffff_ffff] {
                for flag in [0u8, 1, 255] {
                    let mut state = [0xaaaa_aaaau32; 16];
                    state[12] = 0x1234_5678;
                    let bytes = state.as_mut_ptr().cast::<u8>();
                    let panel = core::ptr::NonNull::<u8>::dangling().as_ptr();
                    let expected = [
                        (Step::Enable, panel, 1), (Step::Configure, panel, mode),
                        (Step::SelectPath, panel, u32::from(transition != 2)),
                        (Step::Scale, panel, u32::from(flag != 0)),
                        (Step::VirtualEnable, panel, 1),
                        (Step::EnableIrq, 0x1234_5678usize as *mut u8, 0),
                        (Step::ResetLcd, core::ptr::null_mut(), 0),
                        (Step::Transition, panel, transition),
                    ];
                    let mut index = 0;
                    let result = unsafe { transition_with(panel, mode, transition, bytes, &flag,
                        |step, object, value| {
                            assert_eq!((step, object, value), expected[index]);
                            assert_eq!(bytes.add(7).read(), if transition == 2 { 3 } else { 0 });
                            assert_eq!(bytes.add(8).read(), if index < 5 { 0xaa } else { 1 });
                            index += 1;
                        }) };
                    assert_eq!(result, 0);
                    assert_eq!(index, 8);
                    let mut expected_state = [0xaaaa_aaaau32; 16];
                    expected_state[12] = 0x1234_5678;
                    unsafe {
                        let expected_bytes = expected_state.as_mut_ptr().cast::<u8>();
                        expected_bytes.add(7).write(if transition == 2 { 3 } else { 0 });
                        expected_bytes.add(8).write(1);
                    }
                    assert_eq!(state, expected_state);
                }
            }
        }
    }

    #[test]
    fn scale_flag_is_read_after_configuration() {
        let mut state = [0u32; 16];
        let flag = core::cell::Cell::new(0u8);
        unsafe {
            transition_with(core::ptr::null_mut(), 0, 0, state.as_mut_ptr().cast(),
                flag.as_ptr(), |step, _, value| {
                    if step == Step::SelectPath { flag.set(128); }
                    if step == Step::Scale { assert_eq!(value, 1); }
                });
        }
    }
}
