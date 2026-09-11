//! `channel_control_apply_enable` — original: `FUN_081085d0` @
//! 0x081085d0 (96 bytes; exactly 9 direct `bl` call sites, all
//! unconditional, and no predicated call forms — verified by decoding every
//! ARM B/BL word in osos.dec).
//!
//! Updates one 0x20-byte-strided channel control word in the 0x3840_0000
//! register block. Selector bit 7 chooses the 0x900 or 0xb00 bank; its low
//! seven bits choose the slot. Except for the special `(selector & 0x7f) ==
//! 0 && enable == 0` no-op, the function first invokes the unported routine
//! at 0x081073f8 with the opaque context and selector, then clears control
//! bits 31..26 and 17. A zero `enable` additionally clears bit 21 and sets
//! bit 28; any nonzero value sets bit 21 instead.
//!
//! # Deviation
//!
//! `FUN_081073f8` is not yet ported (and has no `ported` ledger entry), so
//! target builds call it through its verified firmware address. Host builds
//! expose a test-only replacement seam; this preserves the required call
//! before the register read-modify-write without inventing a callee identity.

/// S5L8702 register block containing the two channel-control banks.
const CHANNEL_CONTROL_BASE: usize = 0x3840_0000;
const PRIMARY_BANK_OFFSET: usize = 0x0b00;
const SECONDARY_BANK_OFFSET: usize = 0x0900;
const CHANNEL_CONTROL_STRIDE: usize = 0x20;
const CHANNEL_COUNT: usize = 128;

/// Computes the control-word transition after the state routine has run.
#[inline]
pub const fn channel_control_enabled_word(current: u32, enable: i32) -> u32 {
    let cleared = current & !0xfc02_0000;
    if enable == 0 {
        (cleared & !0x0020_0000) | 0x1000_0000
    } else {
        cleared | 0x0020_0000
    }
}

#[cfg(target_os = "none")]
const CHANNEL_STATE_DISPATCH_ADDR: usize = 0x0810_73f8;

type ChannelStateDispatch = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut CHANNEL_STATE_DISPATCH: Option<ChannelStateDispatch> = None;

#[cfg(not(target_os = "none"))]
static mut HOST_CHANNEL_CONTROL_WORDS: [u32; CHANNEL_COUNT * 2] = [0; CHANNEL_COUNT * 2];

#[cfg(not(target_os = "none"))]
static mut HOST_CHANNEL_CONTROL_WRITES: usize = 0;

/// Calls the state routine at 0x081073f8, whose identity remains unverified.
#[inline(always)]
unsafe fn channel_state_dispatch(context: *mut u8, selector: u32) {
    #[cfg(target_os = "none")]
    {
        let dispatch: ChannelStateDispatch = core::mem::transmute(CHANNEL_STATE_DISPATCH_ADDR);
        dispatch(context, selector);
    }
    #[cfg(not(target_os = "none"))]
    {
        match core::ptr::read_volatile(core::ptr::addr_of!(CHANNEL_STATE_DISPATCH)) {
            Some(dispatch) => { dispatch(context, selector); }
            None => panic!("channel_control_apply_enable requires dispatcher 0x081073f8"),
        }
    }
}

#[inline(always)]
unsafe fn channel_control_register(selector: u32) -> *mut u32 {
    let index = (selector & 0x7f) as usize;
    #[cfg(target_os = "none")]
    {
        let bank = if selector & 0x80 == 0 {
            PRIMARY_BANK_OFFSET
        } else {
            SECONDARY_BANK_OFFSET
        };
        (CHANNEL_CONTROL_BASE + bank + index * CHANNEL_CONTROL_STRIDE) as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        let bank = ((selector >> 7) & 1) as usize;
        core::ptr::addr_of_mut!(HOST_CHANNEL_CONTROL_WORDS)
            .cast::<u32>()
            .add(bank * CHANNEL_COUNT + index)
    }
}

#[inline(always)]
unsafe fn write_channel_control(register: *mut u32, value: u32) {
    register.write_volatile(value);
    #[cfg(not(target_os = "none"))]
    {
        let writes = core::ptr::addr_of_mut!(HOST_CHANNEL_CONTROL_WRITES);
        writes.write_volatile(writes.read_volatile() + 1);
    }
}

/// Applies a channel enable state to its hardware control word.
///
/// `(selector & 0x7f) == 0` with a zero `enable` is the retail no-op: it
/// calls neither the state routine nor the register access. All other
/// selector/enable states dispatch first, then perform the volatile
/// read-modify-write.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn channel_control_apply_enable(
    context: *mut u8,
    selector: u32,
    enable: i32,
) {
    if selector & 0x7f == 0 && enable == 0 {
        return;
    }

    channel_state_dispatch(context, selector);
    let register = channel_control_register(selector);
    write_channel_control(
        register,
        channel_control_enabled_word(register.read_volatile(), enable),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: usize = 0;
    static mut LAST_CONTEXT: usize = 0;
    static mut LAST_SELECTOR: u32 = 0;

    /// The stock callee can change the control state before this routine reads
    /// it. Writing a sentinel here proves that the port retains that ordering.
    unsafe extern "C" fn record_dispatch(context: *mut u8, selector: u32) -> u32 {
        let calls = addr_of_mut!(DISPATCH_CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        addr_of_mut!(LAST_CONTEXT).write_volatile(context as usize);
        addr_of_mut!(LAST_SELECTOR).write_volatile(selector);
        channel_control_register(selector).write_volatile(0xfdff_ffff);
        0
    }

    fn reference(current: u32, enable: i32) -> u32 {
        let mut result = current & !0xfc00_0000;
        result &= !0x0002_0000;
        if enable == 0 {
            result &= !0x0020_0000;
            result |= 0x1000_0000;
        } else {
            result |= 0x0020_0000;
        }
        result
    }

    #[test]
    fn transitions_banks_and_preserves_dispatch_before_register_read() {
        let _dispatch_guard = DISPATCH_LOCK.lock();
        let context = 0x1234_5000usize as *mut u8;
        let cases = [(0u32, 1i32), (0x81, 0), (0xff, -1), (0x45, 0)];

        unsafe {
            addr_of_mut!(CHANNEL_STATE_DISPATCH).write_volatile(Some(record_dispatch));
            addr_of_mut!(DISPATCH_CALLS).write_volatile(0);
            addr_of_mut!(HOST_CHANNEL_CONTROL_WRITES).write_volatile(0);

            for (selector, enable) in cases {
                channel_control_register(selector).write_volatile(0x0123_4567);
                channel_control_apply_enable(context, selector, enable);
                assert_eq!(
                    channel_control_register(selector).read_volatile(),
                    reference(0xfdff_ffff, enable),
                    "selector={selector:#x}, enable={enable}",
                );
                assert_eq!(addr_of!(LAST_CONTEXT).read_volatile(), context as usize);
                assert_eq!(addr_of!(LAST_SELECTOR).read_volatile(), selector);
            }
            assert_eq!(addr_of!(DISPATCH_CALLS).read_volatile(), cases.len());
            assert_eq!(addr_of!(HOST_CHANNEL_CONTROL_WRITES).read_volatile(), cases.len());
            addr_of_mut!(CHANNEL_STATE_DISPATCH).write_volatile(None);
        }
    }

    #[test]
    fn bank_zero_disable_is_a_true_no_op() {
        let _dispatch_guard = DISPATCH_LOCK.lock();
        unsafe {
            addr_of_mut!(CHANNEL_STATE_DISPATCH).write_volatile(Some(record_dispatch));
            addr_of_mut!(DISPATCH_CALLS).write_volatile(0);
            addr_of_mut!(HOST_CHANNEL_CONTROL_WRITES).write_volatile(0);
            for selector in [0, 0x80] {
                channel_control_register(selector).write_volatile(0x8a2b_cdef);
                channel_control_apply_enable(core::ptr::null_mut(), selector, 0);
                assert_eq!(channel_control_register(selector).read_volatile(), 0x8a2b_cdef);
            }
            assert_eq!(addr_of!(DISPATCH_CALLS).read_volatile(), 0);
            assert_eq!(addr_of!(HOST_CHANNEL_CONTROL_WRITES).read_volatile(), 0);
            addr_of_mut!(CHANNEL_STATE_DISPATCH).write_volatile(None);
        }
    }

    #[test]
    fn transition_matches_independent_bit_model() {
        for current in [0, 0xffff_ffff, 0x1234_5678, 0xfc22_0000] {
            for enable in [-1, 0, 1, i32::MAX] {
                assert_eq!(channel_control_enabled_word(current, enable), reference(current, enable));
            }
        }
    }
}
