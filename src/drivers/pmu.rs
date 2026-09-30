//! PMU status bit selected by board generation.
//!
//! `pmu_board_version_status_bit` — original: `FUN_082e5b64` @
//! `0x082e5b64` (76 bytes; the distinct `push {r4,r5,r6,lr}` prologue at
//! `0x082e5bb0` confirms the extent).
//!
//! Binary decoding of every ARM B/BL word in `osos.dec` finds **8 direct
//! `bl` callers**, all unconditional (cond=e; no predicated forms):
//! 0x080608a8, 0x08060958, 0x080609c0, 0x080c8898, 0x080d3ce8,
//! 0x080e36a8, 0x082e5798, and 0x08392ff8.
//!
//! The routine snapshots the incoming r3 word into its stack byte, obtains
//! the lazily cached board version, then holds PMU transaction semaphores 17
//! and 5 while reading one PCF50635 byte. Boards whose high version halfword
//! is 0x11 read register 0x4b and return bit 0; every other board reads
//! register 0x12 and returns bit 2. The raw I2C status is deliberately
//! ignored, so a failed transfer leaves the saved incoming-r3 byte and its
//! selected bit becomes the result.
//!
//! # Deviations
//!
//! The retail ABI has no declared arguments but preserves its incoming r3 in
//! the stack scratch byte before the transfer. Rust exposes r0-r3 explicitly
//! so `incoming_r3` retains that observable failed-transfer behavior; the
//! other three words remain unused. The six direct retail calls resolve to
//! their already-ported Rust functions, replacing direct `bl` edges with
//! normal Rust calls.

use crate::drivers::i2c::{pmu_i2c_read, pmu_i2c_write};
use crate::kernel::task_lock::{kernel_sem17_signal, kernel_sem17_wait, kernel_sem5_signal, kernel_sem5_wait};
use crate::sysinfo::board_version;

/// PCF50635 register read only on boards whose version high halfword is 0x11.
const PMU_BOARD_0X11_STATUS_REGISTER: u32 = 0x4b;
/// PCF50635 register read on every other board generation.
const PMU_OTHER_BOARD_STATUS_REGISTER: u32 = 0x12;
/// PCF50635 register selected by `FUN_082e53d8`; its semantic register name
/// is not established from the retail image.
const PMU_REGISTER_0X4B: u32 = 0x4b;

/// PMU register selected by `FUN_082e5a70`; its hardware role is not
/// established from the retail image.
const PMU_REGISTER_0X0C: u32 = 0x0c;

/// Retail selector-0 scaled PMU write, verified at 0x082e5500.
/// Returns the final semaphore-17 signal word, not the discarded I2C status.
type PmuSelector0ScaledWriteFn = unsafe extern "C" fn(value: u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pmu_write_selector0_scaled_value(value: u32) -> u32 {
    let write: PmuSelector0ScaledWriteFn = core::mem::transmute(0x082e_5500_usize);
    write(value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_selector0_scaled_write(_value: u32) -> u32 {
    panic!("pmu_select_3000_or_3300 requires retail PMU writer 0x082e5500")
}

#[cfg(not(target_os = "none"))]
static mut PMU_SELECTOR0_SCALED_WRITE: PmuSelector0ScaledWriteFn = missing_pmu_selector0_scaled_write;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pmu_write_selector0_scaled_value(value: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_SELECTOR0_SCALED_WRITE))(value)
}

/// pmu_select_3000_or_3300 — original: `FUN_082bc55c` @ `0x082bc55c`.
/// True extent: 24 bytes (16 instruction bytes plus two literal words);
/// the next real function starts at 0x082bc574. Raw ARM branch decoding
/// finds 2 plain inbound BL calls, 0 predicated inbound BL calls, and no
/// outgoing BL instructions; the only outgoing call is an unconditional B.
///
/// Selects 3000 for zero and 3300 for every nonzero input, then tail-calls
/// the selector-0 scaled PMU writer at 0x082e5500. Its final semaphore signal
/// result passes through r0 unchanged. Ghidra incorrectly includes code
/// reached through the tail branch in its reported 92-byte extent.
///
/// Deliberate deviations: the unported writer is invoked through a typed
/// fixed-address boundary (replaceable on hosts). Exposes the observable
/// r0 result even though both known retail callers ignore it. The hardware
/// role and units of these two values are not assumed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_select_3000_or_3300(high: u32) -> u32 {
    pmu_write_selector0_scaled_value(if high == 0 { 3000 } else { 3300 })
}

/// ABI of the still-unported PMU command/response transaction
/// `FUN_0836d260`.
type PmuQueryFn = unsafe extern "C" fn(request: u32, flags: u32, response: *mut u32) -> i32;

const PMU_QUERY_ADDRESS: usize = 0x0836_d260;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pmu_query(request: u32, flags: u32, response: *mut u32) -> i32 {
    let query: PmuQueryFn = core::mem::transmute(PMU_QUERY_ADDRESS);
    query(request, flags, response)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_query(_request: u32, _flags: u32, _response: *mut u32) -> i32 {
    panic!("pmu_query_mode_response requires PMU command transaction 0x0836d260")
}

#[cfg(not(target_os = "none"))]
static mut PMU_QUERY: PmuQueryFn = missing_pmu_query;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pmu_query(request: u32, flags: u32, response: *mut u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_QUERY))(request, flags, response)
}

/// Verified mode/response word transform ABI at `FUN_082e5844`.
/// Its body queries the mode, transforms the response for modes 2 or 4,
/// and returns 1 for other modes. The transform itself remains retail code.
type PmuModeResponseTransformFn = unsafe extern "C" fn(mode: u32, response: *mut u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pmu_transform_mode_response(mode: u32, response: *mut u32) -> u32 {
    let transform: PmuModeResponseTransformFn = core::mem::transmute(0x082e_5844_usize);
    transform(mode, response)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_transform_mode_response(_mode: u32, _response: *mut u32) -> u32 {
    panic!("pmu_transform_mode_response_locked requires retail transform 0x082e5844")
}

#[cfg(not(target_os = "none"))]
static mut PMU_TRANSFORM_MODE_RESPONSE: PmuModeResponseTransformFn = missing_pmu_transform_mode_response;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pmu_transform_mode_response(mode: u32, response: *mut u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_TRANSFORM_MODE_RESPONSE))(mode, response)
}
/// ABI of the still-unported PCF50635 register 0x43 bit-0 update
/// `FUN_0836d5a8`.
type PmuRegister43Bit0Fn = unsafe extern "C" fn(enabled: u32) -> i32;

const PMU_REGISTER_0X43_BIT0_ADDRESS: usize = 0x0836_d5a8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pmu_set_register_0x43_bit0(enabled: u32) -> i32 {
    let set_bit: PmuRegister43Bit0Fn = core::mem::transmute(PMU_REGISTER_0X43_BIT0_ADDRESS);
    set_bit(enabled)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_set_register_0x43_bit0(_enabled: u32) -> i32 {
    panic!("pmu_update_register_0x43_bit0 requires PMU register 0x43 update 0x0836d5a8")
}

#[cfg(not(target_os = "none"))]
static mut PMU_SET_REGISTER_0X43_BIT0: PmuRegister43Bit0Fn = missing_pmu_set_register_0x43_bit0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pmu_set_register_0x43_bit0(enabled: u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_SET_REGISTER_0X43_BIT0))(enabled)
}

/// ABI of the still-unported key-matrix scan `FUN_080d3ce0`.
type KeyMatrixScanFn = unsafe extern "C" fn() -> u32;

const KEY_MATRIX_SCAN_ADDRESS: usize = 0x080d_3ce0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn key_matrix_scan() -> u32 {
    let scan: KeyMatrixScanFn = core::mem::transmute(KEY_MATRIX_SCAN_ADDRESS);
    scan()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_key_matrix_scan() -> u32 {
    panic!("pmu_status_available_without_keypress requires key-matrix scan 0x080d3ce0")
}

#[cfg(not(target_os = "none"))]
static mut KEY_MATRIX_SCAN: KeyMatrixScanFn = missing_key_matrix_scan;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn key_matrix_scan() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(KEY_MATRIX_SCAN))()
}


/// pmu_update_register_0x43_bit0 — original: `FUN_082e5a20` @
/// `0x082e5a20` (44 bytes; 2 unconditional `bl` call sites, binary-verified).
///
/// Holds PMU transaction semaphores 17 then 5 while setting or clearing bit 0
/// of PCF50635 register 0x43. Releases semaphore 5 then 17 unconditionally
/// and returns the underlying register-update status.
///
/// # Deviations
///
/// The bit update at `0x0836d5a8` is not ported. Target builds call its
/// verified typed address; host tests replace that boundary. The four
/// semaphore veneers are existing Rust ports, so their retail direct calls
/// become ordinary Rust calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_update_register_0x43_bit0(enabled: u32) -> i32 {
    kernel_sem17_wait();
    kernel_sem5_wait();
    let status = pmu_set_register_0x43_bit0(enabled);
    kernel_sem5_signal();
    kernel_sem17_signal();

    status
}


/// pmu_write_register_0x0c_one — original: `FUN_082e5a70` @ `0x082e5a70`
/// (60 bytes; 1 plain `bl` and 2 predicated `bl` call sites,
/// binary-verified).
///
/// Writes the byte one to PCF50635 register 0x0c while holding semaphore 17
/// then semaphore 5. Releases semaphore 5 then semaphore 17 unconditionally
/// and returns the raw PMU I2C write status.
///
/// # Deviations
///
/// Retail's five direct callee edges resolve to existing Rust semaphore and
/// PMU-I2C ports, replacing direct `bl` edges with ordinary Rust calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_write_register_0x0c_one() -> i32 {
    let value = 1_u32;

    kernel_sem17_wait();
    kernel_sem5_wait();
    let status = pmu_i2c_write(PMU_REGISTER_0X0C, 1, (&value as *const u32).cast());
    kernel_sem5_signal();
    kernel_sem17_signal();

    status
}
/// pmu_write_register_0x39_scaled_value — original: `FUN_082e5468` @
/// `0x082e5468` (76 bytes; 2 plain inbound `bl` call sites, 0 predicated
/// inbound `bl`, and 5 plain unconditional callee `bl` instructions,
/// binary-verified from `osos.dec`).
///
/// Holds PMU transaction semaphores 17 then 5 while writing the two-byte
/// packed selector-6 command to PCF50635 register 0x39. A zero `value` writes
/// first byte 0x18; every other value writes the low byte of
/// `(value - 0x321) / 100`. The command's second byte is one. Releases
/// semaphore 5 then semaphore 17 unconditionally; retail discards the I2C
/// status.
///
/// # Deviation
///
/// Retail calls the semaphore veneers, ADS unsigned divider, and packed
/// selector helper directly. The Rust port uses existing Rust ports; the
/// direct `bl` edges become ordinary Rust calls and Rust's `u32` division
/// preserves the verified nonzero-input quotient.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_write_register_0x39_scaled_value(value: u32) {
    kernel_sem17_wait();
    kernel_sem5_wait();

    let first_byte = if value == 0 {
        0x18
    } else {
        crate::runtime::rt_div::__rt_udiv(value.wrapping_sub(0x321), 100)
    };
    crate::drivers::i2c::pmu_i2c_write_packed_selector(6, first_byte, 1);

    kernel_sem5_signal();
    kernel_sem17_signal();
}



/// pmu_board_version_status_bit — original: `FUN_082e5b64` @ `0x082e5b64`
/// (76 bytes; 8 unconditional `bl` call sites, binary-verified).
///
/// Reads the generation-selected PMU status byte while holding semaphore 17
/// then semaphore 5, releases 5 then 17 unconditionally, and returns the
/// selected one-bit field. The I2C status is ignored exactly as in retail;
/// therefore its failed-transfer result derives from the low byte of the
/// incoming r3 scratch word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_board_version_status_bit(
    _incoming_r0: u32,
    _incoming_r1: u32,
    _incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    let version = board_version();

    let version_0x11 = (version >> 16 == 0x11) as u32;
    kernel_sem17_wait();
    kernel_sem5_wait();

    let register = PMU_OTHER_BOARD_STATUS_REGISTER
        + version_0x11 * (PMU_BOARD_0X11_STATUS_REGISTER - PMU_OTHER_BOARD_STATUS_REGISTER);
    let mut status_byte = incoming_r3 as u8;
    pmu_i2c_read(register, 1, &mut status_byte);

    kernel_sem5_signal();
    kernel_sem17_signal();

    ((status_byte as u32 >> ((1 - version_0x11) << 1)) & 1) as u32
}
/// pmu_register_0x18_bit0 — original: `FUN_082e572c` @ `0x082e572c`
/// (64 bytes; 5 plain, unconditional callee `bl` instructions; no predicated
/// calls, binary-verified).
///
/// Clears the one-byte stack result, holds PMU transaction semaphores 17 then
/// 5, reads PCF50635 register 0x18, releases 5 then 17, and returns bit zero
/// of the result. The raw I2C status is ignored; because retail explicitly
/// initializes the scratch byte to zero, a failed transfer returns zero.
///
/// # Deviations
///
/// None. All five verified retail callee targets are existing Rust ports.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_register_0x18_bit0() -> u32 {
    let mut status_byte = 0_u8;

    kernel_sem17_wait();
    kernel_sem5_wait();
    pmu_i2c_read(0x18, 1, &mut status_byte);
    kernel_sem5_signal();
    kernel_sem17_signal();

    (status_byte & 1) as u32
}



/// pmu_status_available_without_keypress — original: `FUN_082e576c` @
/// `0x082e576c` (40 bytes; 2 plain, unconditional callee `bl` instructions,
/// no predicated calls, binary-verified).
///
/// Returns one only when the board-selected PMU status bit is set and the
/// 3x3 key-matrix scan returns zero; otherwise returns zero. The PMU check
/// short-circuits the matrix scan when unavailable.
///
/// # Deviations
///
/// The PMU status-bit callee is already ported. `FUN_080d3ce0` is an
/// unported key-matrix scan inferred from its verified GPIO threshold-table
/// behavior, so target builds call its verified address through a no-argument
/// typed boundary and host tests replace that boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_status_available_without_keypress(
    incoming_r0: u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    if pmu_board_version_status_available(incoming_r0, incoming_r1, incoming_r2, incoming_r3) != 0
        && key_matrix_scan() == 0
    {
        1
    } else {
        0
    }
}

/// pmu_board_version_status_available — original: `FUN_082e5794` @
/// `0x082e5794` (20 bytes; one plain, unconditional callee `bl`, no
/// predicated calls; two plain direct callers, binary-verified).
///
/// Calls `pmu_board_version_status_bit` with its four incoming ABI words and
/// normalizes its result to a zero-or-one availability flag.
///
/// # Deviations
///
/// The sole verified retail callee is the existing Rust PMU status-bit port,
/// so the direct `bl` becomes an ordinary Rust call. The explicit ABI words
/// preserve the callee's incoming-r3 failed-transfer behavior. A volatile
/// stack read preserves the retail call-and-normalize structure against LLVM
/// tail-call elimination; it does not change the returned value.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_board_version_status_available(
    incoming_r0: u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    let status = pmu_board_version_status_bit(incoming_r0, incoming_r1, incoming_r2, incoming_r3);
    (core::ptr::read_volatile(&status) != 0) as u32
}

/// pmu_register_0x4b_bit2 — original: `FUN_082e53d8` @ `0x082e53d8`
/// (52 bytes; 6 unconditional `bl` call sites, binary-verified).
///
/// Acquires PMU transaction semaphores 17 then 5, reads one byte from
/// PCF50635 register 0x4b, releases 5 then 17 unconditionally, and returns
/// bit 2. Retail ignores the I2C status: a failed register write leaves the
/// low byte of incoming r3 in the stack scratch byte, so its bit 2 is the
/// result.
///
/// # Deviations
///
/// None. The retail ABI has no declared arguments but saves incoming r3 in
/// the stack scratch byte. Rust exposes r0-r3 explicitly to preserve the
/// failed-transfer result; the other words remain unused. All five direct
/// callee targets are already-ported Rust functions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_register_0x4b_bit2(
    _incoming_r0: u32,
    _incoming_r1: u32,
    _incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    kernel_sem17_wait();
    kernel_sem5_wait();

    let mut status_byte = incoming_r3 as u8;
    pmu_i2c_read(PMU_REGISTER_0X4B, 1, &mut status_byte);

    kernel_sem5_signal();
    kernel_sem17_signal();

    ((status_byte & 4) >> 2) as u32
}

/// store_pmu_register_0x4b_bit2 — original: `FUN_080bfbd4` @ `0x080bfbd4`
/// (24 bytes; 1 plain `bl`, 0 predicated `bl`, binary-verified).
///
/// Queries PCF50635 register 0x4b bit 2 through `pmu_register_0x4b_bit2`,
/// stores that one-bit result through `result`, and returns zero.
///
/// # Deviations
///
/// The retail function inherits r1-r3 unchanged into its one callee. Rust
/// declares those otherwise-undeclared ABI words so the callee preserves its
/// incoming-r3 failed-transfer behavior; the retail `bl` becomes the existing
/// Rust function call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn store_pmu_register_0x4b_bit2(
    result: *mut u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    *result = pmu_register_0x4b_bit2(0, incoming_r1, incoming_r2, incoming_r3);
    0
}

/// pmu_apply_mode_registers — original: `FUN_082e57a8` @ `0x082e57a8`
/// (44 bytes; 4 plain `bl` call sites, 0 predicated `bl`, binary-verified).
///
/// Holds PMU transaction semaphores 17 then 5, writes 0x6f to PCF50635
/// register 0x1a, then writes 10 to register 0x1d. Only when that second
/// write succeeds does it write `mode != 0` to register 0x1b. It always
/// releases semaphore 5 then 17 and returns no value.
///
/// # Deviations
///
/// Retail's five direct callee edges are ordinary Rust calls to the existing
/// semaphore and PMU-I2C ports; ignored status words and release order remain
/// unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_apply_mode_registers(mode: u32) {
    let first_value = 0x6f_u8;
    let mut second_value = 10_u8;

    kernel_sem17_wait();
    kernel_sem5_wait();
    pmu_i2c_write(0x1a, 1, &first_value);
    let status = pmu_i2c_write(0x1d, 1, &mut second_value);
    if status == 0 {
        let mode_value = (mode != 0) as u8;
        pmu_i2c_write(0x1b, 1, &mode_value);
    }
    kernel_sem5_signal();
    kernel_sem17_signal();
}

/// pmu_query_mode_response — original: `FUN_082e57d4` @ `0x082e57d4`
/// (112 bytes; 3 plain inbound `bl` call sites, 0 predicated inbound `bl`
/// call sites; 5 direct callee `bl` instructions, binary-verified).
///
/// Holds PMU transaction semaphores 17 then 5 while issuing one PMU
/// command/response transaction. Mode 1 uses request 7 with flags 3; mode 2
/// uses request 1 with flags 0; modes 3 and 4 use request 2 with flags 0.
/// Other modes skip the transaction and return 1. Both semaphores release in
/// reverse order on every path; a transaction status returns verbatim.
///
/// # Deviations
///
/// The command transaction `FUN_0836d260` has no established higher-level
/// identity. Target builds call its verified load address through a typed
/// boundary; host tests replace the volatile boundary. The semaphore veneers
/// are existing Rust ports, so all five retail direct `bl` edges become
/// ordinary Rust calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_query_mode_response(mode: u32, response: *mut u32) -> i32 {
    kernel_sem17_wait();
    kernel_sem5_wait();
    let status = match mode {
        1 => pmu_query(7, 3, response),
        2 => pmu_query(1, 0, response),
        3 | 4 => pmu_query(2, 0, response),
        _ => 1,
    };
    kernel_sem5_signal();
    kernel_sem17_signal();
    status
}

/// pmu_transform_mode_response_locked — original: `FUN_082bc940` @
/// `0x082bc940` (52 bytes; 2 plain inbound BL, 0 predicated inbound BL;
/// 3 plain callee BL, 0 predicated callee BL, independently binary-verified).
///
/// Waits on semaphore 18, runs the retail mode/response transform, then
/// signals semaphore 18 unconditionally. Semaphore statuses are ignored,
/// including a failed wait; the transform's full result word is preserved.
/// The next real function starts with a push at `0x082bc974`.
///
/// Deliberate deviations: semaphore veneers use existing Rust ports; the
/// unported transform at `0x082e5844` uses a typed target-address seam and a
/// replaceable host callback. No argument validation or status remapping.
///
/// # Safety
/// `response` must satisfy the retail transform's pointer requirements for
/// the supplied mode; no NULL guard is added by this wrapper.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_transform_mode_response_locked(mode: u32, response: *mut u32) -> u32 {
    crate::kernel::task_lock::rom_sem_wait(18);
    let status = pmu_transform_mode_response(mode, response);
    crate::kernel::task_lock::rom_sem_signal(18);
    status
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::i2c::tests::{
        install_raw_i2c_for_test, raw_i2c_calls_for_test, raw_i2c_packets_for_test,
    };
    use parking_lot::Mutex;

    static PMU_QUERY_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PMU_QUERY_ARGS: (u32, u32) = (0, 0);
    static mut PMU_QUERY_RESPONSE: u32 = 0;
    static mut PMU_QUERY_STATUS: i32 = 0;
    static PMU_REGISTER_0X43_BIT0_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PMU_REGISTER_0X43_BIT0_ENABLED: u32 = 0;
    static mut PMU_REGISTER_0X43_BIT0_STATUS: i32 = 0;
    static KEY_MATRIX_SCAN_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut KEY_MATRIX_SCAN_RESULT: u32 = 0;

    static PMU_SELECTOR0_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn encode_selected_value(value: u32) -> u32 {
        // The verified nonzero-input retail encoding; retain a high-bit
        // signal sentinel to detect accidental result normalization.
        0x8000_0000 | (value.wrapping_sub(0x321) / 100)
    }

    struct Selector0Fixture;

    impl Drop for Selector0Fixture {
        fn drop(&mut self) {
            unsafe { PMU_SELECTOR0_SCALED_WRITE = missing_pmu_selector0_scaled_write; }
        }
    }

    #[test]
    fn selector0_distinguishes_zero_from_all_nonzero_words() {
        let _lock = PMU_SELECTOR0_TEST_LOCK.lock();
        let _fixture = Selector0Fixture;
        unsafe {
            PMU_SELECTOR0_SCALED_WRITE = encode_selected_value;
            assert_eq!(pmu_select_3000_or_3300(0), 0x8000_0015);
            for high in [1, 2, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                assert_eq!(pmu_select_3000_or_3300(high), 0x8000_0018);
            }
        }
    }

    static mut TRANSFORM_PHASE: u32 = 0;
    static mut TRANSFORM_STATUS: u32 = 0;

    unsafe extern "C" fn failing_transform_wait(sem: usize) -> usize {
        assert_eq!(sem, 18);
        assert_eq!(TRANSFORM_PHASE, 0);
        TRANSFORM_PHASE = 1;
        9
    }

    unsafe extern "C" fn failing_transform_signal(sem: usize) -> usize {
        assert_eq!(sem, 18);
        assert_eq!(TRANSFORM_PHASE, 2);
        TRANSFORM_PHASE = 3;
        10
    }

    unsafe extern "C" fn transform_under_lock(mode: u32, response: *mut u32) -> u32 {
        assert_eq!(TRANSFORM_PHASE, 1);
        TRANSFORM_PHASE = 2;
        if mode == 4 {
            *response = (*response).wrapping_add(1);
        } else {
            assert!(response.is_null());
        }
        TRANSFORM_STATUS
    }

    struct TransformFixture;

    impl Drop for TransformFixture {
        fn drop(&mut self) {
            unsafe { PMU_TRANSFORM_MODE_RESPONSE = missing_pmu_transform_mode_response; }
        }
    }

    #[test]
    fn mode_transform_releases_after_errors_and_preserves_result_word() {
        let _kernel = install_raw_i2c_for_test(0, 0, 0);
        let _transform = TransformFixture;
        unsafe {
            PMU_TRANSFORM_MODE_RESPONSE = transform_under_lock;
            let kernel = core::ptr::addr_of_mut!(crate::kernel::task_lock::ROM_KERNEL);
            let mut ops = kernel.read_volatile();
            ops.rom_sem_wait = failing_transform_wait;
            ops.rom_sem_signal = failing_transform_signal;
            kernel.write_volatile(ops);
            for status in [0, 1, 0x8000_0000, u32::MAX] {
                TRANSFORM_STATUS = status;
                TRANSFORM_PHASE = 0;
                let mut response = u32::MAX;
                assert_eq!(pmu_transform_mode_response_locked(4, &mut response), status);
                assert_eq!(response, 0);
                assert_eq!(TRANSFORM_PHASE, 3);
            }
            TRANSFORM_STATUS = 1;
            TRANSFORM_PHASE = 0;
            assert_eq!(pmu_transform_mode_response_locked(u32::MAX, core::ptr::null_mut()), 1);
            assert_eq!(TRANSFORM_PHASE, 3);
        }
    }

    unsafe extern "C" fn record_key_matrix_scan() -> u32 {
        KEY_MATRIX_SCAN_RESULT
    }

    struct KeyMatrixScanFixture;

    impl Drop for KeyMatrixScanFixture {
        fn drop(&mut self) {
            unsafe {
                KEY_MATRIX_SCAN = missing_key_matrix_scan;
            }
        }
    }

    unsafe fn install_key_matrix_scan_for_test(result: u32) -> KeyMatrixScanFixture {
        KEY_MATRIX_SCAN_RESULT = result;
        KEY_MATRIX_SCAN = record_key_matrix_scan;
        KeyMatrixScanFixture
    }


    unsafe extern "C" fn record_pmu_set_register_0x43_bit0(enabled: u32) -> i32 {
        PMU_REGISTER_0X43_BIT0_ENABLED = enabled;
        PMU_REGISTER_0X43_BIT0_STATUS
    }

    struct PmuRegister43Bit0Fixture;

    impl Drop for PmuRegister43Bit0Fixture {
        fn drop(&mut self) {
            unsafe {
                PMU_SET_REGISTER_0X43_BIT0 = missing_pmu_set_register_0x43_bit0;
            }
        }
    }

    unsafe fn install_pmu_set_register_0x43_bit0_for_test(status: i32) -> PmuRegister43Bit0Fixture {
        PMU_REGISTER_0X43_BIT0_ENABLED = 0;
        PMU_REGISTER_0X43_BIT0_STATUS = status;
        PMU_SET_REGISTER_0X43_BIT0 = record_pmu_set_register_0x43_bit0;
        PmuRegister43Bit0Fixture
    }


    unsafe extern "C" fn record_pmu_query(request: u32, flags: u32, response: *mut u32) -> i32 {
        PMU_QUERY_ARGS = (request, flags);
        *response = PMU_QUERY_RESPONSE;
        PMU_QUERY_STATUS
    }

    struct PmuQueryFixture;

    impl Drop for PmuQueryFixture {
        fn drop(&mut self) {
            unsafe {
                PMU_QUERY = missing_pmu_query;
            }
        }
    }

    unsafe fn install_pmu_query_for_test(response: u32, status: i32) -> PmuQueryFixture {
        PMU_QUERY_ARGS = (0, 0);
        PMU_QUERY_RESPONSE = response;
        PMU_QUERY_STATUS = status;
        PMU_QUERY = record_pmu_query;
        PmuQueryFixture
    }
    #[test]
    fn register_43_bit_zero_update_forwards_mode_status_and_releases_locks() {
        let _lock = PMU_REGISTER_0X43_BIT0_TEST_LOCK.lock();
        let _callee = unsafe { install_pmu_set_register_0x43_bit0_for_test(-5) };
        let _i2c = install_raw_i2c_for_test(0, 0, 0);

        assert_eq!(unsafe { pmu_update_register_0x43_bit0(0xfeed_beef) }, -5);
        assert_eq!(unsafe { PMU_REGISTER_0X43_BIT0_ENABLED }, 0xfeed_beef);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert!(writes.is_empty());
        assert!(reads.is_empty());
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }


    #[test]
    fn query_modes_select_the_verified_request_pairs() {
        let _lock = PMU_QUERY_TEST_LOCK.lock();
        let _query = unsafe { install_pmu_query_for_test(0xfeed_beef, -7) };
        let _i2c = install_raw_i2c_for_test(0, 0, 0);

        for (mode, request, flags) in [(1, 7, 3), (2, 1, 0), (3, 2, 0), (4, 2, 0)] {
            let mut response = 0;
            assert_eq!(unsafe { pmu_query_mode_response(mode, &mut response) }, -7);
            assert_eq!(response, 0xfeed_beef);
            assert_eq!(unsafe { PMU_QUERY_ARGS }, (request, flags));
        }
    }

    #[test]
    fn invalid_query_mode_skips_the_transaction_and_returns_one() {
        let _lock = PMU_QUERY_TEST_LOCK.lock();
        let _query = unsafe { install_pmu_query_for_test(0xfeed_beef, -7) };
        let mut response = 0x1234_5678;
        let _i2c = install_raw_i2c_for_test(0, 0, 0);

        assert_eq!(unsafe { pmu_query_mode_response(0, &mut response) }, 1);
        assert_eq!(response, 0x1234_5678);
        assert_eq!(unsafe { PMU_QUERY_ARGS }, (0, 0));
    }

    #[test]
    fn register_0c_one_returns_write_status_and_releases_locks() {
        {
            let _i2c = install_raw_i2c_for_test(0, 0, 0);

            assert_eq!(unsafe { pmu_write_register_0x0c_one() }, 0);
            let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
            assert_eq!(writes, std::vec![(0x73, 2, PMU_REGISTER_0X0C as u8)]);

            assert!(reads.is_empty());
            assert_eq!(unsafe { raw_i2c_packets_for_test() }, std::vec![std::vec![0x0c, 1]]);
            assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 0);
        assert_eq!(unsafe { pmu_write_register_0x0c_one() }, -5);
        let (_writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert!(reads.is_empty());
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }
    #[test]
    fn register_39_scaled_value_serializes_zero_and_wrapped_quotient() {
        {
            let _i2c = install_raw_i2c_for_test(0, 0, 0);

            unsafe { pmu_write_register_0x39_scaled_value(0) };

            let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
            assert_eq!(writes, std::vec![(0x73, 3, 0x39)]);
            assert!(reads.is_empty());
            assert_eq!(unsafe { raw_i2c_packets_for_test() }, std::vec![std::vec![0x39, 0x18, 1]]);
            assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 0);
        unsafe { pmu_write_register_0x39_scaled_value(0x321 + 100 * 0x1ff) };
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 3, 0x39)]);
        assert!(reads.is_empty());
        assert_eq!(unsafe { raw_i2c_packets_for_test() }, std::vec![std::vec![0x39, 0xff, 1]]);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn register_18_bit_zero_returns_sample_and_zero_after_transfer_error() {
        {
            let _i2c = install_raw_i2c_for_test(0, 0, 1);

            assert_eq!(unsafe { pmu_register_0x18_bit0() }, 1);
            let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
            assert_eq!(writes, std::vec![(0x73, 1, 0x18)]);
            assert_eq!(reads.len(), 1);
            assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 1);
        assert_eq!(unsafe { pmu_register_0x18_bit0() }, 0);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, 0x18)]);
        assert!(reads.is_empty(), "a failed register write suppresses the read");
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }
    use crate::sysinfo::install_host_cached_board_version;
    extern crate std;

    #[test]
    fn board_0x11_reads_register_4b_and_returns_bit_zero() {
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0001);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 0) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_BOARD_0X11_STATUS_REGISTER as u8)]);
        assert_eq!(reads.len(), 1, "a successful one-byte register read occurs");
        assert_eq!(reads[0].0, 0x73);
        assert_eq!(reads[0].1, 1);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }


    #[test]
    fn board_status_availability_normalizes_selected_status_bit() {
        let _board = install_host_cached_board_version(0x0011_0000);

        {
            let _i2c = install_raw_i2c_for_test(0, 0, 0);
            assert_eq!(unsafe { pmu_board_version_status_available(0, 0, 0, 0) }, 0);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 0);
        assert_eq!(unsafe { pmu_board_version_status_available(0, 0, 0, 1) }, 1);
    }

    #[test]
    fn status_without_keypress_requires_status_then_zero_matrix_scan() {
        let _lock = KEY_MATRIX_SCAN_TEST_LOCK.lock();
        let _board = install_host_cached_board_version(0x0011_0000);

        {
            let _matrix = unsafe { install_key_matrix_scan_for_test(0) };
            let _i2c = install_raw_i2c_for_test(0, 0, 0);
            assert_eq!(unsafe { pmu_status_available_without_keypress(0, 0, 0, 0) }, 0);
        }
        {
            let _matrix = unsafe { install_key_matrix_scan_for_test(7) };
            let _i2c = install_raw_i2c_for_test(0, 0, 1);
            assert_eq!(unsafe { pmu_status_available_without_keypress(0, 0, 0, 0) }, 0);
        }
        let _matrix = unsafe { install_key_matrix_scan_for_test(0) };
        let _i2c = install_raw_i2c_for_test(0, 0, 1);
        assert_eq!(unsafe { pmu_status_available_without_keypress(0, 0, 0, 0) }, 1);
    }
    #[test]
    fn other_boards_read_register_12_and_return_bit_two() {
        let _board = install_host_cached_board_version(0x0010_ffff);
        let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0100);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 0) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_OTHER_BOARD_STATUS_REGISTER as u8)]);
        assert_eq!(reads.len(), 1);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn failed_write_preserves_the_incoming_r3_scratch_bit() {
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(-5, 0, 0);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 1) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_BOARD_0X11_STATUS_REGISTER as u8)]);
        assert!(reads.is_empty(), "a failed register write suppresses the read");
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn register_4b_bit_two_returns_sample_and_preserves_r3_after_write_error() {
        {
            let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0100);

            assert_eq!(unsafe { pmu_register_0x4b_bit2(0, 0, 0, 0) }, 1);
            let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
            assert_eq!(writes, std::vec![(0x73, 1, PMU_REGISTER_0X4B as u8)]);
            assert_eq!(reads.len(), 1, "a successful one-byte register read occurs");
            assert_eq!(reads[0].0, 0x73);
            assert_eq!(reads[0].1, 1);
            assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 0);
        assert_eq!(unsafe { pmu_register_0x4b_bit2(0, 0, 0, 4) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_REGISTER_0X4B as u8)]);
        assert!(reads.is_empty(), "a failed register write suppresses the read");

        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }
    #[test]
    fn stored_register_4b_bit_two_returns_zero_and_forwards_r3() {
        {
            let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0100);
            let mut result = 0xffff_ffff;

            assert_eq!(
                unsafe { store_pmu_register_0x4b_bit2(&mut result, 1, 2, 3) },
                0
            );
            assert_eq!(result, 1);
        }

        let _i2c = install_raw_i2c_for_test(-5, 0, 0);
        let mut result = 0xffff_ffff;
        assert_eq!(
            unsafe { store_pmu_register_0x4b_bit2(&mut result, 1, 2, 4) },
            0
        );
        assert_eq!(result, 1, "failed transfer preserves incoming r3 bit 2");
    }

    #[test]
    fn mode_registers_write_all_values_and_release_locks() {
        let _i2c = install_raw_i2c_for_test(0, 0, 0);

        unsafe { pmu_apply_mode_registers(0xfeed_beef) };

        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 2, 0x1a), (0x73, 2, 0x1d), (0x73, 2, 0x1b)]);
        assert!(reads.is_empty());
        assert_eq!(unsafe { raw_i2c_packets_for_test() }, std::vec![
            std::vec![0x1a, 0x6f],
            std::vec![0x1d, 10],
            std::vec![0x1b, 1],
        ]);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn mode_registers_skip_final_write_after_second_write_error() {
        let _i2c = install_raw_i2c_for_test(-5, 0, 0);

        unsafe { pmu_apply_mode_registers(0) };

        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 2, 0x1a), (0x73, 2, 0x1d)]);
        assert!(reads.is_empty());
        assert_eq!(unsafe { raw_i2c_packets_for_test() }, std::vec![
            std::vec![0x1a, 0x6f],
            std::vec![0x1d, 10],
        ]);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

}
