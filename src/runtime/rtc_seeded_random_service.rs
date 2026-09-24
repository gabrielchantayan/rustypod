//! `rtc_seeded_random_service` — original: `FUN_080548ec` @ `0x080548ec`.
//!
//! True extent: 176 bytes (`0x080548ec..0x0805499c`), ending before its
//! three-word literal pool; the next real function starts at `0x080549a8`.
//! Four plain `bl` call sites reach it; no predicated `bl` calls were found.
//!
//! # Algorithm
//!
//! Acquires the entropy peripheral session. On its first call, reads the seven
//! RTC BCD bytes, adds them, the inherited r4 contribution, the microsecond
//! counter, and the entropy register's word at +8, then stores that seed and
//! drains nineteen entropy words. It reads one entropy word, releases the
//! session token, and returns that word.
//!
//! # Deliberate deviations
//!
//! The ARM entry shim captures the stock ABI's inherited r4 value and passes it
//! to Rust explicitly; C ABI functions cannot otherwise name that register.
//! Host builds replace MMIO/session operations with callbacks.

use crate::drivers::{i2c::pmu_i2c_read_regs, timer::usec_timer_read};

type SessionAcquire = unsafe extern "C" fn() -> u32;
type EntropyRead = unsafe extern "C" fn() -> u32;
type SessionRelease = unsafe extern "C" fn(u32);
type RtcRead = unsafe extern "C" fn(u32, *mut u8) -> i32;
type TimerRead = unsafe extern "C" fn() -> u32;

const ENTROPY_SESSION_ACQUIRE_ADDRESS: usize = 0x0836_d87c;
const ENTROPY_WORD_READ_ADDRESS: usize = 0x0836_d8c8;
const ENTROPY_SESSION_RELEASE_ADDRESS: usize = 0x0836_d8b8;
const INITIALIZED_ADDRESS: usize = 0x089c_d920;
const ENTROPY_WORD_ADDRESS: usize = 0x3c70_0008;
const ENTROPY_SEED_ADDRESS: usize = 0x3c10_0008;

#[cfg(target_arch = "arm")]
unsafe fn entropy_session_acquire() -> u32 {
    let f: SessionAcquire = core::mem::transmute(ENTROPY_SESSION_ACQUIRE_ADDRESS);
    f()
}
#[cfg(target_arch = "arm")]
unsafe fn entropy_word_read() -> u32 {
    let f: EntropyRead = core::mem::transmute(ENTROPY_WORD_READ_ADDRESS);
    f()
}
#[cfg(target_arch = "arm")]
unsafe fn entropy_session_release(token: u32) {
    let f: SessionRelease = core::mem::transmute(ENTROPY_SESSION_RELEASE_ADDRESS);
    f(token)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn zero_word() -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn discard_token(_: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn empty_rtc(_: u32, _: *mut u8) -> i32 { 0 }

#[cfg(not(target_arch = "arm"))]
pub static mut ENTROPY_SESSION_ACQUIRE: SessionAcquire = zero_word;
#[cfg(not(target_arch = "arm"))]
pub static mut ENTROPY_WORD_READ: EntropyRead = zero_word;
#[cfg(not(target_arch = "arm"))]
pub static mut ENTROPY_SESSION_RELEASE: SessionRelease = discard_token;
#[cfg(not(target_arch = "arm"))]
pub static mut RTC_READ: RtcRead = empty_rtc;
#[cfg(not(target_arch = "arm"))]
pub static mut TIMER_READ: TimerRead = zero_word;
#[cfg(not(target_arch = "arm"))]
pub static mut INITIALIZED: *mut u32 = core::ptr::null_mut();
#[cfg(not(target_arch = "arm"))]
pub static mut ENTROPY_SEED: *mut u32 = core::ptr::null_mut();
#[cfg(not(target_arch = "arm"))]
pub static mut ENTROPY_WORD: *mut u32 = core::ptr::null_mut();

#[inline(never)]
unsafe extern "C" fn rtc_seeded_random_service_inner(
    _: u32, _: u32, _: u32, _: u32, inherited_r4: u32,
) -> u32 {
    #[cfg(target_arch = "arm")]
    let (initialized, entropy_word, entropy_seed) = (
        INITIALIZED_ADDRESS as *mut u32,
        ENTROPY_WORD_ADDRESS as *mut u32,
        ENTROPY_SEED_ADDRESS as *mut u32,
    );
    #[cfg(not(target_arch = "arm"))]
    let (initialized, entropy_word, entropy_seed) = (INITIALIZED, ENTROPY_WORD, ENTROPY_SEED);

    #[cfg(target_arch = "arm")]
    let token = entropy_session_acquire();
    #[cfg(not(target_arch = "arm"))]
    let token = ENTROPY_SESSION_ACQUIRE();

    if initialized.read_volatile() == 0 {
        let mut rtc = [0u8; 7];
        #[cfg(target_arch = "arm")]
        pmu_i2c_read_regs(0, rtc.as_mut_ptr());
        #[cfg(not(target_arch = "arm"))]
        RTC_READ(0, rtc.as_mut_ptr());

        #[cfg(target_arch = "arm")]
        let timer = usec_timer_read();
        #[cfg(not(target_arch = "arm"))]
        let timer = TIMER_READ();
        let seed = rtc.iter().fold(
            timer.wrapping_add(inherited_r4).wrapping_add(entropy_word.read_volatile()),
            |sum, &byte| sum.wrapping_add(byte as u32),
        );
        entropy_seed.write_volatile(seed);
        initialized.write_volatile(1);
        for _ in 1..20 {
            #[cfg(target_arch = "arm")]
            entropy_word_read();
            #[cfg(not(target_arch = "arm"))]
            ENTROPY_WORD_READ();
        }
    }

    #[cfg(target_arch = "arm")]
    let result = entropy_word_read();
    #[cfg(not(target_arch = "arm"))]
    let result = ENTROPY_WORD_READ();
    #[cfg(target_arch = "arm")]
    entropy_session_release(token);
    #[cfg(not(target_arch = "arm"))]
    ENTROPY_SESSION_RELEASE(token);
    result
}

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rtc_seeded_random_service(r0: u32, r1: u32, r2: u32, r3: u32) -> u32 {
    rtc_seeded_random_service_inner(r0, r1, r2, r3, 0)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl rtc_seeded_random_service
    .type rtc_seeded_random_service, %function
rtc_seeded_random_service:
    push    {{r4, lr}}
    str     r4, [sp, #-4]!
    bl      rtc_seeded_random_service_inner
    add     sp, sp, #4
    pop     {{r4, pc}}
    .size rtc_seeded_random_service, . - rtc_seeded_random_service
"#);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RTC: [u8; 7] = [0; 7];
    static mut WORD: u32 = 0;
    static mut READS: u32 = 0;
    static mut RELEASED: u32 = 0;

    unsafe extern "C" fn acquire() -> u32 { 0xfeed_beef }
    unsafe extern "C" fn read_word() -> u32 { READS += 1; WORD }
    unsafe extern "C" fn release(token: u32) { RELEASED = token; }
    unsafe extern "C" fn read_rtc(_: u32, out: *mut u8) -> i32 {
        core::ptr::copy_nonoverlapping(RTC.as_ptr(), out, 7); 0
    }
    unsafe extern "C" fn timer() -> u32 { 0xffff_fffe }

    #[test]
    fn seeds_once_from_all_rtc_bytes_and_drains_entropy() {
        let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let (mut initialized, mut entropy_word, mut seed) = (0u32, 5u32, 0xdead_beefu32);
            RTC = [1, 2, 3, 4, 5, 6, 7]; WORD = 0xa5a5_5a5a; READS = 0; RELEASED = 0;
            let saved = (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED);
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED) = (acquire, read_word, release, read_rtc, timer, core::ptr::addr_of_mut!(initialized), core::ptr::addr_of_mut!(entropy_word), core::ptr::addr_of_mut!(seed));
            assert_eq!(rtc_seeded_random_service_inner(0, 0, 0, 0, 9), WORD);
            assert_eq!(seed, 5u32.wrapping_add(0xffff_fffe).wrapping_add(9).wrapping_add(28));
            assert_eq!((initialized, READS, RELEASED), (1, 20, 0xfeed_beef));
            rtc_seeded_random_service_inner(0, 0, 0, 0, 99);
            assert_eq!((seed, READS), (5u32.wrapping_add(0xffff_fffe).wrapping_add(9).wrapping_add(28), 21));
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED) = saved;
        }
    }

    #[test]
    fn veneer_forwards_to_the_rtc_seeded_service() {
        let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let (mut initialized, mut entropy_word, mut seed) = (1u32, 0x1234_5678u32, 0u32);
            let saved_word = WORD;
            WORD = entropy_word; READS = 0; RELEASED = 0;
            let saved = (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED);
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED) = (acquire, read_word, release, read_rtc, timer, core::ptr::addr_of_mut!(initialized), core::ptr::addr_of_mut!(entropy_word), core::ptr::addr_of_mut!(seed));
            assert_eq!(crate::runtime::rtc_seeded_random_service_veneer::rtc_seeded_random_service_veneer(1, 2, 3, 4), entropy_word);
            assert_eq!((READS, RELEASED), (1, 0xfeed_beef));
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE, RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED) = saved;
            WORD = saved_word;
        }
    }
}
