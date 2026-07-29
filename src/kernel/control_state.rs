//! Port of the control-state flags getter `FUN_08292e6c` @ 0x08292e6c
//! (20 bytes, 253 `bl` call sites in osos).
//!
//! Original:
//!
//! ```text
//! ldr r0, [0x8292e80]      ; literal 0x089cc928 — control-state object base
//! ldr r0, [r0, #0x4]       ; flags word @ 0x089cc92c
//! mov r0, r0, lsl #0x14
//! mov r0, r0, lsr #0x14    ; keep low 12 bits
//! bx  lr
//! ```
//!
//! A packed-field getter: the word at 0x089cc92c (offset +4 of the
//! control-subsystem state object @ 0x089cc928) carries a 12-bit flags
//! field in its low bits; this returns exactly that field
//! (`word & 0xFFF`). Callers test individual bits — e.g. the mode gate
//! `flags & 0x10` @ 0x081f6344 — and the sibling setter @ 0x08292e84
//! stores the full word back (using bit 0x4000 as a "conditional store"
//! sentinel that is above this mask and therefore never visible through
//! the getter). Neighbors @ 0x08292c10..0x08292e64 drive a UI
//! "controller" switch (vtable dispatch; "CntrlHistoryFn" string @
//! 0x08292c9c), saving these flags, forcing 0x10, and restoring —
//! which is what the control_state naming records; the individual flag
//! bits' meanings remain with the (unported) writers of 0x089cc92c.
//!
//! # Deviation
//!
//! On target the flags word is read straight from the original firmware
//! address 0x089cc92c (the field belongs to the still-unported control
//! subsystem, so the port must not own a copy — cf. the static-model
//! convention in sync_mutex.rs, which applies only to port-owned
//! globals). Host builds substitute a mock word (`set_mock_flags_word`)
//! so the mask behavior is testable. Codegen on ARM is the same
//! load-and-mask leaf as the original.
//!
//! The sibling setter `control_state_store` (`FUN_08292e84` @ 0x08292e84,
//! 44 bytes) lives below; it writes the same word through the same
//! target-address/mock-word split.

#[cfg(not(target_arch = "arm"))]
use core::ptr::{addr_of, addr_of_mut};

/// Firmware address of the flags word: `*0x089cc928 + 4` in the original
/// (literal-pool base pointer plus the `ldr [r0, #0x4]` offset).
#[cfg(target_arch = "arm")]
const FLAGS_WORD_ADDR: u32 = 0x089c_c92c;

/// Mask applied by the original's `lsl #20; lsr #20` pair.
const FLAGS_MASK: u32 = 0xFFF;

/// Store lock: bit 0x8000 of the *current* state word, tested by the
/// lock-check helper `FUN_08292f58` (`and #0x8000; lsr #15`) that the
/// setter calls before deciding to store.
const STORE_LOCK_BIT: u32 = 0x8000;

/// Override sentinel: bit 0x4000 of the *argument* to the setter means
/// "store anyway" while the word is locked. Always stripped from the
/// stored value by the original's `bic r0, r1, #0x4000`.
const FORCE_STORE_SENTINEL: u32 = 0x4000;

/// Host-test stand-in for the firmware flags word @ 0x089cc92c.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_FLAGS_WORD: u32 = 0;

/// Host only: install the word the getter will read.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_flags_word(word: u32) {
    *addr_of_mut!(MOCK_FLAGS_WORD) = word;
}

#[inline]
fn flags_word() -> u32 {
    #[cfg(target_arch = "arm")]
    unsafe {
        (FLAGS_WORD_ADDR as *const u32).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_FLAGS_WORD)
    }
}

#[inline]
fn set_flags_word(word: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        (FLAGS_WORD_ADDR as *mut u32).write_volatile(word)
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of_mut!(MOCK_FLAGS_WORD) = word;
    }
}

/// Original: `FUN_08292e6c` @ 0x08292e6c (20 bytes) — returns the low
/// 12 bits of the control-state flags word @ 0x089cc92c.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn control_state_flags() -> u32 {
    flags_word() & FLAGS_MASK
}

/// Original: `FUN_08292e84` @ 0x08292e84 (44 bytes, 3 `bl` call sites
/// plus 1 `blne` @ 0x0839f6ec and 1 tail `b` @ 0x08292ce4).
///
/// Guarded store of the control-state word @ 0x089cc92c:
///
/// ```text
/// mov r1, r0
/// str lr, [sp, #-0x4]!
/// bl  0x08292f58          ; locked = (word & 0x8000) >> 15
/// cmp r0, #0
/// beq store
/// tst r1, #0x4000
/// ldreq pc, [sp], #0x4    ; locked and no override sentinel: refuse
/// store:
/// bic r0, r1, #0x4000     ; strip the sentinel from the stored value
/// ldr r1, [0x8292eb0]     ; control-state object base 0x089cc928
/// str r0, [r1, #0x4]      ; state word @ 0x089cc92c
/// ldr pc, [sp], #0x4
/// ```
///
/// Bit 0x8000 of the *current* word is a store lock (tested via the
/// helper @ 0x08292f58, which reads the same object). While locked the
/// store is refused unless the caller sets bit 0x4000 in `word` as a
/// "store anyway" override; the stored value always has the sentinel
/// stripped, so it never lands in the word (and sits above the getter's
/// low-12 mask anyway). The save/force-0x10/restore dance in the
/// neighbors @ 0x08292c10..0x08292e64 (restoring via `saved | 0x4000`)
/// is exactly this override path: it rewrites the word even while
/// locked.
///
/// # Deviation
///
/// Same convention as the getter: on target the word is read and written
/// at the original firmware address 0x089cc92c (not port-owned); host
/// builds use the mock word. The lock-bit read (`bl 0x08292f58` in the
/// original) is inlined here — that helper is a separate function with
/// its own callers and is not part of this port.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn control_state_store(word: u32) {
    let locked = flags_word() & STORE_LOCK_BIT != 0;
    if locked && word & FORCE_STORE_SENTINEL == 0 {
        return;
    }
    set_flags_word(word & !FORCE_STORE_SENTINEL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_all_twelve_low_bits_through() {
        unsafe {
            for bits in [0x000u32, 0x001, 0x010, 0x555, 0xAAA, 0xFFF] {
                set_mock_flags_word(bits);
                assert_eq!(control_state_flags(), bits);
            }
        }
    }

    #[test]
    fn masks_everything_above_bit11() {
        unsafe {
            // Setter's 0x4000 conditional-store sentinel is above the
            // mask: invisible through the getter.
            set_mock_flags_word(0x4000);
            assert_eq!(control_state_flags(), 0);
            set_mock_flags_word(0xFFFF_F000);
            assert_eq!(control_state_flags(), 0);
            set_mock_flags_word(0xDEAD_B123);
            assert_eq!(control_state_flags(), 0x123);
            set_mock_flags_word(0xFFFF_FFFF);
            assert_eq!(control_state_flags(), 0xFFF);
        }
    }

    #[test]
    fn store_writes_word_when_unlocked() {
        unsafe {
            // Lock bit (0x8000) clear: any word is stored as-is except
            // the 0x4000 sentinel, which is always stripped.
            set_mock_flags_word(0x0000_0000);
            control_state_store(0x123);
            assert_eq!(flags_word(), 0x123);
            control_state_store(0xDEAD_B123);
            assert_eq!(flags_word(), 0xDEAD_B123 & !FORCE_STORE_SENTINEL);
        }
    }

    #[test]
    fn store_strips_sentinel_even_when_unlocked() {
        unsafe {
            set_mock_flags_word(0x0000_0000);
            control_state_store(0x010 | FORCE_STORE_SENTINEL);
            assert_eq!(flags_word(), 0x010);
        }
    }

    #[test]
    fn store_refused_when_locked_without_sentinel() {
        unsafe {
            // Lock bit set in the current word and no 0x4000 in the
            // argument: the word is left untouched.
            set_mock_flags_word(STORE_LOCK_BIT | 0x055);
            control_state_store(0x123);
            assert_eq!(flags_word(), STORE_LOCK_BIT | 0x055);
            control_state_store(0xFFFF_FFFF & !FORCE_STORE_SENTINEL);
            assert_eq!(flags_word(), STORE_LOCK_BIT | 0x055);
        }
    }

    #[test]
    fn store_sentinel_overrides_lock() {
        unsafe {
            // Locked, but 0x4000 in the argument forces the store (and
            // the sentinel itself is not stored). This is how the
            // neighbor "controller" switch restores the saved word and
            // clears the lock.
            set_mock_flags_word(STORE_LOCK_BIT | 0x055);
            control_state_store(0x123 | FORCE_STORE_SENTINEL);
            assert_eq!(flags_word(), 0x123);
        }
    }

    #[test]
    fn store_lock_bit_can_be_set_and_cleared_via_sentinel() {
        unsafe {
            set_mock_flags_word(0x000);
            // Lock the word (argument carries 0x8000; no sentinel
            // needed while unlocked).
            control_state_store(STORE_LOCK_BIT | 0x010);
            assert_eq!(flags_word(), STORE_LOCK_BIT | 0x010);
            // Plain stores now refused...
            control_state_store(0x020);
            assert_eq!(flags_word(), STORE_LOCK_BIT | 0x010);
            // ...until the sentinel unlocks it.
            control_state_store(0x020 | FORCE_STORE_SENTINEL);
            assert_eq!(flags_word(), 0x020);
        }
    }
}
