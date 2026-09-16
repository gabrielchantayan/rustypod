//! Counted wide-string character validation against the lazily built
//! retailOS charset table.
//!
//! - `counted_wstr_validate` — original: `FUN_08059c68` @ `0x08059c68`
//!   (148-byte instruction body, `0x08059c68..0x08059cfc`, followed by its
//!   own 8-byte literal pool at `0x08059cfc..0x08059d04`; the next real
//!   function begins at `0x08059d04`). Ghidra's reported 148 bytes omit
//!   the pool.
//!
//! Raw ARM decoded from `work/firmware/osos.dec`:
//!
//! ```text
//! 08059c68  push {r4, r5, lr}
//! 08059c6c  tst  r2, #4            @ flags bit 2 set -> invalid
//! 08059c70  mov  r5, r2
//! 08059c74  mov  r4, r1
//! 08059c78  mov  r3, r0
//! 08059c7c  bne  0x08059ce4        @ return 0
//! 08059c80  cmp  r4, #0
//! 08059c84  beq  0x08059cf4        @ len == 0 -> return 1
//! 08059c88  ldrh r0, [r3]
//! 08059c8c  cmp  r0, #0x20
//! 08059c90  bhi  0x08059c9c
//! 08059c94  tst  r5, #2            @ first char <= 0x20 gated by bit 1
//! 08059c98  bne  0x08059ce4        @ return 0
//! 08059c9c  ldr  r0, [0x8059cfc]   @ flag byte address 0x089cb1a8
//! 08059ca0  ldrb r0, [r0]
//! 08059ca4  cmp  r0, #0
//! 08059ca8  bleq 0x080d5090        @ lazy charset-table init (predicated)
//! 08059cac  ldr  r1, [0x8059d00]   @ table base 0x08a777a8
//! 08059cb0  and  r0, r5, #0x10
//! 08059cb4  mov  r2, r0, lsr #4    @ digit-reject mode
//! 08059cb8  ldrh r0, [r3], #2      @ c = *cursor++
//! 08059cbc  cmp  r0, #0x7a
//! 08059cc0  bhi  0x08059ce4        @ c > 0x7a -> return 0
//! 08059cc4  ldrb r12, [r1, r0]
//! 08059cc8  cmp  r12, #0
//! 08059ccc  beq  0x08059ce4        @ table[c] == 0 -> return 0
//! 08059cd0  cmp  r2, #0
//! 08059cd4  beq  0x08059cec
//! 08059cd8  sub  r0, r0, #0x30
//! 08059cdc  cmp  r0, #9
//! 08059ce0  bhi  0x08059cec        @ non-digit continues; digit falls through
//! 08059ce4  mov  r0, #0            @ return 0
//! 08059ce8  pop  {r4, r5, pc}
//! 08059cec  subs r4, r4, #1
//! 08059cf0  bne  0x08059cb8
//! 08059cf4  mov  r0, #1            @ return 1
//! 08059cf8  pop  {r4, r5, pc}
//! ```
//!
//! Decoding every ARM B/BL word in `osos.dec` finds **5 direct `bl` call
//! sites, all plain and unconditional** (zero predicated callers):
//! `0x08044394`, `0x080443e8`, `0x08044460`, `0x080444b4`, and
//! `0x08044508` — matching Ghidra's reported count. The body's own call
//! traffic is one **predicated** `bleq 0x080d5090` (the lazy table init)
//! and no plain `bl`.
//!
//! All five callers fetch a database string field through the indexed
//! payload lookup wrapper `0x080d6e50`, halve the byte count, pass
//! `flags = 0x1d`, and store the boolean result into an object flag bit;
//! the routine is a "field text characters are acceptable" predicate.
//!
//! # Algorithm
//!
//! `flags & 4` rejects unconditionally. A zero element count accepts.
//! Otherwise, when `flags & 2`, a first element at or below `0x20`
//! rejects. The one-byte initialized flag at `0x089cb1a8` gates a lazy
//! call to the unported table builder `0x080d5090` (fills the 0x80-byte
//! allowed-character table). Each of the `len` `u16` elements must be at
//! most `0x7a` and have a nonzero entry in the table at `0x08a777a8`;
//! with `flags & 0x10`, ASCII digits `0..9` additionally reject. All
//! elements passing returns 1.
//!
//! # Deliberate deviations
//!
//! The predicated `bleq 0x080d5090` becomes an ordinary conditional Rust
//! call through the [`COUNTED_WSTR_VALIDATE_INIT`] seam: target builds
//! transmute the retail address; host builds substitute a recorder. The
//! flag byte and table base are fixed addresses on target and replaceable
//! seams on host so tests can supply fixtures. Byte/element reads are
//! volatile because the init call mutates the table behind the compiler's
//! back; LLVM is not free to cache across it.

use core::ptr;

/// ABI of the still-unported charset-table builder at `0x080d5090`.
pub type CountedWstrValidateInitFn = unsafe extern "C" fn();

/// RetailOS address of the one-byte "charset table initialized" flag.
#[cfg(target_os = "none")]
const VALIDATE_FLAG_BYTE_ADDRESS: usize = 0x089c_b1a8;

/// RetailOS address of the 0x80-byte allowed-character table.
#[cfg(target_os = "none")]
const VALIDATE_TABLE_ADDRESS: usize = 0x08a7_77a8;

/// RetailOS address of the lazy table builder.
#[cfg(target_os = "none")]
const VALIDATE_INIT_ADDRESS: usize = 0x080d_5090;

#[cfg(target_os = "none")]
fn validate_flag_byte() -> *const u8 {
    VALIDATE_FLAG_BYTE_ADDRESS as *const u8
}

#[cfg(target_os = "none")]
fn validate_table() -> *const u8 {
    VALIDATE_TABLE_ADDRESS as *const u8
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_counted_wstr_validate_init() {
    let init: CountedWstrValidateInitFn = core::mem::transmute(VALIDATE_INIT_ADDRESS);
    init()
}

/// Host stand-in flag byte: pretends the table is already initialized so
/// the default seam never reaches the missing retail builder.
#[cfg(not(target_os = "none"))]
static HOST_DEFAULT_FLAG: u8 = 1;

/// Host stand-in table: nothing allowed, matching an unbuilt table that
/// was never populated.
#[cfg(not(target_os = "none"))]
static HOST_DEFAULT_TABLE: [u8; 0x80] = [0; 0x80];

/// Host replacement for the fixed flag-byte address.
#[cfg(not(target_os = "none"))]
pub static mut VALIDATE_FLAG_BYTE: *const u8 = &HOST_DEFAULT_FLAG;

/// Host replacement for the fixed allowed-character table address.
#[cfg(not(target_os = "none"))]
pub static mut VALIDATE_TABLE: *const u8 = HOST_DEFAULT_TABLE.as_ptr();

#[cfg(not(target_os = "none"))]
fn validate_flag_byte() -> *const u8 {
    unsafe { ptr::read_volatile(ptr::addr_of!(VALIDATE_FLAG_BYTE)) }
}

#[cfg(not(target_os = "none"))]
fn validate_table() -> *const u8 {
    unsafe { ptr::read_volatile(ptr::addr_of!(VALIDATE_TABLE)) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_counted_wstr_validate_init() {
    // Host placeholder for the unported table builder. Tests substitute
    // a recorder through the seam.
    panic!("counted_wstr_validate requires init 0x080d5090")
}

/// Active lazy-init boundary.
///
/// `static mut`, swapped at test/bring-up time only — same discipline
/// as the firmware's own hook tables.
pub static mut COUNTED_WSTR_VALIDATE_INIT: CountedWstrValidateInitFn =
    retail_counted_wstr_validate_init;

#[inline(always)]
fn counted_wstr_validate_init_fn() -> CountedWstrValidateInitFn {
    unsafe { ptr::read_volatile(ptr::addr_of!(COUNTED_WSTR_VALIDATE_INIT)) }
}

/// counted_wstr_validate — original: `FUN_08059c68` @ `0x08059c68`
/// (148-byte body plus an 8-byte literal pool; 5 direct, unconditional
/// `bl` call sites and no predicated callers, binary-scanned).
///
/// 1 iff every one of the `len` `u16` elements at `chars` passes the
/// retailOS allowed-character table under `flags`, else 0. See the
/// module header for the exact flag semantics; the stock function has
/// no NULL guard on `chars`.
///
/// # Safety
/// `chars` must be readable for `len` `u16` elements when `len != 0` and
/// `flags & 4 == 0`. On target, the flag byte at `0x089cb1a8`, the table
/// at `0x08a777a8`, and the builder at `0x080d5090` must be mapped as in
/// retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_wstr_validate(
    chars: *const u16,
    len: i32,
    flags: u32,
) -> u32 {
    if flags & 0x4 != 0 {
        return 0;
    }
    if len == 0 {
        return 1;
    }
    if u32::from(chars.read_volatile()) <= 0x20 && flags & 0x2 != 0 {
        return 0;
    }
    if validate_flag_byte().read_volatile() == 0 {
        counted_wstr_validate_init_fn()();
    }
    let table = validate_table();
    let reject_digits = flags & 0x10 != 0;
    let mut cursor = chars;
    let mut remaining = len;
    loop {
        let c = u32::from(cursor.read_volatile());
        cursor = cursor.add(1);
        if c > 0x7a {
            return 0;
        }
        if table.add(c as usize).read_volatile() == 0 {
            return 0;
        }
        if reject_digits && c.wrapping_sub(0x30) <= 9 {
            return 0;
        }
        remaining = remaining.wrapping_sub(1);
        if remaining == 0 {
            break;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut INIT_CALLS: u32 = 0;

    unsafe extern "C" fn record_init() {
        INIT_CALLS += 1;
        TABLE_READY = 1;
    }

    /// Fixture backing store for the flag byte and the allowed-character
    /// table. `record_init` flips the flag, mirroring the retail builder.
    static mut TABLE_READY: u8 = 1;
    static mut TABLE: [u8; 0x80] = [0; 0x80];

    struct SeamGuard {
        init: CountedWstrValidateInitFn,
        flag: *const u8,
        table: *const u8,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                COUNTED_WSTR_VALIDATE_INIT = self.init;
                VALIDATE_FLAG_BYTE = self.flag;
                VALIDATE_TABLE = self.table;
            }
        }
    }

    /// Install the fixture: `ready` seeds the flag byte, `allowed` is the
    /// set of table bytes marked nonzero, and the init recorder fills the
    /// fixture table for the printable ASCII range like the retail
    /// builder's known entries.
    unsafe fn install_fixture(ready: u8, allowed: &[u8]) -> SeamGuard {
        let previous = SeamGuard {
            init: COUNTED_WSTR_VALIDATE_INIT,
            flag: VALIDATE_FLAG_BYTE,
            table: VALIDATE_TABLE,
        };
        TABLE = [0; 0x80];
        for &c in allowed {
            TABLE[c as usize] = 1;
        }
        TABLE_READY = ready;
        INIT_CALLS = 0;
        COUNTED_WSTR_VALIDATE_INIT = record_init;
        VALIDATE_FLAG_BYTE = ptr::addr_of!(TABLE_READY);
        VALIDATE_TABLE = TABLE.as_ptr();
        previous
    }

    /// `tst r2, #4; bne` — bit 2 rejects regardless of string content;
    /// no character is ever read.
    #[test]
    fn flag_bit_two_rejects_everything() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let text: [u16; 2] = [0x61, 0x62];
        unsafe {
            let _seam = install_fixture(1, &[0x61, 0x62]);
            assert_eq!(counted_wstr_validate(text.as_ptr(), 2, 0x4), 0);
            assert_eq!(counted_wstr_validate(text.as_ptr(), 2, 0x1d), 0);
            assert_eq!(INIT_CALLS, 0);
        }
    }

    /// `cmp r4, #0; beq` — a zero element count accepts without touching
    /// the string, the flag byte, or the table.
    #[test]
    fn zero_length_accepts() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _seam = install_fixture(1, &[]);
            assert_eq!(counted_wstr_validate(ptr::null(), 0, 0), 1);
            assert_eq!(counted_wstr_validate(ptr::null(), 0, 0x12), 1);
            assert_eq!(INIT_CALLS, 0);
        }
    }

    /// `flags & 2` rejects only when the FIRST element is at or below
    /// `0x20`; interior low elements are governed by the table instead.
    #[test]
    fn flag_bit_one_gates_only_the_first_element() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let leading: [u16; 2] = [0x20, 0x61];
        let interior: [u16; 2] = [0x61, 0x20];
        let boundary: [u16; 1] = [0x21];
        unsafe {
            let _seam = install_fixture(1, &[0x20, 0x21, 0x61]);
            assert_eq!(counted_wstr_validate(leading.as_ptr(), 2, 0x2), 0);
            assert_eq!(counted_wstr_validate(leading.as_ptr(), 2, 0x0), 1);
            assert_eq!(counted_wstr_validate(interior.as_ptr(), 2, 0x2), 1);
            assert_eq!(counted_wstr_validate(boundary.as_ptr(), 1, 0x2), 1);
        }
    }

    /// `bleq 0x080d5090` — the builder runs exactly when the flag byte is
    /// zero, before any table lookup, even for a string that then fails.
    #[test]
    fn uninitialized_flag_invokes_the_builder_once() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let ok: [u16; 1] = [0x61];
        let bad: [u16; 1] = [0x7b];
        unsafe {
            let _seam = install_fixture(0, &[0x61]);
            assert_eq!(counted_wstr_validate(ok.as_ptr(), 1, 0), 1);
            assert_eq!(INIT_CALLS, 1);
            // The flag flipped: a second call must not rebuild.
            assert_eq!(counted_wstr_validate(bad.as_ptr(), 1, 0), 0);
            assert_eq!(INIT_CALLS, 1);
        }
    }

    /// Elements above `0x7a` and elements with a zero table entry reject;
    /// `0x7a` itself is in range and passes when allowed.
    #[test]
    fn table_bounds_and_membership() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let top: [u16; 1] = [0x7a];
        let above: [u16; 1] = [0x7b];
        let high: [u16; 1] = [0x3042];
        let gap: [u16; 2] = [0x61, 0x62];
        unsafe {
            let _seam = install_fixture(1, &[0x7a, 0x61]);
            assert_eq!(counted_wstr_validate(top.as_ptr(), 1, 0), 1);
            assert_eq!(counted_wstr_validate(above.as_ptr(), 1, 0), 0);
            assert_eq!(counted_wstr_validate(high.as_ptr(), 1, 0), 0);
            assert_eq!(counted_wstr_validate(gap.as_ptr(), 2, 0), 0);
        }
    }

    /// `flags & 0x10` rejects ASCII digits anywhere in the string; the
    /// same digits pass when the bit is clear and the table allows them.
    #[test]
    fn flag_bit_four_rejects_digits() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let digit: [u16; 1] = [0x30];
        let nine: [u16; 1] = [0x39];
        let mixed: [u16; 3] = [0x61, 0x35, 0x62];
        let letters: [u16; 2] = [0x61, 0x62];
        unsafe {
            let _seam = install_fixture(1, &[0x30, 0x35, 0x39, 0x61, 0x62]);
            assert_eq!(counted_wstr_validate(digit.as_ptr(), 1, 0x10), 0);
            assert_eq!(counted_wstr_validate(nine.as_ptr(), 1, 0x10), 0);
            assert_eq!(counted_wstr_validate(mixed.as_ptr(), 3, 0x10), 0);
            assert_eq!(counted_wstr_validate(mixed.as_ptr(), 3, 0x0), 1);
            assert_eq!(counted_wstr_validate(letters.as_ptr(), 2, 0x10), 1);
        }
    }

    /// The countdown walks every element: a failing final element still
    /// rejects, and an all-allowed multi-element string accepts.
    #[test]
    fn every_element_is_checked() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let good: [u16; 4] = [0x61, 0x62, 0x63, 0x64];
        let last_bad: [u16; 4] = [0x61, 0x62, 0x63, 0x65];
        unsafe {
            let _seam = install_fixture(1, &[0x61, 0x62, 0x63, 0x64]);
            assert_eq!(counted_wstr_validate(good.as_ptr(), 4, 0), 1);
            assert_eq!(counted_wstr_validate(last_bad.as_ptr(), 4, 0), 0);
        }
    }
}
