//! The parse context's temp-register recycler.
//!
//! - `release_temp_reg` — original: `FUN_08381f98` @ 0x08381f98
//!   (32 bytes; 36 `bl` + 3 tail `b` call sites, binary-scanned).
//!   SQLite's `sqlite3ReleaseTempReg`.
//!
//! The code generator allocates VDBE registers for intermediate values
//! and hands them back here when an expression is done with them; the
//! `Parse` context keeps a small free list so the next expression reuses
//! the same register instead of growing the frame. The list is a fixed
//! 8-slot array — once it is full, further releases are simply dropped
//! and the register is leaked for the rest of the statement. That cap is
//! the original's, and it is why the function is a no-op so often.
//!
//! `Parse` fields used (all fixed-width, so plain byte offsets are
//! host-independent — no pointer fields are touched):
//!
//! ```text
//! +0x15 n_temp_reg   (u8)      how many slots are in use
//! +0x18 a_temp_reg   (i32[8])  the free list
//! ```
//!
//! Register 0 is never recycled: the original tests the incoming value
//! for zero first, because 0 is SQLite's "no register" sentinel.

/// Byte offset of `Parse.nTempReg` (original: `ldrb r1, [r0, #21]`).
const N_TEMP_REG_OFFSET: usize = 0x15;
/// Byte offset of `Parse.aTempReg` (original: `strcc r2, [r0, #24]`
/// after `add r0, r0, r1, lsl #2`).
const A_TEMP_REG_OFFSET: usize = 0x18;
/// Slots in `Parse.aTempReg` (original: `cmpne r1, #8` — an unsigned
/// compare, so the byte counter can never sneak past the array).
pub const TEMP_REG_SLOTS: u8 = 8;

/// release_temp_reg — original: `FUN_08381f98` @ 0x08381f98 (32 bytes;
/// 39 call sites).
///
/// `sqlite3ReleaseTempReg`: push `reg` onto the parse context's free
/// list. Ignores register 0 (the "no register" sentinel) and silently
/// drops the release when the list is already full.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_temp_reg(parse: *mut u8, reg: i32) {
    if reg == 0 {
        return;
    }
    let count = parse.add(N_TEMP_REG_OFFSET).read();
    if count >= TEMP_REG_SLOTS {
        return;
    }
    parse.add(N_TEMP_REG_OFFSET).write(count + 1);
    (parse.add(A_TEMP_REG_OFFSET) as *mut i32).add(count as usize).write(reg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Parse` context: word-aligned so the free-list stores are
    /// aligned, as they are on target.
    #[repr(align(4))]
    struct ParseContext([u8; 0x48]);

    impl ParseContext {
        fn new(count: u8) -> Self {
            let mut ctx = ParseContext([0xa5; 0x48]);
            ctx.0[N_TEMP_REG_OFFSET] = count;
            for slot in 0..TEMP_REG_SLOTS as usize {
                let at = A_TEMP_REG_OFFSET + slot * 4;
                ctx.0[at..at + 4].copy_from_slice(&0i32.to_le_bytes());
            }
            ctx
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn count(&self) -> u8 {
            self.0[N_TEMP_REG_OFFSET]
        }
        fn slot(&self, index: usize) -> i32 {
            let at = A_TEMP_REG_OFFSET + index * 4;
            i32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
        }
    }

    #[test]
    fn released_registers_stack_up_in_order() {
        let mut ctx = ParseContext::new(0);
        for i in 1..=8i32 {
            unsafe { release_temp_reg(ctx.ptr(), i * 10) };
            assert_eq!(ctx.count(), i as u8);
            assert_eq!(ctx.slot(i as usize - 1), i * 10);
        }
    }

    #[test]
    fn a_full_list_drops_further_releases() {
        let mut ctx = ParseContext::new(TEMP_REG_SLOTS);
        unsafe { release_temp_reg(ctx.ptr(), 99) };
        assert_eq!(ctx.count(), TEMP_REG_SLOTS);
        for slot in 0..TEMP_REG_SLOTS as usize {
            assert_eq!(ctx.slot(slot), 0, "slot {slot} must be untouched");
        }
        // A counter already past the cap (unsigned compare) stays put.
        let mut ctx = ParseContext::new(200);
        unsafe { release_temp_reg(ctx.ptr(), 99) };
        assert_eq!(ctx.count(), 200);
    }

    #[test]
    fn register_zero_is_never_recycled() {
        let mut ctx = ParseContext::new(0);
        unsafe { release_temp_reg(ctx.ptr(), 0) };
        assert_eq!(ctx.count(), 0);
        assert_eq!(ctx.slot(0), 0);
    }

    #[test]
    fn negative_registers_are_stored_like_any_other() {
        // The original only special-cases zero; nothing else is filtered.
        let mut ctx = ParseContext::new(0);
        unsafe { release_temp_reg(ctx.ptr(), -3) };
        unsafe { release_temp_reg(ctx.ptr(), i32::MIN) };
        assert_eq!(ctx.count(), 2);
        assert_eq!(ctx.slot(0), -3);
        assert_eq!(ctx.slot(1), i32::MIN);
    }

    #[test]
    fn nothing_outside_the_counter_and_the_list_is_written() {
        let mut ctx = ParseContext::new(0);
        for i in 1..=8i32 {
            unsafe { release_temp_reg(ctx.ptr(), i) };
        }
        let list = A_TEMP_REG_OFFSET..A_TEMP_REG_OFFSET + TEMP_REG_SLOTS as usize * 4;
        for (i, byte) in ctx.0.iter().enumerate() {
            if i != N_TEMP_REG_OFFSET && !list.contains(&i) {
                assert_eq!(*byte, 0xa5, "byte {i:#x} was clobbered");
            }
        }
    }
}
