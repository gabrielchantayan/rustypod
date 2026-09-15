//! `u16_le_vtable_read_mode` — original: `FUN_081666fc` @ `0x081666fc`
//! (124 bytes; next real function starts at `0x08166778`).
//!
//! Verified call count: five plain unconditional `bl` callers and zero
//! predicated `bl` callers. The body has four unconditional indirect `blx`
//! dispatches. It reads one byte through vtable slot `+0x9c`, enables mode
//! `0x80` through slot `+0xa4` using the target's `+0x50` context, reads the
//! second byte, disables that mode, and returns the two bytes as a little-endian
//! `u16`.
//!
//! The virtual targets have no recovered identities in `names.yaml`, so this
//! port deliberately models them only as byte-read and mode-dispatch slots.
//! The ARM build preserves the retail instruction sequence; host vtable fields
//! use native pointers because host pointers are wider than retailOS words.

/// Receiver whose first word points at the byte-reader and mode-control vtable.
#[repr(C)]
pub struct U16LeReadModeTarget {
    pub vtable: *const U16LeReadModeVtable,
    /// Target words `+0x04..+0x4c`, not accessed by this wrapper.
    pub unresolved_04_4c: [u32; 19],
    /// Target word `+0x50`, supplied as the mode-control context.
    pub mode_context: *mut u8,
}

/// Recovered portion of the receiver vtable.
#[repr(C)]
pub struct U16LeReadModeVtable {
    /// Slots `+0x00..+0x98`, outside this port's recovered contract.
    pub unresolved_00_98: [usize; 39],
    /// Slot `+0x9c`: reads one byte into `output`.
    pub read_byte: unsafe extern "C" fn(
        this: *mut U16LeReadModeTarget,
        context: *mut u8,
        output: *mut u8,
    ),
    /// Slot `+0xa0`, not accessed by this wrapper.
    pub unresolved_a0: usize,
    /// Slot `+0xa4`: changes the byte-read mode for `context`.
    pub set_mode: unsafe extern "C" fn(
        this: *mut U16LeReadModeTarget,
        context: *mut u8,
        mode: u32,
    ),
}

/// Reads a little-endian word, enabling mode `0x80` only for its high byte.
///
/// # Safety
///
/// `this` must be non-NULL, have a readable vtable with valid `+0x9c` and
/// `+0xa4` slots, and contain a valid `+0x50` mode context. `context` follows
/// the unvalidated receiver ABI.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u16_le_vtable_read_mode(
    this: *mut U16LeReadModeTarget,
    context: *mut u8,
    first_seed: u32,
    second_seed: u32,
) -> u16 {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*this).vtable));
    let read_byte = core::ptr::read_volatile(core::ptr::addr_of!((*vtable).read_byte));
    let set_mode = core::ptr::read_volatile(core::ptr::addr_of!((*vtable).set_mode));
    let mut first = first_seed;
    let mut second = second_seed;

    read_byte(this, context, (&mut first as *mut u32).cast());
    set_mode(this, (*this).mode_context, 0x80);
    read_byte(this, context, (&mut second as *mut u32).cast());
    set_mode(this, (*this).mode_context, 0);

    (first as u8 as u16) | ((second as u8 as u16) << 8)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl u16_le_vtable_read_mode
    .type u16_le_vtable_read_mode, %function
u16_le_vtable_read_mode:
    push    {{r2, r3, r4, r5, r6, lr}}
    mov     r4, r0
    ldr     r0, [r0]
    add     r2, sp, #4
    ldr     r3, [r0, #0x9c]
    mov     r0, r4
    mov     r5, r1
    blx     r3
    ldr     r0, [r4]
    ldr     r1, [r4, #0x50]
    ldr     r3, [r0, #0xa4]
    mov     r0, r4
    mov     r2, #0x80
    blx     r3
    ldr     r0, [r4]
    mov     r2, sp
    ldr     r3, [r0, #0x9c]
    mov     r0, r4
    mov     r1, r5
    blx     r3
    ldrb    r0, [sp, #4]
    ldrb    r1, [sp]
    mov     r2, #0
    orr     r5, r0, r1, lsl #8
    ldr     r0, [r4]
    ldr     r1, [r4, #0x50]
    ldr     r3, [r0, #0xa4]
    mov     r0, r4
    blx     r3
    mov     r0, r5
    pop     {{r2, r3, r4, r5, r6, pc}}
    .size u16_le_vtable_read_mode, . - u16_le_vtable_read_mode
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static READS: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static MODES: Mutex<std::vec::Vec<(usize, u32)>> = Mutex::new(std::vec::Vec::new());
    static mut NEXT_BYTES: [u8; 2] = [0; 2];

    unsafe extern "C" fn read_next(
        _this: *mut U16LeReadModeTarget,
        context: *mut u8,
        output: *mut u8,
    ) {
        let index = READS.lock().len();
        READS.lock().push(context as usize);
        output.write(NEXT_BYTES[index]);
    }

    unsafe extern "C" fn record_mode(
        _this: *mut U16LeReadModeTarget,
        context: *mut u8,
        mode: u32,
    ) {
        MODES.lock().push((context as usize, mode));
    }

    fn vtable() -> U16LeReadModeVtable {
        U16LeReadModeVtable {
            unresolved_00_98: [0; 39],
            read_byte: read_next,
            unresolved_a0: 0,
            set_mode: record_mode,
        }
    }

    #[test]
    fn reads_little_endian_bytes_while_bracketing_second_read_with_mode() {
        let _guard = TEST_LOCK.lock();
        READS.lock().clear();
        MODES.lock().clear();
        unsafe { NEXT_BYTES = [0x34, 0x12] };
        let vtable = vtable();
        let mode_context = 0x5678usize as *mut u8;
        let read_context = 0x1234usize as *mut u8;
        let mut target = U16LeReadModeTarget {
            vtable: &vtable,
            unresolved_04_4c: [0; 19],
            mode_context,
        };

        let word = unsafe { u16_le_vtable_read_mode(&mut target, read_context, 0xaa00, 0xbb00) };

        assert_eq!(word, 0x1234);
        assert_eq!(*READS.lock(), [read_context as usize, read_context as usize]);
        assert_eq!(*MODES.lock(), [(mode_context as usize, 0x80), (mode_context as usize, 0)]);
    }

    #[test]
    fn returns_only_bytes_written_by_the_virtual_reader() {
        let _guard = TEST_LOCK.lock();
        READS.lock().clear();
        MODES.lock().clear();
        unsafe { NEXT_BYTES = [0xff, 0x00] };
        let vtable = vtable();
        let mut target = U16LeReadModeTarget {
            vtable: &vtable,
            unresolved_04_4c: [0; 19],
            mode_context: core::ptr::null_mut(),
        };

        let word = unsafe { u16_le_vtable_read_mode(&mut target, core::ptr::null_mut(), 0x1122_3300, 0x4455_6600) };

        assert_eq!(word, 0x00ff);
        assert_eq!(*MODES.lock(), [(0, 0x80), (0, 0)]);
    }
}
