//! bit_buffer_copy — retailOS `FUN_080d9cac` @ 0x080d9cac.
//!
//! Raw `osos.dec` establishes the 192-byte extent from 0x080d9cac through
//! `pop {r3-r9,pc}` at 0x080d9d68; 0x080d9d6c starts the next function.
//! Whole-image A32 decoding finds four incoming plain `bl` calls and no
//! predicated `bl` calls. The body makes three plain `bl` calls, to unported
//! helpers at 0x080cd984, 0x080a9328, and 0x0808ab4c, and no predicated calls.
//!
//! Algorithm: prepare the destination state, select its bit cursor, ensure
//! capacity for the requested bit count, store that count in cursor word zero,
//! then copy source bits MSB-first into the cursor's byte buffer MSB-first.
//! Deliberate deviation: unported callees retain only address-based names;
//! target builds call their fixed addresses while host tests install ABI seams.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BIT_BUFFER_PREPARE: usize = 0x080c_d984;
const RETAIL_BIT_BUFFER_SELECT_CURSOR: usize = 0x080a_9328;
const RETAIL_BIT_BUFFER_ENSURE_CAPACITY: usize = 0x0808_ab4c;

pub type BitBufferPrepare = unsafe extern "C" fn(*mut u32, u32, u32, *mut u32) -> u32;
pub type BitBufferSelectCursor = unsafe extern "C" fn(*mut u32, u32, *mut *mut u32, *mut u32) -> u32;
pub type BitBufferEnsureCapacity = unsafe extern "C" fn(*mut u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BitBufferCopyOps {
    pub prepare: BitBufferPrepare,
    pub select_cursor: BitBufferSelectCursor,
    pub ensure_capacity: BitBufferEnsureCapacity,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_state: *mut u32, _arg: u32, _context: u32, _cursor: *mut u32) -> u32 {
    panic!("install bit-buffer copy host operations before copying bits")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select_cursor(_state: *mut u32, _context: u32, _out: *mut *mut u32, _fallback: *mut u32) -> u32 {
    panic!("install bit-buffer copy host operations before copying bits")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ensure_capacity(_cursor: *mut u32, _bits: u32, _context: u32) -> u32 {
    panic!("install bit-buffer copy host operations before copying bits")
}

#[cfg(not(target_os = "none"))]
pub static mut BIT_BUFFER_COPY_OPS: BitBufferCopyOps = BitBufferCopyOps {
    prepare: missing_prepare,
    select_cursor: missing_select_cursor,
    ensure_capacity: missing_ensure_capacity,
};

#[inline(always)]
unsafe fn prepare(state: *mut u32, arg: u32, context: u32, cursor: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: BitBufferPrepare = unsafe { core::mem::transmute(RETAIL_BIT_BUFFER_PREPARE) };
        return unsafe { helper(state, arg, context, cursor) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(addr_of!(BIT_BUFFER_COPY_OPS.prepare))(state, arg, context, cursor) }
}

#[inline(always)]
unsafe fn select_cursor(state: *mut u32, context: u32, out: *mut *mut u32, fallback: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: BitBufferSelectCursor = unsafe { core::mem::transmute(RETAIL_BIT_BUFFER_SELECT_CURSOR) };
        return unsafe { helper(state, context, out, fallback) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(addr_of!(BIT_BUFFER_COPY_OPS.select_cursor))(state, context, out, fallback) }
}

#[inline(always)]
unsafe fn ensure_capacity(cursor: *mut u32, bits: u32, context: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: BitBufferEnsureCapacity = unsafe { core::mem::transmute(RETAIL_BIT_BUFFER_ENSURE_CAPACITY) };
        return unsafe { helper(cursor, bits, context) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(addr_of!(BIT_BUFFER_COPY_OPS.ensure_capacity))(cursor, bits, context) }
}

/// Copies `bit_count` source bits into a selected destination cursor.
///
/// # Safety
///
/// `state`, `destination`, and the cursor selected by the retail helper must
/// be valid. Cursor word +2 must contain a valid target-width byte pointer
/// for enough bytes to receive the requested bits.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_buffer_copy(
    state: *mut u32,
    source: *const u8,
    source_bit_offset: u32,
    bit_count: u32,
    destination: *mut u32,
    context: u32,
) -> u32 {
    let result = unsafe { prepare(state, destination as usize as u32, context, destination) };
    if result != 0 { return result; }

    let mut cursor = destination;
    let result = unsafe { select_cursor(state.add(3), context, &mut cursor, destination) };
    if result != 0 { return result; }
    let result = unsafe { ensure_capacity(cursor, bit_count, context) };
    if result != 0 { return result; }

    unsafe { cursor.write(bit_count) };
    let mut source_mask = 0x80u8 >> (source_bit_offset & 7);
    let mut source_byte = unsafe { source.add((source_bit_offset >> 3) as usize) };
    let mut destination_mask = 0x80u8;
    let mut destination_byte = unsafe { cursor.add(2).read() as usize as *mut u8 };
    let mut remaining = bit_count;
    while remaining != 0 {
        let mut value = unsafe { destination_byte.read() } & !destination_mask;
        if unsafe { source_byte.read() } & source_mask != 0 { value |= destination_mask; }
        unsafe { destination_byte.write(value) };
        source_mask >>= 1;
        if source_mask == 0 { source_byte = unsafe { source_byte.add(1) }; source_mask = 0x80; }
        destination_mask >>= 1;
        if destination_mask == 0 { destination_byte = unsafe { destination_byte.add(1) }; destination_mask = 0x80; }
        remaining -= 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::BIT_BUFFER_COPY, 0x1000).map(|p| p as usize));
    static mut CURSOR: *mut u32 = core::ptr::null_mut();
    static mut PREPARE_RESULT: u32 = 0;
    static mut SELECT_RESULT: u32 = 0;
    static mut ENSURE_RESULT: u32 = 0;
    static mut ENSURE_ARGS: (u32, u32) = (0, 0);

    unsafe extern "C" fn record_prepare(_state: *mut u32, _arg: u32, _context: u32, _cursor: *mut u32) -> u32 { unsafe { PREPARE_RESULT } }
    unsafe extern "C" fn record_select(_state: *mut u32, _context: u32, out: *mut *mut u32, _fallback: *mut u32) -> u32 {
        unsafe { out.write(CURSOR); SELECT_RESULT }
    }
    unsafe extern "C" fn record_ensure(_cursor: *mut u32, bits: u32, context: u32) -> u32 {
        unsafe { ENSURE_ARGS = (bits, context); ENSURE_RESULT }
    }

    fn install() {
        unsafe {
            BIT_BUFFER_COPY_OPS = BitBufferCopyOps { prepare: record_prepare, select_cursor: record_select, ensure_capacity: record_ensure };
            PREPARE_RESULT = 0; SELECT_RESULT = 0; ENSURE_RESULT = 0; ENSURE_ARGS = (0, 0);
        }
    }

    #[test]
    fn copies_unaligned_msb_first_bits_and_updates_cursor_count() {
        let _guard = LOCK.lock();
        let Some(slab) = *SLAB else { assert!(note_missing_u32_fixture("util/bit_buffer_copy")); return; };
        install();
        let cursor = slab as *mut u32;
        let output = unsafe { (slab as *mut u8).add(0x100) };
        unsafe { cursor.write(0); cursor.add(1).write(0); cursor.add(2).write(output as usize as u32); cursor.add(3).write(0); output.write(0xaa); CURSOR = cursor; }
        let source = [0xac];
        assert_eq!(unsafe { bit_buffer_copy(cursor, source.as_ptr(), 3, 5, cursor, 0x77) }, 0);
        assert_eq!(unsafe { output.read() }, 0x62);
        assert_eq!(unsafe { cursor.read() }, 5);
        assert_eq!(unsafe { ENSURE_ARGS }, (5, 0x77));
    }

    #[test]
    fn capacity_failure_preserves_cursor_and_output() {
        let _guard = LOCK.lock();
        let Some(slab) = *SLAB else { assert!(note_missing_u32_fixture("util/bit_buffer_copy")); return; };
        install();
        let cursor = slab as *mut u32;
        let output = unsafe { (slab as *mut u8).add(0x100) };
        unsafe { cursor.write(0x99); cursor.add(1).write(0); cursor.add(2).write(output as usize as u32); cursor.add(3).write(0); output.write(0xaa); CURSOR = cursor; ENSURE_RESULT = 0x15; }
        let source = [0xff];
        assert_eq!(unsafe { bit_buffer_copy(cursor, source.as_ptr(), 0, 8, cursor, 0) }, 0x15);
        assert_eq!(unsafe { cursor.read() }, 0x99);
        assert_eq!(unsafe { output.read() }, 0xaa);
    }
}
