//! Cursor setup bytecode emitter.
//!
//! `emit_cursor_setup` — original: `FUN_0837a04c` @ `0x0837a04c` (136 bytes,
//! `0x0837a04c..0x0837a0d4`; the next independently entered function starts at
//! `0x0837a0d4`). Raw `osos.dec` decoding finds three plain outbound `bl`
//! instructions and one predicated `blne`; the final `b` tail-calls
//! `vdbe_change_p3`. The two known inbound direct-call sites are at
//! `0x08374b88` and `0x08379b10`.
//!
//! Emits opcode 45 for `cursor`, delegates the associated cursor-column
//! emission to the still-retail helper at `0x0837a0d4`, emits opcode 89, and,
//! when `attach_source_word` is nonzero, assigns the source object's first
//! word to the final operation with the raw `-2` P4 type. It then patches the
//! first operation's P3 to the current VDBE operation count.
//! Deliberate deviation: `0x0837a0d4` has not been ported and its semantic
//! identity is not established, so target builds call that verified retail
//! address directly; host builds dispatch through a test-installable seam.

use super::vdbe::{vdbe_add_op2, vdbe_add_op3, vdbe_change_p3, vdbe_change_p4, Vdbe};
const P4_SOURCE_WORD: i32 = -2;
const OP_CURSOR_SETUP: i32 = 45;
const OP_SET_CURSOR_MODE: i32 = 89;
const P4_KEYINFO: i32 = -2;
type RetailColumnEmitter = unsafe extern "C" fn(*mut u8, *mut u8, i32, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn emit_retail_columns(parse: *mut u8, source: *mut u8, cursor: i32) {
    let operation: RetailColumnEmitter = core::mem::transmute(0x0837_a0d4usize);
    operation(parse, source, cursor, core::ptr::null_mut());
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_retail_column_emitter(
    _parse: *mut u8,
    _source: *mut u8,
    _cursor: i32,
    _columns: *mut u8,
) {
    panic!("retail helper 0x0837a0d4 is unavailable on the host");
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_COLUMN_EMITTER: RetailColumnEmitter = unavailable_retail_column_emitter;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn emit_retail_columns(parse: *mut u8, source: *mut u8, cursor: i32) {
    let operation = core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_COLUMN_EMITTER));
    operation(parse, source, cursor, core::ptr::null_mut());
}

/// Emit the cursor setup sequence recovered from `FUN_0837a04c`.
///
/// # Safety
/// `parse` must hold a target-layout VDBE pointer at +0x0c, `source` must
/// expose a target-width P4 pointer in its first word, and all VDBE storage
/// reached by the called helpers must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_cursor_setup(
    parse: *mut u8,
    source: *mut u8,
    cursor: i32,
    attach_source_word: i32,
) {
    let vdbe = parse.add(0x0c).cast::<u32>().read() as usize as *mut Vdbe;
    let address = vdbe_add_op3(vdbe, OP_CURSOR_SETUP, cursor, 0, 0);
    emit_retail_columns(parse, source, cursor);
    vdbe_add_op2(vdbe, OP_SET_CURSOR_MODE, cursor, (attach_source_word != 0) as i32);
    if attach_source_word != 0 {
        let source_word = source.cast::<u32>().read() as usize as *const u8;
        vdbe_change_p4(vdbe, -1, source_word, P4_SOURCE_WORD);
    }
    vdbe_change_p3(vdbe, address, (*vdbe).n_op);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static SLAB_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EMIT_CURSOR_SETUP, 0x1000).map(|p| p as usize)
    });
    static mut EXPECTED: (usize, usize, i32, usize) = (0, 0, 0, 0);

    unsafe extern "C" fn record_columns(parse: *mut u8, source: *mut u8, cursor: i32, columns: *mut u8) {
        EXPECTED = (parse as usize, source as usize, cursor, columns as usize);
    }

    fn op() -> super::super::vdbe::VdbeOp {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn emits_and_patches_key_info_for_nonzero_flag() {
        let _lock = SLAB_LOCK.lock();
        let Some(address) = *SLAB else { return };
        unsafe {
            let parse = address as *mut u8;
            let source = parse.add(0x100);
            let key_info = source.add(0x80);
            core::ptr::write_bytes(parse, 0, 0x1000);
            source.cast::<u32>().write(key_info as u32);
            let mut ops = [op(), op(), op()];
            let vdbe = parse.add(0x200).cast::<Vdbe>();
            core::ptr::write_bytes(vdbe.cast::<u8>(), 0, core::mem::size_of::<Vdbe>());
            (*vdbe).n_op_alloc = ops.len() as i32;
            (*vdbe).db = parse.add(0x300);
            (*vdbe).a_op = ops.as_mut_ptr();
            parse.add(0x0c).cast::<u32>().write(vdbe as usize as u32);
            RETAIL_COLUMN_EMITTER = record_columns;

            emit_cursor_setup(parse, source, 17, -9);

            assert_eq!(EXPECTED, (parse as usize, source as usize, 17, 0));
            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (45, 17, 0, 2));
            assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2), (89, 17, 1));
            assert_eq!((ops[1].p4, ops[1].p4type), (key_info, -2));
        }
    }

    #[test]
    fn zero_flag_leaves_final_p4_empty() {
        let _lock = SLAB_LOCK.lock();
        let Some(address) = *SLAB else { return };
        unsafe {
            let parse = address as *mut u8;
            let source = parse.add(0x100);
            core::ptr::write_bytes(parse, 0, 0x1000);
            let mut ops = [op(), op(), op()];
            let vdbe = parse.add(0x200).cast::<Vdbe>();
            core::ptr::write_bytes(vdbe.cast::<u8>(), 0, core::mem::size_of::<Vdbe>());
            (*vdbe).n_op_alloc = ops.len() as i32;
            (*vdbe).a_op = ops.as_mut_ptr();
            (*vdbe).db = parse.add(0x300);
            parse.add(0x0c).cast::<u32>().write(vdbe as usize as u32);
            RETAIL_COLUMN_EMITTER = record_columns;

            emit_cursor_setup(parse, source, -3, 0);

            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p3), (45, -3, 2));
            assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p4type), (89, -3, 0, 0));
            assert!(ops[1].p4.is_null());
        }
    }
}
