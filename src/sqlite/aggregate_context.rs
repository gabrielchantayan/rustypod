//! Aggregate-context allocation — the one-time conversion of a function
//! callback's result cell into its zeroed, caller-addressable state.
//!
//! - `aggregate_context` — original: `FUN_0838ee8c` @ **0x0838ee8c**
//!   (120 bytes, 0x0838ee8c..0x0838ef04; **10 `bl` call sites**, all
//!   unconditional, decoded from every ARM `B`/`BL` word in `osos.dec):
//!   upstream SQLite 3.5.9's `sqlite3_aggregate_context`.
//!
//! ### Raw listing
//!
//! ```text
//! 0838ee8c  stmdb sp!,{r4-r6,lr}
//! 0838ee90  ldr   r4,[r0,#0x30]    @ context.pMem
//! 0838ee98  ldrh  r0,[r4,#0x1c]    @ pMem.flags
//! 0838eea0  tst   r0,#0x400        @ MEM_Agg
//! 0838eea8  cmp   r6,#0            @ nByte
//! 0838eeb4  bl    0x0838c074       @ vdbeMemClearExternAndSetNull
//! 0838eed8  bl    0x0838bdb0       @ sqlite3VdbeMemGrow(pMem,nByte,0)
//! 0838eef8  blne 0x08037dc8        @ zero the successful context
//! 0838ef00  ldr   r0,[r4,#0x14]    @ return pMem.z
//! ```
//!
//! The ten direct calls are at 0x082b5a64, 0x082c5014, 0x082c5044,
//! 0x082d2660, 0x082d26dc, 0x082d9700, 0x082d97d0, 0x083928d4,
//! 0x08392958, and 0x083943dc. All use unconditional `bl`: the callee,
//! rather than callers, owns the `MEM_Agg` one-time guard.
//!
//! ### Algorithm
//!
//! `context.p_mem` is the result [`Mem`]. If it already has `MEM_Agg`, return
//! its existing `z` without touching it. Otherwise zero bytes requests first
//! release external value state, stamp `MEM_Null`, and clear `z`. Positive
//! requests grow the result buffer without preserving the old contents,
//! stamp `MEM_Agg`, store `context.p_func` in the low word of `Mem.u`, and
//! zero exactly `n_byte` bytes when growth returned a buffer. Return `z` in
//! every path.
//!
//! ### Deliberate deviations
//!
//! The target's 32-bit pointer layout is represented by [`SqliteContext`]'s
//! named `repr(C)` fields rather than raw offsets. On 64-bit hosts those
//! pointer fields widen naturally; the `Mem.u` assignment explicitly writes
//! its low `u32`, preserving the high word just as the original `str` does.
//! `mem_extern_release` intentionally retains a raw target-layout ABI, so
//! the host build performs its reachable non-aggregate `MEM_Dyn`/`xDel`
//! branch through typed `Mem` fields; target builds call that port directly.
//! The grow and IRAM memzero dependencies are direct calls on every target;
//! no replacement dispatch seam is introduced.

use crate::libc::iram_veneers::iram_memzero_veneer;
#[cfg(target_os = "none")]
use super::mem_extern_release::mem_extern_release;
#[cfg(not(target_os = "none"))]
use super::mem_release::FLAG_DYN;
use super::value_new::MEM_NULL;
use super::vdbe::Mem;
use super::vdbe_mem_grow::vdbe_mem_grow;

/// SQLite 3.5's scalar/aggregate callback context. The output `Mem` is
/// embedded for scalar callbacks; aggregate callbacks use `p_mem` instead.
#[repr(C)]
pub struct SqliteContext {
    /// +0x00: callback's `FuncDef`.
    pub p_func: *mut u8,
    /// +0x04: unmodeled target word between `p_func` and the scratch `Mem`.
    pub _gap_04: [u8; 4],
    /// +0x08: scalar-result scratch cell, not inspected by this function.
    pub s: Mem,
    /// +0x30: aggregate/result cell.
    pub p_mem: *mut Mem,
    /// +0x34: callback error indicator, not inspected by this function.
    pub is_error: i32,
}

#[cfg(target_pointer_width = "32")]
const _SQLITE_CONTEXT_P_MEM_OFFSET: [u8; 0x30] =
    [0; core::mem::offset_of!(SqliteContext, p_mem)];
#[cfg(target_pointer_width = "32")]
const _SQLITE_CONTEXT_IS_ERROR_OFFSET: [u8; 0x34] =
    [0; core::mem::offset_of!(SqliteContext, is_error)];

/// Clear the external arm before the zero-byte result path. The original
/// call is always reached with `MEM_Agg` clear, so its non-aggregate branch
/// is exactly the typed host implementation below.
#[inline(always)]
unsafe fn clear_extern(p_mem: *mut Mem) {
    #[cfg(target_os = "none")]
    mem_extern_release(p_mem.cast());

    #[cfg(not(target_os = "none"))]
    if (*p_mem).flags & FLAG_DYN != 0 {
        let x_del: Option<unsafe extern "C" fn(*mut u8)> =
            core::mem::transmute((*p_mem).x_del);
        if let Some(x_del) = x_del {
            x_del((*p_mem).z);
            (*p_mem).x_del = core::ptr::null_mut();
        }
    }
}

/// aggregate_context — original: `FUN_0838ee8c` @ 0x0838ee8c (120 bytes;
/// 10 unconditional `bl` call sites).
///
/// `sqlite3_aggregate_context`: lazily create and return `n_byte` zeroed
/// aggregate bytes in `context.p_mem`. Once `MEM_Agg` is set, returns the
/// existing buffer without changing any cell field; a zero-sized first
/// request releases external state, leaves a NULL cell, and returns NULL.
/// A failed growth still stamps the aggregate metadata but returns NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn aggregate_context(context: *mut SqliteContext, n_byte: i32) -> *mut u8 {
    let p_mem = (*context).p_mem;
    if (*p_mem).flags & 0x0400 == 0 {
        if n_byte == 0 {
            clear_extern(p_mem);
            (*p_mem).flags = MEM_NULL;
            (*p_mem).z = core::ptr::null_mut();
        } else {
            vdbe_mem_grow(p_mem, n_byte, 0);
            (*p_mem).flags = 0x0400;
            // `str r0,[r4]`: only replace the pointer-sized low word of
            // `Mem.u`; an i64 value's high word is deliberately retained.
            core::ptr::addr_of_mut!((*p_mem).u)
                .cast::<u32>()
                .write((*context).p_func as usize as u32);
            let z = (*p_mem).z;
            if !z.is_null() {
                iram_memzero_veneer(z, n_byte as usize);
            }
        }
    }
    (*p_mem).z
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut X_DEL_ARG: usize = 0;

    unsafe extern "C" fn recording_x_del(z: *mut u8) {
        X_DEL_ARG = z as usize;
    }

    unsafe fn blank_mem() -> Mem {
        core::mem::zeroed()
    }

    unsafe fn context(p_func: *mut u8, p_mem: *mut Mem) -> SqliteContext {
        SqliteContext {
            p_func,
            _gap_04: [0; 4],
            s: blank_mem(),
            p_mem,
            is_error: 0,
        }
    }

    #[test]
    fn existing_aggregate_returns_without_touching_the_cell() {
        unsafe {
            let mut bytes = [0xa5u8; 12];
            let mut p_mem = blank_mem();
            p_mem.flags = 0x0400 | FLAG_DYN;
            p_mem.z = bytes.as_mut_ptr();
            p_mem.u = 0xdead_beef_cafe_babe;
            let mut ctx = context(0x1234_5678usize as *mut u8, &mut p_mem);

            assert_eq!(aggregate_context(&mut ctx, 8), bytes.as_mut_ptr());
            assert_eq!(p_mem.flags, 0x0400 | FLAG_DYN);
            assert_eq!(p_mem.z, bytes.as_mut_ptr());
            assert_eq!(p_mem.u, 0xdead_beef_cafe_babe);
            assert_eq!(bytes, [0xa5; 12]);
        }
    }

    #[test]
    fn zero_sized_first_request_leaves_a_null_cell() {
        unsafe {
            let mut bytes = [0x5au8; 4];
            let mut p_mem = blank_mem();
            X_DEL_ARG = 0;
            p_mem.flags = FLAG_DYN;
            p_mem.z = bytes.as_mut_ptr();
            p_mem.x_del = recording_x_del as *mut () as *mut u8;
            let mut ctx = context(core::ptr::null_mut(), &mut p_mem);

            assert!(aggregate_context(&mut ctx, 0).is_null());
            assert_eq!(X_DEL_ARG, bytes.as_mut_ptr() as usize);
            assert_eq!(p_mem.flags, MEM_NULL);
            assert!(p_mem.z.is_null());
            assert!(p_mem.x_del.is_null());
        }
    }

    #[test]
    fn first_positive_request_grows_stamps_and_zeroes_the_context() {
        unsafe {
            // `vdbe_mem_grow` reads the tag-57 size at payload-8 and its
            // pad word at payload-4. A 64-byte tracked payload avoids an
            // allocator call while exercising the real ported grow helper.
            let mut tracked = [0u32; 18];
            tracked[0] = 64;
            tracked[1] = 0;
            let payload = tracked.as_mut_ptr().add(2).cast::<u8>();
            core::slice::from_raw_parts_mut(payload, 64).fill(0xa5);

            let mut p_mem = blank_mem();
            p_mem.flags = 0x0080;
            p_mem.u = 0xfeed_face_0000_0000;
            p_mem.z = payload;
            p_mem.z_malloc = payload;
            let p_func = 0x8765_4321usize as *mut u8;
            let mut ctx = context(p_func, &mut p_mem);

            assert_eq!(aggregate_context(&mut ctx, 8), payload);
            assert_eq!(p_mem.flags, 0x0400);
            assert_eq!(p_mem.u, 0xfeed_face_8765_4321);
            assert_eq!(&core::slice::from_raw_parts(payload, 8), &[0; 8]);
            assert_eq!(&core::slice::from_raw_parts(payload.add(8), 56), &[0xa5; 56]);
        }
    }
}
