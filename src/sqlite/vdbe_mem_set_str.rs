//! Text/blob installation — how SQLite installs a caller-owned or copied
//! byte string into an existing `Mem`/`sqlite3_value` cell.
//!
//! - `vdbe_mem_set_str` — original: `FUN_0838c158` @ 0x0838c158
//!   (304 bytes, 0x0838c158..0x0838c288; **23 `bl` call sites plus one
//!   `blne`**, binary-scanned from osos.dec — no tail branches).
//!   Upstream SQLite 3.5.x's `sqlite3VdbeMemSetStr` (`int
//!   sqlite3VdbeMemSetStr(Mem *pMem, const char *z, int n, u8 enc,
//!   void (*xDel)(void *))` in `vdbemem.c`).
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c280 is the `mov r0,#0` success
//! return, 0x0838c284 is `ldmia sp!, {r4,r5,r6,r7,r8,r9,r10,pc}`, and
//! 0x0838c288 begins the next function. There is no literal pool.
//!
//! ### Listing
//!
//! ```text
//! 0838c158  stmdb sp!, {r4-r10,lr}
//! 0838c15c  ldr  r9,[sp,#0x20]       @ xDel, fifth argument
//! 0838c160  movs r6,r1                @ z; branch on z != NULL
//! 0838c164  mov  r8,r3                @ enc
//! 0838c168  mov  r5,r0                @ pMem
//! 0838c16c  mov  r4,r2                @ n
//! 0838c170  bne  0x0838c180
//! 0838c174  mov  r0,r5
//! 0838c178  bl   0x0838c13c           @ sqlite3VdbeMemSetNull
//! 0838c17c  b    0x0838c280
//! 0838c180  cmp  r8,#0
//! 0838c184  movne r7,#2               @ MEM_Str
//! 0838c188  moveq r7,#0x10            @ MEM_Blob
//! 0838c18c  cmp  r4,#0
//! 0838c190  bge  0x0838c1d0
//! 0838c194  cmp  r8,#1
//! 0838c198  mov  r4,#0
//! 0838c19c  bne  0x0838c1b8
//! 0838c1a0  ldrb r0,[r6,r4]           @ UTF-8 NUL scan
//! 0838c1a4  cmp  r0,#0
//! 0838c1a8  addne r4,r4,#1
//! 0838c1ac  bne  0x0838c1a0
//! 0838c1b0  b    0x0838c1cc
//! 0838c1b4  add  r4,r4,#2
//! 0838c1b8  add  r1,r6,r4             @ UTF-16 double-NUL scan
//! 0838c1bc  ldrb r1,[r1,#1]
//! 0838c1c0  ldrb r0,[r6,r4]
//! 0838c1c4  orrs r0,r0,r1
//! 0838c1c8  bne  0x0838c1b4
//! 0838c1cc  orr  r7,r7,#0x20          @ MEM_Term
//! 0838c1d0  cmn  r9,#1
//! 0838c1d4  bne  0x0838c220
//! 0838c1d8  tst  r7,#0x20
//! 0838c1dc  mov  r9,r4
//! 0838c1e0  beq  0x0838c1f4
//! 0838c1e4  cmp  r8,#1
//! 0838c1e8  movne r0,#2
//! 0838c1ec  moveq r0,#1
//! 0838c1f0  add  r9,r0,r9             @ bytes to copy
//! 0838c1f4  mov  r2,#0
//! 0838c1f8  mov  r1,r9
//! 0838c1fc  mov  r0,r5
//! 0838c200  bl   0x0838bdb0           @ sqlite3VdbeMemGrow
//! 0838c204  cmp  r0,#0
//! 0838c208  bne  0x0838c278
//! 0838c20c  ldr  r0,[r5,#0x14]        @ pMem->z
//! 0838c210  mov  r2,r9
//! 0838c214  mov  r1,r6
//! 0838c218  bl   0x08037db0           @ __rt_memcpy
//! 0838c21c  b    0x0838c240
//! 0838c220  mov  r0,r5
//! 0838c224  bl   0x0838c04c           @ sqlite3VdbeMemRelease
//! 0838c228  cmp  r9,#0
//! 0838c22c  movne r0,#0x40            @ MEM_Dyn
//! 0838c230  moveq r0,#0x80            @ MEM_Static
//! 0838c234  str  r9,[r5,#0x20]        @ xDel
//! 0838c238  orr  r7,r0,r7
//! 0838c23c  str  r6,[r5,#0x14]        @ z
//! 0838c240  cmp  r8,#0
//! 0838c244  moveq r8,#1               @ blobs retain UTF-8 as enc
//! 0838c248  str  r4,[r5,#0x18]        @ n
//! 0838c24c  movne r0,#3               @ SQLITE_TEXT
//! 0838c250  moveq r0,#4               @ SQLITE_BLOB
//! 0838c254  strh r7,[r5,#0x1c]        @ flags
//! 0838c258  strb r8,[r5,#0x1f]        @ enc
//! 0838c25c  cmp  r8,#1
//! 0838c260  strb r0,[r5,#0x1e]        @ type
//! 0838c264  beq  0x0838c280
//! 0838c268  mov  r0,r5
//! 0838c26c  bl   0x0838be98           @ MemHandleBom
//! 0838c270  cmp  r0,#0
//! 0838c274  beq  0x0838c280
//! 0838c278  mov  r0,#7                @ SQLITE_NOMEM
//! 0838c27c  ldmia sp!, {r4-r10,pc}
//! 0838c280  mov  r0,#0                @ SQLITE_OK
//! 0838c284  ldmia sp!, {r4-r10,pc}
//! ```
//!
//! ### Algorithm
//!
//! A NULL `z` delegates to `sqlite3VdbeMemSetNull` and returns success.
//! Otherwise the initial flags are `MEM_Str`, or `MEM_Blob` when `enc` is
//! zero. A negative `n` is measured in place: bytewise to a single NUL
//! for UTF-8, or two bytes at a time to a double NUL for every other
//! encoding, and sets `MEM_Term`.
//!
//! `xDel == SQLITE_TRANSIENT` grows cell-owned storage and copies the
//! payload, including a measured terminator. Any other `xDel` releases
//! the old dynamic guts, then makes `z` borrowed (`MEM_Static`) for NULL
//! `xDel`, or externally owned (`MEM_Dyn`) otherwise. It stamps `n`,
//! flags, encoding, and API type in that exact order. A zero encoding is
//! a BLOB but is stored with UTF-8 encoding; non-UTF-8 text runs the
//! BOM-strip helper. Allocation failure from either helper becomes
//! `SQLITE_NOMEM`.
//!
//! ### Call sites
//!
//! The binary scan finds 24 direct branches: 23 unconditional `bl` and
//! one `blne` at 0x08386710 in `sqlite3ValueSetStr` @ 0x083866ec. The
//! other callers include `sqlite3VdbeSetColName` @ 0x0838d004 (the
//! shared dispatch slot's target), the large VDBE engine routine
//! `FUN_08386ef8` (three calls), and value/callback wrappers at
//! 0x082b78b0, 0x082c5b3c, 0x082e8980, 0x083862e4, 0x08386524,
//! 0x0838b67c, 0x08391124..0x08391238, 0x08394314, 0x083943d0,
//! 0x083959c8, and 0x083974e4.
//!
//! ### Deviations
//!
//! - `sqlite3VdbeMemGrow` @ 0x0838bdb0 and `MemHandleBom` @ 0x0838be98
//!   are not ported. They form the [`VDBE_MEM_SET_STR_OPS`] seam: target
//!   builds call their retailOS load addresses, while host tests install
//!   recording mocks.
//! - The ported `mem_release` speaks the original's raw 32-bit offsets,
//!   so the existing [`MEM_SET_OPS`](super::vdbe_mem_set_int64::MEM_SET_OPS)
//!   dispatch seam is reused for its call. Host tests replace that slot;
//!   on target its shipped default is the ported release.
//! - The public entry accepts `*mut u8` to match the pre-existing
//!   [`SQLITE_VDBE_MEM_SET_STR`](super::value_set_str::SQLITE_VDBE_MEM_SET_STR)
//!   dispatch signature. It immediately converts to typed `Mem` access;
//!   the pointer representation is identical under the target ABI.

use crate::libc::rt_memcpy::__rt_memcpy;
use super::error::SQLITE_UTF8;
use super::mem_release::FLAG_DYN;
use super::value_set_str::SQLITE_NOMEM;
use super::vdbe::{Mem, MEM_STATIC};
use super::vdbe_mem_realify::SQLITE_OK;
use super::vdbe_mem_set_int64::release_op;
use super::vdbe_mem_set_null::vdbe_mem_set_null;
use super::vdbe_set_col_name::SQLITE_TRANSIENT;

/// `MEM_Str`: the byte payload is text (original: `movne r7,#2`).
pub const MEM_STR: u16 = 0x0002;
/// `MEM_Blob`: the byte payload is a blob (original: `moveq r7,#0x10`).
pub const MEM_BLOB: u16 = 0x0010;
/// `MEM_Term`: a measured terminator follows the payload (original:
/// `orr r7,r7,#0x20`).
pub const MEM_TERM: u16 = 0x0020;
/// API type for text (original: `movne r0,#3`).
pub const SQLITE_TEXT: u8 = 3;
/// API type for blobs (original: `moveq r0,#4`).
pub const SQLITE_BLOB: u8 = 4;

/// ABI of `sqlite3VdbeMemGrow(pMem, size, preserve)` @ 0x0838bdb0.
pub type VdbeMemGrow = unsafe extern "C" fn(p_mem: *mut Mem, size: i32, preserve: i32) -> i32;
/// ABI of SQLite's internal `MemHandleBom(pMem)` @ 0x0838be98.
pub type MemHandleBom = unsafe extern "C" fn(p_mem: *mut Mem) -> i32;

/// RetailOS load address of `sqlite3VdbeMemGrow`.
pub const VDBE_MEM_GROW_ADDRESS: usize = 0x0838_bdb0;
/// RetailOS load address of `MemHandleBom`.
pub const MEM_HANDLE_BOM_ADDRESS: usize = 0x0838_be98;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_mem_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
    let grow: VdbeMemGrow = core::mem::transmute(VDBE_MEM_GROW_ADDRESS);
    grow(p_mem, size, preserve)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_mem_grow(_p_mem: *mut Mem, _size: i32, _preserve: i32) -> i32 {
    panic!("vdbe_mem_set_str requires sqlite3VdbeMemGrow @ 0x0838bdb0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mem_handle_bom(p_mem: *mut Mem) -> i32 {
    let handle_bom: MemHandleBom = core::mem::transmute(MEM_HANDLE_BOM_ADDRESS);
    handle_bom(p_mem)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mem_handle_bom(_p_mem: *mut Mem) -> i32 {
    panic!("vdbe_mem_set_str requires MemHandleBom @ 0x0838be98")
}

/// Indirect dispatch for the unported grow and BOM helpers this setter
/// calls. Host tests install recording implementations; target defaults
/// branch straight into retailOS.
#[derive(Clone, Copy)]
pub struct VdbeMemSetStrOps {
    /// `sqlite3VdbeMemGrow(pMem, size, preserve)` @ 0x0838bdb0.
    pub grow: VdbeMemGrow,
    /// `MemHandleBom(pMem)` @ 0x0838be98.
    pub handle_bom: MemHandleBom,
}

/// Target default: the two remaining retailOS helpers.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_MEM_SET_STR_OPS: VdbeMemSetStrOps = VdbeMemSetStrOps {
    grow: retail_vdbe_mem_grow,
    handle_bom: retail_mem_handle_bom,
};

/// Host default: fail loudly until a test supplies the unported helpers.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_MEM_SET_STR_OPS: VdbeMemSetStrOps = VdbeMemSetStrOps {
    grow: missing_vdbe_mem_grow,
    handle_bom: missing_mem_handle_bom,
};

/// Active grow/BOM helper pair. Host tests install recording mocks.
pub static mut VDBE_MEM_SET_STR_OPS: VdbeMemSetStrOps = DEFAULT_VDBE_MEM_SET_STR_OPS;

/// Reads the grow slot volatile so its host replacement cannot be folded
/// into the default.
#[inline(always)]
unsafe fn grow_op() -> VdbeMemGrow {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_SET_STR_OPS.grow))
}

/// Reads the BOM-handler slot volatile so its host replacement cannot be
/// folded into the default.
#[inline(always)]
unsafe fn handle_bom_op() -> MemHandleBom {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_SET_STR_OPS.handle_bom))
}

/// vdbe_mem_set_str — original: `FUN_0838c158` @ 0x0838c158 (304 bytes;
/// 23 `bl` call sites plus one `blne`).
///
/// `sqlite3VdbeMemSetStr`: install `z` into `p_mem`, measuring it when
/// `n` is negative. A NULL `z` makes the cell NULL. `SQLITE_TRANSIENT`
/// copies into grown cell-owned storage; any other destructor marker
/// releases the prior cell contents and borrows (`MEM_Static`) or owns
/// externally (`MEM_Dyn`) the supplied pointer. The final stores stamp
/// length, flags, encoding, and API type; a non-UTF-8 encoding invokes
/// the BOM handler. Returns `SQLITE_OK` or `SQLITE_NOMEM`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_set_str(
    p_mem: *mut u8,
    z: *mut u8,
    n: i32,
    enc: u8,
    x_del: *mut u8,
) -> i32 {
    let p_mem = p_mem as *mut Mem;
    if z.is_null() {
        vdbe_mem_set_null(p_mem);
        return SQLITE_OK;
    }

    let mut flags = if enc == 0 { MEM_BLOB } else { MEM_STR };
    let mut len = n;
    if len < 0 {
        len = 0;
        if enc == SQLITE_UTF8 {
            while *z.add(len as usize) != 0 {
                len += 1;
            }
        } else {
            while *z.add(len as usize) != 0 || *z.add(len as usize + 1) != 0 {
                len += 2;
            }
        }
        flags |= MEM_TERM;
    }

    if x_del == SQLITE_TRANSIENT {
        let mut copy_len = len;
        if flags & MEM_TERM != 0 {
            copy_len += if enc == SQLITE_UTF8 { 1 } else { 2 };
        }
        if (grow_op())(p_mem, copy_len, 0) != 0 {
            return SQLITE_NOMEM;
        }
        __rt_memcpy((*p_mem).z, z, copy_len as usize);
    } else {
        (release_op())(p_mem as *mut u8);
        let ownership = if x_del.is_null() { MEM_STATIC } else { FLAG_DYN };
        (*p_mem).x_del = x_del;
        flags |= ownership;
        (*p_mem).z = z;
    }

    let mut enc = enc;
    let value_type = if enc == 0 {
        enc = SQLITE_UTF8;
        SQLITE_BLOB
    } else {
        SQLITE_TEXT
    };
    let mem = &mut *p_mem;
    mem.n = len;
    mem.flags = flags;
    mem.enc = enc;
    mem.value_type = value_type;

    if enc != SQLITE_UTF8 && (handle_bom_op())(p_mem) != 0 {
        return SQLITE_NOMEM;
    }
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::value_new::{MEM_NULL, SQLITE_NULL};
    use super::super::vdbe_mem_set_int64::{MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that replace this module's grow/BOM pair.
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GROW_CALLS: u32 = 0;
    static mut GROW_ARG: usize = 0;
    static mut GROW_SIZE: i32 = 0;
    static mut GROW_PRESERVE: i32 = 0;
    static mut GROW_RESULT: i32 = SQLITE_OK;
    static mut BOM_CALLS: u32 = 0;
    static mut BOM_ARG: usize = 0;
    static mut BOM_RESULT: i32 = SQLITE_OK;
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_ARG: usize = 0;
    static mut GROWN_BYTES: [u8; 64] = [0; 64];

    unsafe extern "C" fn recording_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
        GROW_CALLS += 1;
        GROW_ARG = p_mem as usize;
        GROW_SIZE = size;
        GROW_PRESERVE = preserve;
        if GROW_RESULT == SQLITE_OK {
            GROWN_BYTES.fill(0xcc);
            (*p_mem).z = core::ptr::addr_of_mut!(GROWN_BYTES).cast::<u8>();
        }
        GROW_RESULT
    }

    unsafe extern "C" fn recording_handle_bom(p_mem: *mut Mem) -> i32 {
        BOM_CALLS += 1;
        BOM_ARG = p_mem as usize;
        BOM_RESULT
    }

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        RELEASE_CALLS += 1;
        RELEASE_ARG = value as usize;
    }

    /// Restores both shared dispatch tables on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS).write(DEFAULT_VDBE_MEM_SET_STR_OPS);
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    /// Install recorders under both required locks. `MEM_SET_OPS` belongs
    /// to the int64 setter and is shared with its double sibling.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, OpsGuard) {
        let set_str_lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let release_lock = super::super::vdbe_mem_set_int64::tests::ops_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            GROW_CALLS = 0;
            GROW_ARG = 0;
            GROW_SIZE = 0;
            GROW_PRESERVE = 0;
            GROW_RESULT = SQLITE_OK;
            BOM_CALLS = 0;
            BOM_ARG = 0;
            BOM_RESULT = SQLITE_OK;
            RELEASE_CALLS = 0;
            RELEASE_ARG = 0;
            GROWN_BYTES.fill(0xcc);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_SET_STR_OPS),
                VdbeMemSetStrOps {
                    grow: recording_grow,
                    handle_bom: recording_handle_bom,
                },
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps {
                    mem_release: recording_mem_release,
                },
            );
        }
        (set_str_lock, release_lock, OpsGuard)
    }

    /// A `Mem` whose every field has a distinct value. The recording
    /// helpers never release or reallocate it, so a changed field is a
    /// setter write rather than incidental allocator behavior.
    fn garbage_mem(flags: u16, value_type: u8) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn null_z_routes_to_set_null_without_calling_any_helper() {
        let _guards = bench();
        let prior_flags = 0x0fe0 | MEM_BLOB;
        let mut mem = garbage_mem(prior_flags, 0xa5);
        let before_z = mem.z;
        let before_x_del = mem.x_del;
        let before_z_malloc = mem.z_malloc;
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                core::ptr::null_mut(),
                -1,
                3,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(mem.flags, (prior_flags & !0x1f) | MEM_NULL);
        assert_eq!(mem.value_type, SQLITE_NULL);
        assert_eq!(mem.z, before_z);
        assert_eq!(mem.x_del, before_x_del);
        assert_eq!(mem.z_malloc, before_z_malloc);
        assert_eq!(unsafe { GROW_CALLS }, 0);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { BOM_CALLS }, 0);
    }

    #[test]
    fn static_and_dynamic_text_follow_the_release_store_path() {
        let _guards = bench();
        let text = b"albums";
        let external_destructor = 0x0838_581cusize as *mut u8;
        for (x_del, ownership) in [
            (core::ptr::null_mut(), MEM_STATIC),
            (external_destructor, FLAG_DYN),
        ] {
            let mut mem = garbage_mem(0x0fff, 0xa5);
            let rc = unsafe {
                vdbe_mem_set_str(
                    core::ptr::addr_of_mut!(mem).cast(),
                    text.as_ptr() as *mut u8,
                    text.len() as i32,
                    SQLITE_UTF8,
                    x_del,
                )
            };
            assert_eq!(rc, SQLITE_OK);
            assert_eq!(mem.z, text.as_ptr() as *mut u8);
            assert_eq!(mem.x_del, x_del);
            assert_eq!(mem.n, text.len() as i32);
            assert_eq!(mem.flags, MEM_STR | ownership);
            assert_eq!(mem.enc, SQLITE_UTF8);
            assert_eq!(mem.value_type, SQLITE_TEXT);
        }
        assert_eq!(unsafe { RELEASE_CALLS }, 2);
        assert_eq!(unsafe { GROW_CALLS }, 0);
        assert_eq!(unsafe { BOM_CALLS }, 0);
    }

    #[test]
    fn transient_utf8_measures_and_copies_its_nul() {
        let _guards = bench();
        let text = b"albums\0";
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                text.as_ptr() as *mut u8,
                -1,
                SQLITE_UTF8,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(unsafe { GROW_CALLS }, 1);
        assert_eq!(unsafe { GROW_ARG }, core::ptr::addr_of!(mem) as usize);
        assert_eq!(unsafe { GROW_SIZE }, text.len() as i32);
        assert_eq!(unsafe { GROW_PRESERVE }, 0);
        assert_eq!(unsafe { &GROWN_BYTES[..text.len()] }, text);
        assert_eq!(mem.n, (text.len() - 1) as i32);
        assert_eq!(mem.flags, MEM_STR | MEM_TERM);
        assert_eq!(mem.enc, SQLITE_UTF8);
        assert_eq!(mem.value_type, SQLITE_TEXT);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { BOM_CALLS }, 0);
    }

    #[test]
    fn transient_utf16_measures_double_nuls_and_runs_the_bom_handler() {
        let _guards = bench();
        let text = [0x00u8, b'a', 0x00, b'b', 0x00, 0x00];
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                text.as_ptr() as *mut u8,
                -1,
                3,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(unsafe { GROW_SIZE }, text.len() as i32);
        assert_eq!(unsafe { &GROWN_BYTES[..text.len()] }, &text);
        assert_eq!(mem.n, 4);
        assert_eq!(mem.flags, MEM_STR | MEM_TERM);
        assert_eq!(mem.enc, 3);
        assert_eq!(mem.value_type, SQLITE_TEXT);
        assert_eq!(unsafe { BOM_CALLS }, 1);
        assert_eq!(unsafe { BOM_ARG }, core::ptr::addr_of!(mem) as usize);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
    }

    #[test]
    fn blob_stamps_utf8_but_skips_the_bom_handler() {
        let _guards = bench();
        let blob = [0x81u8, 0x00, 0xfe, 0xff];
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                blob.as_ptr() as *mut u8,
                blob.len() as i32,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(mem.n, blob.len() as i32);
        assert_eq!(mem.flags, MEM_BLOB | MEM_STATIC);
        assert_eq!(mem.enc, SQLITE_UTF8);
        assert_eq!(mem.value_type, SQLITE_BLOB);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { GROW_CALLS }, 0);
        assert_eq!(unsafe { BOM_CALLS }, 0);
    }

    #[test]
    fn explicit_transient_length_copies_exactly_that_many_bytes() {
        let _guards = bench();
        let bytes = b"abcdef\0";
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                bytes.as_ptr() as *mut u8,
                3,
                SQLITE_UTF8,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(unsafe { GROW_SIZE }, 3);
        assert_eq!(unsafe { &GROWN_BYTES[..3] }, b"abc");
        assert_eq!(unsafe { GROWN_BYTES[3] }, 0xcc, "no implicit terminator for explicit n");
        assert_eq!(mem.n, 3);
        assert_eq!(mem.flags, MEM_STR);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
    }

    #[test]
    fn grow_failure_returns_nomem_before_any_setter_store() {
        let _guards = bench();
        unsafe { GROW_RESULT = SQLITE_NOMEM };
        let text = b"albums\0";
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let before = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                text.as_ptr() as *mut u8,
                -1,
                SQLITE_UTF8,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_NOMEM);
        assert_eq!(unsafe { GROW_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { BOM_CALLS }, 0);
        assert_eq!(mem.z, before.z);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.flags, before.flags);
        assert_eq!(mem.value_type, before.value_type);
        assert_eq!(mem.enc, before.enc);
        assert_eq!(mem.x_del, before.x_del);
    }

    #[test]
    fn bom_failure_returns_nomem_after_the_final_stores() {
        let _guards = bench();
        unsafe { BOM_RESULT = SQLITE_NOMEM };
        let text = [0x00u8, b'x', 0x00, 0x00];
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let rc = unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                text.as_ptr() as *mut u8,
                -1,
                2,
                SQLITE_TRANSIENT,
            )
        };
        assert_eq!(rc, SQLITE_NOMEM);
        assert_eq!(mem.n, 2);
        assert_eq!(mem.flags, MEM_STR | MEM_TERM);
        assert_eq!(mem.enc, 2);
        assert_eq!(mem.value_type, SQLITE_TEXT);
        assert_eq!(unsafe { BOM_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
    }

    #[test]
    fn empty_utf8_and_utf16_strings_measure_to_zero() {
        let _guards = bench();
        for (bytes, enc, copied) in [
            (&b"\0"[..], SQLITE_UTF8, 1usize),
            (&b"\0\0"[..], 2, 2usize),
        ] {
            let mut mem = garbage_mem(0x0fff, 0xa5);
            let rc = unsafe {
                vdbe_mem_set_str(
                    core::ptr::addr_of_mut!(mem).cast(),
                    bytes.as_ptr() as *mut u8,
                    -1,
                    enc,
                    SQLITE_TRANSIENT,
                )
            };
            assert_eq!(rc, SQLITE_OK);
            assert_eq!(mem.n, 0);
            assert_eq!(mem.flags, MEM_STR | MEM_TERM);
            assert_eq!(unsafe { GROW_SIZE }, copied as i32);
        }
    }

    #[test]
    fn only_documented_fields_change_before_the_helper_calls() {
        let _guards = bench();
        let text = b"db\0";
        let mut mem = garbage_mem(0x0fff, 0xa5);
        let before_u = mem.u;
        let before_r = mem.r.to_bits();
        let before_db = mem.db;
        let before_z_malloc = mem.z_malloc;
        unsafe {
            vdbe_mem_set_str(
                core::ptr::addr_of_mut!(mem).cast(),
                text.as_ptr() as *mut u8,
                -1,
                SQLITE_UTF8,
                SQLITE_TRANSIENT,
            );
        }
        assert_eq!(mem.u, before_u);
        assert_eq!(mem.r.to_bits(), before_r);
        assert_eq!(mem.db, before_db);
        assert_eq!(mem.z_malloc, before_z_malloc);
    }
}
