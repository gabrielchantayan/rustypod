//! Copying a VDBE value cell makes borrowed text/blob storage writable.
//!
//! - `vdbe_mem_copy` — original: `FUN_0838bad0` at load address
//!   **0x0838bad0** (96 bytes, 0x0838bad0..0x0838bb30). The next word is
//!   the separate `sqlite3VdbeMemMakeWriteable` entry, with no literal pool.
//!   Raw ARM decoding finds four direct incoming calls: two unconditional
//!   `bl` (0x082e8aec, 0x08388484) and two predicated calls (`blne`
//!   0x082d971c, `bleq` 0x0838f10c). This is SQLite 3.5.x's
//!   `sqlite3VdbeMemCopy`.
//!
//! The destination's external resources are released, then the target's
//! 0x24-byte `MEMCELLSIZE` copy transfers every field except destination
//! `zMalloc`. `MEM_Dyn` is always removed. String/blob values from a
//! non-static source gain `MEM_Ephem` and are made writable; that status is
//! returned. Typed `Mem` fields deliberately replace the target byte copy so
//! widened host pointers remain coherent.

use super::mem_extern_release::mem_extern_release;
use super::mem_release::FLAG_DYN;
use super::vdbe::{Mem, MEM_STATIC};
use super::vdbe_mem_make_writeable::vdbe_mem_make_writeable;
use super::vdbe_mem_shallow_copy::MEM_EPHEM;

const MEM_STR_OR_BLOB: u16 = 0x0012;

/// vdbe_mem_copy — original: `FUN_0838bad0` @ 0x0838bad0 (96 bytes; 2
/// unconditional and 2 predicated direct `bl` call sites).
///
/// `sqlite3VdbeMemCopy`: release destination external resources, copy the
/// source cell except `z_malloc`, then remove `MEM_Dyn`. A non-static
/// string/blob source is marked ephemeral and materialized by
/// `vdbe_mem_make_writeable`; all other copies return zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_copy(p_to: *mut Mem, p_from: *const Mem) -> i32 {
    (copy_ops().extern_release)(p_to as *mut u8);

    let to = &mut *p_to;
    let from = &*p_from;
    to.u = from.u;
    to.r = from.r;
    to.db = from.db;
    to.z = from.z;
    to.n = from.n;
    to.flags = from.flags & !FLAG_DYN;
    to.value_type = from.value_type;
    to.enc = from.enc;
    to.x_del = from.x_del;

    if to.flags & MEM_STR_OR_BLOB != 0 && from.flags & MEM_STATIC == 0 {
        to.flags |= MEM_EPHEM;
        return (copy_ops().make_writeable)(p_to);
    }
    0
}

/// Direct callees from the raw body. The slot keeps host tests from passing a
/// widened host `Mem` to `mem_extern_release`, which intentionally uses ARM
/// byte offsets; target builds use both ported defaults.
#[derive(Clone, Copy)]
pub struct MemCopyOps {
    pub extern_release: unsafe extern "C" fn(*mut u8),
    pub make_writeable: unsafe extern "C" fn(*mut Mem) -> i32,
}

pub const DEFAULT_MEM_COPY_OPS: MemCopyOps = MemCopyOps {
    extern_release: mem_extern_release,
    make_writeable: vdbe_mem_make_writeable,
};

pub static mut MEM_COPY_OPS: MemCopyOps = DEFAULT_MEM_COPY_OPS;

#[inline(always)]
unsafe fn copy_ops() -> MemCopyOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MEM_COPY_OPS))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_FLAGS: u16 = 0;
    static mut WRITEABLE_CALLS: u32 = 0;
    static mut WRITEABLE_FLAGS: u16 = 0;
    static mut WRITEABLE_RESULT: i32 = 0;

    unsafe extern "C" fn recording_release(value: *mut u8) {
        RELEASE_CALLS += 1;
        RELEASE_FLAGS = (*(value as *const Mem)).flags;
    }

    unsafe extern "C" fn recording_make_writeable(value: *mut Mem) -> i32 {
        WRITEABLE_CALLS += 1;
        WRITEABLE_FLAGS = (*value).flags;
        WRITEABLE_RESULT
    }

    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(MEM_COPY_OPS).write(DEFAULT_MEM_COPY_OPS) }
        }
    }

    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RELEASE_CALLS = 0;
            RELEASE_FLAGS = 0;
            WRITEABLE_CALLS = 0;
            WRITEABLE_FLAGS = 0;
            WRITEABLE_RESULT = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_COPY_OPS),
                MemCopyOps {
                    extern_release: recording_release,
                    make_writeable: recording_make_writeable,
                },
            );
        }
        (guard, OpsGuard)
    }

    fn mem(flags: u16, z: usize, z_malloc: usize) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x1000usize as *mut u8,
            z: z as *mut u8,
            n: -123,
            flags,
            value_type: 3,
            enc: 1,
            x_del: 0x2000usize as *mut u8,
            z_malloc: z_malloc as *mut u8,
        }
    }

    #[test]
    fn copies_all_target_fields_except_z_malloc_and_drops_dyn() {
        let _guard = bench();
        let from = mem(FLAG_DYN | 0x0004, 0x3000, 0x4000);
        let mut to = mem(0x0fff, 0x5000, 0x6000);
        assert_eq!(unsafe { vdbe_mem_copy(&mut to, &from) }, 0);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_FLAGS }, 0x0fff);
        assert_eq!(to.u, from.u);
        assert_eq!(to.r.to_bits(), from.r.to_bits());
        assert_eq!(to.db, from.db);
        assert_eq!(to.z, from.z);
        assert_eq!(to.n, from.n);
        assert_eq!(to.value_type, from.value_type);
        assert_eq!(to.enc, from.enc);
        assert_eq!(to.x_del, from.x_del);
        assert_eq!(to.z_malloc, 0x6000usize as *mut u8);
        assert_eq!(to.flags, 0x0004);
        assert_eq!(unsafe { WRITEABLE_CALLS }, 0);
    }

    #[test]
    fn static_strings_skip_materialization() {
        let _guard = bench();
        let from = mem(MEM_STATIC | FLAG_DYN | 0x0010, 0x3000, 0x4000);
        let mut to = mem(0, 0x5000, 0x6000);
        assert_eq!(unsafe { vdbe_mem_copy(&mut to, &from) }, 0);
        assert_eq!(to.flags, MEM_STATIC | 0x0010);
        assert_eq!(unsafe { WRITEABLE_CALLS }, 0);
    }

    #[test]
    fn non_static_string_becomes_ephemeral_and_returns_writeable_status() {
        let _guard = bench();
        let from = mem(0x0002 | FLAG_DYN, 0x3000, 0x4000);
        let mut to = mem(0, 0x5000, 0x6000);
        unsafe { WRITEABLE_RESULT = 7 };
        assert_eq!(unsafe { vdbe_mem_copy(&mut to, &from) }, 7);
        assert_eq!(to.flags, 0x0002 | MEM_EPHEM);
        assert_eq!(unsafe { WRITEABLE_CALLS }, 1);
        assert_eq!(unsafe { WRITEABLE_FLAGS }, 0x0002 | MEM_EPHEM);
    }
}
