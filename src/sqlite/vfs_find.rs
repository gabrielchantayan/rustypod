//! SQLite registered-VFS lookup.
//!
//! `sqlite_vfs_find` — original: `FUN_083917d8` @ **0x083917d8**
//! (**100 bytes**: 96-byte body `0x083917d8..0x08391838` plus the
//! `ldr r4,[pc,#0x54]` literal pool word `0x08a09918` at `0x08391838`;
//! the next separately linked function `sqlite3_vfs_register` starts at
//! `0x0839183c`. Ghidra's 96-byte extent excludes the literal).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 083917d8  push {r4,r5,r6,lr}
//! 083917dc  ldr  r4,[0x8391838]     ; r4 = 0x08a09918 (SQLite global)
//! 083917e0  mov  r5,r0              ; name
//! 083917e4  ldr  r0,[r4,#0x14]      ; initialized flag
//! 083917e8  cmp  r0,#0
//! 083917ec  bne  0x08391800
//! 083917f0  bl   0x0837db38         ; os-init getter: returns default VFS
//! 083917f4  str  r0,[r4]            ; head = default
//! 083917f8  mov  r0,#1
//! 083917fc  str  r0,[r4,#0x14]      ; initialized = 1
//! 08391800  ldr  r4,[r4]            ; node = head
//! 08391804  b    0x08391828
//! 08391808  cmp  r5,#0              ; name == NULL -> stop, return node
//! 0839180c  beq  0x08391830
//! 08391810  ldr  r1,[r4,#0x10]      ; node->zName
//! 08391814  mov  r0,r5
//! 08391818  bl   0x08391e38         ; strcmp veneer -> strcmp @ 0x08391e44
//! 0839181c  cmp  r0,#0
//! 08391820  beq  0x08391830         ; match -> return node
//! 08391824  ldr  r4,[r4,#0x0c]      ; node = node->pNext
//! 08391828  cmp  r4,#0
//! 0839182c  bne  0x08391808
//! 08391830  mov  r0,r4
//! 08391834  pop  {r4,r5,r6,pc}
//! 08391838  .word 0x08a09918
//! ```
//!
//! **4 direct `bl` call sites, all unconditional** (binary-scanned from
//! `osos.dec`: `0x082dbe6c`, `0x08365468`, `0x08391398`, `0x0839184c`);
//! no predicated call targets it. The two callees decode from raw bytes to
//! `0x0837db38` (a 2-instruction getter returning the default-VFS global
//! `DAT_0837db40`) and `0x08391e38` (the `strcmp` entry veneer).
//!
//! # Algorithm
//!
//! SQLite's `sqlite3_vfs_find`: lazily seed the registry at `0x08a09918`
//! with the built-in default VFS on first use (flag word at `+0x14`), then
//! walk the singly linked `sqlite3_vfs` list (`pNext` at `+0x0c`, `zName`
//! at `+0x10`). A NULL `name` stops at and returns the head; otherwise the
//! first node whose `zName` strcmp-equals `name` is returned, NULL when no
//! node matches. The list is only as long as the registered VFS tables.
//!
//! # Deliberate deviations
//!
//! - The os-init getter (`FUN_0837db38`) is not ported; target builds call
//!   its verified load address `0x0837db38`, host tests install a recorder
//!   through the volatile ops slot (same pattern as `randomness.rs`).
//! - `strcmp` is called through the ported `libc::strcmp` directly, per the
//!   porting rules (names.yaml hooks both `0x08391e38` and `0x08391e44` to
//!   that one symbol).
//! - The target reads and writes the retail BSS registry words at
//!   `0x08a09918` directly; the host uses an equivalent private static.

use super::os_open::SqliteVfs;
use crate::libc::strcmp::strcmp;

/// Still-stock `FUN_0837db38`, the getter returning the built-in default VFS.
pub const OS_INIT_ADDRESS: usize = 0x0837_db38;

/// Retail BSS registry: list head at `+0x00`, initialized flag at `+0x14`.
const VFS_REGISTRY_ADDRESS: usize = 0x08a0_9918;

/// The two registry words this function touches, at their retail offsets.
#[repr(C)]
struct VfsRegistry {
    /// `+0x00`: head of the registered `sqlite3_vfs` list.
    head: *mut SqliteVfs,
    /// `+0x04..+0x14`: untouched by this function.
    _pad: [u32; 4],
    /// `+0x14`: nonzero once `head` has been seeded from the os-init getter.
    initialized: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(VfsRegistry, initialized)];

#[cfg(target_os = "none")]
fn registry() -> *mut VfsRegistry {
    VFS_REGISTRY_ADDRESS as *mut VfsRegistry
}

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTRY: VfsRegistry = VfsRegistry {
    head: core::ptr::null_mut(),
    _pad: [0; 4],
    initialized: 0,
};

#[cfg(not(target_os = "none"))]
fn registry() -> *mut VfsRegistry {
    core::ptr::addr_of_mut!(HOST_REGISTRY)
}

/// ABI of the os-init getter.
pub type OsInitFn = unsafe extern "C" fn() -> *mut SqliteVfs;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_os_init() -> *mut SqliteVfs {
    let os_init: OsInitFn = core::mem::transmute(OS_INIT_ADDRESS);
    os_init()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_os_init() -> *mut SqliteVfs {
    panic!("sqlite_vfs_find requires FUN_0837db38 @ 0x0837db38")
}

/// Callback table for the only unported callee.
#[derive(Clone, Copy)]
pub struct VfsFindOps {
    pub os_init: OsInitFn,
}

/// Target default preserves the retail `bl 0x0837db38` behavior.
pub const DEFAULT_VFS_FIND_OPS: VfsFindOps = VfsFindOps {
    os_init: retail_os_init,
};

/// Active os-init getter. Host tests replace it to observe every call.
pub static mut VFS_FIND_OPS: VfsFindOps = DEFAULT_VFS_FIND_OPS;

/// Volatile dispatch prevents LLVM from folding the target default away.
#[inline(always)]
unsafe fn os_init_op() -> OsInitFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VFS_FIND_OPS.os_init))
}

/// `sqlite3_vfs_find`: return the registered VFS named `name`, the list head
/// when `name` is NULL, or NULL when nothing matches.
///
/// # Safety
///
/// `name` must be NULL or a readable NUL-terminated string. Once seeded, the
/// registry's list must contain readable `sqlite3_vfs` nodes, each with a
/// readable NUL-terminated `zName`. Neither condition is checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_vfs_find(name: *const u8) -> *mut SqliteVfs {
    let registry = registry();
    if (*registry).initialized == 0 {
        (*registry).head = os_init_op()();
        (*registry).initialized = 1;
    }
    let mut node = (*registry).head;
    while !node.is_null() {
        if name.is_null() {
            break;
        }
        if strcmp(name, (*node).name) == 0 {
            break;
        }
        node = (*node).next;
    }
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Recorder {
        calls: u32,
    }

    static mut RECORDER: Recorder = Recorder { calls: 0 };

    unsafe extern "C" fn recorded_os_init() -> *mut SqliteVfs {
        core::ptr::addr_of_mut!(RECORDER).as_mut().unwrap().calls += 1;
        core::ptr::addr_of_mut!(DEFAULT_VFS)
    }

    static mut DEFAULT_VFS: SqliteVfs = vfs(b"unix\0".as_ptr());

    const fn vfs(name: *const u8) -> SqliteVfs {
        SqliteVfs {
            version: 1,
            os_file_size: 0,
            max_pathname: 0,
            next: core::ptr::null_mut(),
            name,
            app_data: core::ptr::null_mut(),
            open: dummy_open,
            delete: 0,
            access: dummy_access,
        }
    }

    unsafe extern "C" fn dummy_open(
        _vfs: *mut SqliteVfs,
        _path: *const u8,
        _file: *mut super::super::os_write::SqliteFile,
        _flags: u32,
        _out_flags: *mut u32,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn dummy_access(
        _vfs: *mut SqliteVfs,
        _path: *const u8,
        _flags: u32,
        _result: *mut i32,
    ) -> i32 {
        0
    }

    /// Reset the shared registry and ops slot; returns the held guard.
    fn reset() -> parking_lot::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VFS_FIND_OPS),
                VfsFindOps { os_init: recorded_os_init },
            );
            let registry = registry();
            (*registry).head = core::ptr::null_mut();
            (*registry).initialized = 0;
            core::ptr::addr_of_mut!(RECORDER).as_mut().unwrap().calls = 0;
        }
        guard
    }

    #[test]
    fn lazy_init_seeds_head_once() {
        let _guard = reset();
        unsafe {
            let found = sqlite_vfs_find(core::ptr::null());
            assert_eq!(found, core::ptr::addr_of_mut!(DEFAULT_VFS));
            assert_eq!((*registry()).initialized, 1);
            assert_eq!((*registry()).head, core::ptr::addr_of_mut!(DEFAULT_VFS));
            assert_eq!(RECORDER.calls, 1);

            sqlite_vfs_find(core::ptr::null());
            assert_eq!(RECORDER.calls, 1, "second lookup must not re-seed");
        }
    }

    #[test]
    fn null_name_returns_head_without_strcmp() {
        let _guard = reset();
        unsafe {
            let mut other = vfs(b"other\0".as_ptr());
            let mut head = vfs(b"head\0".as_ptr());
            head.next = core::ptr::addr_of_mut!(other);
            (*registry()).head = core::ptr::addr_of_mut!(head);
            (*registry()).initialized = 1;

            let found = sqlite_vfs_find(core::ptr::null());
            assert_eq!(found, core::ptr::addr_of_mut!(head));
        }
    }

    #[test]
    fn finds_named_node_past_head() {
        let _guard = reset();
        unsafe {
            let mut target = vfs(b"win32\0".as_ptr());
            let mut head = vfs(b"unix\0".as_ptr());
            head.next = core::ptr::addr_of_mut!(target);
            (*registry()).head = core::ptr::addr_of_mut!(head);
            (*registry()).initialized = 1;

            let found = sqlite_vfs_find(b"win32\0".as_ptr());
            assert_eq!(found, core::ptr::addr_of_mut!(target));
        }
    }

    #[test]
    fn unmatched_name_returns_null() {
        let _guard = reset();
        unsafe {
            let mut head = vfs(b"unix\0".as_ptr());
            (*registry()).head = core::ptr::addr_of_mut!(head);
            (*registry()).initialized = 1;

            assert!(sqlite_vfs_find(b"os2\0".as_ptr()).is_null());
            // strcmp is three-way but case-sensitive: no folded match.
            assert!(sqlite_vfs_find(b"UNIX\0".as_ptr()).is_null());
        }
    }

    #[test]
    fn empty_initialized_list_returns_null() {
        let _guard = reset();
        unsafe {
            (*registry()).initialized = 1;
            assert!(sqlite_vfs_find(b"unix\0".as_ptr()).is_null());
            assert_eq!(RECORDER.calls, 0, "initialized list skips the getter");
        }
    }
}
