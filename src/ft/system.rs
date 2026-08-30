//! FreeType's `ftsystem.c` — the platform seam, which on this device is
//! Apple's own rather than upstream's ANSI/stdio one. Upstream ships
//! `FT_Stream_Open` next to an `ft_ansi_stream_io`/`ft_ansi_stream_close`
//! pair built on `FILE*`; this build ships exactly that shape, three
//! functions in a row, over the firmware's C++ file object:
//!
//! ```text
//! 0x082d3d40  close callback  ->  stream->close
//! 0x082d3d7c  read  callback  ->  stream->read
//! 0x082d3ddc  the opener      ->  called by FT_Stream_Open @ 0x0804f338
//! ```
//!
//! [`ft_platform_stream_open`] is the third of those. It is the reason
//! this is *not* upstream code: it splits the path FreeType hands it into
//! a volume digit and a path (`"0:/Foo/Bar"` -> volume 0, `"/Foo/Bar"`),
//! asks the firmware to open it, and only then fills in the
//! `FT_StreamRec` — a layout confirmation in its own right, since the
//! fields it writes are `size`, `pos`, `descriptor`, `pathname`, `read`
//! and `close` at exactly the offsets `ft/stream.rs` recovered.
//!
//! # Deviations
//!
//! [`ft_platform_file_open`] @ 0x082d3cb4 — the open itself — is ported:
//! `operator new(84)` (the real port, `heap::veneers::operator_new`),
//! then the file object's constructor at 0x08278dc4, then a check of
//! the object's status word at +28: non-zero means the open failed, so
//! the object is destroyed through vtable slot 1 and the out-parameter
//! nulled. The constructor is a whole C++ file-class subsystem and is
//! **not** ported, so it sits behind the [`FT_PLATFORM_FILE_CTOR`]
//! dispatch slot (the singletons.rs pattern) whose default stub fails
//! the open closed. [`ft_platform_stream_close`] @ 0x082d3d40 is ported:
//! it destroys the descriptor through the object's own vtable (slot 1),
//! which — like [`ft_platform_file_open`]'s failure path — is a property
//! of the object, not a hard-coded address, so no dispatch slot is needed.
//! The length query [`ft_platform_file_length`] @ 0x082a5418 is ported:
//! it takes the counted mutex embedded at +0x44 of the object's
//! synchronization owner (+4), rejects a nonzero state byte with error 2,
//! and otherwise returns the open-status word when the directory-entry
//! index is -1 or writes the cached entry length.
//!
//! [`ft_platform_stream_read`] @ 0x082d3d7c is ported too. Its direct
//! C++ file-method seek branch @ 0x082787b8 remains the exact
//! [`FT_PLATFORM_FILE_SEEK`] dispatch seam because that subsystem is not yet
//! ported. Its read branch @ 0x082784b8 now calls
//! [`crate::fs::file_read::retail_file_read`], which supplies the stock zero
//! control word to the unrecovered 0x082784d4 body; that body remains a
//! fail-closed host boundary.
//!
//! The opener takes its file-open dependency as an installable
//! [`FtPlatformFileOps`], the same shape `ft/trace.rs` uses for the
//! unported logger. Its sole entry has the original file-opener ABI;
//! without one installed every open fails with
//! [`FT_PLATFORM_OPEN_FAILED`], as it does when the hardware volume is
//! not mounted.

use crate::ft::stream::FtStream;
use crate::heap::veneers::operator_new;
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

/// The opener's `moveq r0, #9` @ 0x082d3de4 — a null `FT_Stream`. These
/// two codes are the firmware's own numbering, not FreeType's;
/// [`ft_stream_open`](crate::ft::stream::ft_stream_open) only ever tests
/// them against zero.
pub const FT_PLATFORM_NULL_STREAM: i32 = 9;

/// The opener's `moveq r5, #20` @ 0x082d3e18 — the file layer refused,
/// leaving a null handle.
pub const FT_PLATFORM_OPEN_FAILED: i32 = 20;

/// The firmware file-opening API [`ft_platform_stream_open`] is built on.
/// The installed entry is the original 0x082d3cb4 ABI; the seek/read
/// primitives used by the stream callback have their own exact seams below.
#[derive(Clone, Copy)]
pub struct FtPlatformFileOps {
    /// 0x082d3cb4 — open `path` on `volume`, storing the file object in
    /// `*handle` (null when the open failed) and returning 1 on success.
    /// The opener ignores the return value and tests `*handle`.
    pub open: unsafe extern "C" fn(
        volume: i32,
        path: *const u8,
        handle: *mut *mut core::ffi::c_void,
    ) -> i32,
}

/// The installed file opener, or `None` for "no volume". ADDITION — retailOS
/// directly branches to 0x082d3cb4; see the module header.
static mut PLATFORM_FILE_OPS: Option<FtPlatformFileOps> = None;

/// Installs (or with `None` removes) the platform file layer, returning
/// the previous one. ADDITION — see the module header.
///
/// # Safety
/// Not re-entrant: no other thread may be inside
/// [`ft_platform_stream_open`] while the ops are swapped.
pub unsafe fn ft_set_platform_file_ops(
    ops: Option<FtPlatformFileOps>,
) -> Option<FtPlatformFileOps> {
    let slot = core::ptr::addr_of_mut!(PLATFORM_FILE_OPS);
    let previous = slot.read_volatile();
    slot.write_volatile(ops);
    previous
}
/// ABI of the file object's seek wrapper @ 0x082787b8.
///
/// The callback passes its `offset` twice: once as `duplicate_offset` in r1
/// and again as the low word in r2. Raw assembly of the wrapper proves r1 is
/// overwritten before use; r2/r3 and the stack `origin` form the u64 offset
/// and seek origin. The duplicate is retained here to preserve the callback's
/// exact call ABI.
pub type FtPlatformFileSeekFn = unsafe extern "C" fn(
    handle: *mut core::ffi::c_void,
    duplicate_offset: u32,
    offset_low: u32,
    offset_high: u32,
    origin: u32,
) -> i32;

/// Default seek for the unported C++ file layer. It deliberately has no
/// observable effect; the retailOS call's return value is ignored.
unsafe extern "C" fn file_seek_unported(
    _handle: *mut core::ffi::c_void,
    _duplicate_offset: u32,
    _offset_low: u32,
    _offset_high: u32,
    _origin: u32,
) -> i32 {
    0
}

/// Direct 0x082787b8 branch used by [`ft_platform_stream_read`]. Install the
/// real C++ file seek when that class is ported; host tests install a recorder.
pub static mut FT_PLATFORM_FILE_SEEK: FtPlatformFileSeekFn = file_seek_unported;


/// ft_platform_stream_read — original: `FUN_082d3d7c` @ 0x082d3d7c
/// (96 bytes; stored as the `FT_Stream_IoFunc` literal by
/// [`ft_platform_stream_open`] @ 0x082d3ddc).
///
/// Reads `count` bytes from the C++ file object in `stream->descriptor`
/// (+0x0c) at `offset`. It always first calls file seek @ 0x082787b8 as
/// `(handle, offset, offset, 0, 0)`, ignoring that call's status. If and only
/// if both `buffer` and `count` are nonzero, it calls file read @ 0x082784b8
/// as `(handle, count, buffer, &mut transferred)`. The local transferred
/// count starts at zero and is reset to zero when any nonzero read status is
/// returned; it is then returned. Thus null-buffer and zero-count calls are
/// seek-only probes used by `FT_Stream_Seek`.
///
/// The callback never dereferences the file object itself: the sole recovered
/// layout fact is its opaque pointer at `FtStream + 0x0c`, passed unchanged to
/// both file methods. The target-only `FtStream` layout assertions pin that
/// offset. Seek remains an installable ABI seam; the now-ported read wrapper
/// delegates to its unrecovered 0x082784d4 body, whose host default fails
/// closed rather than inventing filesystem I/O.
///
/// # Safety
/// `stream` must be a valid `FtStream` with a descriptor valid for the seek
/// seam and read body. When `buffer` and `count` are nonzero, `buffer` must
/// name `count` writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_platform_stream_read(
    stream: *mut FtStream,
    offset: u32,
    buffer: *mut u8,
    count: u32,
) -> u32 {
    let handle = (*stream).descriptor;
    let seek = core::ptr::addr_of!(FT_PLATFORM_FILE_SEEK).read_volatile();
    seek(handle, offset, offset, 0, 0);

    let mut transferred = 0;
    if !buffer.is_null() && count != 0 {
        if crate::fs::file_read::retail_file_read(handle, count, buffer, &mut transferred) != 0 {
            transferred = 0;
        }
    }
    transferred
}


/// ft_platform_stream_open (the firmware's `FT_Stream_Open` body) —
/// original: `FUN_082d3ddc` @ 0x082d3ddc (120 bytes; 1 `bl` call site,
/// [`ft_stream_open`](crate::ft::stream::ft_stream_open) @ 0x0804f338).
///
/// Opens `pathname` and turns `stream` into a disk stream over it.
/// `pathname` is a volume-qualified path: byte 0 is a decimal digit read
/// as a *signed* char (`ldrb`, `- '0'`, `lsl #24`/`asr #24`) and used as
/// the volume index, byte 1 is a separator that is simply skipped, and
/// the path proper starts at byte 2. Both the volume digit and the
/// two-byte skip are unconditional — there is no format check, and
/// `pathname` itself is never null-tested.
///
/// On success the record gets `size` from the file layer, a zeroed
/// `pos`, the file object as `descriptor`, `pathname + 2` as `pathname`
/// (a pointer *into the caller's string*, not a copy) and the read/close
/// callbacks. `base` is deliberately left alone: a disk stream has no
/// image until [`ft_stream_enter_frame`](crate::ft::stream::ft_stream_enter_frame)
/// allocates one.
///
/// Failure leaves the record completely untouched — including on the
/// [`FT_PLATFORM_OPEN_FAILED`] path, which has already run the open.
///
/// # Safety
/// `stream` must be null or a valid `FtStream`; `pathname` must be a
/// NUL-terminated string of at least two bytes plus the path, and must
/// outlive the stream, which keeps a pointer into it.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_platform_stream_open(
    stream: *mut FtStream,
    pathname: *const u8,
) -> i32 {
    if stream.is_null() {
        return FT_PLATFORM_NULL_STREAM;
    }

    let Some(ops) = core::ptr::addr_of!(PLATFORM_FILE_OPS).read_volatile() else {
        return FT_PLATFORM_OPEN_FAILED;
    };

    let volume = (*pathname).wrapping_sub(b'0') as i8 as i32;
    let path = pathname.add(2);

    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    (ops.open)(volume, path, &mut handle);
    if handle.is_null() {
        return FT_PLATFORM_OPEN_FAILED;
    }

    ft_platform_file_length(handle, &mut (*stream).size);
    (*stream).pathname = path as *mut core::ffi::c_void;
    (*stream).descriptor = handle;
    (*stream).pos = 0;
    (*stream).read = Some(ft_platform_stream_read);
    (*stream).close = Some(ft_platform_stream_close);
    0
}

/// The platform C++ file object is 84 bytes on the ARM target. Only the
/// fields exercised by [`ft_platform_file_length`] are named; the others
/// remain padding rather than invented filesystem state.
///
/// On the target, the synchronization owner pointer is at +0x04, its
/// state byte at +0x08, the directory-entry index at +0x18, the
/// open-status word at +0x1c, and the cached directory-entry length at
/// +0x20. The native-pointer host model intentionally lets the pointer
/// fields expand, while field access preserves the same behavior in tests.
#[repr(C)]
pub struct FtPlatformFile {
    _vtable: *const u8,
    synchronization_owner: *mut FtPlatformFileSynchronizationOwner,
    length_query_state: u8,
    _unknown_09: [u8; 0x0f],
    directory_entry_index: i32,
    open_status: i32,
    cached_entry_length: u32,
    _unknown_24: [u8; 0x30],
}

/// The only recovered part of the object reached through
/// [`FtPlatformFile::synchronization_owner`]: a counted mutex at +0x44.
#[repr(C)]
pub struct FtPlatformFileSynchronizationOwner {
    _unknown_00: [u8; 0x44],
    length_query_lock: CountedMutex,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(FtPlatformFile, synchronization_owner)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(FtPlatformFile, length_query_state)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(FtPlatformFile, directory_entry_index)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(FtPlatformFile, open_status)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(FtPlatformFile, cached_entry_length)];
#[cfg(target_pointer_width = "32")]
const _: [u8; FT_FILE_OBJECT_SIZE] = [0; core::mem::size_of::<FtPlatformFile>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x44] =
    [0; core::mem::offset_of!(FtPlatformFileSynchronizationOwner, length_query_lock)];

/// Allocation size of the firmware's file object (`mov r0, #0x54` @
/// 0x082d3cbc).
pub const FT_FILE_OBJECT_SIZE: usize = 0x54;

/// Offset of the file object's status word (`ldr r1, [r0, #0x1c]` @
/// 0x082d3cfc): zero means the open succeeded.
pub const FT_FILE_STATUS_OFFSET: usize = 0x1c;

/// The third constructor argument at this call site (`mov r2, #0x1` @
/// 0x082d3ce0). Other callers of the constructor pass 0 or 1; what the
/// constructor does with it (a byte store at sub-object +8 and `arg ^ 1`
/// into the base constructor) does not pin down a name.
pub const FT_FILE_OPEN_MODE: u32 = 1;

/// The fifth constructor argument at this call site (`mov r1, #0x10000`
/// @ 0x082d3cd8). Other call sites pass 0x400; the constructor feeds it
/// to a helper whose result it keeps at +0x2c. Some kind of size or
/// budget — carried by value, not named.
pub const FT_FILE_OPEN_FLAGS: u32 = 0x10000;

/// The file-object constructor @ 0x08278dc4. Only
/// [`ft_platform_file_open`]'s argument list is recovered: `this` is the
/// raw `operator new` block, `path` the NUL-terminated path, `volume`
/// the digit split off the front of the FreeType pathname, and `mode` /
/// `flags` / `two` / `zero` the literal immediates 1, 0x10000, 2 and 0
/// (the last three pushed on the stack, ADS-style). Returns `this`, or
/// null when the object could not be built.
pub type FtPlatformFileCtor = unsafe extern "C" fn(
    this: *mut u8,
    path: *const u8,
    mode: u32,
    volume: i32,
    flags: u32,
    two: u32,
    zero: u32,
) -> *mut u8;

/// Default constructor slot: fails the open by returning null, which the
/// ported opener already treats as "open failed" (the original's
/// `beq 0x082d3d20` with r5 = 0). The real constructor @ 0x08278dc4 is a
/// whole C++ file-class subsystem; until it is ported, succeeding here
/// would hand the size query a bogus object, so the stub fails closed.
unsafe extern "C" fn file_ctor_unported(
    this: *mut u8,
    _path: *const u8,
    _mode: u32,
    _volume: i32,
    _flags: u32,
    _two: u32,
    _zero: u32,
) -> *mut u8 {
    let _ = this;
    core::ptr::null_mut()
}

/// The active file-object constructor (see the module header). Swap the
/// slot before the first open; read volatilically at every call, as with
/// every dispatch table in the crate.
pub static mut FT_PLATFORM_FILE_CTOR: FtPlatformFileCtor = file_ctor_unported;

/// ft_platform_file_open — original: `FUN_082d3cb4` @ 0x082d3cb4
/// (112 bytes; 1 `bl` call site, [`ft_platform_stream_open`] @
/// 0x082d3ddc).
///
/// Opens `path` on `volume` as one of the firmware's C++ file objects.
/// Allocates the 84-byte object with `operator new`, runs the
/// file-object constructor over it with the argument set
/// `(path, 1, volume, 0x10000, 2, 0)`, and stores the result in
/// `*handle` *unconditionally* — even when the constructor returned
/// null, in which case the function returns 0. On a non-null object the
/// status word at +0x1c decides: zero means the open succeeded (return
/// 1), non-zero means the constructor built the object but could not
/// open the file, so the object is destroyed through slot 1 of its
/// vtable (the virtual destructor) and `*handle` is nulled before
/// returning 0.
///
/// # Deviations
///
/// The constructor is not ported (see the module header); it is called
/// through the [`FT_PLATFORM_FILE_CTOR`] dispatch slot. Everything else
/// — the allocation size, the literal immediates, the status-word test,
/// the destroy-and-null failure path — is reproduced exactly.
///
/// # Safety
/// `path` must be a NUL-terminated string the constructor can read, and
/// `handle` must be a valid out-pointer. The installed constructor must
/// honor the original's contract: null or a pointer to a file object
/// with a status word at +0x1c and a destructor in vtable slot 1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_platform_file_open(
    volume: i32,
    path: *const u8,
    handle: *mut *mut core::ffi::c_void,
) -> i32 {
    let ctor = core::ptr::addr_of!(FT_PLATFORM_FILE_CTOR).read_volatile();
    let file = ctor(
        operator_new(FT_FILE_OBJECT_SIZE),
        path,
        FT_FILE_OPEN_MODE,
        volume,
        FT_FILE_OPEN_FLAGS,
        2,
        0,
    );
    *handle = file.cast();
    if file.is_null() {
        return 0;
    }
    if file.add(FT_FILE_STATUS_OFFSET).cast::<u32>().read() == 0 {
        return 1;
    }
    let vtable = file.cast::<*const u8>().read();
    let destroy: unsafe extern "C" fn(this: *mut u8) =
        core::mem::transmute(vtable.cast::<*const u8>().add(1).read());
    destroy(file);
    *handle = core::ptr::null_mut();
    0
}

/// ft_platform_file_length — original: `FUN_082a5418` @ 0x082a5418
/// (116 bytes; 20 `bl` call sites, including
/// [`ft_platform_stream_open`] @ 0x082d3ddc).
///
/// Acquires the counted mutex at `handle->synchronization_owner + 0x44`,
/// then reads the platform file object's cached directory-entry metadata.
/// A nonzero state byte returns 2. If the directory-entry index is -1,
/// the output pointer is untouched and the file's open-status word is
/// returned. Otherwise the cached entry length is stored through `size`
/// before releasing the lock and returning 0. Every path releases the
/// same lock; the counted unlock decrements its hold counter before it
/// signals the ROM semaphore.
///
/// The target ABI is exactly `(void *handle, u32 *size) -> i32`: despite
/// Ghidra preserving two phantom parameters, the raw ARM body only reads
/// r0/r1. It performs no null checks on either pointer.
///
/// # Host model
///
/// Native host pointers expand the two pointer-bearing layouts, so tests
/// access their semantic fields rather than pretending that a 64-bit
/// address fits in the target's 32-bit words. The target-only layout
/// assertions above pin every observed ARM offset.
///
/// # Safety
///
/// `handle` must point to an initialized [`FtPlatformFile`] whose
/// synchronization owner is non-null and has an initialized counted
/// mutex. `size` must be a valid writable `u32` on the success path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_platform_file_length(
    handle: *mut core::ffi::c_void,
    size: *mut u32,
) -> i32 {
    let file = handle.cast::<FtPlatformFile>();
    let lock = core::ptr::addr_of_mut!((*(*file).synchronization_owner).length_query_lock);
    mutex_lock_counted(lock);

    let result = if (*file).length_query_state != 0 {
        2
    } else if (*file).directory_entry_index == -1 {
        (*file).open_status
    } else {
        size.write((*file).cached_entry_length);
        0
    };

    mutex_unlock_counted(lock);
    result
}

/// ft_platform_stream_close (the firmware's `FT_Stream_CloseFunc`) —
/// original: `FUN_082d3d40` @ 0x082d3d40 (60 bytes; no direct `bl` call
/// site — planted in `stream->close` by [`ft_platform_stream_open`] @
/// 0x082d3ddc, which loads it from the literal at 0x082d3e58, and
/// reached from there by
/// [`ft_stream_close`](crate::ft::stream::ft_stream_close)).
///
/// A null `stream` is a no-op (`movs r4, r0` / `ldmeqia ...pc`). When
/// the stream's `descriptor` is non-null it is destroyed through slot 1
/// of its vtable — the same virtual-destructor call
/// [`ft_platform_file_open`] makes on its failure path, read out of the
/// object itself, so this port needs no dispatch slot. Either way the
/// record is then scrubbed: `descriptor` (+0xc), `pathname` (+0x10),
/// `size` (+4) and `base` (+0) are all zeroed, in that store order.
///
/// Note what is *not* scrubbed: `pos`, `read` and `close` itself are
/// left in place, so a second `ft_stream_close` on the same record
/// would run this function again (harmlessly — the nulled `descriptor`
/// skips the destroy).
///
/// # Safety
/// `stream` must be null or a valid `FtStream` whose `descriptor` is
/// null or a file object with a destructor in vtable slot 1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_platform_stream_close(stream: *mut FtStream) {
    if stream.is_null() {
        return;
    }
    let descriptor = (*stream).descriptor.cast::<u8>();
    if !descriptor.is_null() {
        let vtable = descriptor.cast::<*const u8>().read();
        let destroy: unsafe extern "C" fn(this: *mut u8) =
            core::mem::transmute(vtable.cast::<*const u8>().add(1).read());
        destroy(descriptor);
    }
    (*stream).descriptor = core::ptr::null_mut();
    (*stream).pathname = core::ptr::null_mut();
    (*stream).size = 0;
    (*stream).base = core::ptr::null_mut();
}

#[cfg(test)]
extern crate std;

/// Serializes the tests that swap the global ops — including
/// `ft/stream.rs`'s, which drive `ft_stream_open` through them (see
/// PORTING.md's test-harness rule: one guard per `#[test]`, never
/// shadowed).
#[cfg(test)]
pub(crate) static TEST_OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::String, vec, vec::Vec};
    use crate::fs::file_read::{reset_retail_file_read_body, RETAIL_FILE_READ_BODY};

    static mut OPEN_VOLUME: i32 = -99;
    static mut OPEN_PATH: [u8; 64] = [0; 64];
    static mut OPEN_CALLS: usize = 0;
    static mut OPEN_SUCCEEDS: bool = true;
    /// The target-layout file and its separately reached lock owner.
    static mut FILE_OBJECT: FtPlatformFile = FtPlatformFile {
        _vtable: core::ptr::null(),
        synchronization_owner: core::ptr::null_mut(),
        length_query_state: 0,
        _unknown_09: [0; 0x0f],
        directory_entry_index: 0,
        open_status: 0,
        cached_entry_length: 0,
        _unknown_24: [0; 0x30],
    };
    static mut FILE_LOCK_OWNER: FtPlatformFileSynchronizationOwner =
        FtPlatformFileSynchronizationOwner {
            _unknown_00: [0; 0x44],
            length_query_lock: CountedMutex {
                mutex: crate::kernel::sync_mutex::Mutex {
                    sem_cell: core::ptr::null_mut(),
                    unused: 0,
                },
                hold_count: 0,
            },
        };

    unsafe extern "C" fn mock_open(
        volume: i32,
        path: *const u8,
        handle: *mut *mut core::ffi::c_void,
    ) -> i32 {
        *core::ptr::addr_of_mut!(OPEN_VOLUME) = volume;
        *core::ptr::addr_of_mut!(OPEN_CALLS) += 1;
        let dst = core::ptr::addr_of_mut!(OPEN_PATH).cast::<u8>();
        let mut i = 0;
        while i < 63 && *path.add(i) != 0 {
            *dst.add(i) = *path.add(i);
            i += 1;
        }
        *dst.add(i) = 0;
        if *core::ptr::addr_of!(OPEN_SUCCEEDS) {
            *handle = core::ptr::addr_of_mut!(FILE_OBJECT).cast();
            1
        } else {
            *handle = core::ptr::null_mut();
            0
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum IoCall {
        Seek {
            handle: usize,
            duplicate_offset: u32,
            offset_low: u32,
            offset_high: u32,
            origin: u32,
        },
        Read {
            handle: usize,
            count: u32,
            buffer: usize,
            control: u32,
        },
    }

    static mut IO_CALLS: Vec<IoCall> = Vec::new();
    static mut READ_STATUS: i32 = 0;
    static mut READ_TRANSFERRED: u32 = 0;

    unsafe extern "C" fn recording_seek(
        handle: *mut core::ffi::c_void,
        duplicate_offset: u32,
        offset_low: u32,
        offset_high: u32,
        origin: u32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(IO_CALLS)).push(IoCall::Seek {
            handle: handle as usize,
            duplicate_offset,
            offset_low,
            offset_high,
            origin,
        });
        6
    }

    unsafe extern "C" fn recording_read(
        handle: *mut core::ffi::c_void,
        count: u32,
        buffer: *mut u8,
        transferred: *mut u32,
        control: u32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(IO_CALLS)).push(IoCall::Read {
            handle: handle as usize,
            count,
            buffer: buffer as usize,
            control,
        });
        *transferred = *core::ptr::addr_of!(READ_TRANSFERRED);
        *core::ptr::addr_of!(READ_STATUS)
    }

    unsafe fn install_io(read_status: i32, read_transferred: u32) {
        *core::ptr::addr_of_mut!(IO_CALLS) = Vec::new();
        *core::ptr::addr_of_mut!(READ_STATUS) = read_status;
        *core::ptr::addr_of_mut!(READ_TRANSFERRED) = read_transferred;
        core::ptr::addr_of_mut!(FT_PLATFORM_FILE_SEEK).write_volatile(recording_seek);
        core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY).write_volatile(recording_read);
    }

    unsafe fn reset_io() {
        core::ptr::addr_of_mut!(FT_PLATFORM_FILE_SEEK).write_volatile(file_seek_unported);
        reset_retail_file_read_body();
    }

    unsafe fn io_calls() -> Vec<IoCall> {
        (*core::ptr::addr_of!(IO_CALLS)).clone()
    }


    unsafe fn install(succeeds: bool) {
        *core::ptr::addr_of_mut!(OPEN_CALLS) = 0;
        *core::ptr::addr_of_mut!(OPEN_VOLUME) = -99;
        *core::ptr::addr_of_mut!(OPEN_SUCCEEDS) = succeeds;
        (*core::ptr::addr_of_mut!(FILE_LOCK_OWNER)).length_query_lock.hold_count = 0;
        (*core::ptr::addr_of_mut!(FILE_OBJECT)).synchronization_owner =
            core::ptr::addr_of_mut!(FILE_LOCK_OWNER);
        (*core::ptr::addr_of_mut!(FILE_OBJECT)).length_query_state = 0;
        (*core::ptr::addr_of_mut!(FILE_OBJECT)).directory_entry_index = 0;
        (*core::ptr::addr_of_mut!(FILE_OBJECT)).open_status = 0;
        (*core::ptr::addr_of_mut!(FILE_OBJECT)).cached_entry_length = 4242;
        let ops = FtPlatformFileOps { open: mock_open };
        ft_set_platform_file_ops(Some(ops));
    }

    unsafe fn opened_path() -> String {
        let bytes = core::ptr::addr_of!(OPEN_PATH).cast::<u8>();
        let mut out = Vec::new();
        let mut i = 0;
        while *bytes.add(i) != 0 {
            out.push(*bytes.add(i));
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn blank_stream() -> FtStream {
        FtStream {
            base: 7 as *mut u8,
            size: 0xdead,
            pos: 0xbeef,
            descriptor: core::ptr::null_mut(),
            pathname: core::ptr::null_mut(),
            read: None,
            close: None,
            memory: core::ptr::null_mut(),
            cursor: core::ptr::null_mut(),
            limit: core::ptr::null_mut(),
        }
    }

    #[test]
    fn open_splits_the_volume_digit_from_the_path_and_fills_the_record() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        let path = b"3:/Fonts/Helvetica.ttf\0";
        unsafe {
            install(true);
            assert_eq!(ft_platform_stream_open(&mut stream, path.as_ptr()), 0);
            assert_eq!(*core::ptr::addr_of!(OPEN_VOLUME), 3);
            assert_eq!(opened_path(), "/Fonts/Helvetica.ttf");
            assert_eq!(stream.size, 4242);
            assert_eq!(stream.pos, 0);
            assert_eq!(stream.descriptor, core::ptr::addr_of_mut!(FILE_OBJECT).cast());
            // A pointer *into* the caller's string, two bytes in.
            assert_eq!(stream.pathname, path.as_ptr().add(2) as *mut core::ffi::c_void);
            assert_eq!(
                stream.read.map(|f| f as usize),
                Some(ft_platform_stream_read as usize)
            );
            assert_eq!(
                stream.close.map(|f| f as usize),
                Some(ft_platform_stream_close as usize)
            );
            // `base` is not part of the opener's job.
            assert_eq!(stream.base, 7 as *mut u8);
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn open_reads_the_volume_digit_as_a_signed_char() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        // `ldrb` then `- '0'` then sign-extend from 8 bits: the digits
        // give 0..9, and anything below '0' wraps to a negative volume
        // rather than a huge one.
        for (first, want) in [(b'0', 0i32), (b'9', 9), (b'/', -1), (0xffu8, 207 - 256)] {
            let mut stream = blank_stream();
            let path = [first, b':', b'x', 0];
            unsafe {
                install(true);
                assert_eq!(ft_platform_stream_open(&mut stream, path.as_ptr()), 0);
                assert_eq!(*core::ptr::addr_of!(OPEN_VOLUME), want, "first byte {first:#x}");
                ft_set_platform_file_ops(None);
            }
        }
    }

    #[test]
    fn a_null_stream_is_rejected_before_anything_is_opened() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        unsafe {
            install(true);
            assert_eq!(
                ft_platform_stream_open(core::ptr::null_mut(), b"0:/x\0".as_ptr()),
                FT_PLATFORM_NULL_STREAM
            );
            assert_eq!(*core::ptr::addr_of!(OPEN_CALLS), 0);
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn a_refused_open_leaves_the_record_untouched() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        unsafe {
            install(false);
            assert_eq!(
                ft_platform_stream_open(&mut stream, b"0:/missing\0".as_ptr()),
                FT_PLATFORM_OPEN_FAILED
            );
            assert_eq!(*core::ptr::addr_of!(OPEN_CALLS), 1);
            assert_eq!((stream.size, stream.pos), (0xdead, 0xbeef));
            assert!(stream.read.is_none() && stream.close.is_none());
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn with_no_file_layer_installed_every_open_fails() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        unsafe {
            assert!(ft_set_platform_file_ops(None).is_none());
            assert_eq!(
                ft_platform_stream_open(&mut stream, b"0:/x\0".as_ptr()),
                FT_PLATFORM_OPEN_FAILED
            );
            assert!(stream.read.is_none());
        }
    }

    // ---------------------------------------------------------------
    // ft_platform_stream_read.

    #[test]
    fn stream_read_seeks_with_the_duplicated_offset_then_returns_read_count() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        let handle = 0x1234_5000usize as *mut core::ffi::c_void;
        let mut buffer = [0u8; 8];
        stream.descriptor = handle;
        unsafe {
            install_io(0, 6);
            assert_eq!(
                ft_platform_stream_read(&mut stream, 0x1020_3040, buffer.as_mut_ptr(), 8),
                6
            );
            assert_eq!(
                io_calls(),
                vec![
                    IoCall::Seek {
                        handle: handle as usize,
                        duplicate_offset: 0x1020_3040,
                        offset_low: 0x1020_3040,
                        offset_high: 0,
                        origin: 0,
                    },
                    IoCall::Read {
                        handle: handle as usize,
                        count: 8,
                        buffer: buffer.as_mut_ptr() as usize,
                        control: 0,
                    },
                ]
            );
            reset_io();
        }
    }

    #[test]
    fn stream_read_discards_a_partial_count_when_file_read_reports_an_error() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        let handle = 0x1234_5000usize as *mut core::ffi::c_void;
        let mut buffer = [0u8; 4];
        stream.descriptor = handle;
        unsafe {
            install_io(-7, 3);
            assert_eq!(ft_platform_stream_read(&mut stream, 99, buffer.as_mut_ptr(), 4), 0);
            assert_eq!(
                io_calls(),
                vec![
                    IoCall::Seek {
                        handle: handle as usize,
                        duplicate_offset: 99,
                        offset_low: 99,
                        offset_high: 0,
                        origin: 0,
                    },
                    IoCall::Read {
                        handle: handle as usize,
                        count: 4,
                        buffer: buffer.as_mut_ptr() as usize,
                        control: 0,
                    },
                ]
            );
            reset_io();
        }
    }

    #[test]
    fn stream_read_uses_null_buffer_or_zero_count_as_a_seek_only_probe() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        let handle = 0x1234_5000usize as *mut core::ffi::c_void;
        let mut buffer = [0u8; 1];
        stream.descriptor = handle;
        unsafe {
            install_io(0, 1);
            assert_eq!(ft_platform_stream_read(&mut stream, 7, core::ptr::null_mut(), 1), 0);
            assert_eq!(ft_platform_stream_read(&mut stream, 8, buffer.as_mut_ptr(), 0), 0);
            assert_eq!(
                io_calls(),
                vec![
                    IoCall::Seek {
                        handle: handle as usize,
                        duplicate_offset: 7,
                        offset_low: 7,
                        offset_high: 0,
                        origin: 0,
                    },
                    IoCall::Seek {
                        handle: handle as usize,
                        duplicate_offset: 8,
                        offset_low: 8,
                        offset_high: 0,
                        origin: 0,
                    },
                ]
            );
            reset_io();
        }
    }

    // ---------------------------------------------------------------
    // ft_platform_file_length.

    /// Sets up the semantic host model; the target assertions above pin
    /// the physical 32-bit layout this same field access compiles to.
    unsafe fn prepare_length_query(
        state: u8,
        directory_entry_index: i32,
        open_status: i32,
        cached_entry_length: u32,
    ) -> *mut core::ffi::c_void {
        let owner = core::ptr::addr_of_mut!(FILE_LOCK_OWNER);
        (*owner).length_query_lock.mutex.sem_cell = core::ptr::null_mut();
        (*owner).length_query_lock.hold_count = 0x51;
        let file = core::ptr::addr_of_mut!(FILE_OBJECT);
        (*file).synchronization_owner = owner;
        (*file).length_query_state = state;
        (*file).directory_entry_index = directory_entry_index;
        (*file).open_status = open_status;
        (*file).cached_entry_length = cached_entry_length;
        file.cast()
    }

    #[test]
    fn length_query_writes_the_cached_length_for_every_non_sentinel_entry() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        unsafe {
            for (entry, length) in [(0, 0), (7, 0x1234_5678), (-2, u32::MAX)] {
                let handle = prepare_length_query(0, entry, -99, length);
                let mut size = 0xdead_beef;
                assert_eq!(ft_platform_file_length(handle, &mut size), 0);
                assert_eq!(size, length, "entry {entry}");
                assert_eq!(
                    (*core::ptr::addr_of!(FILE_LOCK_OWNER)).length_query_lock.hold_count,
                    0x51,
                    "the acquire/release pair balances on success"
                );
            }
        }
    }

    #[test]
    fn length_query_preserves_the_output_on_state_and_missing_entry_errors() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        unsafe {
            let mut size = 0xdead_beef;
            let handle = prepare_length_query(1, 4, -99, 42);
            assert_eq!(ft_platform_file_length(handle, &mut size), 2);
            assert_eq!(size, 0xdead_beef, "state error does not write size");
            assert_eq!((*core::ptr::addr_of!(FILE_LOCK_OWNER)).length_query_lock.hold_count, 0x51);

            let handle = prepare_length_query(0, -1, -37, 42);
            assert_eq!(ft_platform_file_length(handle, &mut size), -37);
            assert_eq!(size, 0xdead_beef, "missing entry does not write size");
            assert_eq!((*core::ptr::addr_of!(FILE_LOCK_OWNER)).length_query_lock.hold_count, 0x51);
        }
    }

    // ---------------------------------------------------------------
    // ft_platform_file_open.

    /// Serializes the tests that swap HEAP_OPS and the ctor slot.
    static FILE_OPEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The block the stub allocator hands out (the file object is 84
    /// bytes; the arena is padded so the +0x1c status word is in range).
    static mut FILE_ARENA: [u8; 128] = [0; 128];

    /// What the recording constructor returns.
    static mut CTOR_RESULT: *mut u8 = core::ptr::null_mut();
    static mut CTOR_CALLS: usize = 0;
    static mut CTOR_THIS: *mut u8 = core::ptr::null_mut();
    static mut CTOR_PATH: *const u8 = core::ptr::null();
    static mut CTOR_ARGS: [u32; 5] = [0; 5];
    static mut CTOR_VOLUME: i32 = -1;
    static mut ALLOC_SIZE: usize = 0;
    static mut DESTROY_CALLS: usize = 0;
    static mut DESTROY_THIS: *mut u8 = core::ptr::null_mut();

    /// The fake vtable: slot 0 unused, slot 1 the recording destructor.
    static mut VTABLE: [usize; 2] = [0; 2];

    unsafe extern "C" fn stub_alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        *core::ptr::addr_of_mut!(ALLOC_SIZE) = size;
        core::ptr::addr_of_mut!(FILE_ARENA).cast()
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut crate::heap::types::HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut crate::heap::types::HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    unsafe extern "C" fn recording_ctor(
        this: *mut u8,
        path: *const u8,
        mode: u32,
        volume: i32,
        flags: u32,
        two: u32,
        zero: u32,
    ) -> *mut u8 {
        *core::ptr::addr_of_mut!(CTOR_CALLS) += 1;
        *core::ptr::addr_of_mut!(CTOR_THIS) = this;
        *core::ptr::addr_of_mut!(CTOR_PATH) = path;
        *core::ptr::addr_of_mut!(CTOR_VOLUME) = volume;
        *core::ptr::addr_of_mut!(CTOR_ARGS) = [mode, flags, two, zero, 0];
        *core::ptr::addr_of!(CTOR_RESULT)
    }

    unsafe extern "C" fn recording_destroy(this: *mut u8) {
        *core::ptr::addr_of_mut!(DESTROY_CALLS) += 1;
        *core::ptr::addr_of_mut!(DESTROY_THIS) = this;
    }

    /// Installs the stub allocator plus the recording constructor.
    fn mock_file_layer(ctor_result: *mut u8) -> std::sync::MutexGuard<'static, ()> {
        let guard = FILE_OPEN_LOCK.lock().unwrap();
        unsafe {
            let mut ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(ops);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                .write_volatile(0x1111_0000 as *mut crate::heap::types::HeapDescriptorDescriptor);
            core::ptr::addr_of_mut!(FT_PLATFORM_FILE_CTOR).write_volatile(recording_ctor);
            *core::ptr::addr_of_mut!(CTOR_RESULT) = ctor_result;
            *core::ptr::addr_of_mut!(CTOR_CALLS) = 0;
            *core::ptr::addr_of_mut!(ALLOC_SIZE) = 0;
            *core::ptr::addr_of_mut!(DESTROY_CALLS) = 0;
            *core::ptr::addr_of_mut!(DESTROY_THIS) = core::ptr::null_mut();
            *core::ptr::addr_of_mut!(VTABLE) = [0, recording_destroy as usize];
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the singletons.rs rule).
    fn restore_file_layer(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe {
            core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS)
                .write_volatile(crate::heap::veneers::DEFAULT_HEAP_OPS);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                .write_volatile(core::ptr::null_mut());
            core::ptr::addr_of_mut!(FT_PLATFORM_FILE_CTOR).write_volatile(file_ctor_unported);
        }
        drop(guard);
    }

    fn arena() -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(FILE_ARENA).cast() }
    }

    #[test]
    fn a_successful_open_allocates_constructs_and_returns_one() {
        let guard = mock_file_layer(arena());
        unsafe {
            // The constructor reports success: status word zero.
            arena().add(FT_FILE_STATUS_OFFSET).cast::<u32>().write(0);
            let path = b"/Fonts/Helvetica.ttf\0";
            let mut handle = 0x1234 as *mut core::ffi::c_void;
            assert_eq!(ft_platform_file_open(3, path.as_ptr(), &mut handle), 1);
            assert_eq!(*core::ptr::addr_of!(ALLOC_SIZE), 0x54);
            assert_eq!(*core::ptr::addr_of!(CTOR_CALLS), 1);
            assert_eq!(*core::ptr::addr_of!(CTOR_THIS), arena());
            assert_eq!(*core::ptr::addr_of!(CTOR_PATH), path.as_ptr());
            assert_eq!(*core::ptr::addr_of!(CTOR_VOLUME), 3);
            assert_eq!(
                *core::ptr::addr_of!(CTOR_ARGS),
                [1, 0x10000, 2, 0, 0],
                "the original's literal immediates, in order"
            );
            assert_eq!(handle, arena().cast());
            assert_eq!(*core::ptr::addr_of!(DESTROY_CALLS), 0);
        }
        restore_file_layer(guard);
    }

    #[test]
    fn a_null_constructing_open_stores_null_and_returns_zero() {
        let guard = mock_file_layer(core::ptr::null_mut());
        unsafe {
            // The out-parameter is written unconditionally — even the
            // constructor's null goes through it before the test.
            let mut handle = 0x1234 as *mut core::ffi::c_void;
            assert_eq!(ft_platform_file_open(0, b"/x\0".as_ptr(), &mut handle), 0);
            assert!(handle.is_null());
            assert_eq!(*core::ptr::addr_of!(CTOR_CALLS), 1);
            assert_eq!(*core::ptr::addr_of!(DESTROY_CALLS), 0);
        }
        restore_file_layer(guard);
    }

    #[test]
    fn a_failing_open_destroys_through_vtable_slot_one_and_nulls_the_handle() {
        let guard = mock_file_layer(arena());
        unsafe {
            // A built object whose open failed: vtable at +0, status at
            // +0x1c non-zero.
            arena().cast::<usize>().write(core::ptr::addr_of!(VTABLE) as usize);
            arena().add(FT_FILE_STATUS_OFFSET).cast::<u32>().write(5);
            let mut handle = core::ptr::null_mut();
            assert_eq!(ft_platform_file_open(1, b"/missing\0".as_ptr(), &mut handle), 0);
            assert_eq!(*core::ptr::addr_of!(DESTROY_CALLS), 1);
            assert_eq!(*core::ptr::addr_of!(DESTROY_THIS), arena());
            assert!(handle.is_null(), "the failed object does not leak into the handle");
        }
        restore_file_layer(guard);
    }

    #[test]
    fn the_default_ctor_slot_fails_the_open_closed() {
        let guard = FILE_OPEN_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(FT_PLATFORM_FILE_CTOR).write_volatile(file_ctor_unported);
            let block = file_ctor_unported(
                arena(),
                b"/x\0".as_ptr(),
                1,
                0,
                0x10000,
                2,
                0,
            );
            assert!(block.is_null());
        }
        drop(guard);
    }

    // ---------------------------------------------------------------
    // ft_platform_stream_close.

    /// Serializes the close tests, which share the recording statics.
    static CLOSE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The fake file object and its fake vtable (slot 0 unused, slot 1
    /// the recording destructor).
    static mut CLOSE_OBJECT: [u8; 16] = [0; 16];
    static mut CLOSE_VTABLE: [usize; 2] = [0; 2];
    static mut CLOSE_DESTROY_CALLS: usize = 0;
    static mut CLOSE_DESTROY_THIS: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn close_recording_destroy(this: *mut u8) {
        *core::ptr::addr_of_mut!(CLOSE_DESTROY_CALLS) += 1;
        *core::ptr::addr_of_mut!(CLOSE_DESTROY_THIS) = this;
    }

    unsafe extern "C" fn sentinel_read(
        _stream: *mut FtStream,
        _offset: u32,
        _buffer: *mut u8,
        _count: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn sentinel_close(_stream: *mut FtStream) {}

    /// A stream with every scrubbed field set to a sentinel, a live
    /// descriptor, and `pos`/`read`/`close` set to their own sentinels.
    fn dirty_stream() -> FtStream {
        unsafe {
            core::ptr::addr_of_mut!(CLOSE_OBJECT)
                .cast::<usize>()
                .write(core::ptr::addr_of!(CLOSE_VTABLE) as usize);
            FtStream {
                base: 0xaaaa_0000 as *mut u8,
                size: 0xbbbb_0000,
                pos: 0xcccc_0000,
                descriptor: core::ptr::addr_of_mut!(CLOSE_OBJECT).cast(),
                pathname: 0xdddd_0000 as *mut core::ffi::c_void,
                read: Some(sentinel_read),
                close: Some(sentinel_close),
                memory: core::ptr::null_mut(),
                cursor: core::ptr::null_mut(),
                limit: core::ptr::null_mut(),
            }
        }
    }

    fn close_guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = CLOSE_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(CLOSE_VTABLE) = [0, close_recording_destroy as usize];
            *core::ptr::addr_of_mut!(CLOSE_DESTROY_CALLS) = 0;
            *core::ptr::addr_of_mut!(CLOSE_DESTROY_THIS) = core::ptr::null_mut();
        }
        guard
    }

    #[test]
    fn a_null_stream_is_a_no_op() {
        let _guard = close_guard();
        unsafe {
            ft_platform_stream_close(core::ptr::null_mut());
            assert_eq!(*core::ptr::addr_of!(CLOSE_DESTROY_CALLS), 0);
        }
    }

    #[test]
    fn a_live_descriptor_is_destroyed_through_vtable_slot_one_and_the_record_scrubbed() {
        let _guard = close_guard();
        let mut stream = dirty_stream();
        unsafe {
            ft_platform_stream_close(&mut stream);
            assert_eq!(*core::ptr::addr_of!(CLOSE_DESTROY_CALLS), 1);
            assert_eq!(
                *core::ptr::addr_of!(CLOSE_DESTROY_THIS),
                core::ptr::addr_of_mut!(CLOSE_OBJECT).cast::<u8>()
            );
            assert!(stream.descriptor.is_null());
            assert!(stream.pathname.is_null());
            assert_eq!(stream.size, 0);
            assert!(stream.base.is_null());
            // What the original does NOT scrub.
            assert_eq!(stream.pos, 0xcccc_0000);
            assert!(stream.read.is_some() && stream.close.is_some());
        }
    }

    #[test]
    fn a_null_descriptor_skips_the_destroy_but_still_scrubs() {
        let _guard = close_guard();
        let mut stream = dirty_stream();
        stream.descriptor = core::ptr::null_mut();
        unsafe {
            ft_platform_stream_close(&mut stream);
            assert_eq!(*core::ptr::addr_of!(CLOSE_DESTROY_CALLS), 0);
            assert!(stream.descriptor.is_null());
            assert!(stream.pathname.is_null());
            assert_eq!(stream.size, 0);
            assert!(stream.base.is_null());
            assert!(stream.close.is_some(), "close stays: a second close is a safe no-op");
        }
    }
}
