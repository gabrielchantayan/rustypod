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
//! the open closed. Still not ported:
//!
//! - 0x082a5418, the length query, which locks a mutex and walks the
//!   object's directory entry.
//! - 0x082d3d7c / 0x082d3d40, the read and close callbacks, which go
//!   through 0x082787b8 (seek) and 0x082784b8 (read) and the object's
//!   virtual destructor.
//!
//! So the opener takes *those* as an installable [`FtPlatformFileOps`],
//! the same shape `ft/trace.rs` uses for the unported logger: every
//! entry is one of the opener's own `bl` targets or stored literals,
//! nothing about the layer below is invented, and the opener's logic —
//! which is what was actually recovered — is reproduced exactly. With
//! no ops installed every open fails with [`FT_PLATFORM_OPEN_FAILED`],
//! which is what the hardware does when the volume is not mounted.

use crate::ft::stream::{FtStream, FtStreamCloseFunc, FtStreamIoFunc};
use crate::heap::veneers::operator_new;

/// The opener's `moveq r0, #9` @ 0x082d3de4 — a null `FT_Stream`. These
/// two codes are the firmware's own numbering, not FreeType's;
/// [`ft_stream_open`](crate::ft::stream::ft_stream_open) only ever tests
/// them against zero.
pub const FT_PLATFORM_NULL_STREAM: i32 = 9;

/// The opener's `moveq r5, #20` @ 0x082d3e18 — the file layer refused,
/// leaving a null handle.
pub const FT_PLATFORM_OPEN_FAILED: i32 = 20;

/// The firmware file API [`ft_platform_stream_open`] is built on. Each
/// field names one address in the original opener.
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
    /// 0x082a5418 — store the open file's length through `size`. Its
    /// return value is discarded by the opener.
    pub size: unsafe extern "C" fn(handle: *mut core::ffi::c_void, size: *mut u32) -> i32,
    /// 0x082d3d7c — the `FT_Stream_IoFunc` the opener plants in
    /// `stream->read`.
    pub read: FtStreamIoFunc,
    /// 0x082d3d40 — the `FT_Stream_CloseFunc` the opener plants in
    /// `stream->close`.
    pub close: FtStreamCloseFunc,
}

/// The installed file layer, or `None` for "no volume". ADDITION — the
/// original hard-codes the four addresses; see the module header.
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

    (ops.size)(handle, &mut (*stream).size);
    (*stream).pathname = path as *mut core::ffi::c_void;
    (*stream).descriptor = handle;
    (*stream).pos = 0;
    (*stream).read = Some(ops.read);
    (*stream).close = Some(ops.close);
    0
}

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
    use std::{string::String, vec::Vec};

    static mut OPEN_VOLUME: i32 = -99;
    static mut OPEN_PATH: [u8; 64] = [0; 64];
    static mut OPEN_CALLS: usize = 0;
    static mut OPEN_SUCCEEDS: bool = true;
    static mut SIZE_CALLS: usize = 0;
    /// The made-up file object the mock hands back.
    static mut FILE_OBJECT: u32 = 0;

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

    unsafe extern "C" fn mock_size(_handle: *mut core::ffi::c_void, size: *mut u32) -> i32 {
        *core::ptr::addr_of_mut!(SIZE_CALLS) += 1;
        *size = 4242;
        0
    }

    unsafe extern "C" fn mock_read(
        _stream: *mut FtStream,
        _offset: u32,
        _buffer: *mut u8,
        _count: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn mock_close(_stream: *mut FtStream) {}

    unsafe fn install(succeeds: bool) -> FtPlatformFileOps {
        *core::ptr::addr_of_mut!(OPEN_CALLS) = 0;
        *core::ptr::addr_of_mut!(SIZE_CALLS) = 0;
        *core::ptr::addr_of_mut!(OPEN_VOLUME) = -99;
        *core::ptr::addr_of_mut!(OPEN_SUCCEEDS) = succeeds;
        let ops = FtPlatformFileOps {
            open: mock_open,
            size: mock_size,
            read: mock_read,
            close: mock_close,
        };
        ft_set_platform_file_ops(Some(ops));
        ops
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
            let ops = install(true);
            assert_eq!(ft_platform_stream_open(&mut stream, path.as_ptr()), 0);
            assert_eq!(*core::ptr::addr_of!(OPEN_VOLUME), 3);
            assert_eq!(opened_path(), "/Fonts/Helvetica.ttf");
            assert_eq!(*core::ptr::addr_of!(SIZE_CALLS), 1);
            assert_eq!(stream.size, 4242);
            assert_eq!(stream.pos, 0);
            assert_eq!(stream.descriptor, core::ptr::addr_of_mut!(FILE_OBJECT).cast());
            // A pointer *into* the caller's string, two bytes in.
            assert_eq!(stream.pathname, path.as_ptr().add(2) as *mut core::ffi::c_void);
            assert_eq!(stream.read.map(|f| f as usize), Some(ops.read as usize));
            assert_eq!(stream.close.map(|f| f as usize), Some(ops.close as usize));
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
            assert_eq!(*core::ptr::addr_of!(SIZE_CALLS), 0);
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
}
