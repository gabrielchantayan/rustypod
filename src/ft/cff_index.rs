//! FreeType CFF index lifetime management (`cffload.c`).
//!
//! A [`CffIndex`] holds an optional frame borrowed from its source
//! [`FtStream`] and a separately allocated offset table.  The CFF font
//! loader constructs five of these records and calls [`cff_index_done`] while
//! unwinding a face.

use crate::ft::stream::{ft_stream_extract_frame, ft_stream_release_frame, ft_stream_seek, FtStream};
use crate::ft::memory::ft_mem_free;
use crate::ft::memory::ft_mem_alloc;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::memzero::memzero_aligned;

/// `CFF_IndexRec` as used by this retailOS build.  The index reader at
/// `0x08083338` zeroes 24 bytes, then stores `stream`, `count`, `off_size`,
/// `data_offset`, `offsets`, and (for an extracted frame) `bytes` at these
/// offsets.
#[repr(C)]
pub struct CffIndex {
    pub stream: *mut FtStream,
    pub count: u32,
    pub off_size: u8,
    pub _padding: [u8; 3],
    pub data_offset: u32,
    pub offsets: *mut u32,
    pub bytes: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, count) == 4);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, off_size) == 8);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, data_offset) == 12);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, offsets) == 16);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, bytes) == 20);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<CffIndex>() == 24);

/// cff_index_done (FreeType `CFF_Index_Done`) — original: `FUN_08087bac` @
/// 0x08087bac (76 bytes, `0x08087bac..0x08087bf8`; the sibling function
/// opens with `push {r4-r9, sl, lr}` at `0x08087bf8`).  Seven direct BL call
/// sites verified by decoding every ARM B/BL word in `osos.dec`: all are
/// unconditional (`0x08082d28`, `0x08082d30`, `0x08082d3c`, `0x08082d44`,
/// `0x08082d50`, `0x0808318c`, and `0x0809a2b8`).
///
/// If `index->stream` is non-null, releases its optional extracted frame,
/// frees the offset table through `stream->memory`, then zeroes all six words
/// of the record.  A null `stream` returns without touching the record; this
/// is the raw ARM `ldreq`/`popeq` path, not a null guard for `index`.
///
/// Deliberate deviation: retail calls the two existing FreeType ports
/// directly, then tail-branches through the IRAM `memzero_aligned` veneer at
/// `0x08037db8`. This port loads all three callees through volatile
/// function-pointer reads: the first two prevent LLVM from inlining their
/// null guards and the third prevents lowering the fixed fill to an AEABI
/// builtin. The resulting indirect calls preserve the same observable order.
///
/// # Safety
/// `index` must point to a valid [`CffIndex`].  When `index->stream` is
/// non-null, its `memory`, `offsets`, and (when its `read` callback is set)
/// `bytes` must satisfy the corresponding FreeType release contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_index_done(index: *mut CffIndex) {
    let stream = (*index).stream;
    if stream.is_null() {
        return;
    }

    if !(*index).bytes.is_null() {
        let release = core::ptr::read_volatile(
            &(ft_stream_release_frame as unsafe extern "C" fn(*mut FtStream, *mut *mut u8)),
        );
        release(stream, &mut (*index).bytes);
    }
    let free = core::ptr::read_volatile(
        &(ft_mem_free as unsafe extern "C" fn(*mut crate::ft::memory::FtMemory, *mut u8)),
    );
    free((*stream).memory, (*index).offsets.cast());
    (*index).offsets = core::ptr::null_mut();

    let zero = core::ptr::read_volatile(
        &(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    zero(index.cast(), core::mem::size_of::<CffIndex>());
}
/// cff_index_forget_element (FreeType `cff_index_forget_element`, cffload.c)
/// — original: `FUN_080d3f60` @ 0x080d3f60 (20 bytes,
/// `0x080d3f60..0x080d3f74`; `push {r4-r7,lr}` at 0x080d3f74 begins the
/// next separately linked function). Five inbound direct `bl` calls are
/// verified from the raw ARM image; all are unconditional and none predicated.
///
/// An index backed by an extracted frame (`index->bytes != NULL`) retains the
/// supplied element pointer. Otherwise this tail-calls
/// [`ft_stream_release_frame`] with the index stream and pointer slot, which
/// returns a disk-stream allocation or simply forgets a memory-stream frame.
/// The release routine clears the slot in either case.
///
/// Deliberate deviation: the retail body tail-branches directly to
/// `ft_stream_release_frame` @ 0x0804fcb8. The volatile function-pointer load
/// retains the existing Rust seam instead of allowing LLVM to inline its
/// release logic.
///
/// # Safety
/// `index` and `pbytes` must be valid. When `index->bytes` is null,
/// `index->stream` and the pointer slot must satisfy
/// [`ft_stream_release_frame`]'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_index_forget_element(
    index: *mut CffIndex,
    pbytes: *mut *mut u8,
) {
    if !(*index).bytes.is_null() {
        return;
    }

    let release = core::ptr::read_volatile(
        &(ft_stream_release_frame as unsafe extern "C" fn(*mut FtStream, *mut *mut u8)),
    );
    release((*index).stream, pbytes);
}
/// cff_index_access_element (FreeType `cff_index_access_element`) — original:
/// `FUN_080d3e9c` @ 0x080d3e9c (196 bytes,
/// `0x080d3e9c..0x080d3f60`; `ldr r2,[r0,#0x14]` at 0x080d3f60 begins the
/// next separately linked function). Two outbound plain BL calls (to
/// `FT_Stream_Seek` and `FT_Stream_ExtractFrame`) and no predicated BL calls
/// are verified by decoding every ARM branch word in `osos.dec`; the three
/// `bls` encodings branch locally and do not write LR.
///
/// Locates an INDEX element's first following nonzero offset, skipping empty
/// elements. A pre-extracted index returns its byte address directly; otherwise
/// it seeks to the element and extracts a stream frame. A null index or an
/// out-of-range element returns `FT_Err_Invalid_Argument` (6) without writing
/// either output; an absent or malformed successor clears both outputs.
///
/// Deliberate deviation: retail uses direct BL instructions. Volatile loads
/// retain the existing Rust stream seams and prevent LLVM from folding either
/// callee into this required callable target.
///
/// # Safety
/// `index`, `pbytes`, and `pbyte_len` must be valid where the corresponding
/// ARM path dereferences them. `offsets` has at least `count + 1` words, and
/// the stream must satisfy the existing seek/extract contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_index_access_element(
    index: *mut CffIndex,
    element: u32,
    pbytes: *mut *mut u8,
    pbyte_len: *mut u32,
) -> i32 {
    if index.is_null() || (*index).count <= element {
        return 6;
    }

    let first_offset = (*index).offsets.add(element as usize).read();
    if first_offset != 0 {
        let mut next_element = element;
        loop {
            next_element = next_element.wrapping_add(1);
            let next_offset = (*index).offsets.add(next_element as usize).read();
            if next_offset != 0 {
                if first_offset < next_offset {
                    let byte_len = next_offset.wrapping_sub(first_offset);
                    pbyte_len.write(byte_len);
                    if !(*index).bytes.is_null() {
                        pbytes.write((*index).bytes.add(first_offset as usize - 1));
                        return 0;
                    }

                    let seek = core::ptr::read_volatile(
                        &(ft_stream_seek as unsafe extern "C" fn(*mut FtStream, u32) -> i32),
                    );
                    let error = seek(
                        (*index).stream,
                        (*index).data_offset.wrapping_add(first_offset).wrapping_sub(1),
                    );
                    if error != 0 {
                        return error;
                    }
                    let extract = core::ptr::read_volatile(
                        &(ft_stream_extract_frame
                            as unsafe extern "C" fn(*mut FtStream, u32, *mut *mut u8) -> i32),
                    );
                    return extract((*index).stream, byte_len, pbytes);
                }
                break;
            }
            if (*index).count <= next_element {
                break;
            }
        }
    }

    pbytes.write(core::ptr::null_mut());
    pbyte_len.write(0);
    0
}
/// cff_index_get_name (FreeType `cff_index_get_name`, cffload.c) — original:
/// `FUN_080a8294` @ 0x080a8294 (132 bytes,
/// `0x080a8294..0x080a8318`; `stmdb sp!,{r2-r8,lr}` at 0x080a8318 begins
/// the next function). Four outgoing plain `bl` instructions and no
/// predicated `bl` instructions are verified by decoding every ARM word in
/// `osos.dec`: `cff_index_access_element`, `ft_mem_alloc`, the
/// `__rt_memcpy` veneer, and `cff_index_forget_element`.
///
/// Accesses a custom CFF SID by index, allocates a length-plus-NUL owned copy
/// through the index stream's memory, then relinquishes the temporary frame.
/// Any access or allocation error returns null. A temporary frame is released
/// after an allocation failure as well, matching the ARM cleanup path.
///
/// Deliberate deviation: retail uses four direct `bl` instructions, including
/// the `0x08037db0` memcpy ROM veneer. Volatile function-pointer reads retain
/// the existing Rust seams and prevent LLVM from inlining allocation or
/// recognizing the copy as a builtin; the observable call order is unchanged.
///
/// # Safety
/// `index` must satisfy the [`cff_index_access_element`] contract, and its
/// stream's memory must satisfy [`ft_mem_alloc`]'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_index_get_name(index: *mut CffIndex, element: u32) -> *mut u8 {
    let mut bytes = core::ptr::null_mut();
    let mut byte_len = 0;
    let access = core::ptr::read_volatile(
        &(cff_index_access_element
            as unsafe extern "C" fn(*mut CffIndex, u32, *mut *mut u8, *mut u32) -> i32),
    );
    let mut error = access(index, element, &mut bytes, &mut byte_len);
    let mut name = core::ptr::null_mut();

    if error == 0 {
        let alloc = core::ptr::read_volatile(
            &(ft_mem_alloc as unsafe extern "C" fn(*mut crate::ft::memory::FtMemory, i32, *mut i32) -> *mut u8),
        );
        name = alloc((*(*index).stream).memory, byte_len.wrapping_add(1) as i32, &mut error);
        if error == 0 {
            let copy = core::ptr::read_volatile(
                &(__rt_memcpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
            );
            copy(name, bytes, byte_len as usize);
            name.add(byte_len as usize).write(0);
        }
        let forget = core::ptr::read_volatile(
            &(cff_index_forget_element as unsafe extern "C" fn(*mut CffIndex, *mut *mut u8)),
        );
        forget(index, &mut bytes);
    }

    name
}




#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::memory::{FtMemory, FtReallocFunc};
    use crate::ft::stream::{FtStreamCloseFunc, FtStreamIoFunc};
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FIRST_FREE: AtomicUsize = AtomicUsize::new(0);
    static SECOND_FREE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn unused_alloc(_memory: *mut FtMemory, _size: i32) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn record_free(_memory: *mut FtMemory, block: *mut u8) {
        match FREE_COUNT.fetch_add(1, Ordering::SeqCst) {
            0 => FIRST_FREE.store(block as usize, Ordering::SeqCst),
            1 => SECOND_FREE.store(block as usize, Ordering::SeqCst),
            _ => panic!("unexpected extra free"),
        }
    }

    unsafe extern "C" fn unused_realloc(
        _memory: *mut FtMemory,
        _cur_size: i32,
        _new_size: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    fn test_memory() -> FtMemory {
        FtMemory {
            user: ptr::null_mut::<c_void>(),
            alloc: unused_alloc,
            free: record_free,
            realloc: unused_realloc as FtReallocFunc,
        }
    }

    fn test_stream(memory: *mut FtMemory, read: Option<FtStreamIoFunc>) -> FtStream {
        FtStream {
            base: ptr::null_mut(),
            size: 0,
            pos: 0,
            descriptor: ptr::null_mut(),
            pathname: ptr::null_mut(),
            read,
            close: None::<FtStreamCloseFunc>,
            memory,
            cursor: ptr::null_mut(),
            limit: ptr::null_mut(),
        }
    }

    #[test]
    fn index_forget_element_releases_only_unextracted_frames() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);
        FIRST_FREE.store(0, Ordering::SeqCst);

        unsafe extern "C" fn read_stub(
            _stream: *mut FtStream,
            _offset: u32,
            _buffer: *mut u8,
            _count: u32,
        ) -> u32 {
            0
        }

        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, Some(read_stub));
        let mut index = CffIndex {
            stream: &mut stream,
            count: 0,
            off_size: 0,
            _padding: [0; 3],
            data_offset: 0,
            offsets: ptr::null_mut(),
            bytes: ptr::null_mut(),
        };
        let mut released = 0x1234usize as *mut u8;

        unsafe { cff_index_forget_element(&mut index, &mut released) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(FIRST_FREE.load(Ordering::SeqCst), 0x1234);
        assert!(released.is_null());

        let mut retained = 0x5678usize as *mut u8;
        index.bytes = 0x9abcusize as *mut u8;
        unsafe { cff_index_forget_element(&mut index, &mut retained) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(retained as usize, 0x5678);
    }

    #[test]
    fn index_done_releases_frame_before_offsets_and_clears_record() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);
        FIRST_FREE.store(0, Ordering::SeqCst);
        SECOND_FREE.store(0, Ordering::SeqCst);

        unsafe extern "C" fn read_stub(
            _stream: *mut FtStream,
            _offset: u32,
            _buffer: *mut u8,
            _count: u32,
        ) -> u32 {
            0
        }

        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, Some(read_stub));
        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: &mut stream,
            count: 7,
            off_size: 3,
            _padding: [0xa5; 3],
            data_offset: 0x4455_6677,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(FIRST_FREE.load(Ordering::SeqCst), bytes as usize);
        assert_eq!(SECOND_FREE.load(Ordering::SeqCst), offsets as usize);
        assert!(index.stream.is_null());
        assert_eq!(index.count, 0);
        assert_eq!(index.off_size, 0);
        assert_eq!(index._padding, [0; 3]);
        assert_eq!(index.data_offset, 0);
        assert!(index.offsets.is_null());
        assert!(index.bytes.is_null());
    }

    #[test]
    fn index_done_for_memory_stream_forgets_frame_without_freeing_it() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);
        FIRST_FREE.store(0, Ordering::SeqCst);

        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, None);
        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: &mut stream,
            count: 1,
            off_size: 1,
            _padding: [0; 3],
            data_offset: 2,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(FIRST_FREE.load(Ordering::SeqCst), offsets as usize);
        assert!(index.stream.is_null());
        assert!(index.offsets.is_null());
        assert!(index.bytes.is_null());
    }

    #[test]
    fn index_done_with_null_stream_leaves_record_untouched() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);

        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: ptr::null_mut(),
            count: 7,
            off_size: 3,
            _padding: [0xa5; 3],
            data_offset: 0x4455_6677,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(index.count, 7);
        assert_eq!(index.off_size, 3);
        assert_eq!(index._padding, [0xa5; 3]);
        assert_eq!(index.data_offset, 0x4455_6677);
        assert_eq!(index.offsets, offsets);
        assert_eq!(index.bytes, bytes);
    }
    #[test]
    fn index_access_skips_empty_elements_and_preserves_invalid_outputs() {
        let _guard = TEST_LOCK.lock();
        let mut data = [0xa0u8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
        let mut offsets = [1u32, 0, 5, 9];
        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, None);
        let mut index = CffIndex {
            stream: &mut stream,
            count: 3,
            off_size: 1,
            _padding: [0; 3],
            data_offset: 0,
            offsets: offsets.as_mut_ptr(),
            bytes: data.as_mut_ptr(),
        };
        let mut bytes = 0x1234usize as *mut u8;
        let mut byte_len = 0x5678_9abc;

        unsafe {
            assert_eq!(cff_index_access_element(ptr::null_mut(), 0, &mut bytes, &mut byte_len), 6);
            assert_eq!(cff_index_access_element(&mut index, 3, &mut bytes, &mut byte_len), 6);
        }
        assert_eq!(bytes as usize, 0x1234);
        assert_eq!(byte_len, 0x5678_9abc);

        assert_eq!(unsafe { cff_index_access_element(&mut index, 0, &mut bytes, &mut byte_len) }, 0);
        assert_eq!(bytes, unsafe { data.as_mut_ptr().add(0) });
        assert_eq!(byte_len, 4);

        offsets[0] = 0;
        assert_eq!(unsafe { cff_index_access_element(&mut index, 0, &mut bytes, &mut byte_len) }, 0);
        assert!(bytes.is_null());
        assert_eq!(byte_len, 0);
    }

    #[test]
    fn index_access_extracts_memory_frames_and_retains_length_on_seek_failure() {
        let _guard = TEST_LOCK.lock();
        let mut data = [0xa0u8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5];
        let mut offsets = [1u32, 3];
        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, None);
        stream.base = data.as_mut_ptr();
        stream.size = data.len() as u32;
        let mut index = CffIndex {
            stream: &mut stream,
            count: 1,
            off_size: 1,
            _padding: [0; 3],
            data_offset: 2,
            offsets: offsets.as_mut_ptr(),
            bytes: ptr::null_mut(),
        };
        let mut bytes = ptr::null_mut();
        let mut byte_len = 0;

        assert_eq!(unsafe { cff_index_access_element(&mut index, 0, &mut bytes, &mut byte_len) }, 0);
        assert_eq!(bytes, unsafe { data.as_mut_ptr().add(2) });
        assert_eq!(byte_len, 2);
        assert_eq!(stream.pos, 4);

        index.data_offset = 6;
        bytes = 0x9876usize as *mut u8;
        assert_eq!(unsafe { cff_index_access_element(&mut index, 0, &mut bytes, &mut byte_len) }, 0x55);
        assert_eq!(byte_len, 2);
        assert_eq!(bytes as usize, 0x9876);
    }
    #[test]
    fn index_name_copies_custom_sid_and_rejects_missing_element() {
        let _guard = TEST_LOCK.lock();
        unsafe extern "C" fn alloc_name(_memory: *mut FtMemory, size: i32) -> *mut u8 {
            std::boxed::Box::into_raw(std::vec![0u8; size as usize].into_boxed_slice()) as *mut u8
        }

        let mut data = *b"Name";
        let mut offsets = [1u32, 5];
        let mut memory = test_memory();
        memory.alloc = alloc_name;
        let mut stream = test_stream(&mut memory, None);
        let mut index = CffIndex {
            stream: &mut stream,
            count: 1,
            off_size: 1,
            _padding: [0; 3],
            data_offset: 0,
            offsets: offsets.as_mut_ptr(),
            bytes: data.as_mut_ptr(),
        };

        let name = unsafe { cff_index_get_name(&mut index, 0) };
        assert_eq!(unsafe { core::slice::from_raw_parts(name, 5) }, b"Name\0");
        assert!(unsafe { cff_index_get_name(&mut index, 1) }.is_null());
    }
}
