//! Finish a file buffer's conversion state.
//!
//! Original: FUN_083d8dbc at 0x083d8dbc, 204 bytes, extent
//! [0x083d8dbc, 0x083d8e88), followed by an independent PUSH.
//! Whole-image aligned raw A32 decoding finds zero incoming plain BLs and
//! one incoming BLNE (0x083d9290). Outbound: five plain BLs, zero predicated
//! BLs, and one indirect MOV PC,IP call through handler vtable slot +0x14.
//!
//! Look up the conversion handler and query its signed slot-0x18 result.
//! A nonnegative result or null saved state succeeds without conversion.
//! Otherwise call slot-0x14 with a local state copy and a 64-byte output
//! range. Result 2 fails; result 3 succeeds without writing. Other results
//! write the returned range through stream_write_all. Preserve the original's
//! inverted writer test: a nonzero writer result FAILS; zero succeeds and
//! adds the output byte count to position with wrapping arithmetic.
//!
//! No target behavioral deviations. Host pointer fields and vtable cells
//! widen through repr(C)/native pointer slots. The two virtual methods are
//! not assigned invented concrete identities. Existing lookup, null-check,
//! dispatch, and writer ports are reused; no new fixed-address seams.

use core::ptr::{addr_of, addr_of_mut};
use crate::app::type_handler_lookup::type_handler_lookup;
use crate::runtime::locale::ptr_or_deref_is_null;
use crate::stdio::fwrite::stream_write_all;
use super::vtable_slot_18_result_dispatch::vtable_slot_18_result_dispatch;

/// Target layout: registry +0x2c, stream +0x30, position +0x34, state +0x38.
/// The opaque prefix is deliberately untouched.
#[repr(C)]
pub struct ConversionFileBuffer {
    pub prefix: [u32; 11],
    pub registry: *mut u8,
    pub stream: u32,
    pub position: u32,
    pub state: *const u8,
}

type FinishConversion = unsafe extern "C" fn(
    *mut u8, *mut *const u8, *mut u8, *mut u8, *mut *mut u8,
) -> i32;

/// # Safety
/// `buffer` must be writable and have a valid typed registry. Its selected
/// handler must support slots six (signed query) and five (finish conversion).
/// Slot five must initialize every byte in its returned output range, within
/// the supplied 64-byte buffer, and set output_next even for results 2/3.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn filebuf_finish_conversion(buffer: *mut ConversionFileBuffer) -> u32 {
    let mut state = addr_of!((*buffer).state).read();
    let registry = addr_of_mut!((*buffer).registry);
    let handler = type_handler_lookup(registry);
    if vtable_slot_18_result_dispatch(handler) >= 0
        || ptr_or_deref_is_null(addr_of!(state)) != 0 {
        return 1;
    }
    let mut output = core::mem::MaybeUninit::<[u8; 64]>::uninit();
    let begin = output.as_mut_ptr().cast::<u8>();
    let mut next = core::ptr::null_mut();
    let handler = type_handler_lookup(registry);
    let vtable = handler.cast::<*const usize>().read();
    let finish: FinishConversion = core::mem::transmute(vtable.add(5).read());
    let result = finish(handler, addr_of_mut!(state), begin, begin.add(64), addr_of_mut!(next));
    let count = (next as usize).wrapping_sub(begin as usize) as i32;
    if result == 2 { return 0; }
    if result == 3 { return 1; }
    if stream_write_all(addr_of!((*buffer).stream), begin, 1, count) != 0 {
        return 0;
    }
    let position = addr_of_mut!((*buffer).position);
    position.write(position.read().wrapping_add(count as u32));
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::typed_handler_registry_lookup::{
        TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK, TYPED_HANDLER_REGISTRY_SLOW_LOOKUP,
    };
    use crate::stdio::linebuf_putc::{LINE_BUF, LINE_BUF_POS};

    #[repr(C)]
    struct Handler {
        vtable: *const usize,
        query: i32,
        result: i32,
        length: usize,
        calls: u32,
    }

    unsafe extern "C" fn lookup(registry: *mut *mut u8, _: *const u32, _: u32, _: u32, _: usize) -> *mut u8 {
        // Registry words 0/1 are otherwise opaque to the real fast lookup.
        registry.read().cast::<*mut u8>().read()
    }
    unsafe extern "C" fn query(handler: *mut u8) -> i32 {
        (*(handler.cast::<Handler>())).query
    }
    unsafe extern "C" fn finish(handler: *mut u8, state: *mut *const u8, begin: *mut u8, end: *mut u8, next: *mut *mut u8) -> i32 {
        let handler = &mut *handler.cast::<Handler>();
        assert_eq!(end.offset_from(begin), 64);
        assert_eq!(state.read() as usize, 0x1234);
        handler.calls += 1;
        state.write(core::ptr::null());
        for index in 0..handler.length { begin.add(index).write(b'x'); }
        next.write(begin.add(handler.length));
        handler.result
    }

    #[test]
    fn signed_preflight_conversion_results_and_inverted_write_outcome() {
        let _lookup_lock = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _writer_lock = crate::stdio::fwrite::tests::HOOK_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _line_lock = crate::stdio::semihost::tests::SWI_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved_lookup = TYPED_HANDLER_REGISTRY_SLOW_LOOKUP;
            let saved_putc = crate::stdio::fwrite::STREAM_WRITE_PUTC;
            let saved_line = addr_of!(LINE_BUF).read();
            let saved_pos = addr_of!(LINE_BUF_POS).read();
            TYPED_HANDLER_REGISTRY_SLOW_LOOKUP = lookup;
            crate::stdio::fwrite::STREAM_WRITE_PUTC = crate::stdio::linebuf_putc::linebuf_putc;
            let mut vtable = [0usize; 7];
            vtable[5] = finish as usize;
            vtable[6] = query as usize;
            let mut handler = Handler { vtable: vtable.as_ptr(), query: 0, result: 0, length: 0, calls: 0 };
            // Native-width opaque pointer in words 0/1; words 2/3 force slow lookup.
            #[repr(C)]
            struct Registry { handler: *mut u8, rest: [u32; 4] }
            let mut registry = Registry { handler: addr_of_mut!(handler).cast(), rest: [0; 4] };
            for (query_result, state, result, length, context) in [
                (0, 0x1234, 0, 4, 0), (i32::MAX, 0x1234, 0, 4, 0),
                (-1, 0, 0, 4, 0), (i32::MIN, 0x1234, 2, 64, 0),
                (-1, 0x1234, 3, 64, 1), (-1, 0x1234, 0, 0, 0),
                (-1, 0x1234, 0, 4, 0), (-1, 0x1234, 1, 4, 0),
                (-1, 0x1234, 0, 4, 1), (-1, 0x1234, 17, 4, 0),
            ] {
                handler.query = query_result;
                handler.result = result;
                handler.length = length;
                handler.calls = 0;
                LINE_BUF_POS = 0;
                addr_of_mut!(LINE_BUF).write([0; 81]);
                let mut buffer = ConversionFileBuffer {
                    prefix: [0x55aa55aa; 11], registry: addr_of_mut!(registry).cast(),
                    stream: context, position: u32::MAX - 1, state: state as *const u8,
                };
                let returned = filebuf_finish_conversion(addr_of_mut!(buffer));
                let converted = query_result < 0 && state != 0;
                let wrote = converted && result != 2 && result != 3;
                let accepted = wrote && (length == 0 || context != 0);
                assert_eq!(returned, u32::from(!(converted && result == 2 || accepted)));
                assert_eq!(buffer.position, if wrote && !accepted { (u32::MAX - 1).wrapping_add(length as u32) } else { u32::MAX - 1 });
                assert_eq!(handler.calls, u32::from(converted));
                assert_eq!(buffer.state as usize, state);
                assert_eq!(buffer.prefix, [0x55aa55aa; 11]);
                assert_eq!(LINE_BUF_POS, if accepted { length as i32 } else { 0 });
                if accepted { assert_eq!(&addr_of!(LINE_BUF).read()[..length], &[b'x'; 4][..length]); }
            }
            TYPED_HANDLER_REGISTRY_SLOW_LOOKUP = saved_lookup;
            crate::stdio::fwrite::STREAM_WRITE_PUTC = saved_putc;
            addr_of_mut!(LINE_BUF).write(saved_line);
            LINE_BUF_POS = saved_pos;
        }
    }
}
