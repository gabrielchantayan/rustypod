//! cxx_new_handler_dispatch — original: `FUN_08266abc` @ 0x08266abc
//! (164 bytes; 10 call sites, among them `operator_new_checked` @
//! 0x08266c70 with code 3 and the C++ runtime's std::ios/exception
//! reporters with codes 4, 8, 9, 0xe, 0xf, 0x10, 0x11, 0x14).
//!
//! The ADS C++ runtime error/new-handler dispatch. It spills all four
//! argument registers at entry (the function is variadic: r0 = code,
//! r1..r3 = message arguments), then reads the registered handler from
//! the global word @ 0x08a0fc08 (via the literal pool word @
//! 0x08266b60). No handler registered -> return immediately. With a
//! handler:
//!
//! - code <= 3 (signed compare — the `operator new` failure family):
//!   `handler(code, NULL)`, no message is built;
//! - code > 3: an 8-byte error-message object {vtable, text} is
//!   constructed in place over the spilled-argument area (placement-new
//!   identity @ 0x082aaddc + ctor @ 0x082a7cf4 storing the DAT_082a7d0c
//!   vtable and a NULL text), the message builder @ 0x082a7c20 fills in
//!   the text, the text is read back through vtable[2], the handler is
//!   called as `handler(code, text)`, and the object is destroyed
//!   through vtable[0] (releasing the tag-3-allocated text).
//!
//! On stock retailOS the whole function is an immediate return at
//! runtime: nothing in osos ever registers a handler (binary-verified —
//! the only reference to 0x08a0fc08 in the entire image is this
//! function's own literal-pool word).
//!
//! Deviation: the message builder @ 0x082a7c20 is NOT ported — it pulls
//! in the RWSTDERR catalog lookup @ 0x08266d28 (getenv + std::string +
//! iostream machinery) and the growable vasprintf @ 0x08266ca0 over the
//! static string table @ DAT_082a7cf0, a subsystem of its own. It sits
//! behind the `format_message` ops slot (same pattern as
//! heap/veneers.rs) whose default stub yields NULL text — unobservable
//! on stock, where the dispatch never gets past the no-handler early
//! return. The vtable[0] text release via the tag-3 `operator delete`
//! is inferred from the builder's alloc/free pair (0x082aad74 /
//! 0x082aad14); the dtor body itself was not recoverable (the vtable
//! lives in runtime-initialized data).

/// Signature of the registered handler — original: the code pointer in
/// the global word @ 0x08a0fc08, called as `handler(code, message)`
/// with `message` NULL for codes <= 3 and a C string for codes > 3.
pub type CxxErrorHandler = unsafe extern "C" fn(code: usize, message: *const u8);

/// The registered C++ error/new handler — original global word @
/// 0x08a0fc08. Never registered in stock retailOS (see the module
/// header), so NULL here. `pub static mut` so a future registration
/// port (and host tests) can install one.
pub static mut CXX_ERROR_HANDLER: Option<CxxErrorHandler> = None;

/// Indirect dispatch for the unported message-building machinery (see
/// the module header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct CxxNewHandlerOps {
    /// Message builder @ 0x082a7c20: formats the error text for `code`
    /// over the variadic message arguments (original: the RWSTDERR
    /// catalog @ 0x08266d28, else the string table @ DAT_082a7cf0
    /// through the growable vasprintf @ 0x08266ca0). Returns a
    /// tag-3-allocated C string or NULL.
    pub format_message: unsafe extern "C" fn(code: usize, args: *const usize) -> *mut u8,
}

/// Default stub: the builder subsystem is not ported (module header) —
/// NULL text, which stock retailOS never observes (no handler is ever
/// registered, so the dispatch returns before reaching the builder).
unsafe extern "C" fn format_message_unported(_code: usize, _args: *const usize) -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired default (see the module header). Host tests swap in a mock
/// builder and restore this afterwards.
pub(crate) const DEFAULT_CXX_NEW_HANDLER_OPS: CxxNewHandlerOps = CxxNewHandlerOps {
    format_message: format_message_unported,
};

/// The active message builder. Default is the documented stub; replaced
/// by host tests. Written once at init on target; tests serialize
/// access.
pub static mut CXX_NEW_HANDLER_OPS: CxxNewHandlerOps = DEFAULT_CXX_NEW_HANDLER_OPS;

/// Reads the ops table (volatile, same rationale as veneers.rs's
/// `heap_ops`: the table is meant to be swapped, and LLVM would
/// otherwise constant-fold the loads to the default stub).
#[inline(always)]
fn new_handler_ops() -> CxxNewHandlerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CXX_NEW_HANDLER_OPS)) }
}

/// The 8-byte error-message scratch object the original builds in place
/// over its spilled-argument area (ctor @ 0x082a7cf4: vtable word from
/// DAT_082a7d0c + NULL text). Modeled as a real stack object; the
/// vtable word is inert here — the two virtual calls the original makes
/// through it (vtable[2] text getter, vtable[0] destructor) are the
/// direct accessors below.
#[repr(C)]
struct CxxErrorMessage {
    /// Original: DAT_082a7d0c (unrecoverable runtime data; inert).
    vtable: usize,
    /// Original: this+4, NULL at construction.
    text: *mut u8,
}

impl CxxErrorMessage {
    /// ctor @ 0x082a7cf4.
    fn new() -> Self {
        CxxErrorMessage {
            vtable: 0,
            text: core::ptr::null_mut(),
        }
    }

    /// build @ 0x082a7c20 (via the ops slot; module-header deviation).
    unsafe fn build(&mut self, code: usize, args: *const usize) {
        self.text = (new_handler_ops().format_message)(code, args);
    }

    /// vtable[2]: the text getter.
    fn text(&self) -> *const u8 {
        self.text
    }

    /// vtable[0]: the destructor — releases the tag-3-allocated text
    /// (inferred from the builder's alloc/free pair 0x082aad74 /
    /// 0x082aad14; the original dtor body was not recoverable).
    unsafe fn destroy(&mut self) {
        if !self.text.is_null() {
            crate::heap::veneers::operator_delete_tag3(self.text);
        }
    }
}

/// Reads the handler global (volatile, same rationale as veneers.rs's
/// `heap_ops`: nothing in this crate writes it on target, so LLVM would
/// otherwise constant-fold the load to None and erase the whole
/// dispatch — observed: the ARM build collapsed to a bare
/// prologue/epilogue).
#[inline(always)]
fn error_handler() -> Option<CxxErrorHandler> {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CXX_ERROR_HANDLER)) }
}

/// cxx_new_handler_dispatch — original: `FUN_08266abc` @ 0x08266abc
/// (164 bytes). See the module header for the algorithm and the
/// message-builder deviation.
///
/// `arg1..arg3` mirror the original's r1..r3, spilled at entry and
/// handed to the message builder as the variadic tail; they are dead
/// for every code <= 3, including the `operator_new_checked` code 3
/// (whose caller sets only r0). The original's code>3 reload of the
/// handler global after the build is folded into the single load here
/// (no builder in existence can register a handler).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_new_handler_dispatch(
    code: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) {
    let Some(handler) = error_handler() else {
        return;
    };
    // Original: `cmp r0,#0x3; bgt` — a SIGNED compare, so a code with
    // bit 31 set takes the no-message path too.
    if (code as i32) <= 3 {
        handler(code, core::ptr::null());
        return;
    }
    let args = [arg1, arg2, arg3];
    let mut message = CxxErrorMessage::new();
    message.build(code, args.as_ptr());
    let text = message.text();
    handler(code, text);
    message.destroy();
}

/// One-argument form for the `HeapVeneerOps.new_handler` slot
/// (heap/veneers.rs): the checked-allocation path passes only a code
/// (always 3), whose variadic tail the original never reads either —
/// `operator_new_checked` sets r0 and branches with r1..r3 live-out
/// from its own body, dead on arrival.
pub unsafe extern "C" fn cxx_new_handler_report(code: usize) {
    cxx_new_handler_dispatch(code, 0, 0, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the handler global / ops table.
    static LOCK: Mutex<()> = Mutex::new(());

    // Call log.
    static mut HANDLER_CALLS: usize = 0;
    static mut LAST_HANDLER_CODE: usize = 0;
    static mut LAST_HANDLER_MESSAGE: *const u8 = core::ptr::null();
    static mut FORMAT_CALLS: usize = 0;
    static mut LAST_FORMAT_CODE: usize = 0;
    static mut LAST_FORMAT_ARGS: [usize; 3] = [0; 3];

    /// The C string the mock builder "formats".
    static MOCK_TEXT: &[u8] = b"mock error text\0";

    unsafe extern "C" fn mock_handler(code: usize, message: *const u8) {
        HANDLER_CALLS += 1;
        LAST_HANDLER_CODE = code;
        LAST_HANDLER_MESSAGE = message;
    }

    unsafe extern "C" fn mock_format_message(code: usize, args: *const usize) -> *mut u8 {
        FORMAT_CALLS += 1;
        LAST_FORMAT_CODE = code;
        LAST_FORMAT_ARGS = [*args, *args.add(1), *args.add(2)];
        MOCK_TEXT.as_ptr() as *mut u8
    }

    /// Resets the log, installs the mock handler + mock builder, and
    /// puts veneers.rs's heap on its mock (the code>3 dtor frees the
    /// text through the real `operator_delete_tag3`). Both returned
    /// guards serialize against the other table-swapping test modules.
    fn mock_dispatch() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let guard = LOCK.lock().unwrap();
        let heap = crate::heap::veneers::tests::mock_heap();
        unsafe {
            HANDLER_CALLS = 0;
            LAST_HANDLER_CODE = 0;
            LAST_HANDLER_MESSAGE = core::ptr::null();
            FORMAT_CALLS = 0;
            LAST_FORMAT_CODE = 0;
            LAST_FORMAT_ARGS = [0; 3];
            core::ptr::addr_of_mut!(CXX_ERROR_HANDLER).write(Some(mock_handler));
            core::ptr::addr_of_mut!(CXX_NEW_HANDLER_OPS).write(CxxNewHandlerOps {
                format_message: mock_format_message,
            });
        }
        (guard, heap)
    }

    /// Restores the documented defaults and zeroes the call log.
    fn teardown() {
        unsafe {
            HANDLER_CALLS = 0;
            LAST_HANDLER_CODE = 0;
            LAST_HANDLER_MESSAGE = core::ptr::null();
            FORMAT_CALLS = 0;
            LAST_FORMAT_CODE = 0;
            LAST_FORMAT_ARGS = [0; 3];
            core::ptr::addr_of_mut!(CXX_ERROR_HANDLER).write(None);
            core::ptr::addr_of_mut!(CXX_NEW_HANDLER_OPS).write(DEFAULT_CXX_NEW_HANDLER_OPS);
        }
    }

    #[test]
    fn no_handler_registered_is_an_immediate_return() {
        let _guard = LOCK.lock().unwrap();
        teardown();
        unsafe {
            // Stock retailOS state: NULL handler. Nothing may run, for
            // any code — not even the message builder for code > 3.
            cxx_new_handler_dispatch(3, 0, 0, 0);
            cxx_new_handler_dispatch(0x11, 1, 2, 3);
            assert_eq!(HANDLER_CALLS, 0);
            assert_eq!(FORMAT_CALLS, 0);
        }
    }

    #[test]
    fn code_up_to_3_calls_the_handler_with_a_null_message() {
        let (_guard, _heap) = mock_dispatch();
        unsafe {
            for code in [0usize, 1, 2, 3] {
                cxx_new_handler_dispatch(code, 0xaa, 0xbb, 0xcc);
                assert_eq!(HANDLER_CALLS, (code + 1) as usize);
                assert_eq!(LAST_HANDLER_CODE, code);
                assert!(
                    LAST_HANDLER_MESSAGE.is_null(),
                    "codes <= 3 never build a message"
                );
            }
            assert_eq!(FORMAT_CALLS, 0, "the builder is a code>3 path");
            // The original's compare is signed: bit-31-set codes take
            // the no-message path too.
            cxx_new_handler_dispatch(0x8000_0004, 0, 0, 0);
            assert_eq!(LAST_HANDLER_CODE, 0x8000_0004);
            assert!(LAST_HANDLER_MESSAGE.is_null());
            assert_eq!(FORMAT_CALLS, 0);
        }
        teardown();
    }

    #[test]
    fn code_above_3_builds_reports_and_releases_the_message() {
        let (_guard, _heap) = mock_dispatch();
        unsafe {
            cxx_new_handler_dispatch(0x11, 0xaa, 0xbb, 0xcc);
            // Builder saw the code and the variadic tail (original: the
            // spilled r1..r3 words).
            assert_eq!(FORMAT_CALLS, 1);
            assert_eq!(LAST_FORMAT_CODE, 0x11);
            assert_eq!(LAST_FORMAT_ARGS, [0xaa, 0xbb, 0xcc]);
            // Handler got the built text (vtable[2] read-back).
            assert_eq!(HANDLER_CALLS, 1);
            assert_eq!(LAST_HANDLER_CODE, 0x11);
            assert_eq!(LAST_HANDLER_MESSAGE, MOCK_TEXT.as_ptr());
            // vtable[0] released the text through the tag-3 delete.
            let (frees, freed, tag) = crate::heap::veneers::tests::free_log();
            assert_eq!(frees, 1, "the message text is released after the report");
            assert_eq!(freed, MOCK_TEXT.as_ptr() as *mut u8);
            assert_eq!(tag, 3);
        }
        teardown();
    }

    #[test]
    fn code_above_3_with_null_text_reports_null_and_releases_nothing() {
        let (_guard, _heap) = mock_dispatch();
        unsafe {
            // Default-stub behavior: builder yields NULL text.
            core::ptr::addr_of_mut!(CXX_NEW_HANDLER_OPS).write(DEFAULT_CXX_NEW_HANDLER_OPS);
            cxx_new_handler_dispatch(8, 1, 2, 3);
            assert_eq!(HANDLER_CALLS, 1);
            assert_eq!(LAST_HANDLER_CODE, 8);
            assert!(LAST_HANDLER_MESSAGE.is_null());
            let (frees, _, _) = crate::heap::veneers::tests::free_log();
            assert_eq!(frees, 0, "NULL text: the dtor's guard skips the delete");
        }
        teardown();
    }

    #[test]
    fn report_shim_forwards_the_code_with_a_dead_tail() {
        let (_guard, _heap) = mock_dispatch();
        unsafe {
            cxx_new_handler_report(3);
            assert_eq!(HANDLER_CALLS, 1);
            assert_eq!(LAST_HANDLER_CODE, 3);
            assert!(LAST_HANDLER_MESSAGE.is_null());
            assert_eq!(FORMAT_CALLS, 0);
        }
        teardown();
    }

    #[test]
    fn default_ops_slot_is_the_unported_stub() {
        assert_eq!(
            DEFAULT_CXX_NEW_HANDLER_OPS.format_message as usize,
            format_message_unported as usize
        );
    }

    #[test]
    fn veneers_default_new_handler_slot_is_the_real_port() {
        assert_eq!(
            crate::heap::veneers::DEFAULT_HEAP_OPS.new_handler as usize,
            cxx_new_handler_report as usize
        );
    }
}
