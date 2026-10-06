//! Genius request initialization, original FUN_0816ea70 at 0x0816ea70.
//! True extent [0x0816ea70,0x0816eb38): 192 instruction bytes and eight
//! literal bytes. Two incoming plain BLs, zero predicated; body has eight
//! plain BLs and one BLEQ (heap_panic), independently decoded from osos.dec.
//! Reclaim memory, perform the retained 0x414-byte allocation, acquire two
//! sources and a metadata context, then fetch one key or a key array. On
//! success attach the element reference and set active; failures retain all
//! earlier writes and leave later fields untouched. Attachment errors are
//! ignored, as in retailOS. No allocation is freed here.
//! Deviations: fixed-address callees use typed BLX seams; host execution of
//! the exported entry is unavailable (panics), while tests exercise the same
//! body with isolated dependencies. Ghidra's missing third context argument
//! and missing fifth/sixth attachment arguments are restored from raw ARM.
//! Attachment's unused r3 argument is deliberately zeroed: raw code at
//! 0x0816ed0c never reads incoming r3 and overwrites it at 0x0816ed34.

trait Backend {
    unsafe fn prepare(&mut self);
    unsafe fn source(&mut self) -> u32;
    unsafe fn provider(&mut self) -> u32;
    unsafe fn context(&mut self, provider: u32, source: u32) -> u32;
    unsafe fn single(&mut self, context: u32, low: u32, high: u32) -> u32;
    unsafe fn multiple(&mut self, context: u32, keys: u32, count: u32) -> u32;
    unsafe fn invalid_keys(&mut self) -> !;
    unsafe fn attach(&mut self, request: *mut u32, low: u32, high: u32);
}

unsafe fn initialize(request: *mut u32, backend: &mut impl Backend) -> u32 {
    backend.prepare();
    let source = backend.source();
    request.add(12).write(source);
    let mut active = 0;
    if source != 0 {
        let provider = backend.provider();
        request.add(11).write(provider);
        if provider != 0 {
            let context = backend.context(provider, request.add(12).read());
            request.add(10).write(context);
            if context != 0 {
                let metadata = if request.cast::<u8>().add(0x40).read() == 0 {
                    backend.single(context, request.read(), request.add(1).read())
                } else {
                    let keys = request.add(14).read();
                    let count = if keys != 0 { request.add(15).read() } else { 0 };
                    if keys == 0 || count == 0 { backend.invalid_keys(); }
                    backend.multiple(context, keys, count)
                };
                request.add(13).write(metadata);
                if metadata != 0 {
                    backend.attach(request, request.read(), request.add(1).read());
                    active = 1;
                }
            }
        }
    }
    request.cast::<u8>().add(0x10).write(active as u8);
    active
}

#[cfg(target_os = "none")]
struct Retail;

#[cfg(target_os = "none")]
impl Backend for Retail {
    unsafe fn prepare(&mut self) {
        let reclaim: unsafe extern "C" fn(u32) = core::mem::transmute(0x0813eb3cusize);
        reclaim(0x180000);
        let _ = crate::heap::veneers::operator_new(0x414);
    }
    unsafe fn source(&mut self) -> u32 {
        let acquire: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x08159bccusize);
        acquire()
    }
    unsafe fn provider(&mut self) -> u32 {
        let acquire: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x08159ca4usize);
        acquire()
    }
    unsafe fn context(&mut self, provider: u32, source: u32) -> u32 {
        let construct: unsafe extern "C" fn(u32, u32, u32) -> u32 = core::mem::transmute(0x082caca0usize);
        construct(provider, source, 0)
    }
    unsafe fn single(&mut self, context: u32, low: u32, high: u32) -> u32 {
        extern "C" {
            fn metadata_fetch_or_null(source: u32, context: u32, low: u32, high: u32) -> u32;
        }
        metadata_fetch_or_null(context, 0, low, high)
    }
    unsafe fn multiple(&mut self, context: u32, keys: u32, count: u32) -> u32 {
        let fetch: unsafe extern "C" fn(u32, u32, u32) -> u32 = core::mem::transmute(0x082ca98cusize);
        fetch(context, keys, count)
    }
    unsafe fn invalid_keys(&mut self) -> ! { crate::heap::veneers::heap_panic() }
    unsafe fn attach(&mut self, request: *mut u32, low: u32, high: u32) {
        let owner = (0x089ca674 as *const u32).read() as *const u32;
        let context = owner.add(12).read();
        let attach: unsafe extern "C" fn(*mut u32, u32, *mut u32, u32, u32, u32) -> u32 =
            core::mem::transmute(0x0816ed0cusize);
        let _ = attach(request, context, request.add(5), 0, low, high);
    }
}

/// Initialize the Genius request and return its new active byte as a word.
/// # Safety
/// `request` must be word-aligned, writable through +0x40, and its embedded
/// objects and firmware globals must satisfy the retail callees' contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn genius_request_initialize(request: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    { initialize(request, &mut Retail) }
    #[cfg(not(target_os = "none"))]
    { let _ = request; panic!("Genius initialization requires retail firmware dependencies") }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    struct Fixture { results: [u32; 4], stage: usize, multiple: bool, attached: bool }
    impl Fixture {
        fn next(&mut self) -> u32 { let value = self.results[self.stage]; self.stage += 1; value }
    }
    impl Backend for Fixture {
        unsafe fn prepare(&mut self) {}
        unsafe fn source(&mut self) -> u32 { self.next() }
        unsafe fn provider(&mut self) -> u32 { self.next() }
        unsafe fn context(&mut self, provider: u32, source: u32) -> u32 {
            assert_eq!((provider, source), (22, 11)); self.next()
        }
        unsafe fn single(&mut self, context: u32, low: u32, high: u32) -> u32 {
            assert_eq!((context, low, high), (33, 0x89abcdef, 0xfedcba98)); self.next()
        }
        unsafe fn multiple(&mut self, context: u32, keys: u32, count: u32) -> u32 {
            assert_eq!((context, keys, count), (33, 0x12345678, 7));
            self.multiple = true; self.next()
        }
        unsafe fn invalid_keys(&mut self) -> ! { panic!("invalid keys") }
        unsafe fn attach(&mut self, request: *mut u32, low: u32, high: u32) {
            assert_eq!((low, high), (0x89abcdef, 0xfedcba98));
            assert_eq!(request.add(13).read(), 44);
            self.attached = true;
        }
    }
    fn request() -> [u32; 17] {
        let mut words = [0xa5a5a5a5; 17];
        words[0] = 0x89abcdef; words[1] = 0xfedcba98;
        words[14] = 0x12345678; words[15] = 7; words[16] = 0;
        words
    }
    #[test]
    fn each_failure_retains_unreached_fields_and_clears_only_active_byte() {
        for failure in 0..4 {
            let mut words = request();
            let mut backend = Fixture { results: [11, 22, 33, 44], stage: 0, multiple: false, attached: false };
            backend.results[failure] = 0;
            assert_eq!(unsafe { initialize(words.as_mut_ptr(), &mut backend) }, 0);
            assert_eq!(backend.stage, failure + 1);
            assert!(!backend.attached);
            assert_eq!(words[4], 0xa5a5a500);
            for (stage, field) in [12, 11, 10, 13].into_iter().enumerate() {
                assert_eq!(words[field], if stage <= failure { backend.results[stage] } else { 0xa5a5a5a5 });
            }
            assert_eq!(words[5], 0xa5a5a5a5);
        }
    }
    #[test]
    fn both_fetch_modes_activate_and_preserve_adjacent_bytes() {
        for mode in [0, 0xff] {
            let mut words = request(); words[16] = mode;
            let mut backend = Fixture { results: [11, 22, 33, 44], stage: 0, multiple: false, attached: false };
            assert_eq!(unsafe { initialize(words.as_mut_ptr(), &mut backend) }, 1);
            assert!(backend.attached); assert_eq!(backend.multiple, mode != 0);
            assert_eq!(words[4], 0xa5a5a501);
        }
    }
    #[test]
    fn array_mode_rejects_either_missing_pointer_or_zero_count_before_fetch() {
        for (keys, count) in [(0, 7), (0x12345678, 0), (0, 0)] {
            let mut words = request(); words[16] = 1; words[14] = keys; words[15] = count;
            let mut backend = Fixture { results: [11, 22, 33, 44], stage: 0, multiple: false, attached: false };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                initialize(words.as_mut_ptr(), &mut backend)
            }));
            assert!(result.is_err()); assert_eq!(backend.stage, 3);
            assert!(!backend.multiple); assert!(!backend.attached);
            assert_eq!(words[13], 0xa5a5a5a5); assert_eq!(words[4], 0xa5a5a5a5);
        }
    }
}
