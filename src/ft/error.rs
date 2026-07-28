//! FreeType's `FT_Err_*` codes, as `fterrdef.h` numbers them and as the
//! ported functions store them. Only the codes that actually appear as
//! immediates in the ported machine code are listed — each one is cited
//! with the instruction that produces it.

/// `FT_Err_Ok` — every success path's `mov rN, #0`.
pub const FT_ERR_OK: i32 = 0x00;

/// `FT_Err_Cannot_Open_Resource` — `ft_stream_open`'s `movne r4, #1`
/// @ 0x0804f348, the only value it turns the platform opener's failure
/// into.
pub const FT_ERR_CANNOT_OPEN_RESOURCE: i32 = 0x01;

/// `FT_Err_Invalid_Argument` — `mov r0, #6` in `ft_stream_new`
/// @ 0x0804f26c/0x0804f2f0 and `mov r4, #6` in `ft_mem_qalloc`
/// @ 0x082cfb24 (a negative size).
pub const FT_ERR_INVALID_ARGUMENT: i32 = 0x06;

/// `FT_Err_Invalid_Library_Handle` — `moveq r0, #33` @ 0x0804f258.
pub const FT_ERR_INVALID_LIBRARY_HANDLE: i32 = 0x21;

/// `FT_Err_Out_Of_Memory` — `moveq r4, #64` in `ft_mem_qalloc`
/// @ 0x082cfb1c.
pub const FT_ERR_OUT_OF_MEMORY: i32 = 0x40;

/// `FT_Err_Invalid_Stream_Operation` — the `mov rN, #85` every failure
/// path in `ftstream.c` stores through `error`.
pub const FT_ERR_INVALID_STREAM_OPERATION: i32 = 0x55;
