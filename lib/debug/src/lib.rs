//! Debug utils for WebAssembly using Cranelift.
use cranelift_codegen::isa::TargetFrontendConfig;
use faerie::{Artifact, Decl};
use std::fmt;
use target_lexicon::{BinaryFormat, Triple};

pub use crate::read_debuginfo::{read_debuginfo, DebugInfoData};
pub use crate::transform::transform_dwarf;
pub use crate::write_debuginfo::{emit_dwarf, ResolvedSymbol, SymbolResolver};

use wasmtime_environ::AddressTransforms;

mod read_debuginfo;
mod transform;
mod write_debuginfo;

impl fmt::Display for transform::Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Transform error: ")?;
        match self {
            transform::Error::GimliError(e) => write!(f, "gimli error, {}", e),
            transform::Error::Custom(s) => write!(f, "{}", s),
        }
    }
}

struct FunctionRelocResolver {}
impl SymbolResolver for FunctionRelocResolver {
    fn resolve_symbol(&self, symbol: usize, addend: i64) -> ResolvedSymbol {
        let name = format!("_wasm_function_{}", symbol);
        ResolvedSymbol::Reloc { name, addend }
    }
}

pub fn emit_debugsections(
    obj: &mut Artifact,
    target_config: &TargetFrontendConfig,
    debuginfo_data: &DebugInfoData,
    at: &AddressTransforms,
) -> Result<(), String> {
    let dwarf =
        transform_dwarf(target_config, debuginfo_data, at).map_err(|err| format!("{}", err))?;
    let resolver = FunctionRelocResolver {};
    emit_dwarf(obj, &dwarf, &resolver);
    Ok(())
}

struct ImageRelocResolver<'a> {
    func_offsets: &'a Vec<u64>,
}

impl<'a> SymbolResolver for ImageRelocResolver<'a> {
    fn resolve_symbol(&self, symbol: usize, addend: i64) -> ResolvedSymbol {
        let func_start = self.func_offsets[symbol];
        ResolvedSymbol::PhysicalAddress(func_start + addend as u64)
    }
}

pub fn emit_debugsections_image(
    triple: Triple,
    target_config: &TargetFrontendConfig,
    debuginfo_data: &DebugInfoData,
    at: &AddressTransforms,
    funcs: &Vec<(*const u8, &[u8])>,
) -> Result<Vec<u8>, String> {
    let ref func_offsets = funcs
        .iter()
        .map(|(ptr, _)| *ptr as u64)
        .collect::<Vec<u64>>();
    let mut obj = Artifact::new(triple, String::from("module"));
    let dwarf =
        transform_dwarf(target_config, debuginfo_data, at).map_err(|err| format!("{}", err))?;
    let resolver = ImageRelocResolver { func_offsets };
    for (i, (_, body)) in funcs.iter().enumerate() {
        let name = format!("___wasm_function_{}", i);
        obj.declare_with(&name, Decl::Function { global: false }, body.to_vec())
            .map_err(|_| String::from("Unable to defaine a function"))?;
    }
    emit_dwarf(&mut obj, &dwarf, &resolver);

    // LLDB is too "magical" about mach-o, generating elf
    let mut bytes = obj
        .emit_as(BinaryFormat::Elf)
        .map_err(|_| String::from("Unable to emit"))?;
    // elf is still missing details...
    patch_faerie_elf(&mut bytes, funcs);

    Ok(bytes)
}

fn patch_faerie_elf(bytes: &mut Vec<u8>, funcs: &Vec<(*const u8, &[u8])>) {
    use std::ffi::CStr;
    use std::os::raw::c_char;

    assert!(
        bytes[0x4] == 2 && bytes[0x5] == 1,
        "bits and endianess in .ELF"
    );
    let e_phoff = unsafe { *(bytes.as_ptr().offset(0x20) as *const u64) };
    let e_phnum = unsafe { *(bytes.as_ptr().offset(0x38) as *const u16) };
    assert!(
        e_phoff == 0 && e_phnum == 0,
        "program header table is empty"
    );
    let e_phentsize = unsafe { *(bytes.as_ptr().offset(0x36) as *const u16) };
    assert!(e_phentsize == 0x38, "size of ph");
    let e_shentsize = unsafe { *(bytes.as_ptr().offset(0x3A) as *const u16) };
    assert!(e_shentsize == 0x40, "size of sh");

    let e_shoff = unsafe { *(bytes.as_ptr().offset(0x28) as *const u64) };
    let e_shnum = unsafe { *(bytes.as_ptr().offset(0x3C) as *const u16) };
    let mut shstrtab_off = 0;
    let mut segments = Vec::new();
    for i in 0..e_shnum {
        let off = e_shoff as isize + i as isize * e_shentsize as isize;
        let sh_type = unsafe { *(bytes.as_ptr().offset(off + 0x4) as *const u32) };
        if sh_type == /* SHT_SYMTAB */ 3 {
            shstrtab_off = unsafe { *(bytes.as_ptr().offset(off + 0x18) as *const u64) };
        }
        if sh_type != /* SHT_PROGBITS */ 1 {
            continue;
        }
        // It is a SHT_PROGBITS, but we need to check sh_name to ensure it is our function
        let sh_name = unsafe {
            let sh_name_off = *(bytes.as_ptr().offset(off) as *const u32);
            CStr::from_ptr(
                bytes
                    .as_ptr()
                    .offset((shstrtab_off + sh_name_off as u64) as isize)
                    as *const c_char,
            )
            .to_str()
            .expect("name")
        };
        if !sh_name.starts_with(".text.___wasm_function_") {
            continue;
        }

        // Function was added at emit_debugsections_image; patch vaddr, and
        // save file location and its size.
        let fn_index = sh_name[".text.___wasm_function_".len()..]
            .parse::<usize>()
            .expect("fn index");
        let (ptr, _) = funcs[fn_index];

        unsafe {
            *(bytes.as_ptr().offset(off + 0x10) as *mut u64) = ptr as u64;
        };
        let sh_offset = unsafe { *(bytes.as_ptr().offset(off + 0x18) as *const u64) };
        let sh_size = unsafe { *(bytes.as_ptr().offset(off + 0x20) as *const u64) };
        segments.push((sh_offset, ptr, sh_size));
    }
    // LLDB wants segments with virtual address set, placing then at the end of ELF.
    let ph = (bytes.len(), segments.len());
    for (sh_offset, v_offset, sh_size) in segments {
        let mut segment = Vec::with_capacity(0x38);
        segment.resize(0x38, 0);
        unsafe {
            *(segment.as_ptr() as *mut u32) = /* PT_LOAD */ 0x1;
            *(segment.as_ptr().offset(0x8) as *mut u64) = sh_offset;
            *(segment.as_ptr().offset(0x10) as *mut u64) = v_offset as u64;
            *(segment.as_ptr().offset(0x18) as *mut u64) = v_offset as u64;
            *(segment.as_ptr().offset(0x20) as *mut u64) = sh_size;
            *(segment.as_ptr().offset(0x28) as *mut u64) = sh_size;
        }
        bytes.extend_from_slice(&segment);
    }
    // Update e_phoff and e_phnum.
    unsafe {
        *(bytes.as_ptr().offset(0x20) as *mut u64) = ph.0 as u64;
        *(bytes.as_ptr().offset(0x38) as *mut u16) = ph.1 as u16;
    }
}
