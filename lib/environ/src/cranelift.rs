//! Support for compiling with Cranelift.

use crate::compilation::{
    AddressTransform, AddressTransforms, Compilation, CompileError, Relocation, RelocationTarget,
    Relocations,
};
use crate::func_environ::{
    get_func_name, get_imported_memory32_grow_name, get_imported_memory32_size_name,
    get_memory32_grow_name, get_memory32_size_name, FuncEnvironment,
};
use crate::module::Module;
use cranelift_codegen::binemit;
use cranelift_codegen::ir;
use cranelift_codegen::ir::ExternalName;
use cranelift_codegen::isa;
use cranelift_codegen::Context;
use cranelift_entity::PrimaryMap;
use cranelift_wasm::{DefinedFuncIndex, FuncIndex, FuncTranslator};
use std::vec::Vec;

/// Implementation of a relocation sink that just saves all the information for later
struct RelocSink {
    /// Relocations recorded for the function.
    func_relocs: Vec<Relocation>,
}

impl binemit::RelocSink for RelocSink {
    fn reloc_ebb(
        &mut self,
        _offset: binemit::CodeOffset,
        _reloc: binemit::Reloc,
        _ebb_offset: binemit::CodeOffset,
    ) {
        // This should use the `offsets` field of `ir::Function`.
        panic!("ebb headers not yet implemented");
    }
    fn reloc_external(
        &mut self,
        offset: binemit::CodeOffset,
        reloc: binemit::Reloc,
        name: &ExternalName,
        addend: binemit::Addend,
    ) {
        let reloc_target = if *name == get_memory32_grow_name() {
            RelocationTarget::Memory32Grow
        } else if *name == get_imported_memory32_grow_name() {
            RelocationTarget::ImportedMemory32Grow
        } else if *name == get_memory32_size_name() {
            RelocationTarget::Memory32Size
        } else if *name == get_imported_memory32_size_name() {
            RelocationTarget::ImportedMemory32Size
        } else if let ExternalName::User { namespace, index } = *name {
            debug_assert!(namespace == 0);
            RelocationTarget::UserFunc(FuncIndex::from_u32(index))
        } else if let ExternalName::LibCall(libcall) = *name {
            RelocationTarget::LibCall(libcall)
        } else {
            panic!("unrecognized external name")
        };
        self.func_relocs.push(Relocation {
            reloc,
            reloc_target,
            offset,
            addend,
        });
    }
    fn reloc_jt(
        &mut self,
        _offset: binemit::CodeOffset,
        _reloc: binemit::Reloc,
        _jt: ir::JumpTable,
    ) {
        panic!("jump tables not yet implemented");
    }
}

impl RelocSink {
    /// Return a new `RelocSink` instance.
    pub fn new() -> Self {
        Self {
            func_relocs: Vec::new(),
        }
    }
}

fn get_address_transform(context: &Context, isa: &isa::TargetIsa) -> Vec<AddressTransform> {
    let mut result = Vec::new();

    let func = &context.func;
    let mut ebbs = func.layout.ebbs().collect::<Vec<_>>();
    ebbs.sort_by_key(|ebb| func.offsets[*ebb]); // Ensure inst offsets always increase

    let encinfo = isa.encoding_info();
    for ebb in ebbs {
        for (offset, inst, _size) in func.inst_offsets(ebb, &encinfo) {
            let srcloc = func.srclocs[inst];
            let address_offset = offset as u64;
            result.push((srcloc, address_offset));
        }
    }
    result
}

fn align_code_buf(buf: &mut Vec<u8>) {
    let new_len = buf.len() + (!buf.len() + 1) % 16;
    buf.resize(new_len, /* fill = */ 0xCC);
}

/// Compile the module using Cranelift, producing a compilation result with
/// associated relocations.
pub fn compile_module<'data, 'module>(
    module: &'module Module,
    function_body_inputs: PrimaryMap<DefinedFuncIndex, &'data [u8]>,
    isa: &dyn isa::TargetIsa,
) -> Result<(Compilation, Relocations, AddressTransforms), CompileError> {
    let mut functions = PrimaryMap::new();
    let mut relocations = PrimaryMap::new();
    let mut address_transforms = PrimaryMap::new();
    for (i, input) in function_body_inputs.into_iter() {
        let func_index = module.func_index(i);
        let mut context = Context::new();
        context.func.name = get_func_name(func_index);
        context.func.signature = module.signatures[module.functions[func_index]].clone();

        let mut trans = FuncTranslator::new();
        trans
            .translate(
                input,
                &mut context.func,
                &mut FuncEnvironment::new(isa.frontend_config(), module),
            )
            .map_err(CompileError::Wasm)?;

        let mut code_buf: Vec<u8> = Vec::new();
        let mut reloc_sink = RelocSink::new();
        let mut trap_sink = binemit::NullTrapSink {};
        context
            .compile_and_emit(isa, &mut code_buf, &mut reloc_sink, &mut trap_sink)
            .map_err(CompileError::Codegen)?;

        align_code_buf(&mut code_buf);

        let at = get_address_transform(&context, isa);

        functions.push(code_buf);
        relocations.push(reloc_sink.func_relocs);
        address_transforms.push(at);
    }

    // TODO: Reorganize where we create the Vec for the resolved imports.
    Ok((Compilation::new(functions), relocations, address_transforms))
}
