use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_entity::EntityRef;
use cranelift_wasm::GlobalInit;
use wasmtime_environ::{Module, VMOffsets};
use wasmtime_runtime::{
    SignatureRegistry, VMGlobalDefinition, VMSharedSignatureIndex, VMTableDefinition,
};

pub struct TableRelocation {
    pub index: usize,
    pub offset: usize,
}

pub fn layout_vmcontext(
    module: &Module,
    target_config: &TargetFrontendConfig,
) -> (Box<[u8]>, Box<[TableRelocation]>) {
    let ofs = VMOffsets::new(target_config.pointer_bytes(), &module);
    let out_len = ofs.size_of_vmctx() as usize;
    let mut out = Vec::with_capacity(out_len);
    out.resize(out_len, 0);

    let mut signature_registry = SignatureRegistry::new();
    for (index, sig) in module.signatures.iter() {
        let offset = ofs.vmctx_vmshared_signature_id(index) as usize;
        let id = signature_registry.register(sig);
        unsafe {
            let to = out.as_mut_ptr().add(offset) as *mut VMSharedSignatureIndex;
            (*to) = id;
        }
    }

    let num_tables_imports = module.imported_tables.len();
    let mut table_relocs = Vec::with_capacity(module.table_plans.len() - num_tables_imports);
    for (index, table) in module.table_plans.iter().skip(num_tables_imports) {
        let def_index = module.defined_table_index(index).unwrap();
        let offset = ofs.vmctx_vmtable_definition(def_index) as usize;
        let current_elements = table.table.minimum as usize;
        unsafe {
            let to = out.as_mut_ptr().add(offset) as *mut VMTableDefinition;
            (*to).current_elements = current_elements;
        }
        table_relocs.push(TableRelocation {
            index: def_index.index(),
            offset,
        });
    }

    let num_globals_imports = module.imported_globals.len();
    for (index, global) in module.globals.iter().skip(num_globals_imports) {
        let def_index = module.defined_global_index(index).unwrap();
        let offset = ofs.vmctx_vmglobal_definition(def_index) as usize;
        let to = unsafe { out.as_mut_ptr().add(offset) as *mut VMGlobalDefinition };
        match global.initializer {
            GlobalInit::I32Const(x) => *unsafe { (*to).as_i32_mut() } = x,
            GlobalInit::I64Const(x) => *unsafe { (*to).as_i64_mut() } = x,
            GlobalInit::F32Const(x) => *unsafe { (*to).as_f32_bits_mut() } = x,
            GlobalInit::F64Const(x) => *unsafe { (*to).as_f64_bits_mut() } = x,
            _ => panic!("unsupported global type"),
        }
    }

    (out.into_boxed_slice(), table_relocs.into_boxed_slice())
}
