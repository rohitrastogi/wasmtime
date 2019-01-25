pub use crate::read_debuginfo::DebugInfoData;
use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_entity::EntityRef;
use std::collections::HashMap;
use wasmtime_environ::AddressTransforms;

use gimli;

use gimli::{
    AttributeValue, CompilationUnitHeader, DebugAbbrev, DebugAddr, DebugAddrBase, DebugLine,
    DebugStr, DebuggingInformationEntry, LocationLists, RangeLists, UnitOffset,
};

use gimli::write;

trait Reader: gimli::Reader<Offset = usize> {}

impl<'input, Endian> Reader for gimli::EndianSlice<'input, Endian> where Endian: gimli::Endianity {}

#[derive(Debug)]
pub enum Error {
    GimliError(gimli::Error),
    Custom(&'static str),
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

struct AddrTransform<'a> {
    at: &'a AddressTransforms,
    code_section_offset: u64,
    function_offsets: &'a [(u64, u32)],
}

impl<'a> AddrTransform<'a> {
    fn translate(&self, addr: u64) -> write::Address {
        for (i, ft) in self.at {
            let (fn_offset, fn_size) = self.function_offsets[i.index()];
            if addr + self.code_section_offset < fn_offset
                || addr + self.code_section_offset > fn_offset + fn_size as u64
            {
                continue;
            }

            if addr + self.code_section_offset == fn_offset {
                return write::Address::Relative {
                    symbol: i.index(),
                    addend: 0,
                };
            }
            let local_off = (addr + self.code_section_offset - fn_offset) as u32;
            for t in ft {
                if t.0.is_default() {
                    continue;
                }
                if local_off <= t.0.bits() {
                    return write::Address::Relative {
                        symbol: i.index(),
                        addend: t.1 as i64,
                    };
                }
            }
            return write::Address::Relative {
                symbol: i.index(),
                addend: ft[ft.len() - 1].1 as i64,
            };
        }
        if addr == 0 {
            return write::Address::Absolute(0);
        }
        panic!("address was not found {}", addr);
    }

    fn diff(&self, addr1: u64, addr2: u64) -> u64 {
        let t1 = self.translate(addr1);
        let t2 = self.translate(addr2);
        if let (
            write::Address::Relative {
                symbol: s1,
                addend: a,
            },
            write::Address::Relative {
                symbol: s2,
                addend: b,
            },
        ) = (t1, t2)
        {
            if s1 != s2 {
                panic!("different symbols");
            }
            (b - a) as u64
        } else {
            unreachable!();
        }
    }

    fn delta(&self, addr1: u64, u: u64) -> u64 {
        self.diff(addr1, addr1 + u)
    }
}

pub struct TransformedDwarf {
    pub encoding: gimli::Encoding,
    pub strings: write::StringTable,
    pub units: write::UnitTable,
    pub line_programs: write::LineProgramTable,
    pub line_strings: write::LineStringTable,
    pub range_lists: write::RangeListTable,
}

struct DebugInputContext<'a, R>
where
    R: Reader,
{
    debug_abbrev: &'a DebugAbbrev<R>,
    debug_str: &'a DebugStr<R>,
    debug_line: &'a DebugLine<R>,
    debug_addr: &'a DebugAddr<R>,
    debug_addr_base: DebugAddrBase<R::Offset>,
    rnglists: &'a RangeLists<R>,
    loclists: &'a LocationLists<R>,
}

type PendingDieRef = (write::UnitEntryId, gimli::DwAt, UnitOffset);

enum FileAttributeContext<'a> {
    Root(write::LineProgramId),
    Children(&'a write::LineProgram, &'a Vec<write::FileId>),
}

fn clone_die_attributes<'a, R>(
    entry: &DebuggingInformationEntry<R>,
    context: &DebugInputContext<R>,
    addr_tr: &'a AddrTransform,
    unit_encoding: &gimli::Encoding,
    current_scope: &mut write::DebuggingInformationEntry,
    current_scope_id: write::UnitEntryId,
    out_strings: &mut write::StringTable,
    die_ref_map: &HashMap<UnitOffset, write::UnitEntryId>,
    pending_die_refs: &mut Vec<PendingDieRef>,
    file_context: FileAttributeContext<'a>,
) -> Result<(), Error>
where
    R: Reader,
{
    let _tag = &entry.tag();
    let mut attrs = entry.attrs();
    let mut low_pc = None;
    while let Some(attr) = attrs.next()? {
        let attr_value = match attr.value() {
            AttributeValue::Addr(u) => {
                let addr = addr_tr.translate(u);
                if attr.name() == gimli::DW_AT_low_pc {
                    low_pc = Some((u, addr));
                }
                write::AttributeValue::Address(addr)
            }
            AttributeValue::Udata(u) => {
                if attr.name() != gimli::DW_AT_high_pc || low_pc.is_none() {
                    write::AttributeValue::Udata(u)
                } else {
                    let u = addr_tr.delta(low_pc.unwrap().0, u);
                    write::AttributeValue::Udata(u)
                }
            }
            AttributeValue::Data1(d) => write::AttributeValue::Data1(d),
            AttributeValue::Data2(d) => write::AttributeValue::Data2(d),
            AttributeValue::Data4(d) => write::AttributeValue::Data4(d),
            AttributeValue::Sdata(d) => write::AttributeValue::Sdata(d),
            AttributeValue::Flag(f) => write::AttributeValue::Flag(f),
            AttributeValue::DebugLineRef(_) => {
                if let FileAttributeContext::Root(id) = file_context {
                    write::AttributeValue::LineProgramRef(id)
                } else {
                    return Err(Error::Custom("unexpected file index attribute"));
                }
            }
            AttributeValue::FileIndex(i) => {
                if let FileAttributeContext::Children(_, file_map) = file_context {
                    write::AttributeValue::FileIndex(file_map[(i - 1) as usize])
                } else {
                    return Err(Error::Custom("unexpected file index attribute"));
                }
            }
            AttributeValue::DebugStrRef(str_offset) => {
                let s = context.debug_str.get_str(str_offset)?.to_slice()?.to_vec();
                write::AttributeValue::StringRef(out_strings.add(s))
            }
            AttributeValue::RangeListsRef(r) => {
                let low_pc = 0;
                let mut ranges = context.rnglists.ranges(
                    r,
                    *unit_encoding,
                    low_pc,
                    &context.debug_addr,
                    context.debug_addr_base,
                )?;
                let mut _result = Vec::new();
                while let Some(range) = ranges.next()? {
                    assert!(range.begin <= range.end);
                    _result.push((range.begin as i64, range.end as i64));
                }
                // FIXME _result contains invalid code offsets; translate_address
                continue; // ignore attribute
            }
            AttributeValue::LocationListsRef(r) => {
                let low_pc = 0;
                let mut locs = context.loclists.locations(
                    r,
                    *unit_encoding,
                    low_pc,
                    &context.debug_addr,
                    context.debug_addr_base,
                )?;
                let mut _result = Vec::new();
                while let Some(loc) = locs.next()? {
                    _result.push((loc.range.begin as i64, loc.range.end as i64, loc.data.0));
                }
                // FIXME _result contains invalid expressions and code offsets
                continue; // ignore attribute
            }
            AttributeValue::Exprloc(ref _expr) => {
                // FIXME _expr contains invalid expression
                continue; // ignore attribute
            }
            AttributeValue::Encoding(e) => write::AttributeValue::Encoding(e),
            AttributeValue::DecimalSign(e) => write::AttributeValue::DecimalSign(e),
            AttributeValue::Endianity(e) => write::AttributeValue::Endianity(e),
            AttributeValue::Accessibility(e) => write::AttributeValue::Accessibility(e),
            AttributeValue::Visibility(e) => write::AttributeValue::Visibility(e),
            AttributeValue::Virtuality(e) => write::AttributeValue::Virtuality(e),
            AttributeValue::Language(e) => write::AttributeValue::Language(e),
            AttributeValue::AddressClass(e) => write::AttributeValue::AddressClass(e),
            AttributeValue::IdentifierCase(e) => write::AttributeValue::IdentifierCase(e),
            AttributeValue::CallingConvention(e) => write::AttributeValue::CallingConvention(e),
            AttributeValue::Inline(e) => write::AttributeValue::Inline(e),
            AttributeValue::Ordering(e) => write::AttributeValue::Ordering(e),
            AttributeValue::UnitRef(ref offset) => {
                if let Some(unit_id) = die_ref_map.get(offset) {
                    write::AttributeValue::ThisUnitEntryRef(*unit_id)
                } else {
                    pending_die_refs.push((current_scope_id, attr.name(), *offset));
                    continue;
                }
            }
            // AttributeValue::DebugInfoRef(_) => {
            //     continue;
            // }
            _ => panic!(), //write::AttributeValue::StringRef(out_strings.add("_")),
        };
        current_scope.set(attr.name(), attr_value);
    }
    Ok(())
}

fn clone_attr_string<R>(
    attr_value: &AttributeValue<R>,
    form: gimli::DwForm,
    debug_str: &DebugStr<R>,
    out_strings: &mut write::StringTable,
) -> Result<write::LineString, gimli::Error>
where
    R: Reader,
{
    let content = match attr_value {
        AttributeValue::DebugStrRef(str_offset) => {
            debug_str.get_str(*str_offset)?.to_slice()?.to_vec()
        }
        AttributeValue::String(b) => b.to_slice()?.to_vec(),
        _ => panic!("Unexpected attribute value"),
    };
    Ok(match form {
        gimli::DW_FORM_strp => {
            let id = out_strings.add(content);
            write::LineString::StringRef(id)
        }
        gimli::DW_FORM_string => write::LineString::String(content),
        _ => panic!("DW_FORM_line_strp or other not supported"),
    })
}

fn clone_line_program<R>(
    unit: &CompilationUnitHeader<R, R::Offset>,
    root: &DebuggingInformationEntry<R>,
    addr_tr: &AddrTransform,
    out_encoding: &gimli::Encoding,
    debug_str: &DebugStr<R>,
    debug_line: &DebugLine<R>,
    out_line_programs: &mut write::LineProgramTable,
    out_strings: &mut write::StringTable,
) -> Result<(write::LineProgramId, Vec<write::FileId>), Error>
where
    R: Reader,
{
    let offset = match root.attr_value(gimli::DW_AT_stmt_list)? {
        Some(gimli::AttributeValue::DebugLineRef(offset)) => offset,
        _ => {
            return Err(Error::Custom("Debug line offset is not found"));
        }
    };
    let comp_dir = root.attr_value(gimli::DW_AT_comp_dir)?;
    let comp_name = root.attr_value(gimli::DW_AT_name)?;
    let out_comp_dir = clone_attr_string(
        comp_dir.as_ref().expect("comp_dir"),
        gimli::DW_FORM_strp,
        debug_str,
        out_strings,
    )?;
    let out_comp_name = clone_attr_string(
        comp_name.as_ref().expect("comp_name"),
        gimli::DW_FORM_strp,
        debug_str,
        out_strings,
    )?;

    let program = debug_line.program(
        offset,
        unit.address_size(),
        comp_dir.and_then(|val| val.string_value(&debug_str)),
        comp_name.and_then(|val| val.string_value(&debug_str)),
    );
    if let Ok(program) = program {
        let header = program.header();
        assert!(header.version() <= 4, "not supported 5");
        let mut out_program = write::LineProgram::new(
            *out_encoding,
            header.minimum_instruction_length(),
            header.maximum_operations_per_instruction(),
            header.line_base(),
            header.line_range(),
            out_comp_dir,
            out_comp_name,
            None,
        );
        let mut dirs = Vec::new();
        dirs.push(out_program.default_directory());
        for dir_attr in header.include_directories() {
            let dir_id = out_program.add_directory(clone_attr_string(
                dir_attr,
                gimli::DW_FORM_string,
                debug_str,
                out_strings,
            )?);
            dirs.push(dir_id);
        }
        let mut files = Vec::new();
        for file_entry in header.file_names() {
            let dir_id = dirs[file_entry.directory_index() as usize];
            let file_id = out_program.add_file(
                clone_attr_string(
                    &file_entry.path_name(),
                    gimli::DW_FORM_string,
                    debug_str,
                    out_strings,
                )?,
                dir_id,
                None,
            );
            files.push(file_id);
        }

        let mut rows = program.rows();
        let mut base_addr: Option<(u64, write::Address)> = None;
        let get_row_address_offset = |offset: u64, base_addr: &(u64, write::Address)| {
            let d = addr_tr.diff(base_addr.0, offset);
            if let write::Address::Relative { addend, .. } = base_addr.1 {
                d + addend as u64
            } else {
                panic!("unexpected address type");
            }
        };

        while let Some((_header, row)) = rows.next_row()? {
            if !out_program.in_sequence() {
                let addr = addr_tr.translate(row.address());
                base_addr = Some((row.address(), addr));
                out_program.begin_sequence(Some(addr));
            }
            if row.end_sequence() {
                let pc = get_row_address_offset(row.address(), base_addr.as_ref().unwrap());
                out_program.end_sequence(pc);
            } else {
                out_program.row().address_offset =
                    get_row_address_offset(row.address(), base_addr.as_ref().unwrap());
                out_program.row().op_index = row.op_index();
                out_program.row().file = {
                    let file = row.file_index();
                    files[(file - 1) as usize]
                };
                out_program.row().line = row.line().unwrap_or(0);
                out_program.row().column = match row.column() {
                    gimli::ColumnType::LeftEdge => 0,
                    gimli::ColumnType::Column(val) => val,
                };
                out_program.row().discriminator = row.discriminator();
                out_program.row().is_statement = row.is_stmt();
                out_program.row().basic_block = row.basic_block();
                out_program.row().prologue_end = row.prologue_end();
                out_program.row().epilogue_begin = row.epilogue_begin();
                out_program.row().isa = row.isa();
                out_program.generate_row();
            }
        }
        let line_program_id = out_line_programs.add(out_program);
        Ok((line_program_id, files))
    } else {
        Err(Error::Custom("Valid line program not found"))
    }
}

fn clone_unit<'a, R>(
    unit: &CompilationUnitHeader<R, R::Offset>,
    context: &DebugInputContext<R>,
    addr_tr: &'a AddrTransform,
    out_encoding: &gimli::Encoding,
    out_units: &mut write::UnitTable,
    out_line_programs: &mut write::LineProgramTable,
    out_strings: &mut write::StringTable,
) -> Result<(), Error>
where
    R: Reader,
{
    let abbrevs = unit.abbreviations(context.debug_abbrev)?;

    let mut die_ref_map = HashMap::new();
    let mut pending_die_refs = Vec::new();
    let mut stack = Vec::new();

    // Iterate over all of this compilation unit's entries.
    let mut entries = unit.entries(&abbrevs);
    let (comp_unit, out_line_program, file_map) =
        if let Some((depth_delta, entry)) = entries.next_dfs()? {
            assert!(depth_delta == 0);
            if entry.tag() == gimli::DW_TAG_compile_unit {
                let unit_id = out_units.add(write::CompilationUnit::new(*out_encoding));
                let comp_unit = out_units.get_mut(unit_id);

                let root_id = comp_unit.root();
                die_ref_map.insert(entry.offset(), root_id);

                let (out_line_program_id, file_map) = clone_line_program(
                    unit,
                    entry,
                    addr_tr,
                    out_encoding,
                    context.debug_str,
                    context.debug_line,
                    out_line_programs,
                    out_strings,
                )?;

                clone_die_attributes(
                    entry,
                    context,
                    addr_tr,
                    &unit.encoding(),
                    comp_unit.get_mut(root_id),
                    root_id,
                    out_strings,
                    &die_ref_map,
                    &mut pending_die_refs,
                    FileAttributeContext::Root(out_line_program_id),
                )?;

                stack.push(root_id);
                let out_line_program = out_line_programs.get(out_line_program_id);
                (comp_unit, out_line_program, file_map)
            } else {
                return Err(Error::Custom("Unexpected unit header"));
            }
        } else {
            return Ok(()); // empty
        };
    while let Some((depth_delta, entry)) = entries.next_dfs()? {
        if depth_delta <= 0 {
            for _ in depth_delta..1 {
                stack.pop();
            }
        } else {
            assert!(depth_delta == 1);
        }
        let parent = stack.last().unwrap();
        let die_id = comp_unit.add(*parent, entry.tag());
        stack.push(die_id);
        let current_scope = comp_unit.get_mut(die_id);

        die_ref_map.insert(entry.offset(), die_id);

        clone_die_attributes(
            entry,
            context,
            addr_tr,
            &unit.encoding(),
            current_scope,
            die_id,
            out_strings,
            &die_ref_map,
            &mut pending_die_refs,
            FileAttributeContext::Children(out_line_program, &file_map),
        )?;
    }
    for (die_id, attr_name, offset) in pending_die_refs {
        let die = comp_unit.get_mut(die_id);
        let unit_id = die_ref_map[&offset];
        die.set(attr_name, write::AttributeValue::ThisUnitEntryRef(unit_id));
    }
    Ok(())
}

pub fn transform_dwarf(
    target_config: &TargetFrontendConfig,
    di: &DebugInfoData,
    at: &AddressTransforms,
) -> Result<TransformedDwarf, Error> {
    let context = DebugInputContext {
        debug_abbrev: &di.dwarf.debug_abbrev,
        debug_str: &di.dwarf.debug_str,
        debug_line: &di.dwarf.debug_line,
        debug_addr: &di.dwarf.debug_addr,
        debug_addr_base: DebugAddrBase(0),
        rnglists: &di.dwarf.ranges,
        loclists: &di.dwarf.locations,
    };

    let out_encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        // TODO: this should be configurable
        // macOS doesn't seem to support DWARF > 3
        version: 3,
        address_size: target_config.pointer_bytes(),
    };

    let addr_tr = AddrTransform {
        at,
        code_section_offset: di.code_section_offset,
        function_offsets: &di.function_offsets,
    };

    let mut out_strings = write::StringTable::default();
    let mut out_units = write::UnitTable::default();
    let mut out_line_programs = write::LineProgramTable::default();

    let out_range_lists = write::RangeListTable::default();
    let out_line_strings = write::LineStringTable::default();

    let mut iter = di.dwarf.debug_info.units();
    while let Some(ref unit) = iter.next().unwrap_or(None) {
        clone_unit(
            unit,
            &context,
            &addr_tr,
            &out_encoding,
            &mut out_units,
            &mut out_line_programs,
            &mut out_strings,
        )?;
    }

    // let unit_range_list = write::RangeList(Vec::new());
    // let unit_range_list_id = out_range_lists.add(unit_range_list.clone());
    // let unit = dwarf.units.get_mut(self.unit_id);
    // let root = unit.root();
    // let root = unit.get_mut(root);
    // root.set(
    //     gimli::DW_AT_ranges,
    //     AttributeValue::RangeListRef(unit_range_list_id),
    // );

    //println!("{:?} \n====\n {:?}", di, at);
    Ok(TransformedDwarf {
        encoding: out_encoding,
        strings: out_strings,
        units: out_units,
        line_programs: out_line_programs,
        line_strings: out_line_strings,
        range_lists: out_range_lists,
    })
}
