use crate::transform::TransformedDwarf;

use gimli::write::{
    Address, DebugAbbrev, DebugInfo, DebugLine, DebugLineStr, DebugRanges, DebugRngLists, DebugStr,
    EndianVec, Result, SectionId, Writer,
};
use gimli::RunTimeEndian;

use faerie::artifact::Decl;
use faerie::*;

struct DebugReloc {
    offset: u32,
    size: u8,
    name: String,
    addend: i64,
}

macro_rules! decl_section {
    ($artifact:ident . $section:ident = $name:ident) => {
        $artifact
            .declare_with(
                SectionId::$section.name(),
                Decl::DebugSection,
                $name.0.writer.into_vec(),
            )
            .unwrap();
    };
}

macro_rules! sect_relocs {
    ($artifact:ident . $section:ident = $name:ident) => {
        for reloc in $name.0.relocs {
            $artifact
                .link_with(
                    faerie::Link {
                        from: SectionId::$section.name(),
                        to: &reloc.name,
                        at: u64::from(reloc.offset),
                    },
                    faerie::Reloc::Debug {
                        size: reloc.size,
                        addend: reloc.addend as i32,
                    },
                )
                .expect("faerie relocation error");
        }
    };
}

pub enum ResolvedSymbol {
    PhysicalAddress(u64),
    Reloc { name: String, addend: i64 },
}

pub trait SymbolResolver {
    fn resolve_symbol(&self, symbol: usize, addend: i64) -> ResolvedSymbol;
}

pub fn emit_dwarf(
    artifact: &mut Artifact,
    dwarf: &TransformedDwarf,
    symbol_resolver: &SymbolResolver,
) {
    let endian = RunTimeEndian::Little;
    let mut debug_abbrev = DebugAbbrev::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_info = DebugInfo::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_str = DebugStr::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_line = DebugLine::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_ranges = DebugRanges::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_rnglists = DebugRngLists::from(WriterRelocate::new(endian, symbol_resolver));
    let mut debug_line_str = DebugLineStr::from(WriterRelocate::new(endian, symbol_resolver));

    let debug_str_offsets = dwarf.strings.write(&mut debug_str).unwrap();
    let debug_line_str_offsets = dwarf.line_strings.write(&mut debug_line_str).unwrap();
    let debug_line_offsets = dwarf
        .line_programs
        .write(&mut debug_line, &debug_line_str_offsets, &debug_str_offsets)
        .unwrap();
    dwarf
        .units
        .write(
            &mut debug_abbrev,
            &mut debug_info,
            &mut debug_ranges,
            &mut debug_rnglists,
            &debug_line_offsets,
            &debug_line_str_offsets,
            &debug_str_offsets,
        )
        .unwrap();

    decl_section!(artifact.DebugAbbrev = debug_abbrev);
    decl_section!(artifact.DebugInfo = debug_info);
    decl_section!(artifact.DebugStr = debug_str);
    decl_section!(artifact.DebugLine = debug_line);

    let debug_ranges_not_empty = !debug_ranges.0.writer.slice().is_empty();
    if debug_ranges_not_empty {
        decl_section!(artifact.DebugRanges = debug_ranges);
    }

    let debug_rnglists_not_empty = !debug_rnglists.0.writer.slice().is_empty();
    if debug_rnglists_not_empty {
        decl_section!(artifact.DebugRngLists = debug_rnglists);
    }

    sect_relocs!(artifact.DebugAbbrev = debug_abbrev);
    sect_relocs!(artifact.DebugInfo = debug_info);
    sect_relocs!(artifact.DebugStr = debug_str);
    sect_relocs!(artifact.DebugLine = debug_line);

    if debug_ranges_not_empty {
        sect_relocs!(artifact.DebugRanges = debug_ranges);
    }

    if debug_rnglists_not_empty {
        sect_relocs!(artifact.DebugRngLists = debug_rnglists);
    }
}

struct WriterRelocate<'a> {
    relocs: Vec<DebugReloc>,
    writer: EndianVec<RunTimeEndian>,
    symbol_resolver: &'a SymbolResolver,
}

impl<'a> WriterRelocate<'a> {
    fn new(endian: RunTimeEndian, symbol_resolver: &'a SymbolResolver) -> Self {
        WriterRelocate {
            relocs: Vec::new(),
            writer: EndianVec::new(endian),
            symbol_resolver,
        }
    }
}

impl<'a> Writer for WriterRelocate<'a> {
    type Endian = RunTimeEndian;

    fn endian(&self) -> Self::Endian {
        self.writer.endian()
    }

    fn len(&self) -> usize {
        self.writer.len()
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write(bytes)
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.writer.write_at(offset, bytes)
    }

    fn write_address(&mut self, address: Address, size: u8) -> Result<()> {
        match address {
            Address::Absolute(val) => self.write_word(val, size),
            Address::Relative { symbol, addend } => {
                match self.symbol_resolver.resolve_symbol(symbol, addend as i64) {
                    ResolvedSymbol::PhysicalAddress(addr) => self.write_word(addr, size),
                    ResolvedSymbol::Reloc { name, addend } => {
                        let offset = self.len() as u64;
                        self.relocs.push(DebugReloc {
                            offset: offset as u32,
                            size,
                            name,
                            addend,
                        });
                        self.write_word(addend as u64, size)
                    }
                }
            }
        }
    }

    fn write_offset(&mut self, val: usize, section: SectionId, size: u8) -> Result<()> {
        let offset = self.len() as u32;
        let name = section.name().to_string();
        self.relocs.push(DebugReloc {
            offset,
            size,
            name,
            addend: val as i64,
        });
        self.write_word(val as u64, size)
    }

    fn write_offset_at(
        &mut self,
        offset: usize,
        val: usize,
        section: SectionId,
        size: u8,
    ) -> Result<()> {
        let name = section.name().to_string();
        self.relocs.push(DebugReloc {
            offset: offset as u32,
            size,
            name,
            addend: val as i64,
        });
        self.write_word_at(offset, val as u64, size)
    }
}
