// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]

use fallible_iterator::FallibleIterator;
use gimli::{Abbreviation, Attribute, Section, UnitHeader, UnitOffset, UnitSectionOffset, UnitType, UnwindSection};
use object::{File, Object, ObjectSection, ObjectSymbol};
use regex::bytes::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fmt::{self, Debug};
use std::fs;
use std::io;
use std::io::{BufWriter, stdout, Write};
use std::iter::Iterator;
use std::process;
use std::result;
use typed_arena::Arena;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    GimliError(gimli::Error),
    ObjectError(object::read::Error),
    IoError,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

fn writeln_error<W: Write, R: Reader>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    err: Error,
    msg: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{}: {}",
        msg,
        match err {
            Error::GimliError(err) => dwarf.format_error(err),
            Error::ObjectError(err) =>
                format!("{}:{:?}", "An object error occurred while reading", err),
            Error::IoError => "An I/O error occurred while writing.".to_string(),
        }
    )
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IoError
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Error::ObjectError(err)
    }
}

pub type Result<T> = result::Result<T, Error>;

trait Reader: gimli::Reader<Offset = usize> + Send + Sync {}

impl<'input, Endian> Reader for gimli::EndianSlice<'input, Endian> where
    Endian: gimli::Endianity + Send + Sync
{
}

type RelocationMap = HashMap<usize, object::Relocation>;

fn add_relocations(
    relocations: &mut RelocationMap,
    file: &object::File,
    section: &object::Section,
) {
    for (offset64, mut relocation) in section.relocations() {
        let offset = offset64 as usize;
        if offset as u64 != offset64 {
            continue;
        }
        let offset = offset as usize;
        match relocation.kind() {
            object::RelocationKind::Absolute => {
                match relocation.target() {
                    object::RelocationTarget::Symbol(symbol_idx) => {
                        match file.symbol_by_index(symbol_idx) {
                            Ok(symbol) => {
                                let addend =
                                    symbol.address().wrapping_add(relocation.addend() as u64);
                                relocation.set_addend(addend as i64);
                            }
                            Err(_) => {
                                eprintln!(
                                    "Relocation with invalid symbol for section {} at offset 0x{:08x}",
                                    section.name().unwrap(),
                                    offset
                                );
                            }
                        }
                    }
                    _ => {}
                }
                if relocations.insert(offset, relocation).is_some() {
                    eprintln!(
                        "Multiple relocations for section {} at offset 0x{:08x}",
                        section.name().unwrap(),
                        offset
                    );
                }
            }
            _ => {
                eprintln!(
                    "Unsupported relocation for section {} at offset 0x{:08x}",
                    section.name().unwrap(),
                    offset
                );
            }
        }
    }
}

/// Apply relocations to addresses and offsets during parsing,
/// instead of requiring the data to be fully relocated prior
/// to parsing.
///
/// Pros
/// - allows readonly buffers, we don't need to implement writing of values back to buffers
/// - potentially allows us to handle addresses and offsets differently
/// - potentially allows us to add metadata from the relocation (eg symbol names)
/// Cons
/// - maybe incomplete
#[derive(Debug, Clone)]
struct Relocate<'a, R: gimli::Reader<Offset = usize>> {
    relocations: &'a RelocationMap,
    section: R,
    reader: R,
}

impl<'a, R: gimli::Reader<Offset = usize>> Relocate<'a, R> {
    fn relocate(&self, offset: usize, value: u64) -> u64 {
        if let Some(relocation) = self.relocations.get(&offset) {
            match relocation.kind() {
                object::RelocationKind::Absolute => {
                    if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        return value.wrapping_add(relocation.addend() as u64);
                    } else {
                        return relocation.addend() as u64;
                    }
                }
                _ => {}
            }
        };
        value
    }
}

impl<'a, R: gimli::Reader<Offset = usize>> gimli::Reader for Relocate<'a, R> {
    type Endian = R::Endian;
    type Offset = R::Offset;

    fn read_address(&mut self, address_size: u8) -> gimli::Result<u64> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_address(address_size)?;
        Ok(self.relocate(offset, value))
    }

    fn read_length(&mut self, format: gimli::Format) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_length(format)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_offset(&mut self, format: gimli::Format) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_offset(format)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_sized_offset(&mut self, size: u8) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_sized_offset(size)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    #[inline]
    fn split(&mut self, len: Self::Offset) -> gimli::Result<Self> {
        let mut other = self.clone();
        other.reader.truncate(len)?;
        self.reader.skip(len)?;
        Ok(other)
    }

    // All remaining methods simply delegate to `self.reader`.

    #[inline]
    fn endian(&self) -> Self::Endian {
        self.reader.endian()
    }

    #[inline]
    fn len(&self) -> Self::Offset {
        self.reader.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.reader.empty()
    }

    #[inline]
    fn truncate(&mut self, len: Self::Offset) -> gimli::Result<()> {
        self.reader.truncate(len)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> Self::Offset {
        self.reader.offset_from(&base.reader)
    }

    #[inline]
    fn offset_id(&self) -> gimli::ReaderOffsetId {
        self.reader.offset_id()
    }

    #[inline]
    fn lookup_offset_id(&self, id: gimli::ReaderOffsetId) -> Option<Self::Offset> {
        self.reader.lookup_offset_id(id)
    }

    #[inline]
    fn find(&self, byte: u8) -> gimli::Result<Self::Offset> {
        self.reader.find(byte)
    }

    #[inline]
    fn skip(&mut self, len: Self::Offset) -> gimli::Result<()> {
        self.reader.skip(len)
    }

    #[inline]
    fn to_slice(&self) -> gimli::Result<Cow<[u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn to_string(&self) -> gimli::Result<Cow<str>> {
        self.reader.to_string()
    }

    #[inline]
    fn to_string_lossy(&self) -> gimli::Result<Cow<str>> {
        self.reader.to_string_lossy()
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> gimli::Result<()> {
        self.reader.read_slice(buf)
    }
}

impl<'a, R: Reader> Reader for Relocate<'a, R> {}

#[derive(Default)]
struct Flags<'a> {
    dwo: bool,
    dwp: bool,
    dwo_parent: Option<object::File<'a>>,
}

fn print_usage(opts: &getopts::Options) -> ! {
    let brief = format!("Usage: {} <options> <file>", env::args().next().unwrap());
    write!(&mut io::stderr(), "{}", opts.usage(&brief)).ok();
    process::exit(1);
}

fn main() {
    let mut opts = getopts::Options::new();

    opts.optopt(
        "",
        "dwo-parent",
        "use the specified file as the parent of the dwo or dwp (e.g. for .debug_addr)",
        "library path",
    );

    let matches = match opts.parse(env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}\n", e).ok();
            print_usage(&opts);
        }
    };
    if matches.free.is_empty() {
        print_usage(&opts);
    }

    let mut flags = Flags::default();

    let arena_mmap = Arena::new();
    let load_file = |path| {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file '{}': {}", path, err);
                process::exit(1);
            }
        };
        let mmap = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                eprintln!("Failed to map file '{}': {}", path, err);
                process::exit(1);
            }
        };
        let mmap_ref = arena_mmap.alloc(mmap);
        match object::File::parse(&**mmap_ref) {
            Ok(file) => Some(file),
            Err(err) => {
                eprintln!("Failed to parse file '{}': {}", path, err);
                process::exit(1);
            }
        }
    };

    flags.dwo_parent = matches.opt_str("dwo-parent").and_then(load_file);
    if flags.dwo_parent.is_some() && !flags.dwo && !flags.dwp {
        eprintln!("--dwo-parent also requires --dwo or --dwp");
        process::exit(1);
    }
    if flags.dwo_parent.is_none() && flags.dwp {
        eprintln!("--dwp also requires --dwo-parent");
        process::exit(1);
    }

    for file_path in &matches.free {
        if matches.free.len() != 1 {
            println!("{}", file_path);
            println!();
        }

        let file = match fs::File::open(&file_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file '{}': {}", file_path, err);
                continue;
            }
        };
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                eprintln!("Failed to map file '{}': {}", file_path, err);
                continue;
            }
        };
        let file = match object::File::parse(&*file) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to parse file '{}': {}", file_path, err);
                continue;
            }
        };

        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let ret = dump_file(&file, endian, &flags);
        match ret {
            Ok(ret) => {
                for func in ret {
                    println!("{:?}", func);
                }
            },
            Err(err) => eprintln!("Failed to dump '{}': {}", file_path, err,),
        }
    }
}

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, Endian>>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else if file.format() == object::BinaryFormat::Xcoff {
        id.xcoff_name()
    } else {
        Some(id.name())
    };

    let data = match name.and_then(|name| file.section_by_name(&name)) {
        Some(ref section) => {
            // DWO sections never have relocations, so don't bother.
            if !is_dwo {
                add_relocations(&mut relocations, file, section);
            }
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = arena_data.alloc(data);
    let reader = gimli::EndianSlice::new(data_ref, endian);
    let section = reader;
    let relocations = arena_relocations.alloc(relocations);
    Ok(Relocate {
        relocations,
        section,
        reader,
    })
}

fn dump_file<Endian>(file: &object::File, endian: Endian, flags: &Flags) -> Result<Vec<Func>>
    where
        Endian: gimli::Endianity + Send + Sync,
{
    let arena_data = Arena::new();
    let arena_relocations = Arena::new();

    let dwo_parent = if let Some(dwo_parent_file) = flags.dwo_parent.as_ref() {
        let mut load_dwo_parent_section = |id: gimli::SectionId| -> Result<_> {
            load_file_section(
                id,
                dwo_parent_file,
                endian,
                false,
                &arena_data,
                &arena_relocations,
            )
        };
        Some(gimli::Dwarf::load(&mut load_dwo_parent_section)?)
    } else {
        None
    };
    let dwo_parent = dwo_parent.as_ref();

    let dwo_parent_units = if let Some(dwo_parent) = dwo_parent {
        Some(
            match dwo_parent
                .units()
                .map(|unit_header| dwo_parent.unit(unit_header))
                .filter_map(|unit| Ok(unit.dwo_id.map(|dwo_id| (dwo_id, unit))))
                .collect()
            {
                Ok(units) => units,
                Err(err) => {
                    eprintln!("Failed to process --dwo-parent units: {}", err);
                    return Ok((vec![]));
                }
            },
        )
    } else {
        None
    };
    let dwo_parent_units = dwo_parent_units.as_ref();

    let mut load_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(
            id,
            file,
            endian,
            false,
            &arena_data,
            &arena_relocations,
        )
    };

    let w = &mut BufWriter::new(io::stdout());

    let mut dwarf = gimli::Dwarf::load(&mut load_section)?;

    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::All);

    return Ok(dump_info(w, &dwarf, dwo_parent_units)?);
}

fn dump_dwp<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
) -> Result<Vec<Func>>
    where
        R::Endian: Send + Sync,
{
    let mut funcs = vec![];
    if dwp.cu_index.unit_count() != 0 {
        for i in 1..=dwp.cu_index.unit_count() {
            let res = dump_dwp_sections(
                w,
                &dwp,
                dwo_parent,
                dwo_parent_units,
                dwp.cu_index.sections(i)?,
            )?;
            for func in res {
                funcs.push(func)
            }
        }
    }

    if dwp.tu_index.unit_count() != 0 {
        for i in 1..=dwp.tu_index.unit_count() {
            let res = dump_dwp_sections(
                w,
                &dwp,
                dwo_parent,
                dwo_parent_units,
                dwp.tu_index.sections(i)?,
            )?;
            for func in res {
                funcs.push(func)
            }
        }
    }

    Ok(funcs)
}

fn dump_dwp_sections<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    sections: gimli::UnitIndexSectionIterator<R>,
) -> Result<Vec<Func>>
    where
        R::Endian: Send + Sync,
{
    let dwarf = dwp.sections(sections, dwo_parent)?;
    return Ok(dump_info(w, &dwarf, dwo_parent_units)?);
}

fn dump_info<R: Reader, W: Write + Send>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
) -> Result<Vec<Func>>
    where
        R::Endian: Send + Sync,
{
    let units = match dwarf.units().collect::<Vec<_>>() {
        Ok(units) => units,
        Err(err) => {
            writeln_error(
                w,
                dwarf,
                Error::GimliError(err),
                "Failed to read unit headers",
            )?;
            return Ok(vec![]);
        }
    };
    let mut res: Vec<Func> = vec![];
    for unit in units {
        for func in dump_unit(w, unit, dwarf, dwo_parent_units)? {
            res.push(func)
        }
    }
    return Ok(res);
}

fn dump_unit<R: Reader, W: Write>(
    w: &mut W,
    header: UnitHeader<R>,
    dwarf: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
) -> Result<Vec<Func>> {
    let mut unit = match dwarf.unit(header) {
        Ok(unit) => unit,
        Err(err) => {
            writeln_error(w, dwarf, err.into(), "Failed to parse unit root entry")?;
            return Ok((vec![]));
        }
    };

    if let Some(dwo_parent_units) = dwo_parent_units {
        if let Some(dwo_id) = unit.dwo_id {
            if let Some(parent_unit) = dwo_parent_units.get(&dwo_id) {
                unit.copy_relocated_attributes(parent_unit);
            }
        }
    }

    let entries_result = dump_entries::<R, W>(unit, dwarf);
    if let Err(err) = entries_result {
        writeln_error(w, dwarf, err, "Failed to dump entries")?;
    }
    return entries_result
}

#[derive(Clone, Debug)]
struct Func {
    name: String,
    args: Vec<Arg>,
}

#[derive(Clone, Debug)]
struct Arg {
    name: String,
    location: i64,
    type_name: String,
    bytes_cnt: u64,
}

fn dump_entries<R: Reader, W: Write>(
    unit: gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<Vec<Func>> {

    let mut cur_func = Func{ name: "".to_string(), args: vec![] };
    let mut functions: Vec<Func> = vec![];
    let mut entries = unit.entries_raw(None)?;
    while !entries.is_empty() {
        let abbrev = entries.read_abbreviation()?;

        let mut funcname = "".to_string();
        let mut argname = "".to_string();
        let mut argoffset = 0;
        let mut bytesize = 0;
        let mut typename = "".to_string();
        for spec in abbrev.map(|x| x.attributes()).unwrap_or(&[]) {
            let attr = entries.read_attribute(*spec)?;
            if let Some(n) = attr.name().static_string() {
                if n == "DW_AT_name" {
                    funcname = get_func_name::<R, W>(&attr, dwarf);
                    argname = get_arg_name::<R, W>(&attr)
                }
                if n == "DW_AT_location" {
                    argoffset = get_arg_loc::<R, W>(&attr, &unit);
                }
                if n == "DW_AT_type" {
                    match abbrev {
                        None => {}
                        Some(rev_val) => {
                            match rev_val.tag().to_string().as_str() {
                                "DW_TAG_formal_parameter" => {
                                    bytesize = get_arg_byte_size::<R, W>(&attr, &unit);
                                    typename = get_arg_type_name::<R, W>(&attr, &unit, dwarf);
                                }
                                _ => {}
                            }
                        }
                    }

                }
            }
        }

        match abbrev {
            None => {}
            Some(rev_val) => {
                match rev_val.tag().to_string().as_str() {
                    "DW_TAG_subprogram" => {
                        cur_func = Func{ name: funcname, args: vec![] };
                        functions.push(cur_func.clone());
                    }
                    "DW_TAG_formal_parameter" => {
                        let arg = Arg{name: argname, location: argoffset, bytes_cnt: bytesize, type_name: typename};
                        functions.last_mut().unwrap().args.push(arg);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(functions)
}

fn get_func_name<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
    dwarf: &gimli::Dwarf<R>,
) -> String {
    let value = attr.value();
    match value {
        gimli::AttributeValue::DebugStrRef(offset) => {
            if let Ok(s) = dwarf.debug_str.get_str(offset) {
                return s.to_string_lossy().unwrap().parse().unwrap();
            } else {
                return "".to_string();
            }
        }
        _ => {return "".to_string();}
    }
}

fn get_arg_loc<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
) -> i64 {
    let value = attr.value();
    return match value {
        gimli::AttributeValue::Exprloc(ref data) => {
            get_frame_offset_by_data::<R, W>(unit.encoding(), data).unwrap()
        }
        _ => { 0 }
    }
}

// from dump_exprloc
fn get_frame_offset_by_data<R: Reader, W: Write>(
    encoding: gimli::Encoding,
    data: &gimli::Expression<R>,
) -> Result<i64> {
    let mut pc = data.0.clone();
    while pc.len() != 0 {
        return match gimli::Operation::parse(&mut pc, encoding) {
            Ok(op) => {
                get_frame_offset::<R, W>(op)
            }
            _ => Err(Error::IoError)
        }
    }

    return Err(Error::IoError);
}

// from dump_op
fn get_frame_offset<R: Reader, W: Write>(
    op: gimli::Operation<R>,
) -> Result<i64> {
    return match op {
        gimli::Operation::FrameOffset { offset } => {
            Ok(offset)
        }
        _  => { Err(Error::IoError) }
    };
}

fn get_arg_name<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
) -> String {
    let value = attr.value();
    return match value {
        gimli::AttributeValue::String(s) => {
            s.to_string_lossy().unwrap().parse().unwrap()
        }
        _ => { "".to_string() }
    }
}

fn get_arg_byte_size<R: Reader, W: Write>(
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
) -> u64 {
    let value = attr.value();
    return match value {
        gimli::AttributeValue::UnitRef(offset) => {
            match offset.to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(_) => {
                    let byte_size = unit.entry(offset).unwrap().attr(gimli::DW_AT_byte_size);
                    match byte_size {
                        Ok(s) => {
                            match s {
                                None => { 0 }
                                Some(byte_size) => { byte_size.value().udata_value().unwrap() }
                            }
                        }
                        Err(_) => { 0 }
                    }
                }
                _ => { 0 }
            }
        }
        _ => { 0 }
    }
}

fn get_arg_type_name<R: Reader, W: Write>(
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> String {
    let value = attr.value();
    return match value {
        gimli::AttributeValue::UnitRef(offset) => {
            match offset.to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(_) => {
                    let die = unit.entry(offset).unwrap();
                    match die.tag() {
                        gimli::DW_TAG_base_type => {
                            let type_name = die.attr(gimli::DW_AT_name);
                            match type_name {
                                Ok(s) => {
                                    match s {
                                        None => { "".to_string() }
                                        Some(typename) => {
                                            return match typename.value() {
                                                gimli::AttributeValue::DebugStrRef(offset) => {
                                                    if let Ok(s) = dwarf.debug_str.get_str(offset) {
                                                        s.to_string_lossy().unwrap().to_string()
                                                    } else {
                                                        "".to_string()
                                                    }
                                                }
                                                gimli::AttributeValue::String(s) => {
                                                    let typename: String = s.to_string_lossy().unwrap().parse().unwrap();
                                                    typename
                                                }
                                                _ => { "".to_string() }
                                            };
                                        }
                                    }
                                }
                                Err(_) => { "".to_string() }
                            }
                        }
                        gimli::DW_TAG_pointer_type => {
                            let base = die.attr(gimli::DW_AT_type);
                            "Ptr[".to_string() + &get_arg_type_name::<R, W>(&base.unwrap().unwrap(), unit, dwarf) + "]"
                        }
                        _ => { "".to_string() }
                    }
                }
                _ => { "".to_string() }
            }
        }
        _ => { "".to_string() }
    }
}
