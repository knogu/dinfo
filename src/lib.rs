// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]

use fallible_iterator::FallibleIterator;
use gimli::{Abbreviation, Attribute, AttributeValue, DebuggingInformationEntry, Section, UnitHeader, UnitOffset, UnitSectionOffset, UnitType, UnwindSection};
use object::{File, Object, ObjectSection, ObjectSymbol};
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::ffi::{c_char, CStr};
use std::ffi::CString;
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

// fn main() {
//     let mut opts = getopts::Options::new();
//
//     let matches = match opts.parse(env::args().skip(1)) {
//         Ok(m) => m,
//         Err(e) => {
//             writeln!(&mut io::stderr(), "{:?}\n", e).ok();
//             print_usage(&opts);
//         }
//     };
//     if matches.free.is_empty() {
//         print_usage(&opts);
//     }
//
//     for file_path in &matches.free {
//         for (fname, args) in get_func_info(file_path).unwrap() {
//             println!("{}", fname);
//             println!("{:?}", args);
//         }
//     }
// }

// Cから呼ぶ
#[no_mangle]
pub extern "C" fn get_func2args(file_path: *const c_char) -> *mut HashMap<String, Vec<ArgOrMember>> {
    let file_path = unsafe { CStr::from_ptr(file_path).to_str().unwrap().to_string() };
    let map = get_func_info(&file_path).unwrap();
    let m = Box::new(map);
    Box::into_raw(m)
}

#[no_mangle]
pub extern "C" fn get_arg_count(m: *mut HashMap<String, Vec<ArgOrMember>>, funcname: *const c_char) -> usize {
    let m = unsafe { &*m };
    let funcname = unsafe { CStr::from_ptr(funcname).to_str().unwrap().to_string() };
    match m.get(&funcname) {
        Some(v) => v.len(),
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn get_ith_arg(m: *mut HashMap<String, Vec<ArgOrMember>>, key: *const c_char, i: usize) -> CArg {
    let m = unsafe { &*m };
    let key = unsafe { CStr::from_ptr(key).to_str().unwrap().to_string() };
    match m.get(&key) {
        Some(v) => {
            println!("{:?}", (*v.get(i).unwrap()).clone());
            let arg = (*v.get(i).unwrap()).clone();
            return convert_arg(&arg);
        },
        None => {
            let arg = ArgOrMember {is_arg: true, name: "dummy".to_string(), location: 0, type_name: "dummy".to_string(), bytes_cnt: 0};
            return convert_arg(&arg);
        },
    }
}

// 構造体の初期化でこれやって、構造体のメンバとして関数名→Func, のmap持ちたい
fn get_func_info(file_path: &String) -> Result<HashMap<String, Vec<ArgOrMember>>> {
    let file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", file_path, err);
            return Err(Error::from(err));
        }
    };
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", file_path, err);
            return Err(Error::from(err));
        }
    };
    let file = match object::File::parse(&*file) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to parse file '{}': {}", file_path, err);
            return Err(Error::from(err));
        }
    };

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    return dump_file(&file, endian);
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

fn dump_file<Endian>(file: &object::File, endian: Endian) -> Result<HashMap<String, Vec<ArgOrMember>>>
    where
        Endian: gimli::Endianity + Send + Sync,
{
    let arena_data = Arena::new();
    let arena_relocations = Arena::new();

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

    return Ok(dump_info(w, &dwarf)?);
}

fn dump_dwp<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
) -> Result<HashMap<String, Vec<ArgOrMember>>>
    where
        R::Endian: Send + Sync,
{
    let mut ret: HashMap<String, Vec<ArgOrMember>> = HashMap::new();
    if dwp.cu_index.unit_count() != 0 {
        for i in 1..=dwp.cu_index.unit_count() {
            let res = dump_dwp_sections(
                w,
                &dwp,
                dwo_parent,
                dwp.cu_index.sections(i)?,
            )?;
            for (fname, args) in res {
                ret.insert(fname, args);
            }
        }
    }

    if dwp.tu_index.unit_count() != 0 {
        for i in 1..=dwp.tu_index.unit_count() {
            let res = dump_dwp_sections(
                w,
                &dwp,
                dwo_parent,
                dwp.tu_index.sections(i)?,
            )?;
            for (fname, args) in res {
                ret.insert(fname, args);
            }
        }
    }

    Ok(ret)
}

fn dump_dwp_sections<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
    sections: gimli::UnitIndexSectionIterator<R>,
) -> Result<HashMap<String, Vec<ArgOrMember>>>
    where
        R::Endian: Send + Sync,
{
    let dwarf = dwp.sections(sections, dwo_parent)?;
    return Ok(dump_info(w, &dwarf)?);
}

fn dump_info<R: Reader, W: Write + Send>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
) -> Result<HashMap<String, Vec<ArgOrMember>>>
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
            return Ok(HashMap::new());
        }
    };
    let mut res: HashMap<String, Vec<ArgOrMember>> = HashMap::new();
    for unit in units {
        for (fname, args) in dump_unit(w, unit, dwarf)? {
            res.insert(fname, args);
        }
    }
    return Ok(res);
}

fn dump_unit<R: Reader, W: Write>(
    w: &mut W,
    header: UnitHeader<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<HashMap<String, Vec<ArgOrMember>>> {
    let unit = match dwarf.unit(header) {
        Ok(unit) => unit,
        Err(err) => {
            writeln_error(w, dwarf, err.into(), "Failed to parse unit root entry")?;
            return Ok((HashMap::new()));
        }
    };

    let entries_result = loop_entries::<R, W>(unit, dwarf);
    if let Err(err) = entries_result {
        writeln_error(w, dwarf, err, "Failed to dump entries")?;
    }
    return entries_result
}

#[derive(Clone, Debug)]
struct Func {
    name: String,
    args: Vec<ArgOrMember>,
    addr: usize,
}

#[derive(Clone, Debug)]
struct Struct {
    name: String,
    args: Vec<ArgOrMember>,
}

#[derive(Clone, Debug)]
pub struct ArgOrMember { // argument or struct's member
    pub is_arg: bool,
    pub name: String,
    pub type_name: String,
    // For struct's member, offset in struct (DW_AT_data_member_location).
    // For argument, offset from rbp
    pub location: i64,
    pub bytes_cnt: u64,
}

#[repr(C)]
pub struct CArg {
    pub is_arg: bool,
    pub name: *const c_char,
    pub location: i64,
    pub type_name: *const c_char,
    pub bytes_cnt: u64,
}

pub fn convert_arg(arg: &ArgOrMember) -> CArg {
    let name = CString::new(arg.name.clone()).unwrap().into_raw();
    let type_name = CString::new(arg.type_name.clone()).unwrap().into_raw();
    CArg {
        is_arg: arg.is_arg,
        name,
        location: arg.location,
        type_name,
        bytes_cnt: arg.bytes_cnt,
    }
}

fn loop_entries<R: Reader, W: Write>(
    unit: gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<HashMap<String, Vec<ArgOrMember>>> {
    let mut func_addr2name: HashMap<usize, String> = HashMap::new();
    let mut func_or_struct_name_2_args_or_members: HashMap<String, Vec<ArgOrMember>> = HashMap::new();
    let mut cur_func_addr: usize = 0;
    let mut cur_funcname = "".to_string();
    let mut cur_struct_name = "".to_string();

    let mut entries = unit.entries_raw(None)?;
    while !entries.is_empty() {
        let abbrev = entries.read_abbreviation()?;

        let mut name = "".to_string();
        let mut offset = 0;
        let mut bytesize = 0;
        let mut type_name = "".to_string();

        for spec in abbrev.map(|x| x.attributes()).unwrap_or(&[]) {
            let attr = entries.read_attribute(*spec)?;
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_name::<R, W>(&attr, dwarf);
                }
                gimli::DW_AT_location | gimli::DW_AT_data_member_location => {
                    offset = get_arg_loc::<R, W>(&attr, &unit);
                }
                gimli::DW_AT_type => {
                    match abbrev.unwrap().tag()  {
                        gimli::DW_TAG_formal_parameter | gimli::DW_TAG_member => {
                            bytesize = get_arg_byte_size::<R, W>(&attr, &unit);
                            type_name = get_arg_type_name::<R, W>(&attr, &unit, dwarf);
                        }
                        _ => {}
                    }
                }
                gimli::DW_AT_low_pc => {
                    match attr.value() {
                        AttributeValue::Addr(address) => {
                            cur_func_addr = address as usize;
                        }
                        _ => {println!("addr err");}
                    }
                }
                _ => {}
            }
        }

        if let Some(rev_val) = abbrev {
            match rev_val.tag() {
                gimli::DW_TAG_subprogram => {
                    func_or_struct_name_2_args_or_members.insert(name.clone(), vec![]);
                    cur_funcname = name.clone();
                    func_addr2name.insert(cur_func_addr, name.clone());
                }
                gimli::DW_TAG_formal_parameter => {
                    let arg = ArgOrMember {is_arg: true,
                        name,
                        location: offset,
                        bytes_cnt: bytesize,
                        type_name
                    };
                    func_or_struct_name_2_args_or_members.get_mut(&*cur_funcname.clone()).unwrap().push(arg.clone());
                }
                gimli::DW_TAG_structure_type => {
                    func_or_struct_name_2_args_or_members.insert(name.clone(), vec![]);
                    cur_struct_name = name;
                }
                gimli::DW_TAG_member => {
                    let member = ArgOrMember{
                        is_arg: false,
                        name,
                        type_name,
                        location: offset,
                        bytes_cnt: bytesize,
                    };
                    func_or_struct_name_2_args_or_members.get_mut(&*cur_struct_name.clone()).unwrap().push(member.clone());
                }
                _ => {}
            }
        }
    }
    Ok(func_or_struct_name_2_args_or_members)
}

fn get_low_pc<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
) -> i64 {
    // match attr.name(({
    //     gimli::DW_AT_high_pc => {
    //         writeln!(w, "<offset-from-lowpc>{}", data)?;
    //     }
    // }
    return match attr.value() {
        gimli::AttributeValue::Exprloc(ref data) => {
            get_frame_offset_by_data::<R, W>(unit.encoding(), data).unwrap()
        }
        gimli::AttributeValue::Udata(data) => {
            data as i64
        }
        _ => { 0 }
    }
}

fn get_arg_loc<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
) -> i64 {
    return match attr.value() {
        gimli::AttributeValue::Exprloc(ref data) => {
            get_frame_offset_by_data::<R, W>(unit.encoding(), data).unwrap()
        }
        gimli::AttributeValue::Udata(data) => {
            data as i64
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

// from dump_attr_value?
fn get_name<R: Reader, W: Write> (
    attr: &gimli::Attribute<R>,
    dwarf: &gimli::Dwarf<R>,
) -> String {
    let value = attr.value();
    return match value {
        gimli::AttributeValue::String(s) => {
            s.to_string_lossy().unwrap().parse().unwrap()
        }
        gimli::AttributeValue::DebugStrRef(offset) => {
            if let Ok(s) = dwarf.debug_str.get_str(offset) {
                return s.to_string_lossy().unwrap().parse().unwrap();
            } else {
                return "".to_string();
            }
        }
        _ => {
            "name not caught".to_string()
        }
    }
}

fn get_arg_byte_size<R: Reader, W: Write>(
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
) -> u64 {
    let value = attr.value();
    if let gimli::AttributeValue::UnitRef(offset) = value {
        if let UnitSectionOffset::DebugInfoOffset(_) = offset.to_unit_section_offset(unit) {
            let byte_size = unit.entry(offset).unwrap().attr(gimli::DW_AT_byte_size).unwrap();
            if let Some(byte_size) = byte_size {
                return byte_size.value().udata_value().unwrap();
            }
        }
    }
    0
}

// これargじゃなくても、attributeにDW_AT_typeを持つやつなら使えそう
fn get_arg_type_name<R: Reader, W: Write>(
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> String {
    let value = attr.value();
    if let gimli::AttributeValue::UnitRef(offset) = value {
        if let UnitSectionOffset::DebugInfoOffset(_) = offset.to_unit_section_offset(unit) {
            let die = unit.entry(offset).unwrap();
            return get_type_name_from_die::<R, W>(die, unit, dwarf).unwrap();
        }
    }
    return "".to_string();
}

fn get_type_name_from_die<R: Reader, W: Write>(
    die: DebuggingInformationEntry<R>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<String> {
    match die.tag() {
        gimli::DW_TAG_base_type => {
            let type_name = die.attr(gimli::DW_AT_name)?;
            if let Some(typename) = type_name {
                return Ok(get_type_name::<R, W>(&typename, dwarf))
            }
            return Ok("base type name is none".to_string())
        }
        gimli::DW_TAG_pointer_type => {
            let base = die.attr(gimli::DW_AT_type);
            let base = &base.unwrap();
            if base.is_none() { // If void *, this becomes true
                return Ok("".to_string());
            }
            return Ok("Ptr[".to_string() + &get_arg_type_name::<R, W>(&base.clone().unwrap(), unit, dwarf) + "]")
        }
        gimli::DW_TAG_structure_type => {
            let type_name = die.attr(gimli::DW_AT_name)?;
            if let Some(typename) = type_name {
                return Ok(get_type_name::<R, W>(&typename, dwarf))
            }
            return Ok("struct type name is none".to_string())
        }
        _ => { return Ok("type not caught".to_string()) }
    }
}

fn get_type_name<R: Reader, W: Write>(
    typename: &gimli::Attribute<R>,
    dwarf: &gimli::Dwarf<R>,
) -> String {
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
