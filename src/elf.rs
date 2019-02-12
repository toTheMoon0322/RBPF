//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

extern crate elfkit;
extern crate num_traits;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use ebpf;
use elf::num_traits::FromPrimitive;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::mem;
use std::str;

// For more information on the BPF instruction set:
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

// Byte offset of the immediate field in the instruction
const BYTE_OFFSET_IMMEDIATE: usize = 4;
// Byte length of the immediate field
const BYTE_LENGTH_IMMEIDATE: usize = 4;
// Index of the text section in the vector of `SectionInfo`s (always the first)
const TEXT_SECTION_INDEX: usize = 0;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BPFRelocationType {
    /// none none
    R_BPF_NONE = 0,
    /// word64 S + A
    R_BPF_64_64 = 1,
    /// wordclass B + A
    R_BPF_64_RELATIVE = 8,
    /// word32 S + A
    R_BPF_64_32 = 10,
}

// Describes a section in the ELF and used for editing in place
struct SectionInfo<'a> {
    // Section virtual address as expressed in the ELF
    va: u64,
    // Length of the section in bytes
    len: u64,
    // Reference to the actual section bytes to be edited in place
    bytes: &'a mut Vec<u8>,
}

impl BPFRelocationType {
    fn from_x86_relocation_type(
        from: &elfkit::relocation::RelocationType,
    ) -> Option<BPFRelocationType> {
        match *from {
            elfkit::relocation::RelocationType::R_X86_64_NONE => {
                Some(BPFRelocationType::R_BPF_NONE)
            }
            elfkit::relocation::RelocationType::R_X86_64_64 => Some(BPFRelocationType::R_BPF_64_64),
            elfkit::relocation::RelocationType::R_X86_64_RELATIVE => {
                Some(BPFRelocationType::R_BPF_64_RELATIVE)
            }
            elfkit::relocation::RelocationType::R_X86_64_32 => Some(BPFRelocationType::R_BPF_64_32),
            _ => None,
        }
    }
}

/// Elf loader/relocator
pub struct EBpfElf {
    /// Elf representation
    elf: elfkit::Elf,
    calls: HashMap<u32, usize>,
}

impl EBpfElf {
    /// Fully loads an ELF, including validation and relocation
    pub fn load(elf_bytes: &[u8]) -> Result<(EBpfElf), Error> {
        let mut reader = Cursor::new(elf_bytes);
        let mut elf = match elfkit::Elf::from_reader(&mut reader) {
            Ok(elf) => elf,
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("Error: Failed to parse elf: {:?}", e),
            ))?,
        };
        if let Err(e) = elf.load_all(&mut reader) {
            Err(Error::new(
                ErrorKind::Other,
                format!("Error: Failed to parse elf: {:?}", e),
            ))?;
        }
        let mut ebpf_elf = EBpfElf {
            elf,
            calls: HashMap::new(),
        };
        ebpf_elf.validate()?;
        ebpf_elf.relocate()?;
        Ok(ebpf_elf)
    }

    /// Get the .text section bytes
    pub fn get_text_bytes(&self) -> Result<&[u8], Error> {
        EBpfElf::content_to_bytes(self.get_section(".text")?)
    }

    /// Get a vector of read-only data sections
    pub fn get_ro_sections(&self) -> Result<Vec<&[u8]>, Error> {
        self.elf
            .sections
            .iter()
            .filter(|section| section.name == b".rodata" || section.name == b".data.rel.ro")
            .map(EBpfElf::content_to_bytes)
            .collect()
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> Result<usize, Error> {
        let entry = self.elf.header.entry;
        let text = self.get_section(".text")?;
        if entry < text.header.addr || entry > text.header.addr + text.header.size {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Entrypoint out of bounds",
            ))?
        }
        let offset = (entry - text.header.addr) as usize;
        if offset % ebpf::INSN_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Entrypoint not multiple of instruction size",
            ))?
        }
        Ok(offset / ebpf::INSN_SIZE)
    }

    /// Get a symbol's instruction offset
    pub fn lookup_bpf_call(&self, hash: u32) -> Option<&usize> {
        self.calls.get(&hash)
    }

    /// Report information on a symbol that failed to be resolved
    pub fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), Error> {
        let file_offset =
            insn_offset * ebpf::INSN_SIZE + self.get_section(".text")?.header.addr as usize;

        let symbols = match self.get_section(".dynsym")?.content {
            elfkit::SectionContent::Symbols(ref bytes) => bytes,
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .dynsym contents",
            ))?,
        };

        let raw_relocation_bytes = match self.get_section(".rel.dyn")?.content {
            elfkit::SectionContent::Raw(ref bytes) => bytes,
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .rel.dyn contents",
            ))?,
        };
        let relocations = EBpfElf::get_relocations(&raw_relocation_bytes[..])?;

        let mut name = "Unknown";
        for relocation in relocations.iter() {
            match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                Some(BPFRelocationType::R_BPF_64_32) => {
                    if relocation.addr as usize == file_offset {
                        name = match str::from_utf8(&symbols[relocation.sym as usize].name) {
                            Ok(string) => string,
                            Err(_) => "Malformed symbol name",
                        };
                    }
                }
                _ => (),
            }
        }
        Err(Error::new(
            ErrorKind::Other,
            format!(
                "Error: Unresolved symbol ({}) at instruction #{:?} (ELF file offset {:#x})",
                name,
                file_offset / ebpf::INSN_SIZE,
                file_offset
            ),
        ))?
    }

    fn get_section(&self, name: &str) -> Result<(&elfkit::Section), Error> {
        match self
            .elf
            .sections
            .iter()
            .find(|section| section.name == name.as_bytes())
        {
            Some(section) => Ok(section),
            None => Err(Error::new(
                ErrorKind::Other,
                format!("Error: No {} section found", name),
            ))?,
        }
    }

    /// Converts a section's raw contents to a slice
    fn content_to_bytes(section: &elfkit::section::Section) -> Result<&[u8], Error> {
        match section.content {
            elfkit::SectionContent::Raw(ref bytes) => Ok(bytes),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get section contents",
            )),
        }
    }

    fn fixup_relative_calls(
        calls: &mut HashMap<u32, usize>,
        prog: &mut Vec<u8>,
    ) -> Result<(), Error> {
        for i in 0..prog.len() / ebpf::INSN_SIZE {
            let mut insn = ebpf::get_insn(prog, i);
            if insn.opc == 0x85 && insn.imm != -1 {
                let insn_idx = (i as i32 + 1 + insn.imm) as isize;
                if insn_idx < 0 || insn_idx as usize >= prog.len() / ebpf::INSN_SIZE {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!("Error: Relative jump at instruction {} is out of bounds", i),
                    ))?;
                }
                // use the instruction index as the key
                let mut key = [0u8; mem::size_of::<i64>()];
                LittleEndian::write_u64(&mut key, i as u64);
                let hash = ebpf::hash_symbol_name(&key);
                if calls.insert(hash, insn_idx as usize).is_some() {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Error: Relocation hash collision while encoding instruction {}",
                            i
                        ),
                    ))?;
                }

                insn.imm = hash as i32;
                prog.splice(
                    i * ebpf::INSN_SIZE..(i * ebpf::INSN_SIZE) + ebpf::INSN_SIZE,
                    insn.to_vec(),
                );
            }
        }
        Ok(())
    }

    /// Validates the ELF
    fn validate(&self) -> Result<(), Error> {
        // Validate header
        if self.elf.header.ident_class != elfkit::types::Class::Class64 {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong class",
            ))?;
        }
        if self.elf.header.ident_endianness != elfkit::types::Endianness::LittleEndian {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong endianess",
            ))?;
        }
        if self.elf.header.ident_abi != elfkit::types::Abi::SYSV {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong abi",
            ))?;
        }
        if self.elf.header.machine != elfkit::types::Machine::BPF {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong machine",
            ))?;
        }
        if self.elf.header.etype != elfkit::types::ElfType::DYN {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong type",
            ))?;
        }

        let text_sections: Vec<_> = self
            .elf
            .sections
            .iter()
            .filter(|section| section.name.starts_with(b".text"))
            .collect();
        if text_sections.len() > 1 {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Multiple text sections, consider removing llc option: -function-sections",
            ))?;
        }

        Ok(())
    }

    // Splits sections from the elf structure so that they may be edited concurrently and in place
    fn split_sections(sections: &mut [elfkit::Section]) -> Vec<&mut elfkit::Section> {
        let mut section_refs = Vec::new();
        if !sections.is_empty() {
            let (s, rest) = sections.split_at_mut(1);
            section_refs.push(&mut s[0]);
            section_refs.append(&mut EBpfElf::split_sections(rest));
        }
        section_refs
    }

    // Gets a mutable reference to a split section by name
    fn get_section_ref<'a, 'b>(
        sections: &'b mut Vec<&'a mut elfkit::Section>,
        name: &str,
    ) -> Result<(&'a mut elfkit::Section), Error> {
        match sections
            .iter()
            .enumerate()
            .find(|section| section.1.name == name.as_bytes())
        {
            Some((index, _)) => Ok(sections.remove(index)),
            None => Err(Error::new(
                ErrorKind::Other,
                format!("Error: No {:?} section", name),
            ))?,
        }
    }

    /// Creates a vector of load sections used to lookup which section
    /// contains a particular ELF virtual address
    fn get_load_sections<'a, 'b>(
        sections: &'a mut Vec<&'b mut elfkit::Section>,
    ) -> Result<(Vec<SectionInfo<'b>>), Error> {
        let mut section_infos = Vec::new();

        // .text section mandatory
        let mut text_section = EBpfElf::get_section_ref(sections, ".text")?;
        match (&mut text_section.content).as_raw_mut() {
            Some(bytes) => {
                section_infos.push(SectionInfo {
                    va: text_section.header.addr,
                    len: text_section.header.size,
                    bytes: bytes,
                });
            }
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .text contents",
            ))?,
        };

        // .rodata section optional
        let mut ro_data_section = EBpfElf::get_section_ref(sections, ".rodata");
        if let Ok(ro_data_section) = ro_data_section {
            match (&mut ro_data_section.content).as_raw_mut() {
                Some(bytes) => {
                    section_infos.push(SectionInfo {
                        va: ro_data_section.header.addr,
                        len: ro_data_section.header.size,
                        bytes: bytes,
                    });
                }
                None => (),
            };
        }

        // .data.rel.ro optional
        let mut data_rel_ro_section = EBpfElf::get_section_ref(sections, ".data.rel.ro");
        if let Ok(data_rel_ro_section) = data_rel_ro_section {
            match (&mut data_rel_ro_section.content).as_raw_mut() {
                Some(bytes) => {
                    section_infos.push(SectionInfo {
                        va: data_rel_ro_section.header.addr,
                        len: data_rel_ro_section.header.size,
                        bytes: bytes,
                    });
                }
                None => (),
            };
        }

        Ok(section_infos)
    }

    /// Relocates the ELF in-place
    fn relocate(&mut self) -> Result<(), Error> {
        // Split and build a mutable list of sections
        let mut sections = EBpfElf::split_sections(&mut self.elf.sections);
        let mut section_infos = EBpfElf::get_load_sections(&mut sections)?;

        // Fixup all program counter relative call instructions
        EBpfElf::fixup_relative_calls(&mut self.calls, &mut section_infos[0].bytes)?;

        // Fixup all the relocations in the relocation section if exists
        let relocations = match EBpfElf::get_section_ref(&mut sections, ".rel.dyn") {
            Ok(rel_dyn_section) => match (&mut rel_dyn_section.content).as_raw_mut() {
                Some(bytes) => Some(EBpfElf::get_relocations(&bytes[..])?),
                _ => None,
            },
            Err(_) => None,
        };

        if let Some(relocations) = relocations {
            // Get the symbol table up front
            let dynsym_section = EBpfElf::get_section_ref(&mut sections, ".dynsym")?;
            let symbols = match (&dynsym_section.content).as_symbols() {
                Some(bytes) => bytes,
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .text contents",
                ))?,
            };

            for relocation in relocations.iter() {
                match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                    Some(BPFRelocationType::R_BPF_64_RELATIVE) => {
                        // Raw relocation between sections.  The instruction being relocated contains
                        // the virtual address that it needs turned into a physical address.  Read it
                        // locate it in the ELF, convert to physical address

                        let mut target_section = None;
                        for (i, info) in section_infos.iter().enumerate() {
                            if info.va <= relocation.addr && relocation.addr < info.va + info.len {
                                target_section = Some(i);
                                break;
                            }
                        }
                        let target_section = match target_section {
                            Some(i) => i,
                            None => Err(Error::new(
                                ErrorKind::Other,
                                format!("Error: Relocation failed, no loadable section contains virtual address {:x?}", relocation.addr),
                            ))?,
                        };

                        // Offset into the section being relocated
                        let target_offset =
                            (relocation.addr - section_infos[target_section].va) as usize;

                        // Offset of the immediate field
                        let mut imm_offset = target_offset + BYTE_OFFSET_IMMEDIATE;

                        // Read the instruction's immediate field which contains virtual
                        // address to convert to physical
                        let refd_va = LittleEndian::read_u32(
                            &section_infos[target_section].bytes
                                [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                        ) as u64;

                        if refd_va == 0 {
                            // TODO Skipping this relocation, the virtual address found at this
                            // target location is zero, so don't know how to turn it into a valid physical
                            // address.
                            // println!(
                            //     "!! Skipped relocation section {:?} target_offset {:?} va {:x?} Referenced va ({:x?}))",
                            //     target_section, target_offset, relocation.addr, refd_va
                            // );
                            continue;
                        }

                        // Find the section that contains the virtual address to convert
                        let mut refd_section = None;
                        for (i, info) in section_infos.iter().enumerate() {
                            if info.va <= refd_va && refd_va < info.va + info.len {
                                refd_section = Some(i);
                                break;
                            }
                        }
                        let refd_section = match refd_section {
                            Some(i) => i,
                            None => Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Error: Relocation to section {:?} at virtual address {:x?} failed, no loadable section contains virtual address {:x?}",
                                    target_section, relocation.addr, refd_va
                                ),
                            ))?,
                        };

                        // Convert into an offset into the referenced section by subtracting
                        // the section's base virtual address
                        let refd_offset = refd_va - section_infos[refd_section].va;

                        // Calculate the symbol's physical address within the referenced section
                        let refd_pa =
                            section_infos[refd_section].bytes.as_ptr() as u64 + refd_offset;

                        // println!(
                        //     "Relocation section {:?} off {:x?} va {:x?} pa {:x?} Referenced section {:?} offset {:x?} va {:x?} pa {:x?}",
                        //     target_section, target_offset, relocation.addr, section_infos[target_section].bytes.as_ptr() as usize + target_offset, refd_section, refd_offset, refd_va, refd_pa
                        // );

                        // Write the physical address back into the target location
                        if target_section == TEXT_SECTION_INDEX {
                            // Instruction lddw spans two instruction slots, split the
                            // physical address into a high and low and write into both slot's imm field

                            LittleEndian::write_u32(
                                &mut section_infos[target_section].bytes
                                    [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                                (refd_pa & 0xFFFFFFFF) as u32,
                            );
                            LittleEndian::write_u32(
                                &mut section_infos[target_section].bytes[imm_offset
                                    + ebpf::INSN_SIZE
                                    ..imm_offset + ebpf::INSN_SIZE + BYTE_LENGTH_IMMEIDATE],
                                (refd_pa >> 32) as u32,
                            );
                        } else {
                            // 64 bit memory location, write entire 64 bit physical address directly
                            LittleEndian::write_u64(
                                &mut section_infos[target_section].bytes
                                    [target_offset..target_offset + mem::size_of::<u64>()],
                                refd_pa,
                            );
                        }
                    }
                    Some(BPFRelocationType::R_BPF_64_32) => {
                        // The .text section has an unresolved call to symbol instruction

                        // Hash the symbol name and stick it into the call instruction's imm
                        // field.  Later that hash will be used to look up the function location.

                        let symbol = &symbols[relocation.sym as usize];
                        let hash = ebpf::hash_symbol_name(&symbol.name);
                        let insn_offset = (relocation.addr - section_infos[0].va) as usize;
                        let imm_offset = insn_offset + BYTE_OFFSET_IMMEDIATE;
                        LittleEndian::write_u32(
                            &mut section_infos[0].bytes
                                [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                            hash,
                        );
                        if symbol.stype == elfkit::types::SymbolType::FUNC && symbol.value != 0 {
                            self.calls.insert(
                                hash,
                                (symbol.value - section_infos[0].va) as usize / ebpf::INSN_SIZE,
                            );
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Unhandled relocation type",
                    ))?,
                }
            }
        }

        Ok(())
    }

    /// Builds a vector of Relocations from raw bytes
    ///
    /// Elfkit does not form BPF relocations and instead just provides raw bytes
    fn get_relocations<R>(mut io: R) -> Result<Vec<elfkit::Relocation>, Error>
    where
        R: std::io::Read,
    {
        let mut relocs = Vec::new();

        while let Ok(addr) = io.read_u64::<LittleEndian>() {
            let info = match io.read_u64::<LittleEndian>() {
                Ok(v) => v,
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to read relocation info",
                ))?,
            };

            let sym = (info >> 32) as u32;
            let rtype = (info & 0xffffffff) as u32;
            let rtype = match elfkit::relocation::RelocationType::from_u32(rtype) {
                Some(v) => v,
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: unknown relocation type",
                ))?,
            };

            let addend = 0; // BPF relocation don't have an addend

            relocs.push(elfkit::relocation::Relocation {
                addr,
                sym,
                rtype,
                addend,
            });
        }

        Ok(relocs)
    }

    #[allow(dead_code)]
    fn dump_data(name: &str, prog: &[u8]) {
        let mut eight_bytes: Vec<u8> = Vec::new();
        println!("{}", name);
        for i in prog.iter() {
            if eight_bytes.len() >= 7 {
                println!("{:02X?}", eight_bytes);
                eight_bytes.clear();
            } else {
                eight_bytes.push(i.clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_validate() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).unwrap();

        elf.validate().expect("validation failed");
        elf.elf.header.ident_class = elfkit::types::Class::Class32;
        elf.validate().expect_err("allowed bad class");
        elf.elf.header.ident_class = elfkit::types::Class::Class64;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::BigEndian;
        elf.validate().expect_err("allowed big endian");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::LittleEndian;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_abi = elfkit::types::Abi::ARM;
        elf.validate().expect_err("allowed wrong abi");
        elf.elf.header.ident_abi = elfkit::types::Abi::SYSV;
        elf.validate().expect("validation failed");
        elf.elf.header.machine = elfkit::types::Machine::QDSP6;
        elf.validate().expect_err("allowed wrong machine");
        elf.elf.header.machine = elfkit::types::Machine::BPF;
        elf.validate().expect("validation failed");
        elf.elf.header.etype = elfkit::types::ElfType::REL;
        elf.validate().expect_err("allowed wrong type");
        elf.elf.header.etype = elfkit::types::ElfType::DYN;
        elf.validate().expect("validation failed");
    }

    #[test]
    fn test_relocate() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        EBpfElf::load(&elf_bytes).expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        assert_eq!(
            0,
            elf.get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );
        elf.elf.header.entry = elf.elf.header.entry + 8;
        assert_eq!(
            1,
            elf.get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint out of bounds")]
    fn test_entrypoint_before_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint out of bounds")]
    fn test_entrypoint_after_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint not multiple of instruction size")]
    fn test_entrypoint_not_multiple_of_instruction_size() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = elf.elf.header.entry + ebpf::INSN_SIZE as u64 + 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    fn test_fixup_relative_calls_back() {
        // call -2
        let mut calls: HashMap<u32, usize> = HashMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 4);

        // // call +6
        let mut calls: HashMap<u32, usize> = HashMap::new();
        prog.splice(44.., vec![0xfa, 0xff, 0xff, 0xff]);
        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 0);
    }

    #[test]
    fn test_fixup_relative_calls_forward() {
        // call +0
        let mut calls: HashMap<u32, usize> = HashMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 1);

        // call +4
        let mut calls: HashMap<u32, usize> = HashMap::new();
        prog.splice(4..8, vec![0x04, 0x00, 0x00, 0x00]);
        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 5);
    }

    #[test]
    #[should_panic(expected = "Error: Relative jump at instruction 0 is out of bounds")]
    fn test_fixup_relative_calls_out_of_bounds_forward() {
        let mut calls: HashMap<u32, usize> = HashMap::new();
        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 1);
    }

    #[test]
    #[should_panic(expected = "Error: Relative jump at instruction 5 is out of bounds")]
    fn test_fixup_relative_calls_out_of_bounds_back() {
        let mut calls: HashMap<u32, usize> = HashMap::new();
        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 4);
    }
}
