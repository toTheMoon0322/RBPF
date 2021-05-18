// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unreachable_code)]

extern crate libc;

use std::fmt::Debug;
use std::mem;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::fmt::Error as FormatterError;
use std::ops::{Index, IndexMut};

use crate::{
    vm::{Config, Executable, ProgramResult, InstructionMeter, Tracer, DynTraitFatPointer, SYSCALL_CONTEXT_OBJECTS_OFFSET},
    ebpf::{self, INSN_SIZE, FIRST_SCRATCH_REG, SCRATCH_REGS, STACK_REG, MM_STACK_START},
    error::{UserDefinedError, EbpfError},
    memory_region::{AccessType, MemoryMapping},
    user_error::UserError,
    x86::*,
};

/// Argument for executing a eBPF JIT-compiled program
pub struct JitProgramArgument<'a> {
    /// The MemoryMapping to be used to run the compiled code
    pub memory_mapping: MemoryMapping<'a>,
    /// Pointers to the context objects of syscalls
    pub syscall_context_objects: [*const u8; 0],
}

struct JitProgramSections {
    pc_section: &'static mut [u64],
    text_section: &'static mut [u8],
}

impl JitProgramSections {
    fn new(pc: usize, code_size: usize) -> Self {
        let _pc_loc_table_size = round_to_page_size(pc * 8);
        let _code_size = round_to_page_size(code_size);
        #[cfg(windows)]
        {
            Self {
                pc_section: &mut [],
                text_section: &mut [],
            }
        }
        #[cfg(not(windows))]
        unsafe {
            let mut raw: *mut libc::c_void = std::ptr::null_mut();
            libc::posix_memalign(&mut raw, PAGE_SIZE, _pc_loc_table_size + _code_size);
            std::ptr::write_bytes(raw, 0x00, _pc_loc_table_size);
            std::ptr::write_bytes(raw.add(_pc_loc_table_size), 0xcc, _code_size); // Populate with debugger traps
            Self {
                pc_section: std::slice::from_raw_parts_mut(raw as *mut u64, pc),
                text_section: std::slice::from_raw_parts_mut(raw.add(_pc_loc_table_size) as *mut u8, _code_size),
            }
        }
    }

    fn seal(&mut self) {
        #[cfg(not(windows))]
        if !self.pc_section.is_empty() {
            unsafe {
                libc::mprotect(self.pc_section.as_mut_ptr() as *mut _, round_to_page_size(self.pc_section.len()), libc::PROT_READ);
                libc::mprotect(self.text_section.as_mut_ptr() as *mut _, round_to_page_size(self.text_section.len()), libc::PROT_EXEC | libc::PROT_READ);
            }
        }
    }
}

impl Drop for JitProgramSections {
    fn drop(&mut self) {
        #[cfg(not(windows))]
        if !self.pc_section.is_empty() {
            unsafe {
                libc::mprotect(self.pc_section.as_mut_ptr() as *mut _, round_to_page_size(self.pc_section.len()), libc::PROT_READ | libc::PROT_WRITE);
                libc::mprotect(self.text_section.as_mut_ptr() as *mut _, round_to_page_size(self.text_section.len()), libc::PROT_READ | libc::PROT_WRITE);
                libc::free(self.pc_section.as_ptr() as *mut _);
            }
        }
    }
}

/// eBPF JIT-compiled program
pub struct JitProgram<E: UserDefinedError, I: InstructionMeter> {
    /// Holds and manages the protected memory
    _sections: JitProgramSections,
    /// Call this with JitProgramArgument to execute the compiled code
    pub main: unsafe fn(&ProgramResult<E>, u64, &JitProgramArgument, &mut I) -> i64,
}

impl<E: UserDefinedError, I: InstructionMeter> Debug for JitProgram<E, I> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", &self.main as *const _))
    }
}

impl<E: UserDefinedError, I: InstructionMeter> PartialEq for JitProgram<E, I> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.main as *const u8, other.main as *const u8)
    }
}

impl<E: UserDefinedError, I: InstructionMeter> JitProgram<E, I> {
    pub fn new(executable: &dyn Executable<E, I>) -> Result<Self, EbpfError<E>> {
        let program = executable.get_text_bytes()?.1;
        let mut jit = JitCompiler::new(program, executable.get_config());
        jit.compile::<E, I>(executable)?;
        let main = unsafe { mem::transmute(jit.result.text_section.as_ptr()) };
        Ok(Self {
            _sections: jit.result,
            main,
        })
    }
}

// Special values for target_pc in struct Jump
const TARGET_PC_TRACE: usize = std::usize::MAX - 13;
const TARGET_PC_TRANSLATE_PC: usize = std::usize::MAX - 12;
const TARGET_PC_TRANSLATE_PC_LOOP: usize = std::usize::MAX - 11;
const TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = std::usize::MAX - 10;
const TARGET_PC_CALL_DEPTH_EXCEEDED: usize = std::usize::MAX - 9;
const TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT: usize = std::usize::MAX - 8;
const TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION: usize = std::usize::MAX - 7;
const TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION: usize = std::usize::MAX - 6;
const TARGET_PC_DIV_BY_ZERO: usize = std::usize::MAX - 5;
const TARGET_PC_EXCEPTION_AT: usize = std::usize::MAX - 4;
const TARGET_PC_SYSCALL_EXCEPTION: usize = std::usize::MAX - 3;
const TARGET_PC_EXIT: usize = std::usize::MAX - 2;
const TARGET_PC_EPILOGUE: usize = std::usize::MAX - 1;

// Special registers:
// RDI Instruction meter (BPF pc limit)
// RBP Stores a constant pointer to original RSP-8
// R10 Stores a constant pointer to JitProgramArgument
// R11 Scratch register for offsetting

const REGISTER_MAP: [u8; 11] = [
    RAX, // 0  return value
    ARGUMENT_REGISTERS[1], // 1
    ARGUMENT_REGISTERS[2], // 2
    ARGUMENT_REGISTERS[3], // 3
    ARGUMENT_REGISTERS[4], // 4
    ARGUMENT_REGISTERS[5], // 5
    CALLEE_SAVED_REGISTERS[2], // 6
    CALLEE_SAVED_REGISTERS[3], // 7
    CALLEE_SAVED_REGISTERS[4], // 8
    CALLEE_SAVED_REGISTERS[5], // 9
    RBX, // 10 stack pointer
];

#[inline]
pub fn emit<T, E: UserDefinedError>(jit: &mut JitCompiler, data: T) -> Result<(), EbpfError<E>> {
    let size = mem::size_of::<T>() as usize;
    if jit.offset_in_text_section + size > jit.result.text_section.len() {
        return Err(EbpfError::ExhausedTextSegment(jit.pc));
    }
    unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = jit.result.text_section.as_ptr().add(jit.offset_in_text_section) as *mut T;
        *ptr = data as T;
    }
    jit.offset_in_text_section += size;
    Ok(())
}

pub fn emit_variable_length<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, data: u64) -> Result<(), EbpfError<E>> {
    match size {
        OperandSize::S0 => Ok(()),
        OperandSize::S8 => emit::<u8, E>(jit, data as u8),
        OperandSize::S16 => emit::<u16, E>(jit, data as u16),
        OperandSize::S32 => emit::<u32, E>(jit, data as u32),
        OperandSize::S64 => emit::<u64, E>(jit, data),
    }
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum OperandSize {
    S0  = 0,
    S8  = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

#[inline]
fn emit_alu<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, opcode: u8, source: u8, destination: u8, immediate: i32, indirect: Option<X86IndirectAccess>) -> Result<(), EbpfError<E>> {
    X86Instruction {
        size,
        opcode,
        first_operand: source,
        second_operand: destination,
        immediate_size: match opcode {
            0xc1 => OperandSize::S8,
            0x81 | 0xc7 => OperandSize::S32,
            0xf7 if source == 0 => OperandSize::S32,
            _ => OperandSize::S0,
        },
        immediate: immediate as i64,
        indirect,
        ..X86Instruction::default()
    }.emit(jit)
}

#[inline]
fn emit_jump_offset<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    jit.text_section_jumps.push(Jump { location: jit.offset_in_text_section, target_pc });
    emit::<u32, E>(jit, 0)
}

#[inline]
fn emit_jcc<E: UserDefinedError>(jit: &mut JitCompiler, code: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0x0f)?;
    emit::<u8, E>(jit, code)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn emit_jmp<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0xe9)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn emit_call<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0xe8)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn set_anchor(jit: &mut JitCompiler, target: usize) {
    jit.handler_anchors.insert(target, jit.offset_in_text_section);
}

/* Explaination of the Instruction Meter

    The instruction meter serves two purposes: First, measure how many BPF instructions are
    executed (profiling) and second, limit this number by stopping the program with an exception
    once a given threshold is reached (validation). One approach would be to increment and
    validate the instruction meter before each instruction. However, this would heavily impact
    performance. Thus, we only profile and validate the instruction meter at branches.

    For this, we implicitly sum up all the instructions between two branches.
    It is easy to know the end of such a slice of instructions, but how do we know where it
    started? There could be multiple ways to jump onto a path which all lead to the same final
    branch. This is, where the integral technique comes in. The program is basically a sequence
    of instructions with the x-axis being the program counter (short "pc"). The cost function is
    a constant function which returns one for every point on the x axis. Now, the instruction
    meter needs to calculate the definite integral of the cost function between the start and the
    end of the current slice of instructions. For that we need the indefinite integral of the cost
    function. Fortunately, the derivative of the pc is the cost function (it increases by one for
    every instruction), thus the pc is an antiderivative of the the cost function and a valid
    indefinite integral. So, to calculate an definite integral of the cost function, we just need
    to subtract the start pc from the end pc of the slice. This difference can then be subtracted
    from the remaining instruction counter until it goes below zero at which point it reaches
    the instruction meter limit. Ok, but how do we know the start of the slice at the end?

    The trick is: We do not need to know. As subtraction and addition are associative operations,
    we can reorder them, even beyond the current branch. Thus, we can simply account for the
    amount the start will subtract at the next branch by already adding that to the remaining
    instruction counter at the current branch. So, every branch just subtracts its current pc
    (the end of the slice) and adds the target pc (the start of the next slice) to the remaining
    instruction counter. This way, no branch needs to know the pc of the last branch explicitly.
    Another way to think about this trick is as follows: The remaining instruction counter now
    measures what the maximum pc is, that we can reach with the remaining budget after the last
    branch.

    One problem are conditional branches. There are basically two ways to handle them: Either,
    only do the profiling if the branch is taken, which requires two jumps (one for the profiling
    and one to get to the target pc). Or, always profile it as if the jump to the target pc was
    taken, but then behind the conditional branch, undo the profiling (as it was not taken). We
    use the second method and the undo profiling is the same as the normal profiling, just with
    reversed plus and minus signs.

    Another special case to keep in mind are return instructions. They would require us to know
    the return address (target pc), but in the JIT we already converted that to be a host address.
    Of course, one could also save the BPF return address on the stack, but an even simpler
    solution exists: Just count as if you were jumping to an specific target pc before the exit,
    and then after returning use the undo profiling. The trick is, that the undo profiling now
    has the current pc which is the BPF return address. The virtual target pc we count towards
    and undo again can be anything, so we just set it to zero.
*/

#[inline]
fn emit_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: Option<usize>) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter {
        match target_pc {
            Some(target_pc) => {
                emit_alu(jit, OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i32 - jit.pc as i32 - 1, None)?; // instruction_meter += target_pc - (jit.pc + 1);
            },
            None => { // If no constant target_pc is given, it is expected to be on the stack instead
                X86Instruction::pop(R11).emit(jit)?;
                emit_alu(jit, OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], jit.pc as i32 + 1, None)?; // instruction_meter -= jit.pc + 1;
                emit_alu(jit, OperandSize::S64, 0x01, R11, ARGUMENT_REGISTERS[0], jit.pc as i32, None)?; // instruction_meter += target_pc;
            },
        }
    }
    Ok(())
}

#[inline]
fn emit_validate_and_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, exclusive: bool, target_pc: Option<usize>) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter {
        X86Instruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1, None).emit(jit)?;
        emit_jcc(jit, if exclusive { 0x82 } else { 0x86 }, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS)?;
        emit_profile_instruction_count(jit, target_pc)?;
    }
    Ok(())
}

#[inline]
fn emit_undo_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], jit.pc as i32 + 1 - target_pc as i32, None)?; // instruction_meter += (jit.pc + 1) - target_pc;
    }
    Ok(())
}

#[inline]
fn emit_profile_instruction_count_of_exception<E: UserDefinedError>(jit: &mut JitCompiler) -> Result<(), EbpfError<E>> {
    emit_alu(jit, OperandSize::S64, 0x81, 0, R11, 1, None)?;
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperandSize::S64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, None)?; // instruction_meter -= pc + 1;
    }
    Ok(())
}

#[inline]
fn emit_conditional_branch_reg<E: UserDefinedError>(jit: &mut JitCompiler, op: u8, src: u8, dst: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc))?;
    X86Instruction::cmp(OperandSize::S64, src, dst, None).emit(jit)?;
    emit_jcc(jit, op, target_pc)?;
    emit_undo_profile_instruction_count(jit, target_pc)
}

#[inline]
fn emit_conditional_branch_imm<E: UserDefinedError>(jit: &mut JitCompiler, op: u8, imm: i32, dst: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc))?;
    X86Instruction::cmp_immediate(OperandSize::S64, dst, imm as i64, None).emit(jit)?;
    emit_jcc(jit, op, target_pc)?;
    emit_undo_profile_instruction_count(jit, target_pc)
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32),
    RegisterPlusConstant64(u8, i64),
    Constant64(i64),
}

#[inline]
fn emit_bpf_call<E: UserDefinedError>(jit: &mut JitCompiler, dst: Value, number_of_instructions: usize) -> Result<(), EbpfError<E>> {
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS) {
        X86Instruction::push(*reg).emit(jit)?;
    }
    X86Instruction::push(REGISTER_MAP[STACK_REG]).emit(jit)?;

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            X86Instruction::push(REGISTER_MAP[0]).emit(jit)?;
            if reg != REGISTER_MAP[0] {
                X86Instruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]).emit(jit)?;
            }
            // Force alignment of RAX
            emit_alu(jit, OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i32 - 1), None)?; // RAX &= !(INSN_SIZE - 1);
            // Store PC in case the bounds check fails
            X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;
            // Upper bound check
            // if(RAX >= jit.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
            X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[STACK_REG], jit.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64).emit(jit)?;
            X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None).emit(jit)?;
            emit_jcc(jit, 0x83, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT)?;
            // Lower bound check
            // if(RAX < jit.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
            X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[STACK_REG], jit.program_vm_addr as i64).emit(jit)?;
            X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None).emit(jit)?;
            emit_jcc(jit, 0x82, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT)?;
            // Calculate offset relative to instruction_addresses
            emit_alu(jit, OperandSize::S64, 0x29, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None)?; // RAX -= jit.program_vm_addr;
            if jit.config.enable_instruction_meter {
                // Calculate the target_pc to update the instruction_meter
                let shift_amount = INSN_SIZE.trailing_zeros();
                debug_assert_eq!(INSN_SIZE, 1<<shift_amount);
                X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]).emit(jit)?;
                emit_alu(jit, OperandSize::S64, 0xc1, 5, REGISTER_MAP[STACK_REG], shift_amount as i32, None)?;
                X86Instruction::push(REGISTER_MAP[STACK_REG]).emit(jit)?;
            }
            // Load host target_address from JitProgramArgument.instruction_addresses
            debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
            X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]).emit(jit)?;
            X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[STACK_REG], jit.result.pc_section.as_ptr() as i64).emit(jit)?;
            emit_alu(jit, OperandSize::S64, 0x01, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None)?; // RAX += jit.result.pc_section;
            X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0)).emit(jit)?; // RAX = jit.result.pc_section[RAX / 8];
        },
        Value::Constant64(_target_pc) => {},
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], X86IndirectAccess::Offset(-8 * CALLEE_SAVED_REGISTERS.len() as i32)).emit(jit)?; // load stack_ptr
    emit_alu(jit, OperandSize::S64, 0x81, 4, REGISTER_MAP[STACK_REG], !(jit.config.stack_frame_size as i32 * 2 - 1), None)?; // stack_ptr &= !(jit.config.stack_frame_size * 2 - 1);
    emit_alu(jit, OperandSize::S64, 0x81, 0, REGISTER_MAP[STACK_REG], jit.config.stack_frame_size as i32 * 3, None)?; // stack_ptr += jit.config.stack_frame_size * 3;
    X86Instruction::store(OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, X86IndirectAccess::Offset(-8 * CALLEE_SAVED_REGISTERS.len() as i32)).emit(jit)?; // store stack_ptr

    // if(stack_ptr >= MM_STACK_START + jit.config.max_call_depth * jit.config.stack_frame_size * 2) throw EbpfError::CallDepthExeeded;
    X86Instruction::load_immediate(OperandSize::S64, R11, MM_STACK_START as i64 + (jit.config.max_call_depth * jit.config.stack_frame_size * 2) as i64).emit(jit)?;
    X86Instruction::cmp(OperandSize::S64, R11, REGISTER_MAP[STACK_REG], None).emit(jit)?;
    // Store PC in case the bounds check fails
    X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;
    emit_jcc(jit, 0x83, TARGET_PC_CALL_DEPTH_EXCEEDED)?;

    match dst {
        Value::Register(_reg) => {
            emit_validate_and_profile_instruction_count(jit, false, None)?;

            X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(jit)?;
            X86Instruction::pop(REGISTER_MAP[0]).emit(jit)?;

            // callq *%r11
            emit::<u8, E>(jit, 0x41)?;
            emit::<u8, E>(jit, 0xff)?;
            emit::<u8, E>(jit, 0xd3)?;
        },
        Value::Constant64(target_pc) => {
            emit_validate_and_profile_instruction_count(jit, false, Some(target_pc as usize))?;

            X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64).emit(jit)?;
            emit_call(jit, target_pc as usize)?;
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }
    emit_undo_profile_instruction_count(jit, 0)?;

    X86Instruction::pop(REGISTER_MAP[STACK_REG]).emit(jit)?;
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
        X86Instruction::pop(*reg).emit(jit)?;
    }
    Ok(())
}

struct Argument {
    index: usize,
    value: Value,
}

#[inline]
fn emit_rust_call<E: UserDefinedError>(jit: &mut JitCompiler, function: *const u8, arguments: &[Argument], return_reg: Option<u8>, check_exception: bool) -> Result<(), EbpfError<E>> {
    let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
    if let Some(reg) = return_reg {
        let dst = saved_registers.iter().position(|x| *x == reg);
        debug_assert!(dst.is_some());
        if let Some(dst) = dst {
            saved_registers.remove(dst);
        }
    }

    // Pass arguments via stack
    for argument in arguments {
        if argument.index < ARGUMENT_REGISTERS.len() {
            continue;
        }
        match argument.value {
            Value::Register(reg) => {
                let src = saved_registers.iter().position(|x| *x == reg);
                debug_assert!(src.is_some());
                if let Some(src) = src {
                    saved_registers.remove(src);
                }
                let dst = saved_registers.len() - (argument.index - ARGUMENT_REGISTERS.len());
                saved_registers.insert(dst, reg);
            },
            Value::RegisterIndirect(reg, offset) => {
                X86Instruction::load(OperandSize::S64, reg, R11, X86IndirectAccess::Offset(offset)).emit(jit)?;
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }
    }

    // Save registers on stack
    for reg in saved_registers.iter() {
        X86Instruction::push(*reg).emit(jit)?;
    }

    // Pass arguments via registers
    for argument in arguments {
        if argument.index >= ARGUMENT_REGISTERS.len() {
            continue;
        }
        let dst = ARGUMENT_REGISTERS[argument.index];
        match argument.value {
            Value::Register(reg) => {
                if reg != dst {
                    X86Instruction::mov(OperandSize::S64, reg, dst).emit(jit)?;
                }
            },
            Value::RegisterIndirect(reg, offset) => {
                X86Instruction::load(OperandSize::S64, reg, dst, X86IndirectAccess::Offset(offset)).emit(jit)?;
            },
            Value::RegisterPlusConstant64(reg, offset) => {
                X86Instruction::load_immediate(OperandSize::S64, R11, offset).emit(jit)?;
                emit_alu(jit, OperandSize::S64, 0x01, reg, R11, 0, None)?;
                X86Instruction::mov(OperandSize::S64, R11, dst).emit(jit)?;
            },
            Value::Constant64(value) => {
                X86Instruction::load_immediate(OperandSize::S64, dst, value).emit(jit)?;
            },
        }
    }

    // TODO use direct call when possible
    X86Instruction::load_immediate(OperandSize::S64, RAX, function as i64).emit(jit)?;
    // callq *%rax
    emit::<u8, E>(jit, 0xff)?;
    emit::<u8, E>(jit, 0xd0)?;

    if let Some(reg) = return_reg {
        X86Instruction::mov(OperandSize::S64, RAX, reg).emit(jit)?;
    }

    // Restore registers from stack
    for reg in saved_registers.iter().rev() {
        X86Instruction::pop(*reg).emit(jit)?;
    }

    if check_exception {
        // Test if result indicates that an error occured
        X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(jit)?;
        X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))).emit(jit)?;
    }
    Ok(())
}

#[inline]
fn emit_address_translation<E: UserDefinedError>(jit: &mut JitCompiler, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) -> Result<(), EbpfError<E>> {
    emit_rust_call(jit, MemoryMapping::map::<UserError> as *const u8, &[
        Argument { index: 3, value: vm_addr }, // Specify first as the src register could be overwritten by other arguments
        Argument { index: 0, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
        Argument { index: 1, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
        Argument { index: 2, value: Value::Constant64(access_type as i64) },
        Argument { index: 4, value: Value::Constant64(len as i64) },
    ], None, true)?;

    // Throw error if the result indicates one
    X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;
    emit_jcc(jit, 0x85, TARGET_PC_EXCEPTION_AT)?;

    // Store Ok value in result register
    X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(jit)?;
    X86Instruction::load(OperandSize::S64, R11, host_addr, X86IndirectAccess::Offset(8)).emit(jit)
}

fn emit_shift<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, opc: u8, src: u8, dst: u8) -> Result<(), EbpfError<E>> {
    if size == OperandSize::S32 {
        emit_alu(jit, OperandSize::S32, 0x81, 4, dst, -1, None)?; // Mask to 32 bit
    }
    if src == RCX {
        if dst == RCX {
            emit_alu(jit, size, 0xd3, opc, dst, 0, None)
        } else {
            X86Instruction::mov(OperandSize::S64, RCX, R11).emit(jit)?;
            emit_alu(jit, size, 0xd3, opc, dst, 0, None)?;
            X86Instruction::mov(OperandSize::S64, R11, RCX).emit(jit)
        }
    } else if dst == RCX {
        X86Instruction::mov(OperandSize::S64, src, R11).emit(jit)?;
        X86Instruction::xchg(OperandSize::S64, src, RCX).emit(jit)?;
        emit_alu(jit, size, 0xd3, opc, src, 0, None)?;
        X86Instruction::mov(OperandSize::S64, src, RCX).emit(jit)?;
        X86Instruction::mov(OperandSize::S64, R11, src).emit(jit)
    } else {
        X86Instruction::mov(OperandSize::S64, RCX, R11).emit(jit)?;
        X86Instruction::mov(OperandSize::S64, src, RCX).emit(jit)?;
        emit_alu(jit, size, 0xd3, opc, dst, 0, None)?;
        X86Instruction::mov(OperandSize::S64, R11, RCX).emit(jit)
    }
}

fn emit_muldivmod<E: UserDefinedError>(jit: &mut JitCompiler, opc: u8, src: u8, dst: u8, imm: Option<i32>) -> Result<(), EbpfError<E>> {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let size = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperandSize::S64 } else { OperandSize::S32 };

    if (div || modrm) && imm.is_none() {
        // Save pc
        X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;

        // test src,src
        emit_alu(jit, size, 0x85, src, src, 0, None)?;

        // Jump if src is zero
        emit_jcc(jit, 0x84, TARGET_PC_DIV_BY_ZERO)?;
    }

    if dst != RAX {
        X86Instruction::push(RAX).emit(jit)?;
    }
    if dst != RDX {
        X86Instruction::push(RDX).emit(jit)?;
    }

    if let Some(imm) = imm {
        X86Instruction::load_immediate(OperandSize::S64, R11, imm as i64).emit(jit)?;
    } else {
        X86Instruction::mov(OperandSize::S64, src, R11).emit(jit)?;
    }

    if dst != RAX {
        X86Instruction::mov(OperandSize::S64, dst, RAX).emit(jit)?;
    }

    if div || modrm {
        // xor %edx,%edx
        emit_alu(jit, size, 0x31, RDX, RDX, 0, None)?;
    }

    emit_alu(jit, size, 0xf7, if mul { 4 } else { 6 }, R11, 0, None)?;

    if dst != RDX {
        if modrm {
            X86Instruction::mov(OperandSize::S64, RDX, dst).emit(jit)?;
        }
        X86Instruction::pop(RDX).emit(jit)?;
    }
    if dst != RAX {
        if div || mul {
            X86Instruction::mov(OperandSize::S64, RAX, dst).emit(jit)?;
        }
        X86Instruction::pop(RAX).emit(jit)?;
    }

    if size == OperandSize::S32 && opc & ebpf::BPF_ALU_OP_MASK == ebpf::BPF_MUL {
        X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(jit)?;
    }
    Ok(())
}

#[inline]
fn emit_set_exception_kind<E: UserDefinedError>(jit: &mut JitCompiler, err: EbpfError<E>) -> Result<(), EbpfError<E>> {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(jit)?;
    X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(8), err_kind as i64).emit(jit)
}

const PAGE_SIZE: usize = 4096;
fn round_to_page_size(value: usize) -> usize {
    (value + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
}

#[derive(Debug)]
struct Jump {
    location: usize,
    target_pc: usize,
}
impl Jump {
    fn get_target_offset(&self, jit: &JitCompiler) -> u64 {
        match jit.handler_anchors.get(&self.target_pc) {
            Some(target) => *target as u64,
            None         => jit.result.pc_section[self.target_pc]
        }
    }
}

pub struct JitCompiler {
    result: JitProgramSections,
    pc_section_jumps: Vec<Jump>,
    text_section_jumps: Vec<Jump>,
    offset_in_text_section: usize,
    pc: usize,
    program_vm_addr: u64,
    handler_anchors: HashMap<usize, usize>,
    config: Config,
}

impl Index<usize> for JitCompiler {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.result.text_section[_index]
    }
}

impl IndexMut<usize> for JitCompiler {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.result.text_section[_index]
    }
}

impl std::fmt::Debug for JitCompiler {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT text_section: [")?;
        for i in self.result.text_section as &[u8] {
            fmt.write_fmt(format_args!(" {:#04x},", i))?;
        };
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT state")
            .field("memory", &self.result.pc_section.as_ptr())
            .field("pc", &self.pc)
            .field("offset_in_text_section", &self.offset_in_text_section)
            .field("pc_section", &self.result.pc_section)
            .field("handler_anchors", &self.handler_anchors)
            .field("pc_section_jumps", &self.pc_section_jumps)
            .field("text_section_jumps", &self.text_section_jumps)
            .finish()
    }
}

impl JitCompiler {
    // Arguments are unused on windows
    fn new(_program: &[u8], _config: &Config) -> JitCompiler {
        #[cfg(windows)]
        {
            panic!("JIT not supported on windows");
        }

        // Scan through program to find actual number of instructions
        let mut pc = 0;
        while pc * ebpf::INSN_SIZE < _program.len() {
            let insn = ebpf::get_insn(_program, pc);
            pc += match insn.opc {
                ebpf::LD_DW_IMM => 2,
                _ => 1,
            };
        }

        JitCompiler {
            result: JitProgramSections::new(pc + 1, pc * 256 + 512),
            pc_section_jumps: vec![],
            text_section_jumps: vec![],
            offset_in_text_section: 0,
            pc: 0,
            program_vm_addr: 0,
            handler_anchors: HashMap::new(),
            config: *_config,
        }
    }

    fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
            executable: &dyn Executable<E, I>) -> Result<(), EbpfError<E>> {
        let (program_vm_addr, program) = executable.get_text_bytes()?;
        self.program_vm_addr = program_vm_addr;

        self.generate_prologue::<E, I>()?;

        // Jump to entry point
        let entry = executable.get_entrypoint_instruction_offset().unwrap_or(0);
        emit_profile_instruction_count(self, Some(entry + 1))?;
        X86Instruction::load_immediate(OperandSize::S64, R11, entry as i64).emit(self)?;
        emit_jmp(self, entry)?;

        // Have these in front so that the linear search of TARGET_PC_TRANSLATE_PC does not terminate early
        self.generate_helper_routines::<E>()?;
        self.generate_exception_handlers::<E>()?;

        while self.pc * ebpf::INSN_SIZE < program.len() {
            let insn = ebpf::get_insn(program, self.pc);

            self.result.pc_section[self.pc] = self.offset_in_text_section as u64;

            if self.config.enable_instruction_tracing {
                X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                emit_call(self, TARGET_PC_TRACE)?;
            }

            let dst = REGISTER_MAP[insn.dst as usize];
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {

                // BPF_LD class
                ebpf::LD_ABS_B   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_H   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_W   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_DW  => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_B   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_H   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_W   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_DW  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                ebpf::LD_DW_IMM  => {
                    emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2))?;
                    self.pc += 1;
                    self.pc_section_jumps.push(Jump { location: self.pc, target_pc: TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION });
                    let second_part = ebpf::get_insn(program, self.pc).imm as u64;
                    let imm = (insn.imm as u32) as u64 | second_part.wrapping_shl(32);
                    X86Instruction::load_immediate(OperandSize::S64, dst, imm as i64).emit(self)?;
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 1, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S8, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 2, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S16, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 4, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S32, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 8, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S64, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 1, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S8, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 2, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S16, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 4, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S32, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 8, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S64, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    emit_alu(self, OperandSize::S32, 0x81, 0, dst, insn.imm, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::ADD32_REG  => {
                    emit_alu(self, OperandSize::S32, 0x01, src, dst, 0, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::SUB32_IMM  => {
                    emit_alu(self, OperandSize::S32, 0x81, 5, dst, insn.imm, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::SUB32_REG  => {
                    emit_alu(self, OperandSize::S32, 0x29, src, dst, 0, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::MOD32_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm))?,
                ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::MOD32_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None)?,
                ebpf::OR32_IMM   => emit_alu(self, OperandSize::S32, 0x81, 1, dst, insn.imm, None)?,
                ebpf::OR32_REG   => emit_alu(self, OperandSize::S32, 0x09, src, dst, 0, None)?,
                ebpf::AND32_IMM  => emit_alu(self, OperandSize::S32, 0x81, 4, dst, insn.imm, None)?,
                ebpf::AND32_REG  => emit_alu(self, OperandSize::S32, 0x21, src, dst, 0, None)?,
                ebpf::LSH32_IMM  => emit_alu(self, OperandSize::S32, 0xc1, 4, dst, insn.imm, None)?,
                ebpf::LSH32_REG  => emit_shift(self, OperandSize::S32, 4, src, dst)?,
                ebpf::RSH32_IMM  => emit_alu(self, OperandSize::S32, 0xc1, 5, dst, insn.imm, None)?,
                ebpf::RSH32_REG  => emit_shift(self, OperandSize::S32, 5, src, dst)?,
                ebpf::NEG32      => emit_alu(self, OperandSize::S32, 0xf7, 3, dst, 0, None)?,
                ebpf::XOR32_IMM  => emit_alu(self, OperandSize::S32, 0x81, 6, dst, insn.imm, None)?,
                ebpf::XOR32_REG  => emit_alu(self, OperandSize::S32, 0x31, src, dst, 0, None)?,
                ebpf::MOV32_IMM  => emit_alu(self, OperandSize::S32, 0xc7, 0, dst, insn.imm, None)?,
                ebpf::MOV32_REG  => X86Instruction::mov(OperandSize::S32, src, dst).emit(self)?,
                ebpf::ARSH32_IMM => emit_alu(self, OperandSize::S32, 0xc1, 7, dst, insn.imm, None)?,
                ebpf::ARSH32_REG => emit_shift(self, OperandSize::S32, 7, src, dst)?,
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, 0xffff, None)?; // Mask to 16 bit
                        }
                        32 => {
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, -1, None)?; // Mask to 32 bit
                        }
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            X86Instruction::bswap(OperandSize::S16, dst).emit(self)?;
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, 0xffff, None)?; // Mask to 16 bit
                        }
                        32 => X86Instruction::bswap(OperandSize::S32, dst).emit(self)?,
                        64 => X86Instruction::bswap(OperandSize::S64, dst).emit(self)?,
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => emit_alu(self, OperandSize::S64, 0x81, 0, dst, insn.imm, None)?,
                ebpf::ADD64_REG  => emit_alu(self, OperandSize::S64, 0x01, src, dst, 0, None)?,
                ebpf::SUB64_IMM  => emit_alu(self, OperandSize::S64, 0x81, 5, dst, insn.imm, None)?,
                ebpf::SUB64_REG  => emit_alu(self, OperandSize::S64, 0x29, src, dst, 0, None)?,
                ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::MOD64_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm))?,
                ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::MOD64_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None)?,
                ebpf::OR64_IMM   => emit_alu(self, OperandSize::S64, 0x81, 1, dst, insn.imm, None)?,
                ebpf::OR64_REG   => emit_alu(self, OperandSize::S64, 0x09, src, dst, 0, None)?,
                ebpf::AND64_IMM  => emit_alu(self, OperandSize::S64, 0x81, 4, dst, insn.imm, None)?,
                ebpf::AND64_REG  => emit_alu(self, OperandSize::S64, 0x21, src, dst, 0, None)?,
                ebpf::LSH64_IMM  => emit_alu(self, OperandSize::S64, 0xc1, 4, dst, insn.imm, None)?,
                ebpf::LSH64_REG  => emit_shift(self, OperandSize::S64, 4, src, dst)?,
                ebpf::RSH64_IMM  => emit_alu(self, OperandSize::S64, 0xc1, 5, dst, insn.imm, None)?,
                ebpf::RSH64_REG  => emit_shift(self, OperandSize::S64, 5, src, dst)?,
                ebpf::NEG64      => emit_alu(self, OperandSize::S64, 0xf7, 3, dst, 0, None)?,
                ebpf::XOR64_IMM  => emit_alu(self, OperandSize::S64, 0x81, 6, dst, insn.imm, None)?,
                ebpf::XOR64_REG  => emit_alu(self, OperandSize::S64, 0x31, src, dst, 0, None)?,
                ebpf::MOV64_IMM  => X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm as i64).emit(self)?,
                ebpf::MOV64_REG  => X86Instruction::mov(OperandSize::S64, src, dst).emit(self)?,
                ebpf::ARSH64_IMM => emit_alu(self, OperandSize::S64, 0xc1, 7, dst, insn.imm, None)?,
                ebpf::ARSH64_REG => emit_shift(self, OperandSize::S64, 7, src, dst)?,

                // BPF_JMP class
                ebpf::JA         => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc))?;
                    emit_jmp(self, target_pc)?;
                },
                ebpf::JEQ_IMM    => emit_conditional_branch_imm(self, 0x84, insn.imm, dst, target_pc)?,
                ebpf::JEQ_REG    => emit_conditional_branch_reg(self, 0x84, src, dst, target_pc)?,
                ebpf::JGT_IMM    => emit_conditional_branch_imm(self, 0x87, insn.imm, dst, target_pc)?,
                ebpf::JGT_REG    => emit_conditional_branch_reg(self, 0x87, src, dst, target_pc)?,
                ebpf::JGE_IMM    => emit_conditional_branch_imm(self, 0x83, insn.imm, dst, target_pc)?,
                ebpf::JGE_REG    => emit_conditional_branch_reg(self, 0x83, src, dst, target_pc)?,
                ebpf::JLT_IMM    => emit_conditional_branch_imm(self, 0x82, insn.imm, dst, target_pc)?,
                ebpf::JLT_REG    => emit_conditional_branch_reg(self, 0x82, src, dst, target_pc)?,
                ebpf::JLE_IMM    => emit_conditional_branch_imm(self, 0x86, insn.imm, dst, target_pc)?,
                ebpf::JLE_REG    => emit_conditional_branch_reg(self, 0x86, src, dst, target_pc)?,
                ebpf::JSET_IMM   => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc))?;
                    emit_alu(self, OperandSize::S64, 0xf7, 0, dst, insn.imm, None)?;
                    emit_jcc(self, 0x85, target_pc)?;
                    emit_undo_profile_instruction_count(self, target_pc)?;
                },
                ebpf::JSET_REG   => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc))?;
                    emit_alu(self, OperandSize::S64, 0x85, src, dst, 0, None)?;
                    emit_jcc(self, 0x85, target_pc)?;
                    emit_undo_profile_instruction_count(self, target_pc)?;
                },
                ebpf::JNE_IMM    => emit_conditional_branch_imm(self, 0x85, insn.imm, dst, target_pc)?,
                ebpf::JNE_REG    => emit_conditional_branch_reg(self, 0x85, src, dst, target_pc)?,
                ebpf::JSGT_IMM   => emit_conditional_branch_imm(self, 0x8f, insn.imm, dst, target_pc)?,
                ebpf::JSGT_REG   => emit_conditional_branch_reg(self, 0x8f, src, dst, target_pc)?,
                ebpf::JSGE_IMM   => emit_conditional_branch_imm(self, 0x8d, insn.imm, dst, target_pc)?,
                ebpf::JSGE_REG   => emit_conditional_branch_reg(self, 0x8d, src, dst, target_pc)?,
                ebpf::JSLT_IMM   => emit_conditional_branch_imm(self, 0x8c, insn.imm, dst, target_pc)?,
                ebpf::JSLT_REG   => emit_conditional_branch_reg(self, 0x8c, src, dst, target_pc)?,
                ebpf::JSLE_IMM   => emit_conditional_branch_imm(self, 0x8e, insn.imm, dst, target_pc)?,
                ebpf::JSLE_REG   => emit_conditional_branch_reg(self, 0x8e, src, dst, target_pc)?,
                ebpf::CALL_IMM   => {
                    // For JIT, syscalls MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // syscall function in the JIT-compiled program).
                    if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        if self.config.enable_instruction_meter {
                            emit_validate_and_profile_instruction_count(self, true, Some(0))?;
                            X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 2) as i32)).emit(self)?;
                            emit_alu(self, OperandSize::S64, 0x29, ARGUMENT_REGISTERS[0], R11, 0, None)?;
                            X86Instruction::mov(OperandSize::S64, R11, ARGUMENT_REGISTERS[0]).emit(self)?;
                            X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 3) as i32)).emit(self)?;
                            emit_rust_call(self, I::consume as *const u8, &[
                                Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
                                Argument { index: 0, value: Value::Register(R11) },
                            ], None, false)?;
                        }

                        X86Instruction::load(OperandSize::S64, R10, RAX, X86IndirectAccess::Offset((SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) as i32 * 8)).emit(self)?;
                        emit_rust_call(self, syscall.function as *const u8, &[
                            Argument { index: 0, value: Value::Register(RAX) }, // "&mut self" in the "call" method of the SyscallObject
                            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
                            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
                            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
                            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
                            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
                            Argument { index: 6, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
                            Argument { index: 7, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
                        ], None, true)?;

                        // Throw error if the result indicates one
                        X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                        emit_jcc(self, 0x85, TARGET_PC_SYSCALL_EXCEPTION)?;

                        // Store Ok value in result register
                        X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(self)?;
                        X86Instruction::load(OperandSize::S64, R11, REGISTER_MAP[0], X86IndirectAccess::Offset(8)).emit(self)?;

                        if self.config.enable_instruction_meter {
                            X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 3) as i32)).emit(self)?;
                            emit_rust_call(self, I::get_remaining as *const u8, &[
                                Argument { index: 0, value: Value::Register(R11) },
                            ], Some(ARGUMENT_REGISTERS[0]), false)?;
                            X86Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 2) as i32)).emit(self)?;
                            emit_undo_profile_instruction_count(self, 0)?;
                        }
                    } else {
                        match executable.lookup_bpf_function(insn.imm as u32) {
                            Some(target_pc) => {
                                emit_bpf_call(self, Value::Constant64(*target_pc as i64), self.result.pc_section.len() - 1)?;
                            },
                            None => {
                                // executable.report_unresolved_symbol(self.pc)?;
                                // Workaround for unresolved symbols in ELF: Report error at runtime instead of compiletime
                                let fat_ptr: DynTraitFatPointer = unsafe { std::mem::transmute(executable) };
                                emit_rust_call(self, fat_ptr.vtable.methods[10], &[
                                    Argument { index: 0, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
                                    Argument { index: 1, value: Value::Constant64(fat_ptr.data as i64) },
                                    Argument { index: 2, value: Value::Constant64(self.pc as i64) },
                                ], None, true)?;
                                X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                                emit_jmp(self, TARGET_PC_SYSCALL_EXCEPTION)?;
                            },
                        }
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]), self.result.pc_section.len() - 1)?;
                },
                ebpf::EXIT      => {
                    emit_validate_and_profile_instruction_count(self, true, Some(0))?;

                    X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], X86IndirectAccess::Offset(-8 * CALLEE_SAVED_REGISTERS.len() as i32)).emit(self)?; // load stack_ptr
                    emit_alu(self, OperandSize::S64, 0x81, 4, REGISTER_MAP[STACK_REG], !(self.config.stack_frame_size as i32 * 2 - 1), None)?; // stack_ptr &= !(jit.config.stack_frame_size * 2 - 1);
                    emit_alu(self, OperandSize::S64, 0x81, 5, REGISTER_MAP[STACK_REG], self.config.stack_frame_size as i32 * 2, None)?; // stack_ptr -= jit.config.stack_frame_size * 2;
                    X86Instruction::store(OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, X86IndirectAccess::Offset(-8 * CALLEE_SAVED_REGISTERS.len() as i32)).emit(self)?; // store stack_ptr

                    // if(stack_ptr < MM_STACK_START) goto exit;
                    X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(self)?;
                    X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], MM_STACK_START as i64).emit(self)?;
                    X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[STACK_REG], None).emit(self)?;
                    X86Instruction::mov(OperandSize::S64, R11, REGISTER_MAP[0]).emit(self)?;
                    emit_jcc(self, 0x82, TARGET_PC_EXIT)?;

                    // else return;
                    X86Instruction::return_near().emit(self)?;
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }

            self.pc += 1;
        }
        self.result.pc_section[self.pc] = self.offset_in_text_section as u64; // Bumper so that the linear search of TARGET_PC_TRANSLATE_PC can not run off

        // Bumper in case there was no final exit
        emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2))?;
        X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
        emit_set_exception_kind::<E>(self, EbpfError::ExecutionOverrun(0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        self.generate_epilogue::<E>()?;
        self.resolve_jumps();
        self.result.seal();

        Ok(())
    }

    fn generate_helper_routines<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            set_anchor(self, TARGET_PC_TRACE);
            // Save registers on stack
            X86Instruction::push(R11).emit(self)?;
            for reg in REGISTER_MAP.iter().rev() {
                X86Instruction::push(*reg).emit(self)?;
            }
            X86Instruction::mov(OperandSize::S64, RSP, REGISTER_MAP[0]).emit(self)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, - 8 * 3, None)?; // RSP -= 8 * 3;
            emit_rust_call(self, Tracer::trace as *const u8, &[
                Argument { index: 0, value: Value::RegisterIndirect(R10, std::mem::size_of::<MemoryMapping>() as i32) }, // jit.tracer
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
            ], None, false)?;
            // Pop stack and return
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, 8 * 3, None)?; // RSP += 8 * 3;
            X86Instruction::pop(REGISTER_MAP[0]).emit(self)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, 8 * (REGISTER_MAP.len() - 1) as i32, None)?; // RSP += 8 * (REGISTER_MAP.len() - 1);
            X86Instruction::pop(R11).emit(self)?;
            X86Instruction::return_near().emit(self)?;
        }

        // Translates a host pc back to a BPF pc by linear search of the pc_section table
        set_anchor(self, TARGET_PC_TRANSLATE_PC);
        X86Instruction::push(REGISTER_MAP[0]).emit(self)?; // Save REGISTER_MAP[0]
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64 - 8).emit(self)?; // Loop index and pointer to look up
        set_anchor(self, TARGET_PC_TRANSLATE_PC_LOOP); // Loop label
        emit_alu(self, OperandSize::S64, 0x81, 0, REGISTER_MAP[0], 8, None)?; // Increase index
        X86Instruction::cmp(OperandSize::S64, R11, REGISTER_MAP[0], Some(X86IndirectAccess::Offset(8))).emit(self)?; // Look up and compare against value at next index
        emit_jcc(self, 0x86, TARGET_PC_TRANSLATE_PC_LOOP)?; // Continue while *REGISTER_MAP[0] <= R11
        X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(self)?; // R11 = REGISTER_MAP[0];
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64).emit(self)?; // REGISTER_MAP[0] = self.result.pc_section;
        emit_alu(self, OperandSize::S64, 0x29, REGISTER_MAP[0], R11, 0, None)?; // R11 -= REGISTER_MAP[0];
        emit_alu(self, OperandSize::S64, 0xc1, 5, R11, 3, None)?; // R11 >>= 3;
        X86Instruction::pop(REGISTER_MAP[0]).emit(self)?; // Restore REGISTER_MAP[0]
        X86Instruction::return_near().emit(self)
    }

    fn generate_exception_handlers<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        // Handler for EbpfError::ExceededMaxInstructions
        set_anchor(self, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], R11).emit(self)?;
        emit_set_exception_kind::<E>(self, EbpfError::ExceededMaxInstructions(0, 0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::CallDepthExceeded
        set_anchor(self, TARGET_PC_CALL_DEPTH_EXCEEDED);
        emit_set_exception_kind::<E>(self, EbpfError::CallDepthExceeded(0, 0))?;
        X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(24), self.config.max_call_depth as i64).emit(self)?; // depth = jit.config.max_call_depth;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::CallOutsideTextSegment
        set_anchor(self, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
        emit_set_exception_kind::<E>(self, EbpfError::CallOutsideTextSegment(0, 0))?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(24)).emit(self)?; // target_address = RAX;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::DivideByZero
        set_anchor(self, TARGET_PC_DIV_BY_ZERO);
        emit_set_exception_kind::<E>(self, EbpfError::DivideByZero(0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::UnsupportedInstruction
        set_anchor(self, TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION);
        emit_alu(self, OperandSize::S64, 0x31, R11, R11, 0, None)?; // R11 = 0;
        X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(0, R11, 0)).emit(self)?;    
        emit_call(self, TARGET_PC_TRANSLATE_PC)?;
        emit_alu(self, OperandSize::S64, 0x81, 0, R11, 2, None)?; // Increment exception pc
        // emit_jmp(self, TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION)?; // Fall-through

        // Handler for EbpfError::UnsupportedInstruction
        set_anchor(self, TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION);
        if self.config.enable_instruction_tracing {
            emit_call(self, TARGET_PC_TRACE)?;
        }
        emit_set_exception_kind::<E>(self, EbpfError::UnsupportedInstruction(0))?;
        // emit_jmp(self, TARGET_PC_EXCEPTION_AT)?; // Fall-through

        // Handler for exceptions which report their pc
        set_anchor(self, TARGET_PC_EXCEPTION_AT);
        emit_profile_instruction_count_of_exception(self)?;
        X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(self)?;
        X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(0), 1).emit(self)?; // is_err = true;
        emit_alu(self, OperandSize::S64, 0x81, 0, R11, ebpf::ELF_INSN_DUMP_OFFSET as i32 - 1, None)?;
        X86Instruction::store(OperandSize::S64, R11, R10, X86IndirectAccess::Offset(16)).emit(self)?; // pc = self.pc + ebpf::ELF_INSN_DUMP_OFFSET;
        emit_jmp(self, TARGET_PC_EPILOGUE)?;

        // Handler for syscall exceptions
        set_anchor(self, TARGET_PC_SYSCALL_EXCEPTION);
        emit_profile_instruction_count_of_exception(self)?;
        emit_jmp(self, TARGET_PC_EPILOGUE)
    }

    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(&mut self) -> Result<(), EbpfError<E>> {
        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            X86Instruction::push(*reg).emit(self)?;
            if *reg == RBP {
                X86Instruction::mov(OperandSize::S64, RSP, RBP).emit(self)?;
            }
        }

        // Save JitProgramArgument
        X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[2], R10).emit(self)?;

        // Initialize and save BPF stack pointer
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[STACK_REG], MM_STACK_START as i64 + self.config.stack_frame_size as i64).emit(self)?;
        X86Instruction::push(REGISTER_MAP[STACK_REG]).emit(self)?;

        // Save pointer to optional typed return value
        X86Instruction::push(ARGUMENT_REGISTERS[0]).emit(self)?;

        // Save initial instruction meter
        emit_rust_call(self, I::get_remaining as *const u8, &[
            Argument { index: 0, value: Value::Register(ARGUMENT_REGISTERS[3]) },
        ], Some(ARGUMENT_REGISTERS[0]), false)?;
        X86Instruction::push(ARGUMENT_REGISTERS[0]).emit(self)?;
        X86Instruction::push(ARGUMENT_REGISTERS[3]).emit(self)?;

        // Initialize other registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[STACK_REG] {
                X86Instruction::load_immediate(OperandSize::S64, *reg, 0).emit(self)?;
            }
        }
        Ok(())
    }

    fn generate_epilogue<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        // Quit gracefully
        set_anchor(self, TARGET_PC_EXIT);
        X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)).emit(self)?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(8)).emit(self)?; // result.return_value = R0;
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], 0).emit(self)?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(0)).emit(self)?;  // result.is_error = false;

        // Epilogue
        set_anchor(self, TARGET_PC_EPILOGUE);

        // Store instruction_meter in RAX
        X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], RAX).emit(self)?;

        // Restore stack pointer in case the BPF stack was used
        X86Instruction::mov(OperandSize::S64, RBP, R11).emit(self)?;
        emit_alu(self, OperandSize::S64, 0x81, 5, R11, 8 * (CALLEE_SAVED_REGISTERS.len()-1) as i32, None)?;
        X86Instruction::mov(OperandSize::S64, R11, RSP).emit(self)?; // RSP = RBP - 8 * (CALLEE_SAVED_REGISTERS.len() - 1).emit(self);

        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            X86Instruction::pop(*reg).emit(self)?;
        }

        X86Instruction::return_near().emit(self)
    }

    fn resolve_jumps(&mut self) {
        for jump in &self.pc_section_jumps {
            self.result.pc_section[jump.location] = jump.get_target_offset(&self);
        }
        for jump in &self.text_section_jumps {
            let offset_value = jump.get_target_offset(&self) as i32
                - jump.location as i32 // Relative jump
                - std::mem::size_of::<i32>() as i32; // Jump from end of instruction
            unsafe {
                libc::memcpy(
                    self.result.text_section.as_ptr().add(jump.location) as *mut libc::c_void,
                    &offset_value as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>(),
                );
            }
        }
        let call_unsupported_instruction = self.handler_anchors.get(&TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION).unwrap();
        let callx_unsupported_instruction = self.handler_anchors.get(&TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION).unwrap();
        for offset in self.result.pc_section.iter_mut() {
            if *offset == *call_unsupported_instruction as u64 {
                // Turns compiletime exception handlers to runtime ones (as they need to turn the host PC back into a BPF PC)
                *offset = *callx_unsupported_instruction as u64;
            }
            *offset = unsafe { (self.result.text_section.as_ptr() as *const u8).add(*offset as usize) } as u64;
        }
    }
}