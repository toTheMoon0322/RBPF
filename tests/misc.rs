// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]

// There are unused mut warnings due to unsafe code.
#![allow(unused_mut)]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]

// This crate would be needed to load bytecode from a BPF-compiled object file. Since the crate
// is not used anywhere else in the library, it is deactivated: we do not want to load and compile
// it just for the tests. If you want to use it, do not forget to add the following
// dependency to your Cargo.toml file:
//
// ---
// elf = "0.0.10"
// ---
//
// extern crate elf;
// use std::path::PathBuf;

extern crate byteorder;
extern crate libc;
extern crate solana_rbpf;

use std::io::{Error, ErrorKind};
use std::fs::File;
use std::io::Read;
use std::ffi::CStr;
use byteorder::{ByteOrder, LittleEndian};
use libc::c_char;
use solana_rbpf::assembler::assemble;
use solana_rbpf::ebpf;
use solana_rbpf::helpers;
use solana_rbpf::MemoryRegion;
use solana_rbpf::{EbpfVmRaw, EbpfVmNoData, EbpfVmMbuff, EbpfVmFixedMbuff};

// The following two examples have been compiled from C with the following command:
//
// ```bash
//  clang -O2 -emit-llvm -c <file.c> -o - | llc -march=bpf -filetype=obj -o <file.o>
// ```
//
// The C source code was the following:
//
// ```c
// #include <linux/ip.h>
// #include <linux/in.h>
// #include <linux/tcp.h>
// #include <linux/bpf.h>
//
// #define ETH_ALEN 6
// #define ETH_P_IP 0x0008 /* htons(0x0800) */
// #define TCP_HDR_LEN 20
//
// #define BLOCKED_TCP_PORT 0x9999
//
// struct eth_hdr {
//     unsigned char   h_dest[ETH_ALEN];
//     unsigned char   h_source[ETH_ALEN];
//     unsigned short  h_proto;
// };
//
// #define SEC(NAME) __attribute__((section(NAME), used))
// SEC(".classifier")
// int handle_ingress(struct __sk_buff *skb)
// {
//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;
//     struct eth_hdr *eth = data;
//     struct iphdr *iph = data + sizeof(*eth);
//     struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*iph);
//
//     /* single length check */
//     if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcp) > data_end)
//         return 0;
//     if (eth->h_proto != ETH_P_IP)
//         return 0;
//     if (iph->protocol != IPPROTO_TCP)
//         return 0;
//     if (tcp->source == BLOCKED_TCP_PORT || tcp->dest == BLOCKED_TCP_PORT)
//         return -1;
//     return 0;
// }
// char _license[] SEC(".license") = "GPL";
// ```
//
// This program, once compiled, can be injected into Linux kernel, with tc for instance. Sadly, we
// need to bring some modifications to the generated bytecode in order to run it: the three
// instructions with opcode 0x61 load data from a packet area as 4-byte words, where we need to
// load it as 8-bytes double words (0x79). The kernel does the same kind of translation before
// running the program, but rbpf does not implement this.
//
// In addition, the offset at which the pointer to the packet data is stored must be changed: since
// we use 8 bytes instead of 4 for the start and end addresses of the data packet, we cannot use
// the offsets produced by clang (0x4c and 0x50), the addresses would overlap. Instead we can use,
// for example, 0x40 and 0x50. See comments on the bytecode below to see the modifications.
//
// Once the bytecode has been (manually, in our case) edited, we can load the bytecode directly
// from the ELF object file. This is easy to do, but requires the addition of two crates in the
// Cargo.toml file (see comments above), so here we use just the hardcoded bytecode instructions
// instead.

#[test]
fn test_vm_block_port() {
    // To load the bytecode from an object file instead of using the hardcoded instructions,
    // use the additional crates commented at the beginning of this file (and also add them to your
    // Cargo.toml). See comments above.
    //
    // ---
    // let filename = "my_ebpf_object_file.o";
    //
    // let path = PathBuf::from(filename);
    // let file = match elf::File::open_path(&path) {
    //     Ok(f) => f,
    //     Err(e) => panic!("Error: {:?}", e),
    // };
    //
    // let text_scn = match file.get_section(".classifier") {
    //     Some(s) => s,
    //     None => panic!("Failed to look up .classifier section"),
    // };
    //
    // let prog = &text_scn.data;
    // ---

    let prog = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
        0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61, 0x40 i.o. 0x4c
        0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x2d, 0x23, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x69, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x71, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x0e, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
        0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x15, 0x02, 0x08, 0x00, 0x99, 0x99, 0x00, 0x00,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let packet = &mut [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x08, 0x00, // ethertype
        0x45, 0x00, 0x00, 0x3b, // start ip_hdr
        0xa6, 0xab, 0x40, 0x00,
        0x40, 0x06, 0x96, 0x0f,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        // Program matches the next two bytes: 0x9999 returns 0xffffffff, else return 0.
        0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
        0xd1, 0xe5, 0xc4, 0x9d,
        0xd4, 0x30, 0xb5, 0xd2,
        0x80, 0x18, 0x01, 0x56,
        0xfe, 0x2f, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, // start data
        0x00, 0x23, 0x75, 0x89,
        0x00, 0x23, 0x63, 0x2d,
        0x71, 0x64, 0x66, 0x73,
        0x64, 0x66, 0x0au8
    ];

    let mut vm = EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();

    let res = vm.execute_program(packet).unwrap();
    println!("Program returned: {:?} ({:#x})", res, res);
    assert_eq!(res, 0xffffffff);
}

#[cfg(not(windows))]
#[test]
fn test_jit_block_port() {
    // To load the bytecode from an object file instead of using the hardcoded instructions,
    // use the additional crates commented at the beginning of this file (and also add them to your
    // Cargo.toml). See comments above.
    //
    // ---
    // let filename = "my_ebpf_object_file.o";
    //
    // let path = PathBuf::from(filename);
    // let file = match elf::File::open_path(&path) {
    //     Ok(f) => f,
    //     Err(e) => panic!("Error: {:?}", e),
    // };
    //
    // let text_scn = match file.get_section(".classifier") {
    //     Some(s) => s,
    //     None => panic!("Failed to look up .classifier section"),
    // };
    //
    // let prog = &text_scn.data;
    // ---

    let prog = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
        0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61, 0x40 i.o. 0x4c
        0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x2d, 0x23, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x69, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x71, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x0e, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
        0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x15, 0x02, 0x08, 0x00, 0x99, 0x99, 0x00, 0x00,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let packet = &mut [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x08, 0x00, // ethertype
        0x45, 0x00, 0x00, 0x3b, // start ip_hdr
        0xa6, 0xab, 0x40, 0x00,
        0x40, 0x06, 0x96, 0x0f,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        // Program matches the next two bytes: 0x9999 returns 0xffffffff, else return 0.
        0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
        0xd1, 0xe5, 0xc4, 0x9d,
        0xd4, 0x30, 0xb5, 0xd2,
        0x80, 0x18, 0x01, 0x56,
        0xfe, 0x2f, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, // start data
        0x00, 0x23, 0x75, 0x89,
        0x00, 0x23, 0x63, 0x2d,
        0x71, 0x64, 0x66, 0x73,
        0x64, 0x66, 0x0au8
    ];

    let mut vm = EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();
    vm.jit_compile().unwrap();

    unsafe {
        let res = vm.execute_program_jit(packet).unwrap();
        println!("Program returned: {:?} ({:#x})", res, res);
        assert_eq!(res, 0xffffffff);
    }
}

// Program and memory come from uBPF test ldxh.
#[test]
fn test_vm_mbuff() {
    let prog = &[
        // Load mem from mbuff into R1
        0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ldhx r1[2], r0
        0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mem = &[
        0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    ];

    let mbuff = [0u8; 32];
    unsafe {
        let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
        let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
        *data     = mem.as_ptr() as u64;
        *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    }

    let mut vm = EbpfVmMbuff::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(mem, &mbuff).unwrap(), 0x2211);
}

// Program and memory come from uBPF test ldxh.
#[test]
fn test_vm_mbuff_with_rust_api() {
    use solana_rbpf::insn_builder::*;

    let mut program = BpfCode::new();
    program
        .load_x(MemSize::DoubleWord).set_dst(0x01).set_src(0x01).set_off(0x00_08).push()
        .load_x(MemSize::HalfWord).set_dst(0x00).set_src(0x01).set_off(0x00_02).push()
        .exit().push();

    let mem = &[
        0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    ];

    let mbuff = [0u8; 32];
    unsafe {
        let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
        let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
        *data     = mem.as_ptr() as u64;
        *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    }

    let mut vm = EbpfVmMbuff::new(Some(program.into_bytes())).unwrap();
    assert_eq!(vm.execute_program(mem, &mbuff).unwrap(), 0x2211);
}

// Program and memory come from uBPF test ldxh.
#[cfg(not(windows))]
#[test]
fn test_jit_mbuff() {
    let prog = &[
        // Load mem from mbuff into R1
        0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ldhx r1[2], r0
        0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mem = &mut [
        0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    ];

    let mut mbuff = [0u8; 32];
    unsafe {
        let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
        let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
        *data     = mem.as_ptr() as u64;
        *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    }

    unsafe {
        let mut vm = EbpfVmMbuff::new(Some(prog)).unwrap();
        vm.jit_compile().unwrap();
        assert_eq!(vm.execute_program_jit(mem, &mut mbuff).unwrap(), 0x2211);
    }
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsb() {
    let prog = &[
        0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x33);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x33);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsh() {
    let prog = &[
        0x28, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x4433);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x4433);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsw() {
    let prog = &[
        0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 =[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x66554433);
    vm.jit_compile().unwrap();

    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x66554433);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsdw() {
    let prog = &[
        0x38, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0xaa99887766554433);
    vm.jit_compile().unwrap();

    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0xaa99887766554433);
    };
}

#[test]
#[should_panic(expected = "Error: out of bounds memory load (insn #0),")]
fn test_vm_err_ldabsb_oob() {
    let prog = &[
        0x38, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mem = &mut [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.execute_program(mem).unwrap();

    // Memory check not implemented for JIT yet.
}

#[test]
#[should_panic(expected = "Error: out of bounds memory load (insn #0),")]
fn test_vm_err_ldabsb_nomem() {
    let prog = &[
        0x38, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();

    // Memory check not implemented for JIT yet.
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindb() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x88);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x88);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindh() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x48, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x9988);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x9988);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindw() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x40, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0x88776655);
    vm.jit_compile().unwrap();

    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x88776655);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldinddw() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x58, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut mem2 = mem1.clone();
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem1).unwrap(), 0xccbbaa9988776655);
    vm.jit_compile().unwrap();

    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0xccbbaa9988776655);
    };
}

#[test]
#[should_panic(expected = "Error: out of bounds memory load (insn #1),")]
fn test_vm_err_ldindb_oob() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x38, 0x10, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mem = &mut [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.execute_program(mem).unwrap();

    // Memory check not implemented for JIT yet.
}

#[test]
#[should_panic(expected = "Error: out of bounds memory load (insn #1),")]
fn test_vm_err_ldindb_nomem() {
    let prog = &[
        0xb7, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x38, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();

    // Memory check not implemented for JIT yet.
}

#[test]
#[should_panic(expected = "Error: no program or elf set")]
fn test_vm_exec_no_program() {
    let mut vm = EbpfVmNoData::new(None).unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0xBEE);
}

fn verifier_success(_prog: &[u8]) -> Result<(), Error> {
    Ok(())
}

fn verifier_fail(_prog: &[u8]) -> Result<(), Error> {
    Err(Error::new(ErrorKind::Other,
                   "Gaggablaghblagh!"))
}

#[test]
fn test_verifier_success() {
    let prog = assemble(
        "mov32 r0, 0xBEE
         exit",
    ).unwrap();
    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.set_verifier(verifier_success).unwrap();
    vm.set_program(&prog).unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0xBEE);
}

#[test]
#[should_panic(expected = "Gaggablaghblagh!")]
fn test_verifier_fail() {
    let prog = assemble(
        "mov32 r0, 0xBEE
         exit",
    ).unwrap();
    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.set_verifier(verifier_fail).unwrap();
    vm.set_program(&prog).unwrap();
    //assert_eq!(vm.execute_program().unwrap(), 0xBEE);
}

#[test]
#[should_panic(expected = "Error: Execution exceeded maximum number of instructions")]
fn test_non_terminating() {
    let prog = &[
        0xb7, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x07, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();
    vm.set_max_instruction_count(1000).unwrap();
    vm.execute_program().unwrap();
}

#[test]
fn test_non_terminate_capped() {
    let prog = &[
        0xb7, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x07, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();
    vm.set_max_instruction_count(6).unwrap();
    let _ = vm.execute_program();
    assert!(vm.get_last_instruction_count() == 6);
}

#[test]
fn test_non_terminate_early() {
    let prog = &[
        0xb7, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x07, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();
    vm.set_max_instruction_count(1000).unwrap();
    let _ = vm.execute_program();
    assert!(vm.get_last_instruction_count() == 1000);
}

#[test]
fn test_get_last_instruction_count() {
    let prog = &[
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut vm = EbpfVmNoData::new(Some(prog)).unwrap();
    vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf).unwrap();
    let _ = vm.execute_program();
    println!("count {:?}", vm.get_last_instruction_count());
    assert!(vm.get_last_instruction_count() == 1);
}

#[allow(unused_variables)]
pub fn bpf_helper_string_verify(addr: u64, unused2: u64, unused3: u64, unused4: u64,
                                unused5: u64, ro_regions: &[MemoryRegion], unused7: &[MemoryRegion]) -> Result<(()), Error> {
    for region in ro_regions.iter() {
        if region.addr <= addr && (addr as u64) < region.addr + region.len {
            let c_buf: *const c_char = addr as *const c_char;
            let max_size = region.addr + region.len - addr;
            unsafe {
                for i in 0..max_size {
                    if std::ptr::read(c_buf.offset(i as isize)) == 0 {
                        return Ok(());
                    }
                }
            }
            return Err(Error::new(ErrorKind::Other, "Error: Unterminated string"));
       }

    }
    Err(Error::new(ErrorKind::Other, "Error: Load segfault, bad string pointer"))
}

#[allow(unused_variables)]
pub fn bpf_helper_string(addr: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    let c_buf: *const c_char = addr as *const c_char;
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    match c_str.to_str() {
        Ok(slice) => println!("log: {:?}", slice),
        Err(e) => println!("Error: Cannot print invalid string"),
    };
    0
}

pub fn bpf_helper_u64 (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    println!("dump_64: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}", arg1, arg2, arg3, arg4, arg5);
    0
}

#[test]
fn test_load_elf() {
    let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.register_helper_ex("log_64", None, bpf_helper_u64).unwrap();
    vm.set_elf(&elf).unwrap();
    vm.execute_program().unwrap();
}

#[test]
fn test_symbol_relocation() {
        let prog = &mut [
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[4..8], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111, 0];

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_program(prog).unwrap();
    vm.execute_program(&mut mem).unwrap();
}

#[test]
fn test_helper_parameter_on_stack() {
    let prog = &mut [
        0xbf, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = r10
        0x07, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, // r1 += -256
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[20..24], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111, 0];

    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.execute_program(&mut mem).unwrap();
}

#[test]
#[should_panic(expected = "Error: Load segfault, bad string pointer")]
fn test_null_string() {
    let prog = &mut [
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = 0
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[12..16], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111, 0];

    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.execute_program(&mut mem).unwrap();
}

#[test]
#[should_panic(expected = "Error: Unterminated string")]
fn test_unterminated_string() {
    let prog = &mut [
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[4..8], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111];

    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.execute_program(&mut mem).unwrap();
}

#[test]
#[should_panic(expected = "[JIT] Error: helper verifier function not supported by jit")]
fn test_jit_call_helper_wo_verifier() {
    let prog = &mut [
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[4..8], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111, 0];

    let mut vm = EbpfVmRaw::new(Some(prog)).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.jit_compile().unwrap();
    unsafe { assert_eq!(vm.execute_program_jit(&mut mem).unwrap(), 0); }
}

#[test]
#[should_panic(expected = "Error: Unresolved symbol at instruction #0")]
fn test_symbol_unresolved() {
        let prog = &mut [
        0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // call -1
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    LittleEndian::write_u32(&mut prog[4..8], ebpf::hash_symbol_name(b"log"));

    let mut mem = [72, 101, 108, 108, 111, 0];

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.set_program(prog).unwrap();
    vm.execute_program(&mut mem).unwrap();
}

#[test]
#[should_panic(expected = "Error: Unresolved symbol (log_64) at instruction #520 (ELF file offset 0x1040)")]
fn test_symbol_unresolved_elf() {
    let mut file = File::open("tests/elfs/unresolved_helper.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_elf(&elf).unwrap();
    vm.execute_program().unwrap();
}

#[test]
fn test_custom_entrypoint() {
    let mut file = File::open("tests/elfs/unresolved_helper.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    elf[24] = 72; // nine instructions should leave only two left in text section

    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_elf(&elf).unwrap();
    vm.execute_program().unwrap();
    assert_eq!(2, vm.get_last_instruction_count());
}

#[test]
fn test_bpf_to_bpf_depth() {
    let mut file = File::open("tests/elfs/multiple_file.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_elf(&elf).unwrap();

    for i in 0..ebpf::MAX_CALL_DEPTH {
        println!("Depth: {:?}", i);
        let mut mem = [i as u8];
        assert_eq!(vm.execute_program(&mut mem).unwrap(), 0);
    }
}

#[test]
#[should_panic(expected = "Exceeded max BPF to BPF call depth of")]
fn test_bpf_to_bpf_too_deep() {
    let mut file = File::open("tests/elfs/multiple_file.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_elf(&elf).unwrap();

    let mut mem = [ebpf::MAX_CALL_DEPTH as u8];
    vm.execute_program(&mut mem).unwrap();
}

#[test]
fn test_relative_call() {
    let mut file = File::open("tests/elfs/relative_call.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.set_elf(&elf).unwrap();

    let mut mem = [1 as u8];
    vm.execute_program(&mut mem).unwrap();
}

#[test]
fn test_bpf_to_bpf_scratch_registers() {
    let mut file = File::open("tests/elfs/scratch_registers.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmRaw::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.register_helper_ex("log_64", None, bpf_helper_u64).unwrap();
    vm.set_elf(&elf).unwrap();

    let mut mem = [1];
    assert_eq!(vm.execute_program(&mut mem).unwrap(), 112);
}

#[test]
fn test_bpf_to_bpf_pass_stack_reference() {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let mut vm = EbpfVmNoData::new(None).unwrap();
    vm.register_helper_ex("log", Some(bpf_helper_string_verify), bpf_helper_string).unwrap();
    vm.register_helper_ex("log_64", None, bpf_helper_u64).unwrap();
    vm.set_elf(&elf).unwrap();

    assert_eq!(vm.execute_program().unwrap(), 42);
}
