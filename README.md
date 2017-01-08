# rbpf

![](misc/rbpf_256.png)

Rust (user-space) virtual machine for eBPF

[![Build Status](https://travis-ci.org/iovisor/rbpf.svg?branch=master)](https://travis-ci.org/qmonnet/rbpf)

* [Description](#description)
* [Link to the crate](#link-to-the-crate)
* [API](#api)
* [Example uses](#example-uses)
* [Feedback welcome!](#feedback-welcome)
* [Questions / Answers](#questions--answers)
* [Caveats](#caveats)
* [_To do_ list](#to-do-list)
* [License](#license)
* [Inspired by](#inspired-by)
* [Other resources](#other-resources)

## Description

This crate contains a virtual machine for eBPF program execution. BPF, as in
_Berkeley Packet Filter_, is an assembly-like language initially developed for
BSD systems, in order to filter packets in the kernel with tools such as
tcpdump so as to avoid useless copies to user-space. It was ported to Linux,
where it evolved into eBPF (_extended_ BPF), a faster version with more
features. While BPF programs are originally intended to run in the kernel, the
virtual machine of this crate enables running it in user-space applications;
it contains an interpreter as well as a x86_64 JIT-compiler for eBPF programs.

It is based on Rich Lane's [uBPF software](https://github.com/iovisor/ubpf/),
which does nearly the same, but is written in C.

## Link to the crate

This crate is available from [crates.io](https://crates.io/crates/rbpf), so it
should work out of the box by adding it as a dependency in your `Cargo.toml`
file:

```toml
[dependencies]
rbpf = "0.0.2"
```

You can also use the development version from this GitHub repository. This
should be as simple as putting this inside your `Cargo.toml`:

```toml
[dependencies]
rbpf = { git = "https://github.com/qmonnet/rbpf" }
```

Of course, if you prefer, you can clone it locally, possibly hack the crate,
and then indicate the path of your local version in `Cargo.toml`:

```toml
[dependencies]
rbpf = { path = "path/to/rbpf" }
```

Then indicate in your source code that you want to use the crate:

```rust
extern crate rbpf;
```

## API

The API is pretty well documented inside the source code. You should also be
able to access [an online version of the documentation from
here](https://docs.rs/releases/search?query=rbpf). Here is a summary of how to
use it.

Here are the steps to follow to run an eBPF program with rbpf:

1. Create a virtual machine. There are several kinds of machines, we will come
   back on this later. When creating the VM, pass the eBPF program as an
   argument to the constructor.
2. If you want to use some helper functions, register them into the virtual
   machine.
3. If you want a JIT-compiled program, compile it.
4. Execute your program: either run the interpreter or call the JIT-compiled
   function.

eBPF has been initially designed to filter packets (now it has some other hooks
in the Linux kernel, such as kprobes, but this is not covered by rbpf). As a
consequence, most of the load and store instructions of the program are
performed on a memory area representing the packet data. However, in the Linux
kernel, the eBPF program does not immediately access this data area: initially,
it has access to a C `struct sk_buff` instead, which is a buffer containing
metadata about the packet—including memory addresses of the beginning and of
the end of the packet data area. So the program first loads those pointers from
the `sk_buff`, and then can access the packet data.

This behavior can be replicated with rbpf, but it is not mandatory. For this
reason, we have several structs representing different kinds of virtual
machines:

* `struct EbpfVmMbuffer` mimics the kernel. When the program is run, the
  address provided to its first eBPF register will be the address of a metadata
  buffer provided by the user, and that is expected to contains pointers to the
  start and the end of the packet data memory area.

* `struct EbpfVmFixedMbuff` has one purpose: enabling the execution of programs
  created to be compatible with the kernel, while saving the effort to manually
  handle the metadata buffer for the user. In fact, this struct has a static
  internal buffer that is passed to the program. The user has to indicate the
  offset values at which the eBPF program expects to find the start and the end
  of packet data in the buffer. On calling the function that runs the program
  (JITted or not), the struct automatically updates the addresses in this
  static buffer, at the appointed offsets, for the start and the end of the
  packet data the program is called upon.

* `struct EbpfVmRaw` is for programs that want to run directly on packet data.
  No metadata buffer is involved, the eBPF program directly receives the
  address of the packet data in its first register. This is the behavior of
  uBPF.

* `struct EbpfVmNoData` does not take any data. The eBPF program takes no
  argument whatsoever, and its return value is deterministic. Not so sure there
  is a valid use case for that, but if nothing else, this is very useful for
  unit tests.

All these structs implement the same public functions:

```rust
// called with EbpfVmMbuff:: prefix
pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmMbuff<'a>

// called with EbpfVmFixedMbuff:: prefix
pub fn new(prog: &'a std::vec::Vec<u8>, data_offset: usize, data_end_offset: usize) -> EbpfVmFixedMbuff<'a>

// called with EbpfVmRaw:: prefix
pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmRaw<'a>

// called with EbpfVmNoData:: prefix
pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmNoData<'a>
```

This is used to create a new instance of a VM. The return type is dependent of
the struct from which the function is called. For instance,
`rbpf::EbpfVmRaw::new(my_program)` would return an instance of `struct
rbpf::EbpfVmRaw`. When a program is loaded, it is checked with a very simple
verifier (nothing close to the one for Linux kernel).

For `struct EbpfVmFixedMbuff`, two additional arguments must be passed to the
constructor: `data_offset` and `data_end_offset`. They are the offset (byte
number) at which the pointers to the beginning and to the end, respectively, of
the memory area of packet data are to be stored in the internal metadata buffer
each time the program is executed. Other structs do not use this mechanism and
do not need those offsets.

```rust
pub fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>)
```

You can use for example `my_vm.set_prog(my_program);` to change the loaded
program after the VM instance creation. This program is checked with the
verifier.

```rust
pub fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64)
```

This function is used to register a helper function. The VM stores its
registers in a hashmap, so the key can be any `u32` value you want. It may be
useful for programs that should be compatible with the Linux kernel, and
therefore must use specific helper numbers.

```rust
// for struct EbpfVmMbuff
pub fn prog_exec(&self, mem: &'a mut std::vec::Vec<u8>, mbuff: &'a mut std::vec::Vec<u8>) -> u64

// for struct EbpfVmFixedMbuff and struct EbpfVmRaw
pub fn prog_exec(&self, mem: &'a mut std::vec::Vec<u8>) -> u64

// for struct EbpfVmNoData
pub fn prog_exec(&self) -> u64
```

Interprets the loaded program. The function takes a reference to the packet
data and the metadata buffer, or only to the packet data, or nothing at all,
depending on the kind of the VM used. The value returned is the result of the
eBPF program.

```rust
pub fn jit_compile(&mut self)
```

JIT-compile the loaded program, for x86_64 architecture. If the program is to
use helper functions, they must be registered into the VM before this function
is called. The generated assembly function is internally stored in the VM.

```rust
// for struct EbpfVmMbuff
pub fn prog_exec_jit(&self, mem: &'a mut std::vec::Vec<u8>, mbuff: &'a mut std::vec::Vec<u8>) -> u64

// for struct EbpfVmFixedMbuff and struct EbpfVmRaw
pub fn prog_exec_jit(&self, mem: &'a mut std::vec::Vec<u8>) -> u64

// for struct EbpfVmNoData
pub fn prog_exec_jit(&self) -> u64
```

Calls the JIT-compiled program. The arguments to provide are the same as for
`prog_exec()`, again depending on the kind of VM that is used. The result of
the JIT-compiled program should be the same as with the interpreter, but it
should run faster. Note that if errors occur during the program execution, the
JIT-compiled version does not handle it as well as the interpreter, and the
program may crash.

## Example uses

### Simple example

This comes from the unit test `test_vm_add`.

```rust
extern crate rbpf;

fn main() {

    // This is the eBPF program, in the form of bytecode instructions.
    let prog = vec![
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    ];

    // Instantiate a struct EbpfVmNoData. This is an eBPF VM for programs that
    // takes no packet data in argument.
    // The eBPF program is passed to the constructor.
    let vm = rbpf::EbpfVmNoData::new(&prog);

    // Execute (interpret) the program. No argument required for this VM.
    assert_eq!(vm.prog_exec(), 0x3);
}
```

### With JIT, on packet data

This comes from the unit test `test_jit_ldxh`.

```rust
extern crate rbpf;

fn main() {
    let prog = vec![
        0x71, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxh r0, [r1+2]
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    ];

    // Let's use some data.
    let mut mem = vec![
        0xaa, 0xbb, 0x11, 0xcc, 0xdd
    ];

    // This is an eBPF VM for programs reading from a given memory area (it
    // directly reads from packet data)
    let mut vm = rbpf::EbpfVmRaw::new(&prog);

    // This time we JIT-compile the program.
    vm.jit_compile();

    // Then we execute it. For this kind of VM, a reference to the packet data
    // must be passed to the function that executes the program.
    assert_eq!(vm.prog_exec_jit(&mut mem), 0x11);
}
```
### Using a metadata buffer

This comes from the unit test `test_jit_mbuff` and derives from the unit test
`test_jit_ldxh`.

```rust
extern crate rbpf;

fn main() {
    let prog = vec![
        // Load mem from mbuff at offset 8 into R1
        0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ldhx r1[2], r0
        0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut mem = vec![
        0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    ];

    // Just for the example we create our metadata buffer from scratch, and
    // we store the pointers to packet data start and end in it.
    let mut mbuff = vec![0u8; 32];
    unsafe {
        let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
        let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
        *data     = mem.as_ptr() as u64;
        *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    }

    // This eBPF VM is for program that use a metadata buffer.
    let mut vm = rbpf::EbpfVmMbuff::new(&prog);

    // Here again we JIT-compile the program.
    vm.jit_compile();

    // Here we must provide both a reference to the packet data, and to the
    // metadata buffer we use.
    assert_eq!(vm.prog_exec_jit(&mut mem, &mut mbuff), 0x2211);
}
```

### Loading code from an object file; and using a virtual metadata buffer

This comes from unit test `test_vm_block_port`.

This example requires the following additional crates, you may have to add them
to your `Cargo.toml` file.

```toml
[dependencies]
rbpf = "0.0.2"
byteorder = "0.5.3"
elf = "0.0.10"
```

It also uses a kind of VM that uses an internal buffer used to simulate the
`sk_buff` used by eBPF programs in the kernel, without having to manually
create a new buffer for each packet. It may be useful for programs compiled for
the kernel and that assumes the data they receive is a `sk_buff` pointing to
the packet data start and end addresses. So here we just provide the offsets at
which the eBPF program expects to find those pointers, and the VM handles takes
in charger the buffer update so that we only have to provide a reference to the
packet data for each run of the program.

```rust
extern crate byteorder;
extern crate elf;
use std::path::PathBuf;

extern crate rbpf;
use rbpf::helpers;

fn main() {
    // Load a program from an ELF file, e.g. compiled from C to eBPF with
    // clang/LLVM. Some minor modification to the bytecode may be required.
    let filename = "my_ebpf_object_file.o";

    let path = PathBuf::from(filename);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    // Here we assume the eBPF program is in the ELF section called
    // ".classifier".
    let text_scn = match file.get_section(".classifier") {
        Some(s) => s,
        None => panic!("Failed to look up .classifier section"),
    };

    let ref prog = &text_scn.data;

    // This is our data: a real packet, starting with Ethernet header
    let mut packet = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x08, 0x00,             // ethertype
        0x45, 0x00, 0x00, 0x3b, // start ip_hdr
        0xa6, 0xab, 0x40, 0x00,
        0x40, 0x06, 0x96, 0x0f,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
        0xd1, 0xe5, 0xc4, 0x9d,
        0xd4, 0x30, 0xb5, 0xd2,
        0x80, 0x18, 0x01, 0x56,
        0xfe, 0x2f, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, // start data
        0x00, 0x23, 0x75, 0x89,
        0x00, 0x23, 0x63, 0x2d,
        0x71, 0x64, 0x66, 0x73,
        0x64, 0x66, 0x0a
    ];

    // This is an eBPF VM for programs using a virtual metadata buffer, similar
    // to the sk_buff that eBPF programs use with tc and in Linux kernel.
    // We must provide the offsets at which the pointers to packet data start
    // and end must be stored: these are the offsets at which the program will
    // load the packet data from the metadata buffer.
    let mut vm = rbpf::EbpfVmFixedMbuff::new(&prog, 0x40, 0x50);

    // We register a helper function, that can be called by the program, into
    // the VM.
    vm.register_helper(helpers::BPF_TRACE_PRINTF_IDX, helpers::bpf_trace_printf);

    // This kind of VM takes a reference to the packet data, but does not need
    // any reference to the metadata buffer: a fixed buffer is handled 
    // internally by the VM.
    let res = vm.prog_exec(&mut packet);
    println!("Program returned: {:?} ({:#x})", res, res);
}
```

## Feedback welcome!

This is the author's first try at writing Rust code. He learned a lot in the
process, but there remains a feeling that this crate has a kind of C-ish style
in some places instead of the Rusty look the author would like it to have. So
feedback (or PRs) are welcome, including about ways you might see to take
better advantage of Rust features.

## Questions / Answers

### What Rust version is needed?

This crate is known to be compatible with Rust version 1.14.0. Older versions
of Rust have not been tested.

### Why implementing an eBPF virtual machine in Rust?

As of this writing, there is no particular use case for this crate at the best
of the author's knowledge. The author happens to work with BPF on Linux and to
know how uBPF works, and he wanted to learn and experiment with Rust—no more
than that.

### What are the differences with uBPF?

Other than the language, obviously? Well, there are some differences:

* Some constants, such as the maximum length for programs or the length for the
  stack, differs between uBPF and rbpf. The latter uses the same values as the
  Linux kernel, while uBPF has its own values.

* When an error occur while a program is run by uBPF, the function running the
  program silently returns the maximum value as an error code, while rbpf
  `panic!()`.

* The registration of helper functions, that can be called from within an eBPF
  program, is not handled in the same way.

* The distinct structs permitting to run program either on packet data, or with
  a metadata buffer (simulated or not) is a specificity of rbpf.

* As for performance: theoretically the JIT programs are expected to run at the
  same speed, while the C interpreter of uBPF should go slightly faster than
  rbpf. But this has not been asserted yet. Benchmarking both programs would be
  an interesting thing to do.

### Can I use it with the “classic” BPF (a.k.a cBPF) version?

No. This crate only works with extended BPF (eBPF) programs. For CBPF programs,
such as used by tcpdump (as of today) for example, you may be interested in the
[bpfjit crate](https://crates.io/crates/bpfjit) written by Alexander Polakov
instead.

### What functionalities are implemented?

Running and JIT-compiling eBPF programs works. There is also a mechanism to
register user-defined helper functions. The eBPF implementation of the Linux
kernel comes with [some additional
features](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md):
a high number of helpers, several kind of maps, tail calls.

* Additional helpers should be easy to add, but very few of the existing Linux
  helpers have been replicated in rbpf so far.

* Tail calls (“long jumps” from an eBPF program into another) are not
  implemented. This is probably not trivial to design and implement.

* The interaction with maps is done through the use of specific helpers, so
  this should not be difficult to add. The maps themselves can reuse the maps
  in the kernel (if on Linux), to communicate with in-kernel eBPF programs for
  instance; or they can be handled in user space. Rust has arrays and hashmaps,
  so their implementation should be pretty straightforward (and may be added to
  rbpf in the future).

### What about program validation?

The ”verifier” of this crate is very short and has nothing to do with the
kernel verifier, which means that it accepts programs that may not be safe. On
the other hand, you probably do not run this in a kernel here, so it will not
crash your system. Implementing a verifier similar to the one in the kernel is
not trivial, and we cannot “copy” it since it is under GPL license.

### What about safety then?

Rust has a strong emphasize on safety. Yet to have the eBPF VM work, some
“unsafe” blocks of code are used. The VM, taken as an eBPF interpreter, can
`panic!()` but should not crash. Please file an issue otherwise.

As for the JIT-compiler, it is a different story, since runtime memory checks
are more complicated to implement in assembly. It _will_ crash if your
JIT-compiled program tries to perform unauthorized memory accesses. Usually, it
could be a good idea to test your program with the interpreter first.

Oh, and if your program has infinite loops, even with the interpreter, you're
on your own.

## Caveats

* This create is **under development** and the API may be subject to change.

* The JIT compiler produces an unsafe program: memory access are not tested at
  runtime (yet). Use with caution.

* Contrary to the interpreter, if a division by 0 is attempted, the JIT program
  returns `0xffffffffffffffff` and exits cleanly (no `panic!()`). This is
  because the author has not found how to make `panic!()` work from the
  generated assembly so far.

* A very little number of eBPF instructions have not been implemented yet. This
  should not be a problem for the majority of eBPF programs.

* Beware of turnips. Turnips are disgusting.

## _To do_ list

* Implement some traits (`Clone`, `Drop`, `Debug` are good candidate).
* Provide built-in support for user-space array and hash BPF maps.
* Improve safety of JIT-compiled programs with runtime memory checks.
* Replace `panic!()` by cleaner error handling.
* Add helpers (some of those supported in the kernel, such as checksum update, could be helpful).
* Improve verifier. Could we find a way to directly support programs compiled with clang?
* Maybe one day, tail calls?
* JIT-compilers for other architectures?
* eBPF assembler _à la_ uBPF, to have more readable unit tests?
* …

## License

Following the effort of the Rust language project itself in order to ease
integration with other projects, the rbpf crate is distributed under the terms
of both the MIT license and the Apache License (Version 2.0).

See
[LICENSE-APACHE](https://github.com/qmonnet/rbpf/blob/master/LICENSE-APACHE)
and [LICENSE-MIT](https://github.com/qmonnet/rbpf/blob/master/LICENSE-MIT) for
details.

## Inspired by

* [uBPF](https://github.com/iovisor/ubpf), a C user-space implementation of an
  eBPF virtual machine, with a JIT-compiler (and also including assembler and
  disassembler from and to the human-readable form of the instructions, such as
  in `mov r0, 0x1337`), by Rich Lane for Big Switch Networks (2015)

* [_Building a simple JIT in
  Rust_](http://www.jonathanturner.org/2015/12/building-a-simple-jit-in-rust.html),
  by Jonathan Turner (2015)

* [bpfjit](https://github.com/polachok/bpfjit) (also [on
  crates.io](https://crates.io/crates/bpfjit)), a Rust crate exporting the cBPF
  JIT compiler from FreeBSD 10 tree to Rust, by Alexander Polakov (2016)

## Other resources

* Kernel documentation about BPF: [Documentation/networking/filter.txt
  file](https://www.kernel.org/doc/Documentation/networking/filter.txt)

* [_Dive into BPF: a list of reading
  material_](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf),
  a blog article listing documentation for BPF and related technologies (2016)

* [The Rust programming language](https://www.rust-lang.org)
