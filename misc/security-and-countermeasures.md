# Attack Vectors Relevant to BPF Execution
There are three categories: Sabotage, extraction, manipulation.

## Sabotage
Hindering or preventing the operations of the surrounding system.

### Denial of Service
Crafting programs to achieve the best ratio of price (compute budget) to computation power consumption.
An attacker would try to pay the least price to maximally clog up the network with useless program execution.

## Extraction
Extracting secret information from the surrounding system (such as private keys).

### Buffer Overruns
If there is no bounds check an attacker can simply read more data at the end of an array than what should be possible.
In an extreme case this can be the entire memory of the surrounding system from that point onwards.

### Side Channel Attacks
Using resource measurements of performance, power, memory and network to gain knowledge about the surrounding system that should not be accessible.
As long as we don't offer any such resource measurements through syscalls, there should be no attack surface here.

## Manipulation
Manipulating the state of the surrounding system in a way that is not intended / allowed.

### Buffer Overflows
Similar to the buffer overrun but with writing instead of reading data.

### Code Injection
Without sufficient validation of inputs an attacker can get their own program to be included into something else which is then executed (with potentially higher privileges).

### Privilege Escalation
The attacker giving themselves more rights e.g. by overwriting their own permissions / settings in the surrounding system.

### Self Modifying Code
Crafting a program which modifies itself at runtime allows an attacker to circumvent static analysis and program validation.

### Return Oriented Programming
If self modifying code is not possible, a different approach with similar properties named ROP is used instead.
The idea is to patch together a program of various snippets (called gadets),
made of the epiloge of functions / procedures found in the machine code section of the compiled program,
and to chain them together using the return pointer (thus the name return-oriented) of the stack or a link register.
The attacker requires control over the stack pointer (e.g. by a buffer overflow) or another way of control-flow-hijacking to get the ROP attack going (pivot point).



# Countermeasures & Protection Mechanisms
This is the list of security features we have in place to address the previously discussed attack vectors.

### Validator
All programs are checked to only contain valid instructions before being compiled and executed.
(Source Code)[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/verifier.rs#L183]

### Address Translation
- All accesses to memory are bounds checked by segments (Source Code)[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/memory_region.rs#L56].
- Segments are read-only (write-protected) or read-and-write (Source Code)[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/memory_region.rs#L129].
- The mapping is fixed after VM creation, preventing privilege escalation (Source Code)[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/vm.rs#L438].
- But syscalls can cast pointers and perform arithmetic on them, effectively circumventing the mapping.

### Stack Protection
The stack has:
- An overflow check (Source Code (Interpreter push))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/call_frames.rs#L86] (Source Code (JIT push))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/jit.rs#L591]
- An underflow check (Source Code (Interpreter pop))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/call_frames.rs#L103] (Source Code (JIT pop))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/jit.rs#L1253]
- And the stack-pointer is stored separately from what the program can access, only a copy is mapped into the register set (Source Code (Interpreter push))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/vm.rs#L858] (Source Code (Interpreter pop))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/vm.rs#L909] (Source Code (JIT push))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/jit.rs#L584] (Source Code (JIT pop))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/jit.rs#L1246]
Also, address translation of the stack segment contains unmapped gaps the size of a stack frame between two actual stack frames to detect buffer overruns on the stack.

### Compute Budget
Programs are preemptively stopped once they consumed their compute budget DOS attacks (Source Code (Interpreter))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/vm.rs#L924] (Source Code (JIT))[https://github.com/solana-labs/rbpf/blob/bf99726782ded39e9b945c5f051bec989ed00ca8/src/jit.rs#L488].


## JIT

### Memory Protection
The machine code segment is write-protected after compilation which prevents self modifying code (Source Code)[hhttps://github.com/solana-labs/rbpf/blob/e18d880480ec1772461b8eb4e25a809a4a26dd79/src/jit.rs#L70].
The executable rights are revoked after the compiled program is evicted from the cache which prevents [JIT_spraying](https://en.wikipedia.org/wiki/JIT spraying) (Source Code)[https://github.com/solana-labs/rbpf/blob/e18d880480ec1772461b8eb4e25a809a4a26dd79/src/jit.rs#L85].

### Machinecode Diversification
Based on the paper: Homescu, Andrei, et al. ["Librando: transparent code randomization for just-in-time compilers"](https://www.ics.uci.edu/~ahomescu/ccs13librando_printed.pdf)
Proceedings of the 2013 ACM SIGSAC conference on Computer & Communications Security. 2013.

#### NOP Salting
Implemented, see [Source Code](https://github.com/solana-labs/rbpf/blob/608a756110111eccfee463f7def896e7f1ce6a38/src/jit.rs#L1463).

#### Immediate Value Encryption
Implemented, see [Source Code](https://github.com/solana-labs/rbpf/blob/608a756110111eccfee463f7def896e7f1ce6a38/src/jit.rs#L230).

#### Environment Encryption
Implemented, see [Source Code](https://github.com/solana-labs/rbpf/blob/608a756110111eccfee463f7def896e7f1ce6a38/src/jit.rs#L910).

#### Reordering
Because of unpredictable dynamic jumps such as the `callx` instruction, none of these can be implemented:
- Instruction
- Basic block
- Function

#### Instruction Substitution
Not implemented.

#### Register Reallocation
Not implemented.