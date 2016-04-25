using RR; using Cxx
session = icxx"""rr::ReplaySession::create("");"""
RR.step_until_exec!(session); for i = 1:2000; RR.step!(session); end
imageh = RR.read_exe(session)
modules = Gallium.GlibcDyldModules.load_library_map(current_task(session), imageh)
did_fixup, regs = RR.fixup_RC(current_task(session), icxx"$(current_task(session))->regs();")
stack = Gallium.stackwalk(regs, current_task(session), modules, rich_c = true)
stack[end].stacktop = !did_fixup

cxx"""
#include <cxxabi.h>
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/MC/MCInstrInfo.h"
using namespace llvm;
"""


include(Pkg.dir("RR","scratch","disassembler.jl"))

using DWARF.CallFrameInfo
using Gallium.Unwinder: find_fde
using ObjFileBase: handle

function get_insts(stack)
    stack = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    base, mod = Gallium.find_module(modules, UInt(stack.ip))
    modrel = UInt(UInt(stack.ip)-base)
    loc, fde = find_fde(mod, modrel)
    cie = realize_cie(fde)
    nbytes = UInt(CallFrameInfo.fde_range(fde, cie))
    seek(handle(mod), loc)
    insts = read(handle(mod), UInt8, nbytes)
    base, loc, insts
end

function ASTInterpreter.execute_command(state, stack, ::Val{:disas}, command)
    base, loc, insts = get_insts(stack)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    disasm_around_ip(STDOUT, insts, UInt64(x.ip-loc-base-(x.stacktop?0:1)); ipbase=base+loc, circular = false)
    return false
end

function update_stack!(state)
    did_fixup, regs = RR.fixup_RC(current_task(session), icxx"$(current_task(session))->regs();")
    stack = Gallium.stackwalk(regs, current_task(session), modules, rich_c = true)
    stack[end].stacktop = !did_fixup
    state.interp = state.top_interp = Gallium.NativeStack(stack,state.top_interp.modules)
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:si}, command)
    RR.single_step!(session)
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:ip}, command)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    println(x.ip)
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:nb}, command)
    # First determine the ip of the next branch
    base, loc, insts = get_insts(stack)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    ctx = DisAsmContext()
    Offset = UInt(x.ip - loc - base)
    branchip = 0
    while Offset <= sizeof(insts)
        (Inst, InstSize) = getInstruction(insts, Offset; ctx = ctx)
        if mayAffectControlFlow(Inst,ctx)
            branchip = base + loc + Offset
            break
        end
        Offset += InstSize
        free(Inst)
    end
    @assert branchip != 0
    icxx"$(current_task(session))->vm()->add_breakpoint($branchip,rr::BKPT_USER);"
    RR.step_until_bkpt!(session)
    icxx"$(current_task(session))->vm()->remove_breakpoint($branchip,rr::BKPT_USER);"
    update_stack!(state)
    return true
end

function demangle(name)
    startswith(name,"_Z") || return name
    status = Ref{Cint}()
    bufsize = Ref{Csize_t}(0)
    str = icxx"""
        abi::__cxa_demangle($(pointer(name)),nullptr,
        &$bufsize, &$status);
    """
    @assert status[] == 0
    ret = bytestring(str)
    Libc.free(str)
    ret
end

using DataStructures

"""
Show the five instructions surrounding ipoffset (two before, two after), with an
indicator which instruction is at ipoffset.
"""
function disasm_around_ip(io, insts, ipoffset; ipbase = 0, circular = true)
    Offset = 0
    ctx = DisAsmContext()
    const InstInfo = Tuple{Int,Bool,AbstractString}
    buf = circular ? CircularBuffer{InstInfo}(5) : Vector{InstInfo}()
    targetn = typemax(Int64)
    ipinstoffset = 0
    while Offset < sizeof(insts) && targetn > 0
        (Inst, InstSize) = getInstruction(insts, Offset; ctx = ctx)
        lastoffset = Offset
        Offset += InstSize
        iobuf = IOContext(IOBuffer(),:disasmctx=>ctx)
        print(iobuf, Inst)
        push!(buf, (lastoffset, mayAffectControlFlow(Inst,ctx),
            takebuf_string(iobuf.io)))
        targetn -= 1
        if circular && Offset > ipoffset && targetn > 2 # Two more
            ipinstoffset = lastoffset
            targetn = 2
        end
        free(Inst)
    end
    for i = 1:length(buf)
        off, branch, inst = buf[i]
        attarget = off == ipinstoffset
        p = string(attarget ? "=> " : "   ",
            "0x",hex(UInt64(ipbase+off),2sizeof(UInt64)),"<+",off,">:",
            inst)
        if attarget
            print_with_color(:yellow, io, p)
        elseif branch
            print_with_color(:red, io, p)
        else
            print(io, p)
        end
        println(io)
    end
end

function ASTInterpreter.print_status(x::Gallium.CStackFrame; kwargs...)
    print("Stopped in function ")
    println(demangle(Gallium.Unwinder.symbolicate(modules, UInt64(x.ip))))
    if x.line != 0
        # Print file here
    else
        base, loc, insts = get_insts(x)
        disasm_around_ip(STDOUT, insts, UInt64(x.ip-loc-base-(x.stacktop?0:1)); ipbase=base+loc)
    end
end

function ASTInterpreter.print_frame(io, num, x::Gallium.CStackFrame)
    print(io, "[$num] ")
    print(io, demangle(Gallium.Unwinder.symbolicate(modules, UInt64(x.ip))), " ")
    if x.line != 0
      print(io, " at ",x.file,":",x.line)
    end
    println(io)
end

ASTInterpreter.RunDebugREPL(Gallium.NativeStack(stack, modules))
