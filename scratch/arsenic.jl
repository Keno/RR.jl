using RR; using Cxx
using RR: current_session
session = icxx"""rr::ReplaySession::create("");"""
timeline = icxx"""new rr::ReplayTimeline{std::move($session),rr::ReplaySession::Flags{}};""";
session = nothing
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
RR.step_until_exec!(current_session(timeline))
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
for i = 1:2000;
RR.step!(current_session(timeline));
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
end
imageh = RR.read_exe(current_session(timeline))
modules = Gallium.GlibcDyldModules.load_library_map(current_task(current_session(timeline)), imageh)
did_fixup, regs = RR.fixup_RC(current_task(current_session(timeline)), icxx"$(current_task(current_session(timeline)))->regs();")
stack = Gallium.stackwalk(regs, current_task(current_session(timeline)), modules, rich_c = true)
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
using Gallium: Location

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
    did_fixup, regs = RR.fixup_RC(current_task(current_session(timeline)), icxx"$(current_task(current_session(timeline)))->regs();")
    stack = Gallium.stackwalk(regs, current_task(current_session(timeline)), modules, rich_c = true)
    stack[end].stacktop = !did_fixup
    state.interp = state.top_interp = Gallium.NativeStack(stack,state.top_interp.modules)
end
update_stack!(state::Void) = nothing

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:si}, command)
    RR.single_step!(timeline)
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rsi}, command)
    RR.reverse_single_step!(current_session(timeline),current_task(current_session(timeline)),timeline)
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:ip}, command)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    println(x.ip)
    return false
end

function ASTInterpreter.execute_command(state, stack, ::Val{:when}, command)
    show(STDOUT, UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();"))
    println(STDOUT); println(STDOUT)
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
    icxx"$(current_task(current_session(timeline)))->vm()->add_breakpoint($branchip,rr::BKPT_USER);"
    RR.step_until_bkpt!(current_session(timeline))
    icxx"$(current_task(current_session(timeline)))->vm()->remove_breakpoint($branchip,rr::BKPT_USER);"
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

function count_total_ticks(reader)
    icxx"""
        $reader.rewind();
        rr::TraceFrame frame;
        while (true) {
            rr::TraceFrame next_frame = $reader.read_frame();
            if ($reader.at_end())
                break;
            frame = next_frame;
        }
        frame.ticks();
    """
end
total_ticks = count_total_ticks(icxx"rr::TraceReader{$(current_session(timeline))->trace_reader()};")

using TerminalExtensions; using Gadfly; using Colors
const repl_theme = Gadfly.Theme(
    panel_fill=colorant"black", default_color=colorant"orange", major_label_color=colorant"white",
    minor_label_color=colorant"white", key_label_color=colorant"white", key_title_color=colorant"white",
    line_width=1mm
   )
eval(Gadfly,quote
   function writemime(io::IO, ::MIME"image/png", p::Plot)
       draw(PNG(io, Compose.default_graphic_width,
                Compose.default_graphic_height), p)
   end
end)

function collect_mark_ticks()
    map(unsafe_load,icxx"""
    std::vector<uint64_t> ticks;
    for(auto it : $timeline->reverse_exec_checkpoints) {
        ticks.push_back(it.first.ptr->key.ticks);
    }
    ticks;
    """)
end

function collect_mark_ticks(marks)
    ticks = UInt[]
    for mark in marks
        push!(ticks, icxx"$mark.ptr->key.ticks;")
    end
    ticks
end

function ASTInterpreter.execute_command(state, stack, ::Val{:timeline}, command)
    me = UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();")
    ticks = []
    contains(command, "internal") && (ticks = collect_mark_ticks())
    explicit_ticks = collect_mark_ticks(mark_stack)
    colors = [colorant"orange",colorant"green",colorant"purple"]
    (length(ticks) != 0) && unshift!(colors, colorant"blue")
    display(
    plot(x=[ticks...,0,me,23549392659,explicit_ticks...],
        y=[zeros(Int,length(ticks))...,0,0,0,zeros(Int,length(explicit_ticks))...],
        color=[[:internal_tick for _ in 1:length(ticks)]...,:end,:me,:end,
            [:explicit_tick for _ in 1:length(explicit_ticks)]...],
        Geom.point,Geom.line,repl_theme,Guide.xlabel("Time"),
        Guide.ylabel("Timeline"),
        Scale.color_discrete_manual(colors...))
    )
    println()
    println("The timeline is intact.")
    return false
end

const mark_stack = Any[]
function ASTInterpreter.execute_command(state, stack, ::Val{:mark}, command)
    push!(mark_stack,icxx"$timeline->mark();")
    return false
end

using ProgressMeter
when(session) = UInt64(icxx"$(current_task(session))->tick_count();")
when() = when(current_session(timeline))
current_vm() = current_task(current_session(timeline))
function ASTInterpreter.execute_command(state, stack, ::Val{:timejump}, command)
    subcmd = split(command)[2:end]
    if startswith(subcmd[1],"@")
        n = parse(Int, subcmd[1][2:end])
        icxx"$timeline->seek_to_mark($(mark_stack[n]));"
        icxx"$timeline->apply_breakpoints_and_watchpoints();"
        println("We have arrived.")
        update_stack!(state)
        return true
    end
    n = parse(Int, subcmd[1])
    me = when()
    target = me + n
    p = Progress(n, 1, "Time travel in progress (forwards)...", 50)
    function check_for_breakpoint(res)
        if icxx"$res.break_status.breakpoint_hit;"
            regs = icxx"$(current_task(current_session(timeline)))->regs();"
            if RR.process_lowlevel_conditionals(Location(timeline, Gallium.ip(regs)), regs)
                println("Interrupted by breakpoint.")
                update_stack!(state)
                return true
            end
        end
        false
    end
    while when() < target
        # Step past any breakpoints
        if RR.at_breakpoint(timeline)
            RR.emulate_single_step!(timeline, current_vm()) || RR.single_step!(timeline)
        end
        res = RR.step!(current_session(timeline), target)
        if icxx"$res.break_status.approaching_ticks_target;"
            break
        end
        check_for_breakpoint(res) && return true
        icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        now = when()
        now != me && ProgressMeter.update!(p, Int64(now - me))
    end
    while when() < target
        res = RR.single_step!(timeline)
        check_for_breakpoint(res) && return true
        now = when()
        now != me && ProgressMeter.update!(p, Int64(now - me))
    end
    icxx"$timeline->apply_breakpoints_and_watchpoints();"
    println("We have arrived.")
    update_stack!(state)
    return true
end

function Gallium.breakpoint(timeline::RR.ReplayTimeline, fname::Symbol)
    h, base, sym = Gallium.lookup_sym(modules, fname)
    addr = Gallium.RemoteCodePtr(base + ObjFileBase.deref(sym).st_value)
    Gallium.breakpoint(timeline, addr)
end

function Gallium.breakpoint(timeline::RR.ReplayTimeline, addr)
    bp = Gallium.Breakpoint()
    Gallium.add_location(bp, Gallium.Location(timeline, addr))
    bp
end

function Gallium.enable(timeline::RR.ReplayTimeline, loc::Location)
    icxx"$timeline->add_breakpoint(
            $(current_task(current_session(timeline))), $(loc.addr));"
end

function Gallium.disable(timeline::RR.ReplayTimeline, loc::Location)
    icxx"$timeline->remove_breakpoint(
            $(current_task(current_session(timeline))), $(loc.addr));"
end

function Gallium.print_location(io::IO, vm::RR.ReplayTimeline, loc)
    print(io, "In RR timeline at address ")
    show(io, loc.addr)
    println(io)
end

function ASTInterpreter.execute_command(state, stack, ::Val{:c}, command)
    RR.single_step!(timeline)
    try
        RR.continue!(timeline)
    catch err
        !isa(err, InterruptException) && rethrow(err)
    end
    update_stack!(state)
    return true
end

ASTInterpreter.RunDebugREPL(Gallium.NativeStack(stack, modules))
