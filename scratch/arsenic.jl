using RR; using Cxx
using RR: current_session
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

import Gallium.GlibcDyldModules: compute_entry_ptr

current_vm(timeline) = current_task(current_session(timeline))
current_vm() = current_vm(timeline)
function replay(trace_dir="")
    session = icxx"""rr::ReplaySession::create($(pointer(trace_dir)));"""
    timeline = icxx"""new rr::ReplayTimeline{std::move($session),rr::ReplaySession::Flags{}};""";
    session = nothing
    icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
    RR.step_until_exec!(current_session(timeline))
    regs = icxx"$(current_vm(timeline))->regs();"
    rsp = Gallium.get_dwarf(regs, Gallium.X86_64.inverse_dwarf[:rsp])
    icxx"""
    rr::AutoRemoteSyscalls remote($(current_vm(timeline)));
    rr::Session::make_private_shared(remote,$(current_vm(timeline))->vm()->mapping_of($rsp));
    """
    icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
    task = current_task(current_session(timeline))
    entrypt = compute_entry_ptr(RR.saved_auxv(task))
    icxx"$timeline->add_breakpoint($task, $entrypt);"
    RR.step_until_bkpt!(timeline)
    icxx"$timeline->remove_breakpoint($task, $entrypt);"
    icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
    imageh = RR.read_exe(current_session(timeline))
    modules = Gallium.GlibcDyldModules.load_library_map(current_task(current_session(timeline)), imageh)

    timeline, modules
end

function compute_remap()
    t = current_task(current_session(timeline))
    regs = icxx"$t->regs();"
    rsp = Gallium.get_dwarf(regs, Gallium.X86_64.inverse_dwarf[:rsp])
    map = icxx"""
    $t->vm()->mapping_of($rsp);
    """
    @assert icxx"$map.local_addr;" != C_NULL
    Gallium.Remap[Gallium.Remap(icxx"$map.map.start();",icxx"$map.map.size();",
    pointer_to_array(Ptr{UInt8}(icxx"$map.local_addr;"), (icxx"$map.map.size();",), false))]
end
#=
stack_remap = compute_remap()

current_vm(timeline) = Gallium.TransparentRemap(current_task(current_session(timeline)), stack_remap::Vector{Gallium.Remap})
current_vm() = current_vm(timeline)
=#

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

function compute_stack(modules)
    task = current_task(current_session(timeline));
    did_fixup, regs = RR.fixup_RC(task, icxx"$task->regs();")
    stack, RCs = Gallium.stackwalk(regs, current_task(current_session(timeline)), modules, rich_c = true, collectRCs = true)
    if length(stack) != 0
        stack[end].stacktop = !did_fixup
    end
    Gallium.NativeStack(stack,RCs,modules)
end

function update_stack!(state)
    state.interp = state.top_interp = compute_stack(state.top_interp.modules)
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
        code = ASTInterpreter.readfileorhist(x.file)
        if code !== nothing
            ASTInterpreter.print_sourcecode(
                code, x.line, x.declfile, x.declline)
            return
        end
    end
    base, loc, insts = get_insts(x)
    disasm_around_ip(STDOUT, insts, UInt64(x.ip-loc-base-(x.stacktop?0:1)); ipbase=base+loc)
end

function ASTInterpreter.print_frame(io, num, x::Gallium.CStackFrame)
    print(io, "[$num] ")
    print(io, demangle(Gallium.Unwinder.symbolicate(modules, UInt64(x.ip))), " ")
    if x.line != 0
      print(io, " at ",x.file,":",x.line)
    end
    println(io)
end

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

immutable TimelineEvent
    t::Int
    label::Symbol
end

start_time(timeline) = TimelineEvent(0, :start)
end_time(timeline) = TimelineEvent(RR.count_total_ticks(timeline), :end)
const timeline_default_colors = [colorant"orange",colorant"green",colorant"purple",colorant"blue"]
function timeline_layers(events; timeline_id = 0, pointfilterset=[])
    y = [timeline_id for _ in 1:length(events)]
    filterids = find(x->!(x.label in pointfilterset),events)
    [layer(x=map(x->x.t, events[filterids]),
        y=y[filterids],
        color = map(x->x.label, events[filterids]), Geom.point),
        layer(x=map(x->x.t, events),
            y=y, Geom.line)]
end

function plot_timeline(events, colors = timeline_default_colors; timeline_id = 0)
    display(
    plot(timeline_layers(events, timeline_id = timeline_id)...;
        repl_theme,Guide.xlabel("Time"),
        Guide.ylabel("Timeline"),
        Scale.color_discrete_manual(colors...))
    )
end

function ASTInterpreter.execute_command(state, stack, ::Val{:timeline}, command)
    me = TimelineEvent(UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();"),
        :me)
    ticks = []
    contains(command, "internal") && (ticks = collect_mark_ticks())
    ticks = [TimelineEvent(t, :internal_tick) for t in ticks]
    explicit_ticks = [TimelineEvent(t, :explicit_tick) for t in collect_mark_ticks(mark_stack)]
    colors = [colorant"orange",colorant"green",colorant"purple"]
    (length(ticks) != 0) && unshift!(colors, colorant"blue")
    display(plot_timeline([ticks..., start_time(timeline),
        me, end_time(timeline), explicit_ticks], colors))
    println("The timeline is intact.")
    return false
end

const mark_stack = Any[]
function ASTInterpreter.execute_command(state, stack, ::Val{:mark}, command)
    push!(mark_stack,icxx"$timeline->mark();")
    return false
end

using ProgressMeter
import RR: when
when() = when(current_session(timeline))
function ASTInterpreter.execute_command(state, stack, ::Val{:timejump}, command)
    subcmd = split(command)[2:end]
    if startswith(subcmd[1],"@")
        n = parse(Int, subcmd[1][2:end])
        icxx"$timeline->seek_to_mark($(mark_stack[n]));"
        icxx"$timeline->apply_breakpoints_and_watchpoints();"
        global stack_remap = compute_remap()
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
    syms = Gallium.lookup_syms(modules, fname)
    bp = Gallium.Breakpoint()
    for (h, base, sym) in syms
        addr = Gallium.RemoteCodePtr(base + ObjFileBase.deref(sym).st_value)
        Gallium.add_location(bp, Gallium.Location(timeline, addr))
    end
    bp
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

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:reg}, command)
    ns = state.top_interp
    @assert isa(ns, Gallium.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    regname = Symbol(split(command,' ')[2])
    if !haskey(Gallium.X86_64.inverse_dwarf, regname)
        print_with_color(:red, STDOUT, "No such register\n")
        return false
    end
    show(UInt(Gallium.get_dwarf(RC, Gallium.X86_64.inverse_dwarf[regname])))
    println(); println()
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:finish}, command)
    ns = state.top_interp
    @assert isa(ns, Gallium.NativeStack)
    parentRC = ns.RCs[end-(state.level)]
    theip = Gallium.ip(parentRC)
    RR.step_to_address!(timeline, theip; disable_bps = true)
    update_stack!(state)
    return true
end


RunDebugREPL() = ASTInterpreter.RunDebugREPL(compute_stack(modules))
