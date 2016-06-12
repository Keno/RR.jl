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
    base, mod = Gallium.find_module(timeline, modules, UInt(stack.ip))
    modrel = UInt(UInt(stack.ip)-base)
    if isnull(mod.xpdata)
        loc, fde = find_fde(mod, modrel)
        seekloc = loc
        cie = realize_cie(fde)
        nbytes = UInt(CallFrameInfo.fde_range(fde, cie))
    else
        entry = Gallium.Unwinder.find_seh_entry(mod, modrel)
        loc = entry.start
        # Need to translate from virtual to file addresses. Hardcode 0xa00 for
        # now.
        seekloc = loc - 0xa00
        nbytes = entry.stop - entry.start
    end
    if ObjFileBase.isrelocatable(handle(mod))
        # For JIT frames, base is the start of .text, so we need to add that
        # offset back
        text = first(filter(x->sectionname(x)==
            ObjFileBase.mangle_sname(handle(mod),"text"),Sections(handle(mod))))
        seekloc += sectionoffset(text)
    end
    seek(handle(mod), seekloc)
    insts = read(handle(mod), UInt8, nbytes)
    base, loc, insts
end

function ASTInterpreter.execute_command(state, stack, ::Val{:disas}, command)
    base, loc, insts = get_insts(stack)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    disasm_around_ip(STDOUT, insts, UInt64(x.ip-loc-base-(x.stacktop?0:1)); ipbase=base+loc, circular = false)
    return false
end

function compute_stack(modules, task = current_task(current_session(timeline)))
    did_fixup, regs = RR.fixup_RC(task, icxx"$task->regs();")
    stack, RCs = Gallium.stackwalk(regs, task, modules, rich_c = true, collectRCs = true)
    if length(stack) != 0
        stack[end].stacktop = !did_fixup
    end
    Gallium.NativeStack(stack,RCs,modules,task)
end

function update_stack!(state, task = current_task(current_session(timeline)))
    state.interp = state.top_interp = compute_stack(state.top_interp.modules, task)
end
update_stack!(state::Void, _ = nothing) = nothing

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:si}, command)
    RR.single_step!(timeline)
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rsi}, command)
    task = isa(stack, Gallium.NativeStack) ? stack.session : current_task(current_session(timeline))
    RR.reverse_single_step!(current_session(timeline),task,timeline)
    update_stack!(state)
    return true
end

"""
Attempt to reverse step until the entry to the current function.
"""
function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rf}, command)
    # Algorithm:
    # 1. Determine the location of the function entry point.
    # 2. Determine how to compute the CFA, both here and at the function entry
    #    point.
    # 3. Continue unless the CFA matches
    
    # Determine module
    stack = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    mod, base, ip = Gallium.modbaseip_for_stack(state, stack)
    modrel = UInt(ip - base)
    loc, fde = Gallium.Unwinder.find_fde(mod, modrel)
    
    # Compute CFI
    ciecache = nothing
    isa(mod, Module) && (ciecache = mod.ciecache)
    cie::DWARF.CallFrameInfo.CIE, ccoff = realize_cieoff(fde, ciecache)
    target_delta = modrel - loc
    
    entry_rs = CallFrameInfo.evaluate_program(fde, UInt(0), cie = cie, ciecache = ciecache, ccoff=ccoff)
    here_rs =  CallFrameInfo.evaluate_program(fde, target_delta, cie = cie, ciecache = ciecache, ccoff=ccoff)

    # Compute the CFA here
    regs = icxx"$(current_task(current_session(timeline)))->regs();"
    here_cfa = Gallium.Unwinder.compute_cfa_addr(current_task(current_session(timeline)), regs, here_rs)
    here_rsp = Gallium.get_dwarf(regs, :rsp)
    
    # Set a breakpoint at function entry
    bp = Gallium.breakpoint(timeline, base + loc)
    
    # Reverse continue until the breakpoint is hit at a matching CFA, or until
    # we're at a breakpoint higher up the stack (which would imply that we missed it)
    while true
        RR.reverse_continue!(timeline)
        # TODO: Check that we're at the right breakpoint
        new_regs = icxx"$(current_task(current_session(timeline)))->regs();"
        new_cfa = Gallium.Unwinder.compute_cfa_addr(current_task(current_session(timeline)), new_regs, entry_rs)
        if here_cfa == new_cfa
            break
        elseif Gallium.get_dwarf(new_regs, :rsp) > here_rsp
            println("WARNING: May have missed function call.")
            break
        end
    end
    Gallium.disable(bp)
    
    # Step once more to get out of the function
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
    found, symb = symbolicate_frame(timeline, modules, x)
    println(symb)
    if x.line != 0
        code = ASTInterpreter.readfileorhist(x.file)
        if code !== nothing
            ASTInterpreter.print_sourcecode(
                code, x.line, x.declfile, x.declline)
            return
        end
    end
    ipoffset = 0
    ipbase = x.ip
    if found
        base, loc, insts = get_insts(x)
        ipbase = base+loc
        ipoffset = UInt64(x.ip-loc-base-(x.stacktop?0:1))
    else
        insts = Gallium.load(current_vm(timeline), Gallium.RemotePtr{UInt8}(x.ip), 40)
    end
    disasm_around_ip(STDOUT, insts, ipoffset; ipbase=ipbase)
end

function symbolicate_frame(session, modules, x)
    found = false
    symb = "Unknown Function"
    try
        symb = demangle(Gallium.Unwinder.symbolicate(session, modules, UInt64(x.ip)))
        found = !contains(symb, "Unknown")
    catch err
        (!isa(err, ErrorException) || !contains(err.msg, "found")) && rethrow(err)
    end
    found, symb
end

function ASTInterpreter.print_frame(io, num, x::Gallium.CStackFrame)
    print(io, "[$num] ")
    found, symb = symbolicate_frame(timeline, modules, x)
    print(io, symb, " ")
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
        push!(ticks, icxx"$(mark.mark).ptr->proto.key.ticks;")
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
    plot(timeline_layers(events, timeline_id = timeline_id)...,
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
    display(plot_timeline([ticks; start_time(timeline);
        me; end_time(timeline); explicit_ticks], colors))
    println("The timeline is intact.")
    return false
end

immutable AnnotatedMark
    mark
    annotation::String
end

const mark_stack = AnnotatedMark[]
function ASTInterpreter.execute_command(state, stack, ::Val{:mark}, command)
    push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",command[5:end]))
    return false
end

using JLD
"""
List all marks.
"""
function ASTInterpreter.execute_command(state, stack, ::Val{:marks}, command)
    subcmds = split(command," ")[2:end]
    if isempty(subcmds) || subcmds[1] == "list"
        for (i,mark) in enumerate(mark_stack)
            println("[$i] Mark (",mark.annotation,")")
        end
    elseif subcmds[1] == "save"
        annotations = map(x->x.annotation,mark_stack)
        marks = map(x->reinterpret(UInt8,[icxx"$(x.mark)->ptr.proto".data]),mark_stack)
        @save "marks.jld" annotations marks
    elseif subcmds[1] == "load"
        @load "marks.jld" annotations marks
        pms = map(x->cxxt"rr::ReplayTimeline::ProtoMark"{312}(reinterpret(NTuple{312,UInt8},x)[]),marks)
        println("Recreating marks. One moment please...")
        for (annotation, pm) in zip(annotations, pms)
            RR.seek(timeline, pm)
            push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",annotation))
        end
    else
        print_with_color(:red, "Unknown subcommand\n")
    end
    return false
end


using ProgressMeter
import RR: when
when() = when(current_session(timeline))
function ASTInterpreter.execute_command(state, stack, ::Val{:timejump}, command)
    subcmd = split(command)[2:end]
    if startswith(subcmd[1],"@")
        n = parse(Int, subcmd[1][2:end])
        icxx"$timeline->seek_to_mark($(mark_stack[n].mark));"
        icxx"$timeline->apply_breakpoints_and_watchpoints();"
        #global stack_remap = compute_remap()
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
        now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
    end
    while when() < target
        res = RR.single_step!(timeline)
        check_for_breakpoint(res) && return true
        now = when()
        now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
    end
    icxx"$timeline->apply_breakpoints_and_watchpoints();"
    println("We have arrived.")
    update_stack!(state)
    return true
end

function Gallium.breakpoint(timeline::RR.ReplayTimeline, fname::Symbol)
    syms = Gallium.lookup_syms(timeline, modules, fname)
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

global focus_tid = 0
function ASTInterpreter.execute_command(state, stack, ::Val{:c}, command)
    RR.single_step!(timeline)
    try
        while true
            res = RR.continue!(timeline)
            stop_task = icxx"$res.break_status.task;"
            (focus_tid == 0 || (stop_task != 0 && focus_tid == icxx"$stop_task->rec_tid;")) && break
        end
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

function ASTInterpreter.execute_command(state, stack, ::Val{:task}, command)
    subcommand = split(command, " ")[2:end]
    if subcommand[1] == "list"
        icxx"""
            for (auto &task : $(current_session(timeline))->tasks())
                $:(println(IOContext(STDOUT,:modules=>modules),
                    icxx"return task.second;"); nothing);
        """
        println(STDOUT)
    elseif subcommand[1] == "select"
        n = parse(Int, subcommand[2])
        (n < 1 || n > icxx"$(current_session(timeline))->tasks().size();") &&
            (print_with_color(:red, STDERR, "Not a valid task"); return false)
        it = icxx"$(current_session(timeline))->tasks().begin();"
        while n > 1
            icxx"++$it;";
            n -= 1
        end
        update_stack!(state, icxx"$it->second;")
        return true
    end
    return false
end


function prepare_remote_execution(timeline)
    session = icxx"$(current_session(timeline))->clone_diversion();"
end

function prepare_remote_execution(session::RR.ReplaySession)
    session = icxx"$session->clone_diversion();"
end

function run_function(f, timeline, func, val)
    diversion = prepare_remote_execution(timeline)
    
    # Pick an arbitrary task to run our expression
    task = icxx"$diversion->tasks().begin()->second;"
    regs = icxx"$task->regs();"
    
    # Find the function ip
    (h, base, sym)  = Gallium.lookup_sym(timeline, modules, func)
    addr = base + ObjFileBase.deref(sym).st_value
    
    # Set up the call frame
    Gallium.set_ip!(regs, addr)
    new_rsp = Gallium.get_dwarf(regs, :rsp)-250
    new_rsp -= (new_rsp % 16)
    new_rsp += 8
    Gallium.set_dwarf!(regs, :rsp, new_rsp)
    
    # Set return address to 0
    Gallium.store!(task, Gallium.RemotePtr{UInt64}(new_rsp), UInt64(0))
    
    # Set up arguments
    Gallium.set_dwarf!(regs, :rdi, val)

    # Writes registers back to task
    icxx"$task->set_regs($regs);"
    
    # Alright, let's go
    while true
        res = icxx"$diversion->diversion_step($task);"
        if icxx"$res.status == rr::DiversionSession::DIVERSION_CONTINUE;" ||
            icxx"$res.break_status.signal != 0;"
            break
        end
    end
    
    f(task)
end


RunDebugREPL() = ASTInterpreter.RunDebugREPL(compute_stack(modules))
