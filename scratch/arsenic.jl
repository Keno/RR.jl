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
using AbstractTrees

import Gallium.GlibcDyldModules: compute_entry_ptr


current_vm() = current_vm(timeline)

#=
stack_remap = compute_remap()

current_vm(timeline) = Gallium.TransparentRemap(current_task(current_session(timeline)), stack_remap::Vector{Gallium.Remap})
current_vm() = current_vm(timeline)
=#

function get_insts(session, stack)
    stack = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    base, mod = Gallium.find_module(session, modules, UInt(stack.ip))
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


function Gallium.continue!(session::RR.ReplayTimeline)
    RR.single_step!(timeline)
    while true
        res = RR.continue!(timeline)
        stop_task = icxx"$res.break_status.task;"
        (focus_tid == 0 || (stop_task != 0 && focus_tid == icxx"$stop_task->rec_tid;")) && break
    end
end

global focus_tid = 0




RunDebugREPL() = ASTInterpreter.RunDebugREPL(compute_stack(modules))
