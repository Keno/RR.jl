#=
mkdir /dev/cpuset
mount -t cpuset cpuset /dev/cpuset
cd /dev/cpuset
mkdir default
mkdir rr
cd default
echo 0-6 > cpuset.cpus
while read i; do /bin/echo $i; done < ../tasks > tasks
cd ..
cd rr
echo 7 > cpuset.cpus
=#
using RR; using Cxx
using RR: current_session
session = icxx"""rr::ReplaySession::create("");"""
timeline = icxx"""new rr::ReplayTimeline{std::move($session),rr::ReplaySession::Flags{}};""";
session = nothing
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
open("/dev/cpuset/rr/tasks","w") do f
    print(f,icxx"$(current_task(current_session(timeline)))->real_tgid();")
end


function check_consistency()
    session = current_session(timeline)
    task = current_task(session)
    ticks = icxx"$task->tick_count();"
    traceticks = icxx"$session->current_trace_frame().ticks();"
    @show (ticks, traceticks)
end


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

const ctx = DisAsmContext()

for i = 1:100
  RR.single_step!(current_session(timeline))
end

function do_and_check_single!()
    task = current_task(current_session(timeline))
    regs = icxx"$task->regs();"
    ip = Gallium.ip(regs)
    insts = RR.load(current_task(current_session(timeline)),
      Gallium.RemotePtr{UInt8}(UInt(ip)), 20)
    @show insts
    @show UInt(ip)
    (Inst, InstSize) = getInstruction(insts, 0; ctx = ctx)
    @show (Inst, InstSize)
    @show icxx"$Inst->getOpcode();"
    ticks = icxx"$task->tick_count();"
    iscondbranch = isConditionalBranch(Inst, ctx)
    free(Inst)
    RR.single_step!(current_session(timeline))
    @assert icxx"$task->tick_count();" == ticks + iscondbranch
end
