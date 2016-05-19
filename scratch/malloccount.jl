timeline, modules = replay("")
for i = 1:2000
RR.step!(current_session(timeline))
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
end

stacktraces = Any[]
using Gallium: breakpoint, conditional
cache = Gallium.Unwinder.CFICache(100_000)
bp = conditional(breakpoint(timeline, :malloc)) do loc, RC
    stack = UInt[]
    bt = Gallium.rec_backtrace(RC, current_vm(loc.vm), modules, true, cache) do RC
        push!(stack,UInt(Gallium.ip(RC)))
        return true
    end
    push!(stacktraces, stack)
    return false
end
ASTInterpreter.execute_command(nothing, nothing, Val{:mark}(), "mark")
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 128000000")

cache = Gallium.Unwinder.CFICache(100_000)
Profile.init(n=10^9)
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump @1")
@profile ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 128000000")
IJulia=1
using ProfileView
ProfileView.svgwrite("profile.svg", C = true)
