stacktraces = Any[]
using Gallium: breakpoint, conditional
bp = conditional(breakpoint(timeline, :malloc)) do loc, RC
    stack = UInt[]
    bt = Gallium.rec_backtrace(RC, current_task(current_session(loc.vm)), modules, true) do RC
        push!(stack,UInt(Gallium.ip(RC)))
        return true
    end
    push!(stacktraces, stack)
    return false
end
ASTInterpreter.execute_command(nothing, nothing, Val{:mark}(), "mark")
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 8000000")

#=
Profile.init(n=10^9)
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump @1")
@profile ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 8000000")
IJulia=1
using ProfileView
ProfileView.svgwrite("profile.svg", C = true)
=#
