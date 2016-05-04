stack_map = icxx"""
    auto maps = $(current_task(current_session(timeline)))->vm()->maps();
    auto it = maps.begin();
    for (;it != maps.end(); ++it)
        if (it->map.tracee_fd() >= 0)
            return &(it->map);
    return (const rr::KernelMapping*)nullptr;
"""
stack = RR.map_remote(current_task(current_session(timeline)), stack_map);
stack_remap = Gallium.Remap[Gallium.Remap(icxx"$stack_map->start();",icxx"$stack_map->size();",stack)]

# Override
current_vm(timeline) = Gallium.TransparentRemap(current_task(current_session(timeline)), stack_remap::Vector{Gallium.Remap})
current_vm() = current_vm(timeline)

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
#ASTInterpreter.execute_command(nothing, nothing, Val{:mark}(), "mark")
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 10000")

cache = Gallium.Unwinder.CFICache(100_000)
Profile.init(n=10^9)
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 32000000")
IJulia=1
using ProfileView
ProfileView.svgwrite("profile.svg", C = true)
