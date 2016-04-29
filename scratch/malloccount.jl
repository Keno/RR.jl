stacktraces = Any[]
using Gallium: breakpoint, conditional
conditional(breakpoint(timeline, :malloc)) do loc, RC
    push!(stacktraces, Gallium.stackwalk(RC,
      current_task(current_session(loc.vm)), modules, rich_c = true))
    return false
end
