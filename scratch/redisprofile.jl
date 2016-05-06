using Gallium: get_dwarf

push!(ASTInterpreter.SEARCH_PATH, "/home/kfischer/cs262project/redis/src")
push!(ASTInterpreter.SEARCH_PATH, "/home/kfischer/cs262project/redis/deps/hiredis/")

bp1 = Gallium.breakpoint(timeline, :write)
bp2 = Gallium.breakpoint(timeline, :read)

writes = Any[]
Gallium.conditional(bp1) do loc, RC
    fd = UInt(get_dwarf(RC, :rdi))
    buf = Gallium.RemotePtr{UInt8}(get_dwarf(RC, :rsi))
    len = get_dwarf(RC, :rdx)
    data = RR.load(current_vm(), buf, len)
    push!(writes, (fd, data))
    return false
end

reads = Any[]
Gallium.conditional(bp2) do loc, RC
    fd = UInt(get_dwarf(RC, :rdi))
    buf = Gallium.RemotePtr{UInt8}(get_dwarf(RC, :rsi))
    # Step to exit
    RC′ = Gallium.Unwinder.unwind_step(current_vm(), modules, RC)[2]
    RR.step_to_address!(timeline, Gallium.ip(RC′); disable_bps = true)
    len = get_dwarf(RC, :rax)
    data = RR.load(current_vm(), buf, len)
    push!(reads, (fd, data))
    return false
end

RR.continue!(timeline)

#RunDebugREPL()
