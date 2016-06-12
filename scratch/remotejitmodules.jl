timeline, modules = replay("/home/kfischer/.local/share/rr/julia-47")

using Gallium: RemotePtr, LazyJITModules
using ObjFileBase

#Gallium.breakpoint(timeline, :jl_exit)
#Gallium.breakpoint(timeline, :chidr)
#Gallium.breakpoint(timeline, 0x7f735e37dc74)
RR.continue!(timeline)

modules = Gallium.MultiASModules{RR.AddressSpaceUid}(Dict{RR.AddressSpaceUid, Any}()) do session
    imageh = RR.read_exe(session)
    LazyJITModules(Gallium.GlibcDyldModules.load_library_map(session, imageh), 0)
end

function Gallium.retrieve_obj_data(timeline::Union{RR.ReplayTimeline, RR.ReplaySession}, ip)
    run_function(timeline, :jl_get_dobj_data, ip) do task
        regs = icxx"$task->regs();"
        @assert UInt(Gallium.ip(regs)) == 0
        array_ptr = Gallium.get_dwarf(regs, :rax)
        @show array_ptr
        data_ptr = Gallium.load(task, RemotePtr{RemotePtr{UInt8}}(array_ptr))
        data_size = Gallium.load(task, RemotePtr{Csize_t}(array_ptr+8))
        Gallium.load(task, data_ptr, data_size)
    end
end

function Gallium.retrieve_section_start(timeline::Union{RR.ReplayTimeline, RR.ReplaySession}, ip)
    run_function(timeline, :jl_get_section_start, ip) do task
        regs = icxx"$task->regs();"
        (UInt(Gallium.ip(regs)) == 0) || return RemotePtr{Void}(0)
        addr = Gallium.get_dwarf(regs, :rax)
        RemotePtr{Void}(addr)
    end
end

#focus_tid = 7308
RunDebugREPL()
