module RR

    using Cxx
    using Gallium
    import Gallium: load, mapped_file
    using ObjFileBase
    
    function __init__()
        Libdl.dlopen(joinpath(ENV["HOME"],"rr-build/lib/librrlib.so"),
            Libdl.RTLD_GLOBAL)
        Cxx.addHeaderDir(joinpath(ENV["HOME"],"rr/src"), kind = C_System)
        Cxx.addHeaderDir(joinpath(ENV["HOME"],"rr-build"), kind = C_System)
        cxx"""
            #include <ReplaySession.h>
            #include <ReplayTask.h>
        """
    end
    __init__()
    
    const ReplaySession = cxxt"rr::ReplaySession::shr_ptr"
    
    function Base.current_task(session::ReplaySession)
        icxx"$session->current_task();"
    end
    
    function step_until_exec!(session)
        while !icxx"$session->done_initial_exec();"
            step!(session)
        end
    end
    
    function step!(session)
        icxx"$session->replay_step(rr::RUN_CONTINUE);"
    end
    
    function single_step!(session)
        icxx"$session->replay_step(rr::RUN_SINGLESTEP);"
    end

    function step_until_bkpt!(session)
        while !icxx"$session->replay_step(rr::RUN_CONTINUE).break_status.breakpoint_hit;"
        end
    end

    function Base.show(io::IO, frame::rcpp"rr::TraceFrame")
        print(io,icxx"$frame.ticks();",": ")
        print_with_color(:green,io,bytestring(icxx"$frame.event().str();"))
        if icxx"$frame.event().is_syscall_event();"
            println(io, " ", bytestring(
                icxx"rr::state_name($frame.event().Syscall().state);"))
        end
    end
    
    function read_exe(vm)
       readmeta(IOBuffer(open(read,bytestring(icxx"$vm->exe_image();"))))
   end

    function read_exe(session::ReplaySession)
        t = current_task(session)
        @assert t != C_NULL
        read_exe(icxx"$t->vm();")
    end
    
    const AddrSpace = cxxt"rr::AddressSpace::shr_ptr"
    
    
    
    # Remote memory operations
    function Cxx.cppconvert{T}(ptr::RemotePtr{T})
        icxx"rr::remote_ptr<$T>{$(ptr.ptr)};"
    end
    function Cxx.cppconvert(ptr::RemoteCodePtr)
        icxx"rr::remote_code_ptr{$(ptr.ptr)};"
    end
    Base.convert(::Type{UInt64}, ptr::vcpp"rr::remote_code_ptr") =
        icxx"$ptr.register_value();"
    Base.convert{T}(::Type{UInt64}, ptr::cxxt"rr::remote_ptr<$T>") =
        icxx"$ptr.as_int();"
    
    typealias RRRemotePtr{T} Union{RemotePtr{T}, cxxt"rr::remote_ptr<$T>"}
    function load{T<:Cxx.CxxBuiltinTypes}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = icxx"$vm->read_mem($ptr,&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res
    end

    function load{T}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = reinterpret(T,map(unsafe_load,icxx"$vm->read_mem(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(T)),&$ok);"))[]
        ok[] || error("Failed to read memory at address $ptr")
        res
    end

    saved_auxv(vm::AddrSpace) = map(unsafe_load,icxx"$vm->saved_auxv();")
    saved_auxv(vm::pcpp"rr::ReplayTask") = saved_auxv(icxx"$vm->vm();")

    function mapped_file(vm::pcpp"rr::ReplayTask", ptr)
        @assert icxx"$vm->vm()->has_mapping($ptr);"
        bytestring(icxx"$vm->vm()->mapping_of($ptr).map.fsname();")
    end

    import Gallium.GlibcDyldModules: load_library_map, compute_entry_ptr
    function load_library_map(task::pcpp"rr::ReplayTask", imageh)
        slide = compute_entry_ptr(saved_auxv(task)) -
            imageh.file.header.e_entry
        load_library_map(task, imageh, slide)
    end
    
    # Registers
    import Gallium.Registers: ip, invalidate_regs!, set_sp!, set_ip!, set_dwarf!, get_dwarf
    const RRRegisters = Union{rcpp"rr::Registers",vcpp"rr::Registers"}

    Base.copy(regs::RRRegisters) = icxx"rr::Registers{$regs};"
    ip(regs::RRRegisters) = icxx"$regs.ip();"
    invalidate_regs!(regs::RRRegisters) = nothing # RR does not track validity
    set_sp!(regs::RRRegisters, sp) = icxx"$regs.set_sp($(RemotePtr{Void}(sp)));"
    set_ip!(regs::RRRegisters, ip) = icxx"$regs.set_ip($(RemoteCodePtr(ip)));"
    function set_dwarf!(regs::RRRegisters, regno, val)
        gdbregno = Gallium.X86_64.inverse_gdb[Gallium.X86_64.dwarf_numbering[regno]]
        valr = Ref{UInt64}(UInt64(val))
        icxx"$regs.write_register((rr::GdbRegister)$gdbregno,&$valr,sizeof(uintptr_t));"
    end
    function get_dwarf(regs::RRRegisters, regno)
        gdbregno = Gallium.X86_64.inverse_gdb[Gallium.X86_64.dwarf_numbering[regno]]
        buf = Ref{UInt64}(0)
        defined = Ref{Bool}()
        icxx"$regs.read_register((uint8_t*)&$buf, (rr::GdbRegister)$gdbregno, &$defined);"
        buf[]
    end

    """
        RR hooks syscall instructions by inserting a call instruction and
        redirecting to its own mapped page. If we're on that page, do the first
        unwind step manually to get the correct register context.
    """
    function fixup_RC(task::pcpp"rr::ReplayTask", RC)
        RC = copy(RC)
        theip = ip(RC)
        vm = icxx"$task->vm();"
        did_fixup = false
        if UInt64(icxx"$vm->rr_page_start();") <= UInt64(theip) <= UInt64(icxx"$vm->rr_page_start() +
                $vm->rr_page_size();")
            set_ip!(RC,load(task, RemotePtr{RemoteCodePtr}(icxx"$RC.sp();")))
            set_sp!(RC,UInt64(icxx"$RC.sp();")+sizeof(Ptr{Void}))
            did_fixup = true
        end
        did_fixup, RC
    end
    
end # module
