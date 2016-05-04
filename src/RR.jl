module RR

    using Cxx
    using Gallium
    import Gallium: load, write_mem, mapped_file, enable, disable
    using Gallium: process_lowlevel_conditionals, Location
    using ObjFileBase

    function __init__()
        Libdl.dlopen(joinpath(ENV["HOME"],"rr-build/lib/librrlib.so"),
            Libdl.RTLD_GLOBAL)
        Cxx.addHeaderDir(joinpath(ENV["HOME"],"rr/src"), kind = C_System)
        Cxx.addHeaderDir(joinpath(ENV["HOME"],"rr-build"), kind = C_System)
        cxx"""
            #include <ReplaySession.h>
            #include <ReplayTask.h>
            #include <ReplayTimeline.h>
            #include <AutoRemoteSyscalls.h>
        """
    end
    __init__()

    const ReplaySession = Union{cxxt"rr::ReplaySession::shr_ptr",pcpp"rr::ReplaySession"}
    const ReplayTimeline = Union{pcpp"rr::ReplayTimeline"}

    function Base.current_task(session::ReplaySession)
        @assert icxx"$session != 0;"
        task = icxx"$session->current_task();"
        @assert task != 0
        task
    end

    current_session(timeline::ReplayTimeline) = icxx"&$timeline->current_session();"

    function step_until_exec!(session)
        while !icxx"$session->done_initial_exec();"
            step!(session)
        end
    end

    function step!(session)
        icxx"$session->replay_step(rr::RUN_CONTINUE);"
    end

    function step!(session, target)
        icxx"""
            rr::ReplaySession::StepConstraints c(rr::RUN_CONTINUE);
            c.ticks_target = $target;
            $session->replay_step(c);
        """
    end

    function reverse_single_step!(session, task, timeline)
        icxx"""
        auto stop_filter = [&](rr::ReplayTask* t) -> bool {
            return true;
        };
        auto interrupt_check = [&]() { return false; };
        $timeline->reverse_singlestep(
            $task->tuid(), $task->tick_count(), stop_filter, interrupt_check);
        """
    end

    function single_step!(session)
        icxx"$session->replay_step(rr::RUN_SINGLESTEP);"
    end

    function at_breakpoint(timeline::ReplayTimeline)
        loc = Gallium.Location(timeline,
            ip(icxx"$(current_task(current_session(timeline)))->regs();"))
        haskey(Gallium.bps_at_location, loc)        
    end

    function orig_byte(task,addr)
        icxx"""
            auto it = $task->vm()->breakpoints.find($addr);
            assert(it != $task->vm()->breakpoints.end());
            it->second.overwritten_data;
        """
    end

    function emulate_single_step!(timeline::ReplayTimeline,
            vm = current_task(current_session(timeline)))
        task = current_task(current_session(timeline))
        regs = icxx"$(task)->regs();"
        insts = load(task, RemotePtr{UInt8}(ip(regs)), 15)
        insts[1] = orig_byte(task, ip(regs))
        Gallium.X86_64.instemulate!(insts, vm, regs) || return false
        icxx"$task->set_regs($regs);"
        return true
    end

    function single_step!(timeline::ReplayTimeline)
        # To get past any breakpoints, check if our current location
        # is a breakpoint location and if so, temporarily clear it
        # while stepping past.
        did_disable = false
        loc = Gallium.Location(timeline,
            ip(icxx"$(current_task(current_session(timeline)))->regs();"))
        if haskey(Gallium.bps_at_location, loc)
            disable(loc)
            did_disable = true
        end
        res = single_step!(current_session(timeline))
        if did_disable
            enable(loc)
        end
        res
    end

    function step_until_bkpt!(session::ReplaySession)
        while disable_sigint() do
                !icxx"$session->replay_step(rr::RUN_CONTINUE).break_status.breakpoint_hit;"
            end
        end
    end

    function step_until_bkpt!(timeline::ReplayTimeline)
        while true
            exited, bp_hit = disable_sigint() do
                res = icxx"$(current_session(timeline))->replay_step(rr::RUN_CONTINUE);"
                (icxx"$res.status == rr::REPLAY_EXITED;",
                 icxx"$res.break_status.breakpoint_hit;")
            end
            exited && return false
            bp_hit && return true
            icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        end
    end
    
    function continue!(timeline)
        while step_until_bkpt!(timeline)
            regs = icxx"$(current_task(current_session(timeline)))->regs();"
            if process_lowlevel_conditionals(Location(timeline, ip(regs)), regs)
                break
            end
            # Step past the breakpoint
            single_step!(timeline)
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

    function read_exe(task)
        @assert task != C_NULL
        readmeta(IOBuffer(open(read,bytestring(icxx"$task->vm()->exe_image();"))))
    end

    function read_exe(session::ReplaySession)
        read_exe(current_task(session))
    end

    using Gallium.Hooking: PROT_READ, PROT_WRITE
    # Mapping remote mappings
    function map_remote(task, mapping::cxxt"const rr::KernelMapping*")
        fd = icxx"""
            rr::AutoRemoteSyscalls remote($task);
            rr::ScopedFd local_fd = remote.retrieve_fd($(mapping)->tracee_fd());
            return dup(local_fd.get());
        """
        msize = icxx"$(mapping)->size();";
        addr = ccall(:mmap,
            Ptr{UInt8}, (Ptr{Void},Csize_t,Cint,Cint,Cint,Int64),
            C_NULL, msize, PROT_READ | PROT_WRITE, Base.Mmap.MAP_SHARED, fd, 0)
        systemerror("mmap",addr==Ptr{Void}(-1))
        r = pointer_to_array(addr, (msize,), false)
        ccall(:close, Void, (Cint,), fd)
        r
    end

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
    Base.convert{T}(::Type{RemotePtr{T}}, ptr::cxxt"rr::remote_ptr<$T>") =
        RemotePtr{T}(UInt(ptr))

    typealias RRRemotePtr{T} Union{RemotePtr{T}, cxxt"rr::remote_ptr<$T>"}
    function load{T<:Cxx.CxxBuiltinTypes}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = icxx"$vm->read_mem($ptr,&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res
    end

    function load{T}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = Ref{T}()
        icxx"$vm->read_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(T)),(uint8_t*)&$res,&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res[]
    end
    
    function write_mem{T}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T}, val::T)
        ok = Ref{Bool}(true)
        res = Ref{T}(val)
        icxx"$vm->write_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(T)),(uint8_t*)&$res,&$ok);"
        ok[] || error("Failed to write memory at address $ptr")
        nothing
    end

    function load{T}(vm::pcpp"rr::ReplayTask", ptr::RRRemotePtr{T}, n)
        ok = Ref{Bool}(true)
        res = Vector{T}(n)
        icxx"$vm->read_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(n*sizeof(T)),$(Ptr{UInt8}(pointer(res))),&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res
    end

    saved_auxv(vm::pcpp"rr::ReplayTask") = map(unsafe_load,icxx"$vm->vm()->saved_auxv();")

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
        gdbregno = Gallium.X86_64.dwarf2gdb(regno)
        valr = Ref{UInt64}(UInt64(val))
        icxx"$regs.write_register((rr::GdbRegister)$gdbregno,&$valr,sizeof(uintptr_t));"
    end
    function get_dwarf(regs::RRRegisters, regno)
        gdbregno = Gallium.X86_64.dwarf2gdb(regno)
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
        did_fixup = false
        if UInt64(icxx"$task->vm()->rr_page_start();") <= UInt64(theip) <= UInt64(icxx"$task->vm()->rr_page_start() +
                $task->vm()->rr_page_size();")
            set_ip!(RC,load(task, RemotePtr{RemoteCodePtr}(icxx"$RC.sp();")))
            set_sp!(RC,UInt64(icxx"$RC.sp();")+sizeof(Ptr{Void}))
            did_fixup = true
        end
        did_fixup, RC
    end

end # module
