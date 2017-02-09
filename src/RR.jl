module RR

    using Cxx
    using NativeDebugger
    import NativeDebugger: fallible_load, load, store!, mapped_file, enable, disable, ip
    using NativeDebugger: Location
    using ObjFileBase
    
    import Base: ==

    function __init__()
        DEPS_DIR = joinpath(dirname(@__FILE__),"..","deps")
        Libdl.dlopen(joinpath(DEPS_DIR,"usr/lib/librr.so"),
            Libdl.RTLD_GLOBAL)
        Cxx.addHeaderDir(joinpath(DEPS_DIR,"src/rr/src"), kind = C_System)
        Cxx.addHeaderDir(joinpath(DEPS_DIR,"build/rr"), kind = C_System)
        cxx"""
            #include <RecordSession.h>
            #include <RecordTask.h>
            #include <ReplayTask.h>
            #include <ReplayTimeline.h>
            #include <AutoRemoteSyscalls.h>
            #include <GdbServer.h>
            #include <algorithm>
            #include <kernel_metadata.h>
        """
    end
    __init__()

    const ReplayTask = pcpp"rr::ReplayTask"
    const AnyTask = Union{ReplayTask,pcpp"rr::RecordTask",pcpp"rr::Task"}
    const ReplaySession = Union{cxxt"rr::ReplaySession::shr_ptr",pcpp"rr::ReplaySession"}
    const RecordSession = Union{cxxt"rr::RecordSession::shr_ptr",pcpp"rr::RecordSession"}
    const ReplayTimeline = Union{pcpp"rr::ReplayTimeline"}
    const Session = Union{ReplaySession, RecordSession}

    function Base.current_task(session::ReplaySession)
        @assert icxx"$session != 0;"
        task = icxx"$session->current_task();"
        @assert Ptr{Void}(task) != C_NULL
        task
    end
    
    function Base.current_task(session::RecordSession)
        @assert icxx"$session != 0;"
        task = icxx"$session->scheduler().current();"
        @assert Ptr{Void}(task) != C_NULL
        task
    end
    Base.current_task(timeline::ReplayTimeline) =
        current_task(current_session(timeline))
    Base.current_task(task::AnyTask) = task

    current_session(timeline::ReplayTimeline) = icxx"&$timeline->current_session();"
    current_session(session::Session) = session

    function step_until_exec!(session)
        while !icxx"$session->done_initial_exec();"
            step!(session)
        end
    end

    function step!(session::ReplaySession)
        icxx"$session->replay_step(rr::RUN_CONTINUE);"
    end
    
    function step!(session::RecordSession)
        icxx"$session->record_step();"
    end


    function step!(session::ReplaySession, target; target_is_event = false)
        icxx"""
            rr::ReplaySession::StepConstraints c(rr::RUN_CONTINUE);
            if ($target_is_event)
                c.stop_at_time = $target;
            else
                c.ticks_target = $target;
            $session->replay_step(c);
        """
    end

    function reverse_continue!(timeline)
        icxx"""
        auto stop_filter = [&](rr::ReplayTask* t) -> bool {
            return true;
        };
        auto interrupt_check = [&]() { return false; };
        $timeline->reverse_continue(
            stop_filter, interrupt_check);
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
    reverse_single_step!(timeline) = reverse_single_step!(current_session(timeline),
        current_task(current_session(timeline)), timeline)

    function NativeDebugger.single_step!(session::ReplaySession)
        while true
            status = icxx"$session->replay_step(rr::RUN_SINGLESTEP);"
            if icxx"$status.break_status.singlestep_complete == true;"
                return true
            elseif icxx"$status.status == rr::REPLAY_EXITED;"
                return false
            end
        end
    end

    function at_breakpoint(timeline::ReplayTimeline)
        loc = NativeDebugger.Location(timeline,
            ip(icxx"$(current_task(current_session(timeline)))->regs();"))
        haskey(NativeDebugger.bps_at_location, loc)        
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
        addr = ip(regs)
        icxx"""
            auto it = $task->vm()->breakpoints.find($addr);
            it == $task->vm()->breakpoints.end();
        """ && return false
        insts = load(task, RemotePtr{UInt8}(ip(regs)), 15)
        insts[1] = orig_byte(task, addr)
        NativeDebugger.X86_64.instemulate!(insts, vm, regs) || return false
        icxx"$task->set_regs($regs);"
        return true
    end

    function NativeDebugger.single_step!(timeline::ReplayTimeline)
        # To get past any breakpoints, check if our current location
        # is a breakpoint location and if so, temporarily clear it
        # while stepping past.
        did_disable = false
        loc = NativeDebugger.Location(timeline,
            ip(icxx"$(current_task(current_session(timeline)))->regs();"))
        if haskey(NativeDebugger.bps_at_location, loc)
            disable(loc)
            did_disable = true
        end
        res = NativeDebugger.single_step!(current_session(timeline))
        if did_disable
            enable(loc)
        end
        res
    end

    function NativeDebugger.step_until_bkpt!(session::ReplaySession)
        while disable_sigint() do
                !icxx"$session->replay_step(rr::RUN_CONTINUE).break_status.breakpoint_hit;"
            end
        end
    end
    
    # We consider the last thread exit to be an implicit breakpoint
    function is_last_thread_exit(status)
        is_task_exit(status) && icxx"$status.task->task_group()->task_set().size() == 1;"
    end
    
    function is_task_exit(status)
        icxx"$status.task_exit == true;"
    end
    
    is_break_sig(status) = icxx"$status.signal != nullptr;" && (
      icxx"$status.signal->si_signo == 11;" ||
      icxx"$status.signal->si_signo == 4;")

    function NativeDebugger.step_until_bkpt!(timeline::ReplayTimeline; only_current_tgid = false)
        current_tgid = icxx"$(current_task(timeline))->tgid();"
        while true
            icxx"$timeline->apply_breakpoints_and_watchpoints();"
            icxx"$(current_session(timeline))->set_visible_execution(true);"
            local res
            exited, bp_hit = disable_sigint() do
                res = icxx"$(current_session(timeline))->replay_step(rr::RUN_CONTINUE);"
                (icxx"$res.status == rr::REPLAY_EXITED;",
                 icxx"$res.break_status.breakpoint_hit;" ||
                 icxx"!$res.break_status.watchpoints_hit.empty();" ||
                 is_last_thread_exit(icxx"$res.break_status;") ||
                 is_break_sig(icxx"$res.break_status;"))
            end
            if !only_current_tgid || icxx"$(current_task(timeline))->tgid();" == current_tgid
                exited && return (false, res)
                bp_hit && return (true, res)
            end
            icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        end
    end
    
    function step_to_address!(timeline::ReplayTimeline, theip; disable_bps = false)
        if disable_bps
            icxx"$timeline->unapply_breakpoints_and_watchpoints();"
        else
            NativeDebugger.single_step!(timeline)
        end
        icxx"$(current_task(current_session(timeline)))->vm()->add_breakpoint($theip, rr::BKPT_USER);"
        NativeDebugger.step_until_bkpt!(current_session(timeline))
        icxx"$(current_task(current_session(timeline)))->vm()->remove_breakpoint($theip, rr::BKPT_USER);"
        disable_bps && icxx"$timeline->apply_breakpoints_and_watchpoints();"
        nothing
    end
    
    function NativeDebugger.continue!(timeline::ReplayTimeline; only_current_tgid = false)
        while true
            bp_hit, res = NativeDebugger.step_until_bkpt!(timeline; only_current_tgid = only_current_tgid)
            bp_hit || return res
            regs = icxx"$(current_task(current_session(timeline)))->regs();"
            if process_lowlevel_conditionals(Location(timeline, ip(regs)), regs)
                return res
            end
            # Step past the breakpoint
            NativeDebugger.single_step!(timeline)
        end
    end

    immutable TraceFrameIterator
        reader
    end
    
    Base.start(it::TraceFrameIterator) = nothing
    function Base.next(it::TraceFrameIterator, _)
        icxx"$(it.reader).read_frame();", nothing
    end
    Base.done(it::TraceFrameIterator, _) = icxx"$(it.reader).at_end();"
    Base.iteratorsize(it::TraceFrameIterator) = Base.SizeUnknown()

    function Base.show(io::IO, frame::Union{rcpp"rr::TraceFrame",vcpp"rr::TraceFrame"})
        print(io,icxx"$frame.ticks();",": ")
        print_with_color(:green,io,String(icxx"$frame.event().str();"))
        if icxx"$frame.event().is_syscall_event();"
             println(io, " ", unsafe_string(
                icxx"rr::state_name($frame.event().Syscall().state);"))
        end
    end
    tid(frame::Union{rcpp"rr::TraceFrame",vcpp"rr::TraceFrame"}) = icxx"$frame.tid();"
    time(frame::Union{rcpp"rr::TraceFrame",vcpp"rr::TraceFrame"}) = icxx"$frame.time();"

    function NativeDebugger.read_exe(task::AnyTask)
        @assert task != C_NULL
        readmeta(IOBuffer(open(read,Cxx.unsafe_string(icxx"$task->vm()->exe_image();"))))
    end

    function NativeDebugger.read_exe(session::Session)
        NativeDebugger.read_exe(current_task(session))
    end
    
    NativeDebugger.read_exe(timeline::ReplayTimeline) =
        NativeDebugger.read_exe(current_session(timeline))

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

    immutable TaskUid
        tuid::cxxt"rr::TaskUid"
    end
    ==(a::TaskUid, b::TaskUid) = icxx"$(a.tuid) == $(b.tuid);"
    tuid(task::AnyTask) = TaskUid(icxx"$task->tuid();")

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

    typealias RRRemotePtr{T} Union{RemotePtr{T,UInt32}, RemotePtr{T,UInt64}, cxxt"rr::remote_ptr<$T>"}
    NativeDebugger.RemotePtr{T}(ptr::cxxt"rr::remote_ptr<$T>") = NativeDebugger.RemotePtr{T}(UInt64(ptr))
    NativeDebugger.RemoteCodePtr(ptr::cxxt"rr::remote_code_ptr") = NativeDebugger.RemoteCodePtr(UInt64(ptr))
    function load{T<:Cxx.CxxBuiltinTypes}(vm::AnyTask, ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = icxx"$vm->read_mem($ptr,&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res
    end
    load(vm::ReplaySession, ptr) = load(current_task(vm), ptr)

    function load{T}(vm::AnyTask, ptr::RRRemotePtr{T})
        ok = Ref{Bool}(true)
        res = Ref{T}()
        icxx"$vm->read_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(T)),(uint8_t*)$(Base.unsafe_convert(Ptr{Void},res)),&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res[]
    end
    
    function store!{T}(vm::AnyTask, ptr::RRRemotePtr{T}, val::T)
        ok = Ref{Bool}(true)
        res = Ref{T}(val)
        icxx"$vm->write_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(T)),(uint8_t*)&$res,&$ok);"
        ok[] || error("Failed to write memory at address $ptr")
        nothing
    end

    function store!{T}(vm::AnyTask, ptr::RRRemotePtr{T}, vec::Vector{T})
        ok = Ref{Bool}(true)
        icxx"$vm->write_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(sizeof(vec)),$(Ptr{UInt8}(pointer(vec))),&$ok);"
        ok[] || error("Failed to write memory at address $ptr")
        nothing
    end

    function load{T}(vm::AnyTask, ptr::RRRemotePtr{T}, n)
        ok = Ref{Bool}(true)
        res = Vector{T}(n)
        icxx"$vm->read_bytes_helper(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(n*sizeof(T)),$(Ptr{UInt8}(pointer(res))),&$ok);"
        ok[] || error("Failed to read memory at address $ptr")
        res
    end

    function fallible_load{T}(vm::AnyTask, ptr::RRRemotePtr{T}, n)
        ok = Ref{Bool}(true)
        res = Vector{T}(n)
        size = icxx"$vm->read_bytes_fallible(
            rr::remote_ptr<uint8_t>($(UInt64(ptr))),
            $(n*sizeof(T)),$(Ptr{UInt8}(pointer(res))));"
        resize!(res, div(size, sizeof(T)))
        res
    end

    load(vm::ReplayTimeline, args...) =
        load(current_task(current_session(vm)), args...)

    store!(vm::ReplayTimeline, args...) =
        store!(current_task(current_session(vm)), args...)

    # Task `12345` mmap_hardlink_1_julia at ip-loc
    function Base.show(io::IO, task::AnyTask)
        modules = get(io, :modules, nothing)
        ip = UInt(NativeDebugger.ip(fixup_RC(task,icxx"$task->regs();")[2]))
        session = icxx"&$task->session();"
        ssession = icxx"$session->as_replay();"
        ssession == C_NULL && (ssession = icxx"$session->as_record();")
        ssession == C_NULL && (ssession = icxx"$session->as_diversion();")
        print(io, "Task `", icxx"$task->tid;", "` (rec ",
            icxx"$task->rec_tid;", ") ",
            unsafe_string(icxx"$task->vm()->exe_image();"),
            " at 0x",hex(ip)," ",modules !== nothing ?
            NativeDebugger.Unwinder.symbolicate(ssession, modules, ip) : "")
    end

    saved_auxv(vm::pcpp"rr::ReplayTask") = convert(Vector{UInt8}, icxx"$vm->vm()->saved_auxv();")

    function mapped_file(vm::AnyTask, ptr)
        @assert icxx"$vm->vm()->has_mapping($ptr);"
        unsafe_string(icxx"""
            auto &mapping = $vm->vm()->mapping_of($ptr);
            return mapping.recorded_map.is_vdso() ?
              "linux-vdso.so.1" : mapping.map.fsname().c_str();
        """)
    end
    mapped_file(vm::ReplayTimeline, ptr) =
        mapped_file(current_task(current_session(vm)), ptr)

    function NativeDebugger.segment_base(vm::AnyTask, ptr)
        ptr = UInt64(ptr)
        @assert icxx"$vm->vm()->has_mapping($ptr);"
        NativeDebugger.RemotePtr(icxx"$vm->vm()->mapping_of($ptr).map.start();")
    end
    NativeDebugger.segment_base(vm::ReplayTimeline, ptr) =
        NativeDebugger.segment_base(current_task(current_session(vm)), ptr)
    

    import NativeDebugger.GlibcDyldModules: load_library_map, compute_entry_ptr
    function load_library_map(task::pcpp"rr::ReplayTask", imageh)
        slide = compute_entry_ptr(task, saved_auxv(task)) -
            imageh.file.header.e_entry
        load_library_map(task, imageh, slide)
    end

    # Registers
    import NativeDebugger.Registers: ip, invalidate_regs!, set_sp!, set_ip!,
        set_dwarf!, get_dwarf, getarch
    const RRRegisters = Union{rcpp"rr::Registers",vcpp"rr::Registers"}

    getarch(regs::RRRegisters) = icxx"$regs.arch() == rr::x86_64;" ?
        NativeDebugger.X86_64.X86_64Arch() : NativeDebugger.X86_32.X86_32Arch()
    getarch(task::AnyTask) = icxx"$task->arch() == rr::x86_64;" ?
        NativeDebugger.X86_64.X86_64Arch() : NativeDebugger.X86_32.X86_32Arch()
    getarch(timeline::ReplayTimeline) = getarch(current_task(current_session(timeline)))
    Base.copy(regs::RRRegisters) = icxx"rr::Registers{$regs};"
    ip(regs::RRRegisters) = RemoteCodePtr(icxx"$regs.ip();")
    invalidate_regs!(regs::RRRegisters) = nothing # RR does not track validity
    set_sp!(regs::RRRegisters, sp) = icxx"$regs.set_sp($(RemotePtr{Void}(sp)));"
    set_ip!(regs::RRRegisters, ip) = icxx"$regs.set_ip($(RemoteCodePtr(ip)));"
    function set_dwarf!(regs::RRRegisters, regno::Integer, val)
        if isa(getarch(regs), NativeDebugger.X86_64.X86_64Arch)
            # fs_base and gs_base do not have gdb equivalents
            if regno == NativeDebugger.X86_64.inverse_dwarf[:fs_base]
                return icxx"$regs.fs_base();"
            elseif regno == NativeDebugger.X86_64.inverse_dwarf[:gs_base]
                return icxx"$regs.gs_base();"
            end
            gdbregno = NativeDebugger.X86_64.dwarf2gdb(regno)
            valr = Ref{UInt64}(UInt64(val))
            icxx"$regs.write_register((rr::GdbRegister)$gdbregno,&$valr,$(sizeof(UInt64)));"
        else
            gdbregno = NativeDebugger.X86_32.dwarf2gdb(regno)
            @show val
            valr = Ref{UInt32}(UInt32(val))
            icxx"$regs.write_register((rr::GdbRegister)$gdbregno,&$valr,$(sizeof(UInt32)));"
        end
    end
    function get_dwarf(regs::RRRegisters, regno::Integer)
        if isa(getarch(regs), NativeDebugger.X86_64.X86_64Arch)
            # fs_base and gs_base do not have gdb equivalents
            if regno == NativeDebugger.X86_64.inverse_dwarf[:fs_base]
                return icxx"$regs.fs_base();"
            elseif regno == NativeDebugger.X86_64.inverse_dwarf[:gs_base]
                return icxx"$regs.gs_base();"
            end
            gdbregno = NativeDebugger.X86_64.dwarf2gdb(regno)
        else
            gdbregno = NativeDebugger.X86_32.dwarf2gdb(regno)
        end
        buf = Ref{UInt64}(0)
        defined = Ref{Bool}()
        icxx"$regs.read_register((uint8_t*)&$buf, (rr::GdbRegister)$gdbregno, &$defined);"
        buf[]
    end
    function Base.convert(::Type{NativeDebugger.X86_64.BasicRegs}, regs::RRRegisters)
        retregs = NativeDebugger.X86_64.BasicRegs()
        for i in NativeDebugger.X86_64.basic_regs
            set_dwarf!(retregs, i, get_dwarf(regs, i))
        end
        retregs
    end
    Base.show(io::IO, regs::RRRegisters) = show(io, NativeDebugger.X86_64.BasicRegs(regs))

    function NativeDebugger.get_thread_area_base(task::AnyTask, entry)
        icxx"""
            for (auto &area : $task->thread_areas()) {
                if (area.entry_number == $entry) {
                    return area.base_addr;
                }
            }
            return (unsigned int)0;
        """
    end
    NativeDebugger.get_thread_area_base(timeline::ReplayTimeline, entry) =
        NativeDebugger.get_thread_area_base(current_task(timeline), entry)

    """
        RR hooks syscall instructions by inserting a call instruction and
        redirecting to its own mapped page. If we're on that page, do the first
        unwind step manually to get the correct register context.
    """
    function fixup_RC(task::AnyTask, RC)
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
    
    when(session::ReplaySession) = UInt64(icxx"$(current_task(session))->tick_count();")
    when(timeline::ReplayTimeline) = when(current_session(timeline))
    
    function count_total_ticks(reader)
        icxx"""
            ssize_t nticks = 0;
            $reader.rewind();
            rr::TraceFrame frame;
            while (true) {
                rr::TraceFrame next_frame = $reader.read_frame();
                if ($reader.at_end())
                    break;
                frame = next_frame;
                nticks = std::max(nticks, frame.ticks());
            }
            nticks;
        """
    end
    function count_total_ticks(timeline::ReplayTimeline)
        session = current_session(timeline)
        count_total_ticks(icxx"rr::TraceReader{$session->trace_reader()};")
    end
    
    function proto_mark(timeline)
        icxx"$timeline->proto_mark();"
    end
    
    function seek(timeline, mark::cxxt"rr::ReplayTimeline::ProtoMark")
        icxx"$timeline->seek_to_proto_mark($mark);"
    end
    
    immutable AddressSpaceUid
        pid::Int32
        serial::UInt32
        exec_count::UInt32
    end
    
    NativeDebugger.current_asid(task::AnyTask) = 
        reinterpret(AddressSpaceUid, [icxx"$task->vm()->uid();".data])[]
        
    NativeDebugger.current_asid(session::ReplaySession) =
        NativeDebugger.current_asid(current_task(session))

    NativeDebugger.current_asid(timeline::ReplayTimeline) =
        NativeDebugger.current_asid(current_session(timeline))

    silence!(timeline) =
        icxx"$(current_session(timeline))->set_visible_execution(false);"

    NativeDebugger.ip(task::AnyTask) = NativeDebugger.ip(icxx"$task->regs();")
    NativeDebugger.ip(timeline::ReplayTimeline) = NativeDebugger.ip(current_task(current_session(timeline)))

    function NativeDebugger.breakpoint(timeline::RR.ReplayTimeline, modules, fname::Symbol)
        syms = NativeDebugger.lookup_syms(timeline, modules, fname)
        bp = NativeDebugger.Breakpoint()
        for (h, base, sym) in syms
            addr = NativeDebugger.RemoteCodePtr(base + ObjFileBase.symbolvalue(sym,
                ObjFileBase.Sections(ObjFileBase.handle(h))))
            NativeDebugger.add_location(bp, NativeDebugger.Location(timeline, addr))
        end
        bp
    end

    function NativeDebugger.breakpoint(timeline::RR.ReplayTimeline, addr)
        bp = NativeDebugger.Breakpoint()
        NativeDebugger.add_location(bp, NativeDebugger.Location(timeline, addr))
        bp
    end

    function NativeDebugger.enable(timeline::RR.ReplayTimeline, loc::Location)
        icxx"$timeline->add_breakpoint(
                $(current_task(current_session(timeline))), $(loc.addr));"
    end

    function NativeDebugger.disable(timeline::RR.ReplayTimeline, loc::Location)
        icxx"$timeline->remove_breakpoint(
                $(current_task(current_session(timeline))), $(loc.addr));"
    end

    function NativeDebugger.print_location(io::IO, vm::RR.ReplayTimeline, loc)
        print(io, "In RR timeline at address ")
        show(io, loc.addr)
        println(io)
    end

    NativeDebugger.getregs(task::AnyTask) = icxx"$task->regs();"
    NativeDebugger.getregs(timeline::ReplayTimeline) =
        NativeDebugger.getregs(current_task(timeline))
    
    function replay(trace_dir=""; step_to_entry=true)
        session = icxx"""rr::ReplaySession::create($(pointer(trace_dir)));"""
        timeline = icxx"""new rr::ReplayTimeline{std::move($session),rr::ReplaySession::Flags{}};""";
        session = nothing
        icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        icxx"$(current_session(timeline))->set_visible_execution(true);"
        icxx"""
            rr::ReplaySession::Flags result;
            result.redirect_stdio = true;
            $(current_session(timeline))->set_flags(result);
        """
        RR.step_until_exec!(current_session(timeline))
        task = current_task(current_session(timeline))
        if step_to_entry
          icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
          entrypt = compute_entry_ptr(task,RR.saved_auxv(task))
          icxx"$timeline->add_breakpoint($task, $entrypt);"
          NativeDebugger.step_until_bkpt!(timeline)
          icxx"$timeline->remove_breakpoint($task, $entrypt);"
          icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        end
        imageh = NativeDebugger.read_exe(current_session(timeline))
        modules = NativeDebugger.GlibcDyldModules.load_library_map(task, imageh)

        timeline, modules
    end
    
    const preload_thread_locals = 0x70001000
    const stub_scratch_1 = preload_thread_locals
    function unwind_step_rr_extended_jump(sess, base, RC)
        RC′ = copy(RC)
        # First figure out which stub we're in and how far
        # we're into the stub
        arch = NativeDebugger.getarch(sess)
        stub_size = isa(arch, NativeDebugger.X86_64.X86_64Arch) ?
          79 : 44
        ptrT = NativeDebugger.intptr(arch)
        ip = UInt64(NativeDebugger.ip(RC))
        procrel = rem(ip-base, stub_size)
        if procrel != 0
            set_dwarf!(RC′, :rsp, NativeDebugger.load(sess,
              RemotePtr{ptrT,ptrT}(preload_thread_locals+sizeof(ptrT))))
        end
        local return_addr
        if isa(arch, NativeDebugger.X86_64.X86_64Arch)
            lo = NativeDebugger.load(sess, RemotePtr{UInt32, UInt64}(ip-procrel+53))
            hi = NativeDebugger.load(sess, RemotePtr{UInt32, UInt64}(ip-procrel+61))
            return_addr = (UInt64(hi) << 32) | lo
            jump_stub = NativeDebugger.load(sess, RemotePtr{UInt64, UInt64}(ip-procrel+71))
            if NativeDebugger.load(sess, RemotePtr{UInt32, UInt64}(jump_stub+5)) == 0x5e5a5c5a 
                # This is the _syscall_hook_trampoline_5a_5e_c3, which doesn't
                # return to where it was called, because the function is too short
                # Just pretend we're before the syscall.
                return_addr -= 5
            end
        else
            return_addr = NativeDebugger.load(sess, RemotePtr{UInt32, UInt32}(ip-procrel+35))
        end
        set_ip!(RC′, return_addr)
        RC′
    end
    
    function get_synthetic_modules(session)
        modules = Dict{RR.AddressSpaceUid,Dict{NativeDebugger.RemotePtr{Void},NativeDebugger.SyntheticModule}}()
        reader = icxx"rr::TraceReader{$(RR.current_session(session))->trace_reader()};"
        icxx"$reader.rewind();"
        for frame in RR.TraceFrameIterator(reader)
            start = Ref{UInt64}(0)
            size = Ref{UInt64}(0)
            while icxx"""
                bool found = false;
                auto km = $reader.read_mapped_region(nullptr, &found);
                if (found) {
                  $start = km.start().as_int();
                  $size = km.size();
                }
                return found;
                """
                if icxx"$frame.event().type() == rr::EV_PATCH_SYSCALL;"
                    symbolicate = (session, RC)->(true, "RR Syscall Stub")
                    get_proc_bounds = (session, ip)->(0x1:0x1000)-1
                    # XXX: This is incorrect for multi-as replays
                    asid = NativeDebugger.current_asid(session)
                    !haskey(modules, asid) &&
                      (modules[asid] = Dict{UInt64,NativeDebugger.SyntheticModule}())
                    modules[asid][NativeDebugger.RemotePtr{Void}(start[])] =
                      NativeDebugger.SyntheticModule(start[], size[],
                        unwind_step_rr_extended_jump, symbolicate, get_proc_bounds)
                end
            end
        end
        modules
    end
    
end # module
