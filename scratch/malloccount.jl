timeline, modules = replay("/home/kfischer/.local/share/rr/llc-43/")
for i = 1:2000
RR.step!(current_session(timeline))
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
end

using Gallium: RemotePtr

h,base,sym = Gallium.lookup_sym(timeline, modules, :malloc)
hook_addr = Gallium.RemoteCodePtr(base + ObjFileBase.deref(sym).st_value)
jit, callbacks = create_remote_jit(timeline, hook_addr)
icxx"$callbacks->session = $(pointer_from_objref(timeline));"

task = current_task(current_session(timeline))

# Ok, now allocate space (2GB) for the data buffer
data_buffer_start = 0x70001000
data_buffer_size = 2*1024*1024*1024
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($data_buffer_start, $data_buffer_size,
    PROT_READ | PROT_WRITE,
    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($data_buffer_start+$data_buffer_size,0x1000,
    PROT_NONE,
    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""

let __current_compiler__ = TargetClang
    cxx"""
    #include <stdint.h>
    #include "/home/kfischer/rr/src/preload/instrument_interface.h"
    extern "C" {        
        static inline uint64_t native_read_pmc(uint32_t counter)
        {
            uint32_t low, high;
        	asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));
        	return low | ((uint64_t)high) << 32;
        }
        extern uint64_t data_buffer_start;
        void malloc_hook() __attribute__((preserve_all)) {
            (&data_buffer_start)[++data_buffer_start] =
                rr_pmc2ticks(native_read_pmc(0));
        }
        
        void free_hook(uint64_t addr) __attribute__((preserve_all)) {
            (&data_buffer_start)[++data_buffer_start] = 
                addr | ((uint64_t)1 << 63); // tag so we now this is a free record
        }
        
        void malloc_ret_hook() __attribute__((preserve_all)) {
            register uint64_t buffer asm("rax");
            (&data_buffer_start)[++data_buffer_start] = buffer;
        }
    }
    """
end

trace_func(jit, callbacks, :malloc, "malloc_hook", "malloc_ret_hook")
trace_func(jit, callbacks, :free, "free_hook")
#bp1 = Gallium.breakpoint(timeline, :malloc)
#bp2 = Gallium.breakpoint(timeline, :free)

#=
    bp = Gallium.breakpoint(timeline, :malloc)
    bp = Gallium.breakpoint(timeline, exit_hook)
=#

#=
replacement = [hook_template; zeros(UInt8,nbytes-length(hook_template))]
Gallium.store!(task, RemotePtr{UInt8}(hook_addr), replacement)
Gallium.store!(task, RemotePtr{UInt8}(buffer_start_addr), 
    Gallium.Hooking.hook_tail_template([code;orig_bytes[1:nbytes]],UInt(hook_addr)+nbytes)
)
disassemble(orig_bytes[1:nbytes])

bp = Gallium.breakpoint(timeline, :malloc)
=#

#=
stacktraces = UInt64[]
using Gallium: breakpoint, conditional
cache = Gallium.Unwinder.CFICache(100_000)
bp = conditional(breakpoint(timeline, :malloc)) do loc, RC
    bt = Gallium.rec_backtrace(RC, current_vm(loc.vm), modules, true, cache) do RC
        push!(stacktraces,UInt(Gallium.ip(RC)))
        return true
    end
    push!(stacktraces, UInt(0))
    return false
end
ASTInterpreter.execute_command(nothing, nothing, Val{:mark}(), "mark")
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 128000000")
=#

#=
cache = Gallium.Unwinder.CFICache(100_000)
Profile.init(n=10^9)
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump @1")
@profile ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 128000000")
IJulia=1
using ProfileView
ProfileView.svgwrite("profile.svg", C = true)

stacktraces = UInt64[]
ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump @1")
@profile ASTInterpreter.execute_command(nothing, nothing, Val{:timejump}(), "timejump 22001343342")
=#
#=
@load "traces.jl"

symb_map = Dict(ip => Gallium.Unwinder.symbolicate(modules,ip) for ip in
    filter(x->x!=0,unique(stacktraces)))
callframes = UInt64[]
for idx in find(x->x==0, stacktraces)
    idx+2 <= length(stacktraces) || continue
    push!(callframes, stacktraces[idx+2])
end
using StatsBase
map(x->(demangle(symb_map[x[1]]),x[2]),sort(collect(countmap(callframes)), by=x->x[2]))
=#
