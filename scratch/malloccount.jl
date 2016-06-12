timeline, modules = replay("/home/kfischer/.local/share/rr/llc-39/")
for i = 1:2000
RR.step!(current_session(timeline))
icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
end

using Gallium: RemotePtr

always_free_addresses = icxx"""
    rr::TraceReader reader{$(current_session(timeline))->trace_reader()};
    reader.rewind();
    rr::ReplaySession::always_free_address_space(reader);
"""

task = current_task(current_session(timeline))
h,base,sym = Gallium.lookup_sym(timeline, modules, :malloc)
hook_addr = Gallium.RemoteCodePtr(base + ObjFileBase.deref(sym).st_value)

base_ticks_ptr = icxx"""
    REMOTE_PTR_FIELD($(current_task(current_session(timeline)))->preload_globals,base_ticks);
"""

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

# Now allocate some memory for the JIT
start_addr = 0x00007f0892ecb000
region_size = 0x10000 # 16 pages
code_mem = start_addr
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($code_mem, $region_size,
    PROT_EXEC | PROT_READ,
    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""
ro_mem = start_addr + region_size
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($ro_mem, $region_size,
    PROT_READ,
    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""
rw_mem = start_addr + 2region_size
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($rw_mem, $region_size,
    PROT_READ | PROT_WRITE,
    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""

include(Pkg.dir("Gallium","src","remoteir.jl"))

@cxxm "uint64_t GalliumCallbacks::allocateMem(uint32_t kind, uint64_t Size, uint64_t Align)" begin
    global code_mem, ro_mem, rw_mem
    if kind == icxx"llvm::sys::Memory::MF_EXEC | llvm::sys::Memory::MF_READ;"
        code_mem += code_mem % Align
        ret = code_mem
        code_mem += Size
        return UInt64(ret)
    elseif kind == icxx"llvm::sys::Memory::MF_READ;"
        ro_mem += ro_mem % Align
        ret = ro_mem
        ro_mem += Size
        return UInt64(ret)
    elseif kind == icxx"llvm::sys::Memory::MF_READ | llvm::sys::Memory::MF_WRITE;"
        rw_mem += rw_mem % Align
        ret = rw_mem
        rw_mem += Size
        return UInt64(ret)
    else
        error("Unknown kind")
    end
end

@cxxm "void GalliumCallbacks::writeMem(uint64_t remote, uint8_t *localaddr, size_t size)" begin
    @show remote
    Gallium.store!(unsafe_pointer_to_objref(icxx"$this->session;"),RemotePtr{UInt8}(remote),
        pointer_to_array(localaddr, size, false))
end

cxx"""
    extern "C" {
        extern llvm::LLVMContext jl_LLVMContext;
        void jl_error(const char *);
    }
    #include "llvm/AsmParser/Parser.h"
"""
function parseIR(str)
    icxx"""
        llvm::SMDiagnostic Err;
        auto mod = llvm::parseAssembly(
            llvm::MemoryBufferRef(
            llvm::StringRef($(pointer(str)),$(sizeof(str))),
            llvm::StringRef("<in-memory>")),
            Err, jl_LLVMContext);
        if (mod == nullptr)
        {
            std::string message = "Failed to parse LLVM Assembly: \n";
            llvm::raw_string_ostream stream(message);
            Err.print("julia",stream,true);
            jl_error(stream.str().c_str());
        }
        return mod.release();
    """
end

mod = parseIR("""
module asm "
.text
.align 4,0x90
.globl malloc_hook
malloc_hook:
pushq %rax
pushq %rcx
pushq %rdx
pushq %r10
pushq %r11
pushq %r12
movq \$$(UInt64(base_ticks_ptr)), %r10
movq (%r10), %r11
addq \$8, %r10
movl (%r10), %r12d
movq \$$(UInt64(data_buffer_start)), %rax
movq (%rax), %rbx
addq \$16, %rbx
movq %rbx, (%rax)
subq \$8, %rbx
leaq	(%rax,%rbx), %rbx
movq %rdi, (%rbx)
movq \$0, %rcx
addq \$8, %rbx
rdpmc
shlq	\$32, %rdx
movl	%eax, %eax
orq	%rax, %rdx
xor %r10, %r10
subq %r12, %r10
subq	%r10, %rdx
movl    %edx, %edx
addq	%r11, %rdx
movq	%rdx, (%rbx)
popq %r12
popq %r11
popq %r10
popq %rbx
popq %rdx
popq %rcx
popq %rax
"
""")

jit = icxx"""
auto callbacks = GalliumCallbacks{};
callbacks.session = $(pointer_from_objref(timeline));
new RemoteJIT(*llvm::EngineBuilder().selectTarget(),new RCMemoryManager(std::move(callbacks)));
"""
icxx"""
$jit->addModule(std::unique_ptr<llvm::Module>($mod));
"""

buffer_start_addr = icxx"""$jit->findSymbol("malloc_hook").getAddress();"""
# Find an address within 32 bit of the hook address
#=buffer_start_addr = RemotePtr{UInt8}(icxx"""
    for (auto range : $always_free_addresses) {
        if (std::abs((intptr_t)(range.start().as_int() - $(UInt64(hook_addr)))) < INT32_MAX/2) {
            return range.start().as_int();
        } else if (std::abs((intptr_t)(range.end().as_int() - 0x1000 - $(UInt64(hook_addr)))) < INT32_MAX/2) {
            return range.end().as_int() - 0x1000;
        }
    }
    return (uint64_t)0;
""")
@assert buffer_start_addr != 0
=#

# Allocate some space for our buffer
#=
icxx"""
rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
remote.infallible_mmap_syscall($buffer_start_addr, 0x1000, PROT_READ | 
    PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
"""
=#

code = [
    0x50; # pushq %rax
    0x51; # pushq %rcx
    0x52; # pushq %rdx
    0x53; # pushq %rbx
    0x41; 0x52; #pushq %r10
    0x41; 0x53; #pushq %r11
    0x41; 0x54; #pushq %r12
    # Load tick parameters
    # movq &$preload_globals->base_ticks, %r10
    0x49; 0xba; reinterpret(UInt8,[UInt64(base_ticks_ptr)]);
    0x4d; 0x8b; 0x1a; # movq (%r10), %r11
    0x49; 0x83; 0xc2; 0x08 # addq $8, %r10
    0x45; 0x8b; 0x22; # movl (%r10), %r12d
    # movq $data_buffer_start, %rax
    0x48; 0xb8; reinterpret(UInt8,[UInt64(data_buffer_start)]);
    0x48; 0x8b; 0x18; # movq (%rax), %rbx
    0x48; 0x83; 0xc3; 0x10; # addq $16, %rbx
    0x48; 0x89; 0x18; # movq %rbx, (%rax)
    0x48; 0x83; 0xeb; 0x08; # subq $8, %rbx
    0x48; 0x8d; 0x1c; 0x18; #	leaq	(%rax,%rbx), %rbx
    0x48; 0x89; 0x3b; # movq %rdi, (%rbx)
    # movq $0, %rcx
    0x48; 0xc7; 0xc1; 0x00; 0x00; 0x00; 0x00;
    0x48; 0x83; 0xc3; 0x08 # addq $8, %rbx
    0x0F; 0x33; #rdpmc
    0x48; 0xc1; 0xe2; 0x20; # shlq	$32, %rdx
    0x89; 0xc0; 	      # movl	%eax, %eax
    0x48; 0x09; 0xc2; 	  # orq	%rax, %rdx
    # Compute the real ticks value
    0x4d; 0x31; 0xd2;     # xor %r10, %r10
    0x4d; 0x29; 0xe2;     # subq %r12, %r10
    0x4c; 0x29; 0xd2;     # subq	%r10, %rdx
    0x89; 0xd2;           # movl    %edx, %edx
    0x4c; 0x01; 0xda;     # addq	%r11, %rdx
    0x48; 0x89; 0x13; 	  # movq	%rdx, (%rbx)
    0x41; 0x5c; # popq %r12
    0x41; 0x5b; # popq %r11
    0x41; 0x5a; # popq %r10
    0x5b; # popq %rbx
    0x5a; # popq %rdx
    0x59; # popq %rcx
    0x58; # popq %rax
]

TargetClang = Cxx.new_clang_instance(false)
let __current_compiler__ = TargetClang
    cxx"""
    #include <stdint.h>
    extern "C" {
        __attribute__((naked)) void malloc_hook3() {
            asm ("pushq %r11\n" // extra alignment
                 "callq malloc_hook2\n"
                 "popq %r11\n"
                 "nopl 0L(%rax,%rax,1)\n"
                 "nopl 0L(%rax,%rax,1)\n"
                 "nopl 0L(%rax,%rax,1)\n"
                 "nopl 0L(%rax,%rax,1)\n"
                 "int \$3");
        }
        
        static inline uint64_t native_read_pmc(uint32_t counter) __attribute__((preserve_all))
        {
            uint32_t low, high;
        	asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));
        	return low | ((uint64_t)high) << 32;
        }
        extern uint64_t data_buffer_start;
        void malloc_hook2() __attribute__((preserve_all)) {
            (&data_buffer_start)[++data_buffer_start] = native_read_pmc(0);
        }
    }
    """
end

function lookup_external_symbol(modules, name)::UInt64
    @show name
    name == "data_buffer_start" && return data_buffer_start
    return 0
end

shadowmod = Cxx.instance(TargetClang).shadow
hookf = icxx"""$shadowmod->getFunction("malloc_hook3");"""
xf = icxx"""$shadowmod->getFunction("malloc_hook2");"""

cxxinclude(Pkg.dir("DIDebug","src","FunctionMover.cpp"))
targetmod = icxx"""new llvm::Module("Target Module", $hookf->getParent()->getContext());"""
icxx"""
$targetmod->setDataLayout($hookf->getParent()->getDataLayout());
FunctionMover2 mover($targetmod);
MapFunction($hookf, &mover);
MapFunction($xf, &mover);
"""

icxx"""
$jit->addModule(std::unique_ptr<llvm::Module>($targetmod));
"""
buffer_start_addr = icxx"""$jit->findSymbol("malloc_hook3").getAddress();"""
@assert buffer_start_addr != 0

hook_template = Gallium.Hooking.hook_asm_template(UInt64(hook_addr),
    UInt64(buffer_start_addr); call = false)
orig_bytes = Gallium.load(task, RemotePtr{UInt8}(hook_addr), length(hook_template)+15)
nbytes = Gallium.Hooking.determine_nbytes_to_replace(length(hook_template), orig_bytes)


replacement = [hook_template; zeros(UInt8,nbytes-length(hook_template))]
Gallium.store!(task, RemotePtr{UInt8}(hook_addr), replacement)
Gallium.store!(task, RemotePtr{UInt8}(buffer_start_addr+9), 
    Gallium.Hooking.hook_tail_template(orig_bytes[1:nbytes],UInt(hook_addr)+nbytes)
)
disassemble(orig_bytes[1:nbytes])

bp = Gallium.breakpoint(timeline, :malloc)

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
