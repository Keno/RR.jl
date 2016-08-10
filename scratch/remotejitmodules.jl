timeline, modules = replay("/home/kfischer/.local/share/rr/julia-60")

jit, callbacks = create_remote_jit(timeline, 0)
icxx"$callbacks->session = $(pointer_from_objref(timeline));"

push!(ASTInterpreter.SEARCH_PATH, "/home/kfischer/julia/src")

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

include("remoteclang.jl")
Cxx.cxxinclude(RemoteClang, "/home/kfischer/julia/src/interpreter.c")

using Base: REPL

function computevartypemap(state, stack)
    frame_variables = Any[]
    frame_values = Dict{Symbol,Any}()
    function add_framevar(dbgs, vardie, name)
        dwarfT = get(DWARF.extract_attribute(vardie,DWARF.DW_AT_type))
        try 
            T = Cxx.juliatype(dwarf2Cxx(dbgs, dwarfT.value))
            push!(frame_variables, Symbol(name)=>T)
        end
    end
    function found_cb(dbgs, vardie, getreg, name, val)
        add_framevar(dbgs, vardie, name)
        frame_values[Symbol(name)] = (getreg, val)
    end
    iterate_frame_variables(state, stack, found_cb, add_framevar)
    frame_variables, frame_values
end

#
# Determine which parameters are unused. Complain if some parameter that is
# unavailable is being used and return which unsued parameters can be safely
# deleted.
#
function DiagnoseUnavailableUsed(FD, unavailable)
    FD = pcpp"clang::FunctionDecl"(Ptr{Void}(FD))
    params = [Cxx.getParmVarDecl(FD,i-1) for i = 1:Cxx.getNumParams(FD)]
    todelete = Int[]
    for (i,param) in enumerate(params)
        param_used = Cxx.IsDeclUsed(param)
        if param_used && (i in unavailable)
            # TODO: Error with source location
            error("Used unavailable parameter `$(Cxx._decl_name(param))`")
        end
        !param_used && push!(todelete, i)
    end
    todelete
end

function realize_remote_values(frame_variables, frame_values, idxs)
    ret = Any[]
    for i in idxs
        getreg, val = frame_values[frame_variables[i][1]]
        val = realize_remote_value(frame_variables[i][2], val, getreg)
        push!(ret, val)
    end
    ret
end

function ASTInterpreter.language_specific_prompt(state, stack::Union{Gallium.CStackFrame, Gallium.NativeStack})
    panel = CxxREPL.CreateCxxREPL(RemoteClang; name = :targetcxx,
        prompt = "Target C++ > ",
        main_mode = state.main_mode)
        
    function run_code(line)
        try
            line = string(line,"\n;")
            toplevel = CxxREPL.isTopLevelExpression(RemoteClang,string(line,'\0'))
            if toplevel
                eval(Cxx.process_cxx_string(line, toplevel,
                    false, :REPL, 1, 1; compiler = RemoteClang))
                return nothing
            else
                startvarnum, sourcebuf, exprs, isexprs, icxxs =
                    Cxx.process_body(RemoteClang,line,false,false,:REPL,1,1)
                source = takebuf_string(sourcebuf)
                args = Expr(:tuple,exprs...)
                frame_variables, frame_values = computevartypemap(state, stack)
                unavailables = length(exprs) .+ map(x->x[1],filter(x->!haskey(frame_values,x[2]),
                    enumerate(map(x->x[1],frame_variables))))
                return eval(quote
                    t = $args
                    FD,_,_ = Cxx.CreateFunctionWithBody(Cxx.instance($RemoteClang),$source,typeof(t).parameters...;
                        named_args = $frame_variables)
                    FD = pcpp"clang::FunctionDecl"(Ptr{Void}(FD))
                    todelete = DiagnoseUnavailableUsed(FD, $unavailables)
                    # First mark these as used to allow codegen
                    for i in todelete
                        Cxx.SetDeclUsed(Cxx.instance($RemoteClang),
                            Cxx.getParmVarDecl(FD, i-1))
                    end
                    Cxx.EmitTopLevelDecl(Cxx.instance($RemoteClang), FD)
                    fdecl = Cxx.EmitDeclRef(Cxx.instance($RemoteClang),
                        Cxx.CreateDeclRefExpr(Cxx.instance($RemoteClang), FD))
                    nfdecl = Cxx.DeleteUnusedArguments(fdecl, todelete .- 1)
                    available = setdiff(
                        collect(1:$(length(frame_variables))), todelete .- length(t))
                    return run_func(timeline, jit, callbacks, nfdecl,
                        Cxx.juliatype(Cxx.GetFunctionReturnType(FD)), $RemoteClang,
                        Any[t..., realize_remote_values($frame_variables, $frame_values, available)...])
                end)
            end
        catch err
            bt = catch_backtrace()
            @show err
            Base.show_backtrace(STDOUT, bt)
        end
        return nothing
    end

    panel.on_done = (s,buf,ok)->begin
        if !ok
            return REPL.transition(s, :abort)
        end
        line = takebuf_string(buf)
        if !isempty(line)
            val = run_code(line)
            if !REPL.ends_with_semicolon(line)
                val != nothing && display(val)
            end
        end
        REPL.reset_state(s)
    end
    
    panel
end

#focus_tid = 7308
RunDebugREPL()


#=
let __current_compiler__ = RemoteClang
cxx"""
void foo5() {
write(1, "Hello\n", 6);
}
"""
end
run_func(timeline, jit, callbacks, "foo", RemoteClang)
=#
