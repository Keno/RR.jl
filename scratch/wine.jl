using ObjFileBase, COFF

timeline, modules = replay("/home/kfischer/.local/share/rr/wine64-12");
function step_to_syscall(number)
  succ = true
  while succ
      session = current_session(timeline)
      frame = icxx"$session->current_trace_frame();"
      event = icxx"$frame.event();"
      succ = icxx"$(RR.step!(session)).status != rr::REPLAY_EXITED;"
      # If we're exiting the connect call
      if icxx"$event.is_syscall_event();" &&
          icxx"$event.Syscall().state == rr::EXITING_SYSCALL;" &&
          icxx"$event.Syscall().number == $number;";
            break
     end
   end
end

sock_fd = 0
# Run until connection to the wine server
while true
  step_to_syscall(42);
  regs = icxx"$(current_task(current_session(timeline)))->regs();";
  path = String(Gallium.load(current_task(current_session(timeline)),
    Gallium.RemotePtr{UInt8}(Gallium.get_dwarf(regs, :rsi)+2), 108))
  sock_fd = Gallium.get_dwarf(regs, :rdi)
  @show path[1:6]
  if String(path[1:6]) ==  "socket"
      break
  end
end

# Run until we receive the request fd
while true
  step_to_syscall(47);
  regs = icxx"$(current_task(current_session(timeline)))->regs();";
  if sock_fd == Gallium.get_dwarf(regs, :rdi)
      break
  end
end
step_to_syscall(72);
request_fd = Gallium.get_dwarf(icxx"$(current_task(current_session(timeline)))->regs();", :rdi)

using Wine
while true
  step_to_syscall(1);
  regs = icxx"$(current_task(current_session(timeline)))->regs();";
  if request_fd == Gallium.get_dwarf(regs, :rdi)
      try
        global req
        regs = icxx"$(current_task(current_session(timeline)))->regs();";
        req = Wine.load_request(current_task(current_session(timeline)), Gallium.get_dwarf(regs, :rsi))
      catch err
        @show err
        isa(err, ErrorException) && err.msg == "unknown request" && continue
      end
      break
  end
end

regs = icxx"$(current_task(current_session(timeline)))->regs();";
req = Wine.load_request(current_task(current_session(timeline)), Gallium.get_dwarf(regs, :rsi))
peb = req.entry

function Gallium.Win64DyldMoudles.get_peb_addr(vm)
    return peb
end

RR.continue!(timeline)

function reload_modules()
    global modules
    imageh = RR.read_exe(current_session(timeline))
    modules = Gallium.GlibcDyldModules.load_library_map(current_task(current_session(timeline)), imageh)
    win64modules = Gallium.Win64DyldMoudles.load_library_map(current_task(current_session(timeline)))
    merge!(modules, win64modules)
    nothing
end
