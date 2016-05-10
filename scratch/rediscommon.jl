using Gallium: get_dwarf
using Colors

push!(ASTInterpreter.SEARCH_PATH, "/home/kfischer/cs262project/redis/src")
push!(ASTInterpreter.SEARCH_PATH, "/home/kfischer/cs262project/redis/deps/hiredis/")

function trace_rw(timeline, modules)
  bp1 = Gallium.breakpoint(timeline, :write)
  bp2 = Gallium.breakpoint(timeline, :read)
  bp3 = Gallium.breakpoint(timeline, :accept)
  bp4 = Gallium.breakpoint(timeline, :close)

  writes = Any[]
  Gallium.conditional(bp1) do loc, RC
      fd = UInt(get_dwarf(RC, :rdi))
      buf = Gallium.RemotePtr{UInt8}(get_dwarf(RC, :rsi))
      len = get_dwarf(RC, :rdx)
      data = RR.load(current_vm(), buf, len)
      push!(writes, (fd, when(timeline), data))
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
      (len == (-1%UInt)) && return false
      data = RR.load(current_vm(), buf, len)
      push!(reads, (fd, when(timeline), data))
      return false
  end
  
  accepts = Any[]
  Gallium.conditional(bp3) do loc, RC
      # Step to exit
      RC′ = Gallium.Unwinder.unwind_step(current_vm(), modules, RC)[2]
      RR.step_to_address!(timeline, Gallium.ip(RC′); disable_bps = true)
      fd = get_dwarf(RC, :rax)
      push!(accepts, (when(timeline), fd))
      return false
  end

  closes = Any[]
  Gallium.conditional(bp4) do loc, RC
      fd = UInt(get_dwarf(RC, :rdi))
      push!(closes, (when(timeline), fd))
      return false
  end


  RR.continue!(timeline)
  
  total_ticks = RR.count_total_ticks(timeline)
  reads, writes, accepts, closes, total_ticks
end

const paper_theme = theme = let mm = Gadfly.mm
Theme(highlight_width = 0.mm, default_point_size=0.6mm,
    panel_stroke = colorant"black",
    default_color = colorant"black",
    grid_color = colorant"black",
    major_label_font_size = 3.0mm,
    plot_padding = 0mm,
    major_label_color = colorant"black",
    minor_label_color = colorant"black");
end;

immutable Message
    send_id::Int
    recv_id::Int
    send_idx::Int
    recv_idx::Int
    send_t::Int
    recv_t::Int
    send_fd::UInt
    recv_fd::UInt
end
Message(send_idx, recv_idx, send_t, recv_t, send_fd, recv_fd) =
  Message(0, 0, send_idx, recv_idx, send_t, recv_t, send_fd, recv_t)

# Identify edges in the communications graph
function correlate_messages(writes, reads, write_id = 0, read_id = 0)
    messages = Message[]
    for (i, (fd, t, message)) in enumerate(writes)
        for (j, (fd′, t′, message′)) in enumerate(reads)
            if message == message′
                push!(messages, Message(write_id, read_id, i, j, t, t′, fd, fd′))
            end
        end
    end
    messages
end

function compute_fd_ranges(accepts, closes)
    # For each succesful accepts (that did not return -1, compute when it was closed)
    ranges = Any[]
    for a in filter(x->x[2]!=(-1%UInt),accepts)
        i = findfirst(c->(c[1]>=a[1] && c[2]==a[2]), closes)
        i == 0 && continue
        r = a[1]:(closes[i][1])
        push!(ranges, (r,a[2]))
    end
    ranges
end

function compute_range(ranges, when, fd)
    findfirst(r->((when in r[1]) && r[2] == fd),ranges)
end

colors = [colorant"purple",colorant"purple",colorant"orange",colorant"green"]
