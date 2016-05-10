include("rediscommon.jl")

timeline, modules = replay("/home/kfischer/.local/share/rr/redis-cli-6");
client_id = 0
client_reads, client_writes, client_accepts, client_closes, client_nticks = trace_rw(timeline, modules);
client_ends = [start_time(timeline); end_time(timeline)]
client_layers = timeline_layers([
client_ends;
map(x->TimelineEvent(x[2],:read), client_reads);
map(x->TimelineEvent(x[2],:write), client_writes);
]; timeline_id = client_id);

server_id = 1
timeline, modules = replay("/home/kfischer/.local/share/rr/redis-server-0");
server_reads, server_writes, server_accepts, server_closes, server_nticks = trace_rw(timeline, modules);
server_ends = [start_time(timeline); end_time(timeline);]
server_layers = timeline_layers([
server_ends;
map(x->TimelineEvent(x[2],:read), server_reads);
map(x->TimelineEvent(x[2],:write), server_writes);
]; timeline_id = server_id);

display(
plot(client_layers..., server_layers...,
    repl_theme,Guide.xlabel("Time"),
    Guide.ylabel("Timeline"),
    Scale.color_discrete_manual(colors...), Scale.y_continuous(minvalue=-1, maxvalue=2))
)

ctos = correlate_messages(client_writes, server_reads)
stoc = correlate_messages(server_writes, client_reads)

layers =
[[layer(x=[m.send_t, m.recv_t], y=[client_id, server_id], Geom.line, Theme(default_color=colorant"red")) for m in ctos];
 [layer(x=[m.send_t, m.recv_t], y=[server_id, client_id], Geom.line, Theme(default_color=colorant"blue")) for m in stoc]]

# Now make a plot 
p1(theme) = plot(client_layers..., server_layers..., layers...,
   theme,Guide.xlabel("Time"),
   Guide.ylabel("Timeline"),
   Guide.yticks(label = false),
   Scale.color_discrete_manual(colors...), Scale.y_continuous(minvalue=-1, maxvalue=2))
display(p1(repl_theme))

# Make a second plot that aligns the start and receive of the message
client_start = ctos[1].send_t
server_start = ctos[1].recv_t

client_layers2 = timeline_layers([
TimelineEvent(client_nticks-client_start, :end);
map(x->TimelineEvent(x[2]-client_start,:read), filter(x->x[2]>=client_start,client_reads));
map(x->TimelineEvent(x[2]-client_start,:write), filter(x->x[2]>=client_start,client_writes));
]; timeline_id = client_id, pointfilterset=[:end]);

server_layers2 = timeline_layers([
TimelineEvent(server_nticks-server_start, :end);
map(x->TimelineEvent(x[2]-server_start,:read), filter(x->x[2]>=server_start,server_reads));
map(x->TimelineEvent(x[2]-server_start,:write), filter(x->x[2]>=server_start,server_writes));
]; timeline_id = server_id, pointfilterset=[:end]);

layers2 =
[[layer(x=[m.send_t - client_start, m.recv_t - server_start], 
    y=[client_id, server_id], Geom.line, Theme(default_color=colorant"red",line_width=1mm)) for m in ctos];
 [layer(x=[m.send_t - server_start, m.recv_t - client_start],
    y=[server_id, client_id], Geom.line, Theme(default_color=colorant"blue",line_width=1mm)) for m in stoc]];

println()

p2(theme) = plot(client_layers2..., server_layers2..., layers2...,
   theme,Guide.xlabel("Time"),
   Guide.ylabel("Timeline"),
   Scale.color_discrete_manual(colorant"purple",colorant"orange"), Scale.y_continuous(minvalue=-1, maxvalue=2),
   Guide.yticks(label = false),
   Coord.cartesian(xmin = 0#=, xmax = max(stoc[1].recv_t-client_start,stoc[1].send_t-server_start)+1,=#
   ))
display(p2(repl_theme))

draw(PDF("p1.pdf", 8.5Compose.cm, 2inch), p1(paper_theme))
draw(PDF("p2.pdf", 8.5Compose.cm, 2inch), p2(paper_theme))

println()

client_layers3 = Any[]

server_id = 0
timeline, modules = replay("/home/kfischer/.local/share/rr/redis-server-1");
server_reads, server_writes, server_accepts, server_closes, server_nticks = trace_rw(timeline, modules);
server_ends = [start_time(timeline); end_time(timeline);]
server_layers3 = timeline_layers([
server_ends;
map(x->TimelineEvent(x[2],:read), server_reads);
map(x->TimelineEvent(x[2],:write), server_writes);
]; timeline_id = server_id);

server_ranges = compute_fd_ranges(server_accepts, server_closes);

all_stoc = Any[]
client_offsets = Any[]
client_messages = Any[]
all_client_reads = Any[]
message_layers = Any[]
client_layers3 = Any[]
server_id = 0
for i = 7:16
    global timeline, modules
    timeline, modules = replay("/home/kfischer/.local/share/rr/redis-cli-$i");
    client_reads, client_writes, client_accepts, client_closes, client_nticks = trace_rw(timeline, modules)
    ctos = correlate_messages(client_writes, server_reads)
    stoc = correlate_messages(server_writes, client_reads)
    server_fd = stoc[1].send_fd
    range = compute_range(server_ranges, stoc[1].send_t, server_fd)
    ctos = collect(filter(x->(x.recv_fd == server_fd && x.recv_t in server_ranges[range][1]), ctos))
    push!(all_client_reads, client_reads)
    client_offset = ctos[1].recv_t - ctos[1].send_t
    push!(client_offsets, client_offset)
    push!(client_messages, (ctos, stoc))
    append!(all_stoc, stoc)
    client_id = i-6
    append!(client_layers3, timeline_layers([
    TimelineEvent(client_offset, :start);
    TimelineEvent(RR.count_total_ticks(timeline)+client_offset, :end);
    map(x->TimelineEvent(x[2]+client_offset,:read), client_reads);
    map(x->TimelineEvent(x[2]+client_offset,:write), client_writes);
    ]; timeline_id = client_id)
    )
    append!(message_layers,
    [[layer(x=[m.send_t+client_offset, m.recv_t], y=[client_id, server_id], Geom.line, Theme(default_color=colorant"red",line_width=1mm)) for m in ctos];
     [layer(x=[m.send_t, m.recv_t+client_offset], y=[server_id, client_id], Geom.line, Theme(default_color=colorant"blue",line_width=1mm)) for m in stoc]])
end

pmulticlient(theme) = plot(client_layers3..., server_layers3..., message_layers...,
    theme,Guide.xlabel("Time"),
    Guide.ylabel("Timeline"),
    Scale.color_discrete_manual(colors...), Scale.y_continuous(minvalue=-1, maxvalue=11),
    Guide.yticks(label = false),
    Coord.cartesian(xmin = minimum(client_offsets)+145000,
    xmax = minimum(client_offsets)+180000,ymin=-1,ymax=11
    #=, xmax = max(stoc[1].recv_t-client_start,stoc[1].send_t-server_start)+1,=#
    ))

display(pmulticlient(repl_theme))
draw(PDF("pmulticlient.pdf", 8.5Compose.cm, 2inch), pmulticlient(paper_theme))


# IDEA: Trace the execution of a message across machines
# IDEA: Combine with DFSan to trace dataflow across systems

#RunDebugREPL()
