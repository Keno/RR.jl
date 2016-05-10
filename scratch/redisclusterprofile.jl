include("rediscommon.jl")

basedir = "/home/kfischer/cs262project/redis/utils/create-cluster/traces"

reads = Dict{Int,Vector{Any}}()
writes = Dict{Int,Vector{Any}}()
accepts = Dict{Int,Vector{Any}}()
closes = Dict{Int,Vector{Any}}()

timeline, modules = replay(joinpath(basedir,"redis-cli-0"));
client_id = 0
client_reads, client_writes, client_accepts, client_closes, client_nticks = trace_rw(timeline, modules);
reads[0] = client_reads
writes[0] = client_writes
client_ends = [start_time(timeline); end_time(timeline)]
client_layers = timeline_layers([
client_ends;
map(x->TimelineEvent(x[2],:read), client_reads);
map(x->TimelineEvent(x[2],:write), client_writes);
]; timeline_id = client_id);

server_layers = Any[]
nticks = Dict{Any,Int}()
for i = 0:5
  server_id = i+1
  timeline, modules = replay(joinpath(basedir,"redis-server-$i"))
  server_reads, server_writes, server_accepts, server_closes, server_nticks = trace_rw(timeline, modules);
  reads[server_id] = server_reads
  writes[server_id] = server_writes
  accepts[server_id] = server_accepts
  closes[server_id] = server_closes
  nticks[server_id] = server_nticks
  server_ends = [start_time(timeline); end_time(timeline);]
  append!(server_layers,timeline_layers([
  server_ends;
  map(x->TimelineEvent(x[2],:read), server_reads);
  map(x->TimelineEvent(x[2],:write), server_writes);
  ]; timeline_id = server_id));
end

messages = Dict{Any,Any}()
for i=0:6, j=0:6
    @show (i,j)
    messages[i=>j] = correlate_messages(writes[i], reads[j], i, j)
end

ranges = Dict{Int,Any}()
for i = 1:6
    ranges[i] = compute_fd_ranges(accepts[i], closes[i]);
end

# Filter messages by range
for i = 1:6
    if isempty(messages[0=>i])
        messages[i=>0] = Message[]
        continue
    end
    m = messages[0=>i][1]
    server_fd = m.recv_id
    range = compute_range(ranges[i], m.send_t, server_fd)
    messages[i=>0] = collect(filter(x->((x.send_fd == server_fd) && x.send_t in range), messages[i=>0]))
end

all_messages = reduce(vcat,map(collect,values(messages)))

m_colors = [colorant"red",colorant"blue",colorant"green",colorant"orange",colorant"purple",colorant"black",colorant"magenta"]

m_offset = messages[0=>6][1].recv_t

client_layers = timeline_layers([
client_ends;
map(x->TimelineEvent(x[2]+m_offset,:read), client_reads);
map(x->TimelineEvent(x[2]+m_offset,:write), client_writes);
]; timeline_id = client_id);


layers = [layer(x=[m.send_t + ((m.send_id == 0) ? m_offset : 0), m.recv_t + ((m.recv_id == 0) ? m_offset : 0)], 
    y=[m.send_id, m.recv_id], Geom.line, Theme(default_color=m_colors[m.send_id+1],line_width=0.5mm)) for m in all_messages];
 
preplication(theme) = plot(client_layers..., server_layers..., layers...,
    theme,Guide.xlabel("Time"),
    Guide.ylabel("Timeline"),
    Coord.Cartesian(xmin = m_offset),
    Scale.color_discrete_manual(colors...), Scale.y_continuous(minvalue=-1, maxvalue=7))

display(preplication(repl_theme))
draw(PDF("preplication.pdf", 17Compose.cm, 2inch), preplication(paper_theme))
