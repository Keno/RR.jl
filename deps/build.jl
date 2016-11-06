!isdir("src") && mkdir("src")
!isdir("src/rr") && cd("src") do
    run(`git clone https://github.com/mozilla/rr`)
end
!isdir("build/rr") && run(`mkdir -p build/rr`)
DEPS_DIR=pwd()
!isfile("build/rr/build.ninja") && cd("build/rr") do
    run(`cmake -G Ninja -DRR_BUILD_SHARED=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(DEPS_DIR)/usr ../../src/rr`)
end
cd("build/rr") do
    run(`ninja`)
    run(`ninja install`)
end
