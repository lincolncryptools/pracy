cmake_minimum_required(VERSION 3.11)

project(pracom)

# Use C++17 and crash if that is not available/possible
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_COMPILER "g++")

add_executable(main)

set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/include")

target_sources(main PUBLIC
  "${SRC_DIR}/z.cpp"
  "${SRC_DIR}/g.cpp"
  "${SRC_DIR}/h.cpp"
  "${SRC_DIR}/gt.cpp"
  "${SRC_DIR}/env.cpp"
  "${SRC_DIR}/ops.cpp"
  "${SRC_DIR}/abe_types.cpp"
  "${SRC_DIR}/abe_scheme.cpp"
  "${SRC_DIR}/benchmark.c"
  "${SRC_DIR}/main.cpp")

target_include_directories(main PUBLIC ${INCLUDE_DIRS})

set(WARN_ERROR_FLAGS
  -Wall -Wextra -Wundef -Wshadow -Wpointer-arith
  -Wcast-align -Wwrite-strings -Wfatal-errors
  -Wcast-qual -Wswitch-default -Wswitch-enum -Wunreachable-code)

# set(SANITIZER_FLAGS
#   -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer
#   -fsanitize=undefined -fsanitize=float-divide-by-zero
#   -fsanitize=float-cast-overflow)

# set(OPTS -g)
set(OPTS -O2 -fpermissive)

set(POLICY_LEN "5" CACHE STRING "The size of the policy")
set(BENCH_ITERS "10" CACHE STRING "The number of iteration for each benchmark")
option(MULTI_AUTH "Whether the scheme supports multiple authorities")
option(OT_NEGS "Whether the scheme support OT-type negations")

if(MULTI_AUTH)
  target_compile_definitions(main PRIVATE MULTI_AUTH=1)
endif()

if(OT_NEGS)
  target_compile_definitions(main PRIVATE OT_NEGS=1)
endif()

include_directories(/home/pracy/libs/relic-0.5.0/usr/local/include)

target_compile_definitions(main PRIVATE POLICY_LEN=${POLICY_LEN} BENCH_ITERS=${BENCH_ITERS})
target_compile_options(main PUBLIC ${WARN_ERROR_FLAGS} ${OPTS} ${SANITIZER_FLAGS})
target_link_options(main PUBLIC ${OPTS} ${SANITIZER_FLAGS})

target_link_libraries(main PUBLIC gmp)
target_link_libraries(main PUBLIC /home/pracy/libs/relic-0.5.0/usr/local/lib/librelic.so)
