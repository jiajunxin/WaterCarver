cmake_minimum_required(VERSION 3.5)
project(Watercarver)
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -flto -Wall")
set(LIB_SHUFFLE_NAME lib)
set(TEST_SHUFFLE_NAME test)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(LIB_SHUFFLE_SRC
        src/WaterCarver.cpp
        src/Cipher_elg.cpp
        src/CurvePoint.cpp
        src/ElGammal.cpp
        src/FakeZZ.cpp
        src/func_pro.cpp
        src/func_ver.cpp
        src/Functions.cpp
        src/G_q.cpp
        src/Mod_p.cpp
        src/multi_expo.cpp
        src/Pedersen.cpp
        src/Permutation.cpp
        src/Prover_toom.cpp
        src/SchnorrProof.cpp
        src/Verifier_toom.cpp
        src/CipherTable.cpp
        src/Utils.cpp
        src/sha256.cpp
        src/NIZKProof.cpp
        src/RemoteShuffler.cpp
        src/VerifierClient.cpp src/GoApis.cpp src/GoApis.h)
set(TEST_SHUFFLE_SRC ${LIB_SHUFFLE_SRC})
list(APPEND TEST_SHUFFLE_SRC src/test.cpp)
if (CMAKE_HOST_WIN32)
    set(SHUFFLE_LIB
            ntl
            gmp
            boost_system-mt
            boost_filesystem-mt
            pthread
            boost_regex-mt
            boost_thread-mt
            boost_context-mt
            gomp
            )
else()
    set(SHUFFLE_LIB
            ntl
            gmp
            boost_system
            boost_filesystem
            pthread
            boost_regex
            boost_thread
            boost_context
            gomp
            )
endif ()
add_library(${LIB_SHUFFLE_NAME} SHARED ${LIB_SHUFFLE_SRC})
set_target_properties(${LIB_SHUFFLE_NAME} PROPERTIES OUTPUT_NAME shuffle)
target_link_libraries(${LIB_SHUFFLE_NAME} ${SHUFFLE_LIB})
install(TARGETS ${LIB_SHUFFLE_NAME} LIBRARY DESTINATION ${LIBRARY_OUTPUT_PATH})
add_executable(${TEST_SHUFFLE_NAME} ${TEST_SHUFFLE_SRC})
target_link_libraries(${TEST_SHUFFLE_NAME} ${SHUFFLE_LIB})