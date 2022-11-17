project(TimerThread_ut)

add_executable(${PROJECT_NAME} TimerThreadTest.cpp
                               main.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES SKIP_BUILD_RPATH OFF)
target_link_libraries(${PROJECT_NAME} PRIVATE TimerThread gtest pthread protobuf)

add_test(TimerThread_ut ${PROJECT_NAME})
set_property(TEST ${PROJECT_NAME} PROPERTY ENVIRONMENT LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib)
set_property(TEST ${PROJECT_NAME} APPEND PROPERTY ENVIRONMENT DBF_AGT_PROFILE_PATH=${CMAKE_BINARY_DIR}/bin/.xml)
