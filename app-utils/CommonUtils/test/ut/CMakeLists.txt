project(common_utils_ut)

add_executable(${PROJECT_NAME} CommonUtilsTest.cpp 
                               BaseGraphTest.cpp 
                               BaseGraphCustomKeyTest.cpp 
                               KeyTest.cpp
                               CompositeEntityEngineTest.cpp
                               ExpressionEntityEngineTest.cpp
                               main.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES SKIP_BUILD_RPATH OFF)
target_link_libraries(${PROJECT_NAME} PRIVATE CommonUtils gtest pthread protobuf)

add_test(common_utils_ut ${PROJECT_NAME})
set_property(TEST common_utils_ut PROPERTY ENVIRONMENT LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:${CMAKE_BINARY_DIR}/src/external-repos/protobuf/install/lib)
