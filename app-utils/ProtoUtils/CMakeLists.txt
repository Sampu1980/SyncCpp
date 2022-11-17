project (ProtoUtils)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_LIBRARY_OUTPUT_DIRECTORY})

#if(BUILD_TESTING)
#    add_subdirectory(test/ut)
#endif()

add_library(${PROJECT_NAME} SHARED
            src/ProtoUtils.cpp
           )

add_compile_options(-O3)

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC logger protobuf)
install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)

