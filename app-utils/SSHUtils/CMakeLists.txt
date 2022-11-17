project (SSHUtils)

# TODO remove once in global project
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_LIBRARY_OUTPUT_DIRECTORY})

add_library(${PROJECT_NAME} SHARED 
            src/SSHCommon.cpp
           )

target_include_directories(${PROJECT_NAME} PUBLIC include
                                                  ${DBF_GEN_INCLUDE_DIR}
                                                  ${DBF_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} PUBLIC logger)

add_dependencies(${PROJECT_NAME} dbf_lib)

install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)
