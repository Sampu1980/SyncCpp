project (DbiCliAdapter)

# TODO remove once in global project
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_LIBRARY_OUTPUT_DIRECTORY})

add_library(${PROJECT_NAME} SHARED
            src/DbiCliAdapter.cpp
            src/InfoTable.cpp
           )

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC osif_thanos)
install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)
