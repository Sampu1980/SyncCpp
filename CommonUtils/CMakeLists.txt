project (CommonUtils)

# TODO remove once in global project
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_LIBRARY_OUTPUT_DIRECTORY})

# google test configuration for unit testing
if(BUILD_TESTING)
    add_subdirectory(test/ut)
endif()

add_compile_options(-O2)

add_library(${PROJECT_NAME} SHARED 
            src/Key.cpp
            src/BaseGraph.cpp
            src/Utils.cpp
            src/CompositeEntityEngine.cpp
            src/ExpressionEntityEngine.cpp
            src/RecursiveSharedMutex.cpp
            src/ExpressionHelpers.cpp
            src/Expression.cpp
           )

target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} PUBLIC logger fmt boost_date_time)

install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)
