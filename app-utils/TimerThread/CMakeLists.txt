project (TimerThread)

# TODO remove once in global project
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_LIBRARY_OUTPUT_DIRECTORY})

if(BUILD_TESTING)
    link_directories( ${GTEST_LIB_DIR} )
    add_subdirectory(test/ut)
endif(BUILD_TESTING)

add_library(${PROJECT_NAME} SHARED 
            src/TimerThread.cpp
            src/SystemTimeLeapHandler.cpp
           )

target_include_directories(${PROJECT_NAME} PUBLIC include)
find_package(Boost
                1.61.0
                COMPONENTS thread chrono timer system
                REQUIRED)
target_link_libraries(${PROJECT_NAME} PUBLIC ${Boost_LIBRARIES})

set(OTHER_LINK_LIBRARIES BaseSystem logger)
target_link_libraries(${PROJECT_NAME} PUBLIC ${OTHER_LINK_LIBRARIES})

install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)
