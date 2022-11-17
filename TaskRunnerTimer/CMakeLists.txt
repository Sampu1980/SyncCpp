project(TaskRunnerTimer)

add_library(${PROJECT_NAME} STATIC
        include/app-utils/TimerInterface.h
        include/app-utils/TimerReal.h src/TimerReal.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC TaskRunner)