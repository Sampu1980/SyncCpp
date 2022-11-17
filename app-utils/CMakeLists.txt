project (AppUtils)

add_subdirectory(DbiCliAdapter)
add_subdirectory(TimerThread)
add_subdirectory(CommonUtils)
add_subdirectory(ProtoUtils)
add_subdirectory(StringUtils)
add_subdirectory(TaskRunner)
add_subdirectory(TaskRunnerTimer)

if (CONTROLLER_BUILD)
add_subdirectory(SSHUtils)
add_subdirectory(CertUtils)
endif()

create_package(libapputils "App Utils Libs" ${CMAKE_CURRENT_BINARY_DIR})
