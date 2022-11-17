project (CertUtils)


set(SM_COMPILE_DB true)

set(COMMON_LIB_SRCS
src/BaseUtils.cpp
src/Certificate.cpp
src/CertificateFactory.cpp
src/CertificateGlobals.cpp
src/CertificateValidator.cpp
src/CertUtils.cpp
src/CRL.cpp
src/CRLFileLoader.cpp
src/EndEntityCertificate.cpp
src/LocalCertificate.cpp
src/PeerCertificate.cpp
src/TrustedCertificate.cpp
src/PKCS12FileLoader.cpp
src/PKCS7FileLoader.cpp
src/timer_providers/NullTimer.cpp
src/timer_providers/NullTimerSubscriber.cpp
src/X509CertificateDBFHelper.cpp
)

# NOTE: If force-enabling debug, dont forget to also rebuild sec-manager with the same debug parameters
#set(DEBUG_BUILD ON)
if(DEBUG_BUILD)
    add_compile_options(-Og -ggdb3 -fno-omit-frame-pointer -fasynchronous-unwind-tables)
    #add_compile_options(-fsanitize=address)
    #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -static-libasan")
else()
    add_compile_options(-O2)
endif(DEBUG_BUILD)

add_library(${PROJECT_NAME} SHARED ${COMMON_LIB_SRCS})

target_include_directories(${PROJECT_NAME} PUBLIC include
                                                  ${DBF_GEN_INCLUDE_DIR}
                                                  ${DBF_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} PUBLIC BaseSystem
                                             boost_locale
                                             logger
                                             crypto
                                             dbf_lib
                                             boost_locale)

add_dependencies(${PROJECT_NAME} dbf_lib icl_cpp)


install(TARGETS ${PROJECT_NAME} COMPONENT libapputils DESTINATION ${INSTALL_THANOS_LIB_PATH})

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib)
