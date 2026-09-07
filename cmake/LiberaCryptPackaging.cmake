# CPack configuration for standalone LiberaCrypt builds.
#
# The normal install() rules above remain the single source of truth for the
# package contents. CPack only turns that install tree into release archives.

if(NOT LIBERAC_IS_TOP_LEVEL)
    return()
endif()

set(CPACK_PACKAGE_NAME "LiberaCrypt")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Portability-first C11 cryptography library")
set(CPACK_PACKAGE_VENDOR "LiberaCrypt")
set(CPACK_PACKAGE_CONTACT
    "https://github.com/samdae5back/LiberaCrypt/issues")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/packages")
set(CPACK_PACKAGE_CHECKSUM "SHA256")

if(BUILD_SHARED_LIBS)
    set(LIBERAC_PACKAGE_LINKAGE shared)
else()
    set(LIBERAC_PACKAGE_LINKAGE static)
endif()

set(LIBERAC_PACKAGE_PLATFORM "${CMAKE_SYSTEM_NAME}")
if(CMAKE_SYSTEM_PROCESSOR)
    string(APPEND LIBERAC_PACKAGE_PLATFORM "-${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(CPACK_PACKAGE_FILE_NAME
    "LiberaCrypt-${PROJECT_VERSION}-${LIBERAC_PACKAGE_PLATFORM}-${LIBERAC_PACKAGE_LINKAGE}")

# Binary archives use the platform's conventional portable archive format.
# Source archives provide both formats so release tooling can publish either.
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "LiberaCrypt-${PROJECT_VERSION}-Source")
set(CPACK_SOURCE_IGNORE_FILES
    "/[.]git/"
    "/build[^/]*/"
    "/cmake-build[^/]*/"
    "/packages/"
    "~$"
)

include(CPack)
