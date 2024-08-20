cmake_minimum_required(VERSION 3.5)

project(NetworkAnalyzer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the Qt Widgets and PrintSupport package
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets PrintSupport)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets PrintSupport)

# Find the pcap library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Add the necessary include directories for pcap
include_directories(${PCAP_INCLUDE_DIRS})

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    filemonitor.h filemonitor.cpp
    IMonitor.h
    pcapinterpreter.h pcapinterpreter.cpp
    IInterpreter.h
    logger.h logger.cpp
    networkdevicefinder.h networkdevicefinder.cpp
    ConsoleHandler.h
    pcapcapturer.h pcapcapturer.cpp
    IPacketFilter.h
    pcapfile.h
    sourceipfilter.h
    destinationipfilter.h
    protocolfilter.h
    packetfiltermanager.h
    analysiswindow.h analysiswindow.cpp analysiswindow.ui
    qcustomplot.cpp qcustomplot.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(NetworkAnalyzer
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(NetworkAnalyzer SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(NetworkAnalyzer
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Link the pcap library, Qt Widgets, and PrintSupport
target_link_libraries(NetworkAnalyzer PRIVATE Qt${QT_VERSION_MAJOR}::Widgets Qt${QT_VERSION_MAJOR}::PrintSupport ${PCAP_LIBRARIES})

# Bundle settings for macOS and iOS
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.NetworkAnalyzer)
endif()
set_target_properties(NetworkAnalyzer PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS NetworkAnalyzer
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(NetworkAnalyzer)
endif()
