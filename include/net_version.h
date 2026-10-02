/**
 * @file net_version.h
 * @brief The release of smallest_tcp this source is (Semantic Versioning).
 *
 * The one place the version is written: CMakeLists.txt reads it for
 * project(VERSION).  CI raises PATCH with every release, one per push to
 * main that passes; MAJOR and MINOR are raised by hand
 * (docs/release-process.md).
 */

#ifndef NET_VERSION_H
#define NET_VERSION_H

#define NET_VERSION_MAJOR 0
#define NET_VERSION_MINOR 1
#define NET_VERSION_PATCH 10

/** The version as one number, for #if: 0x00MMmmpp */
#define NET_VERSION                                                            \
  ((NET_VERSION_MAJOR << 16) | (NET_VERSION_MINOR << 8) | NET_VERSION_PATCH)

#define NET_VERSION_STR_(x) #x
#define NET_VERSION_STR(x) NET_VERSION_STR_(x)

/** "MAJOR.MINOR.PATCH" */
#define NET_VERSION_STRING                                                     \
  NET_VERSION_STR(NET_VERSION_MAJOR)                                           \
  "." NET_VERSION_STR(NET_VERSION_MINOR) "." NET_VERSION_STR(NET_VERSION_PATCH)

#endif /* NET_VERSION_H */
