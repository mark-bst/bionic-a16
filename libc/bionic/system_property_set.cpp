/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <async_safe/log.h>
#include <async_safe/CHECK.h>

#include "private/bionic_defs.h"
#include "platform/bionic/macros.h"
#include "private/ScopedFd.h"

static const char property_service_socket[] = "/dev/socket/" PROP_SERVICE_NAME;
static const char property_service_for_system_socket[] =
    "/dev/socket/" PROP_SERVICE_FOR_SYSTEM_NAME;
static const char* kServiceVersionPropertyName = "ro.property_service.version";

class PropertyServiceConnection {
 public:
  PropertyServiceConnection(const char* name) : last_error_(0) {
    socket_.reset(::socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (socket_.get() == -1) {
      last_error_ = errno;
      return;
    }

    // If we're trying to set "sys.powerctl" from a privileged process, use the special
    // socket. Because this socket is only accessible to privileged processes, it can't
    // be DoSed directly by malicious apps. (The shell user should be able to reboot,
    // though, so we don't just always use the special socket for "sys.powerctl".)
    // See b/262237198 for context
    const char* socket = property_service_socket;
    if (strcmp(name, "sys.powerctl") == 0 &&
        access(property_service_for_system_socket, W_OK) == 0) {
      socket = property_service_for_system_socket;
    }

    const size_t namelen = strlen(socket);
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    strlcpy(addr.sun_path, socket, sizeof(addr.sun_path));
    addr.sun_family = AF_LOCAL;
    socklen_t alen = namelen + offsetof(sockaddr_un, sun_path) + 1;

    if (TEMP_FAILURE_RETRY(connect(socket_.get(),
                                   reinterpret_cast<sockaddr*>(&addr), alen)) == -1) {
      last_error_ = errno;
      socket_.reset();
    }
  }

  bool IsValid() {
    return socket_.get() != -1;
  }

  int GetLastError() {
    return last_error_;
  }

  bool RecvInt32(int32_t* value) {
    int result = TEMP_FAILURE_RETRY(recv(socket_.get(), value, sizeof(*value), MSG_WAITALL));
    return CheckSendRecvResult(result, sizeof(*value));
  }

  int socket() {
    return socket_.get();
  }

 private:
  bool CheckSendRecvResult(int result, int expected_len) {
    if (result == -1) {
      last_error_ = errno;
    } else if (result != expected_len) {
      last_error_ = -1;
    } else {
      last_error_ = 0;
    }

    return last_error_ == 0;
  }

  ScopedFd socket_;
  int last_error_;

  friend class SocketWriter;
};

class SocketWriter {
 public:
  explicit SocketWriter(PropertyServiceConnection* connection)
      : connection_(connection), iov_index_(0), uint_buf_index_(0) {
  }

  SocketWriter& WriteUint32(uint32_t value) {
    CHECK(uint_buf_index_ < kUintBufSize);
    CHECK(iov_index_ < kIovSize);
    uint32_t* ptr = uint_buf_ + uint_buf_index_;
    uint_buf_[uint_buf_index_++] = value;
    iov_[iov_index_].iov_base = ptr;
    iov_[iov_index_].iov_len = sizeof(*ptr);
    ++iov_index_;
    return *this;
  }

  SocketWriter& WriteString(const char* value) {
    uint32_t valuelen = strlen(value);
    WriteUint32(valuelen);
    if (valuelen == 0) {
      return *this;
    }

    CHECK(iov_index_ < kIovSize);
    iov_[iov_index_].iov_base = const_cast<char*>(value);
    iov_[iov_index_].iov_len = valuelen;
    ++iov_index_;

    return *this;
  }

  bool Send() {
    if (!connection_->IsValid()) {
      return false;
    }

    if (writev(connection_->socket(), iov_, iov_index_) == -1) {
      connection_->last_error_ = errno;
      return false;
    }

    iov_index_ = uint_buf_index_ = 0;
    return true;
  }

 private:
  static constexpr size_t kUintBufSize = 8;
  static constexpr size_t kIovSize = 8;

  PropertyServiceConnection* connection_;
  iovec iov_[kIovSize];
  size_t iov_index_;
  uint32_t uint_buf_[kUintBufSize];
  size_t uint_buf_index_;

  BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS(SocketWriter);
};

struct prop_msg {
  unsigned cmd;
  char name[PROP_NAME_MAX];
  char value[PROP_VALUE_MAX];
};

static int send_prop_msg(const prop_msg* msg) {
  PropertyServiceConnection connection(msg->name);
  if (!connection.IsValid()) {
    return connection.GetLastError();
  }

  int result = -1;
  int s = connection.socket();

  const int num_bytes = TEMP_FAILURE_RETRY(send(s, msg, sizeof(prop_msg), 0));
  if (num_bytes == sizeof(prop_msg)) {
    // We successfully wrote to the property server but now we
    // wait for the property server to finish its work.  It
    // acknowledges its completion by closing the socket so we
    // poll here (on nothing), waiting for the socket to close.
    // If you 'adb shell setprop foo bar' you'll see the POLLHUP
    // once the socket closes.  Out of paranoia we cap our poll
    // at 250 ms.
    pollfd pollfds[1];
    pollfds[0].fd = s;
    pollfds[0].events = 0;
    const int poll_result = TEMP_FAILURE_RETRY(poll(pollfds, 1, 250 /* ms */));
    if (poll_result == 1 && (pollfds[0].revents & POLLHUP) != 0) {
      result = 0;
    } else {
      // Ignore the timeout and treat it like a success anyway.
      // The init process is single-threaded and its property
      // service is sometimes slow to respond (perhaps it's off
      // starting a child process or something) and thus this
      // times out and the caller thinks it failed, even though
      // it's still getting around to it.  So we fake it here,
      // mostly for ctl.* properties, but we do try and wait 250
      // ms so callers who do read-after-write can reliably see
      // what they've written.  Most of the time.
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Property service has timed out while trying to set \"%s\" to \"%s\"",
                            msg->name, msg->value);
      result = 0;
    }
  }

  return result;
}

static constexpr uint32_t kProtocolVersion1 = 1;
static constexpr uint32_t kProtocolVersion2 = 2;  // current

static atomic_uint_least32_t g_propservice_protocol_version = 0;

static void detect_protocol_version() {
  char value[PROP_VALUE_MAX];
  if (__system_property_get(kServiceVersionPropertyName, value) == 0) {
    g_propservice_protocol_version = kProtocolVersion1;
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "Using old property service protocol (\"%s\" is not set)",
                          kServiceVersionPropertyName);
  } else {
    uint32_t version = static_cast<uint32_t>(atoll(value));
    if (version >= kProtocolVersion2) {
      g_propservice_protocol_version = kProtocolVersion2;
    } else {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Using old property service protocol (\"%s\"=\"%s\")",
                            kServiceVersionPropertyName, value);
      g_propservice_protocol_version = kProtocolVersion1;
    }
  }
}

static const char* __prop_error_to_string(int error) {
  switch (error) {
  case PROP_ERROR_READ_CMD: return "PROP_ERROR_READ_CMD";
  case PROP_ERROR_READ_DATA: return "PROP_ERROR_READ_DATA";
  case PROP_ERROR_READ_ONLY_PROPERTY: return "PROP_ERROR_READ_ONLY_PROPERTY";
  case PROP_ERROR_INVALID_NAME: return "PROP_ERROR_INVALID_NAME";
  case PROP_ERROR_INVALID_VALUE: return "PROP_ERROR_INVALID_VALUE";
  case PROP_ERROR_PERMISSION_DENIED: return "PROP_ERROR_PERMISSION_DENIED";
  case PROP_ERROR_INVALID_CMD: return "PROP_ERROR_INVALID_CMD";
  case PROP_ERROR_HANDLE_CONTROL_MESSAGE: return "PROP_ERROR_HANDLE_CONTROL_MESSAGE";
  case PROP_ERROR_SET_FAILED: return "PROP_ERROR_SET_FAILED";
  }
  return "<unknown>";
}

int bst_hack_system_property_set(const char *key, const char *value);
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_set(const char* key, const char* value) {
  if (key == nullptr) return -1;
  if (value == nullptr) value = "";

  if (g_propservice_protocol_version == 0) {
    detect_protocol_version();
  }

  if (g_propservice_protocol_version == kProtocolVersion1) {
    // Old protocol does not support long names or values
    if (strlen(key) >= PROP_NAME_MAX) return -1;
    if (strlen(value) >= PROP_VALUE_MAX) return -1;
    if (!bst_hack_system_property_set(key, value))
        return 0;

    prop_msg msg;
    memset(&msg, 0, sizeof msg);
    msg.cmd = PROP_MSG_SETPROP;
    strlcpy(msg.name, key, sizeof msg.name);
    strlcpy(msg.value, value, sizeof msg.value);

    return send_prop_msg(&msg);
  } else {
    // New protocol only allows long values for ro. properties only.
    if (strlen(value) >= PROP_VALUE_MAX && strncmp(key, "ro.", 3) != 0) return -1;
    if (!bst_hack_system_property_set(key, value))
        return 0;
    // Use proper protocol
    PropertyServiceConnection connection(key);
    if (!connection.IsValid()) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": connection failed: %m", key,
                            value);
      return -1;
    }

    SocketWriter writer(&connection);
    if (!writer.WriteUint32(PROP_MSG_SETPROP2).WriteString(key).WriteString(value).Send()) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": write failed: %m", key,
                            value);
      return -1;
    }

    int result = -1;
    if (!connection.RecvInt32(&result)) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": recv failed: %m", key, value);
      return -1;
    }

    if (result != PROP_SUCCESS) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": %s (0x%x)", key, value,
                            __prop_error_to_string(result), result);
      return -1;
    }

    return 0;
  }
}
int get_packagname_from_pid(pid_t pid,char *app_name) {
#define MAX_NAME_LENGTH      64
    int debug = 0;
    int result = 0;
    char comm_name[sizeof("/proc/cmdline") + 8];

    snprintf(comm_name, sizeof(comm_name), "/proc/%d/cmdline", pid);
    int fd = TEMP_FAILURE_RETRY(open(comm_name, O_RDONLY));
    if (fd == -1) {
        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "error trying to open %s\n", comm_name);
        return result;
    }

    int bytes_read = TEMP_FAILURE_RETRY(read(fd, app_name, MAX_NAME_LENGTH));

    if (bytes_read == -1) {
        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "error trying to read %s\n", comm_name);
        close(fd);
        return result;
    }

    if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "name is  %s\n", app_name);
    close(fd);
    result = 1;
    return result;
}

// BS4-9670 Puzzle & Dragon error 70 fix: Helper function to reverse the bluestacks packageName prefix.
// We are inverting packageName as the error70 sdk is detecting bluestacks based on the prefix present
// in strings section in the libc.so object.
void reverse(char* str) {
    int i;
    int n;
    char temp;
    n = strlen(str);
    for( i = 0; i < n/2; i++) {
        temp = str[i];
        str[i]=str[n-i-1];
        str[n-i-1]=temp;
    }
}

// Helper function to determine if we should modify system properties being read by an app.
// We try and read pid specific /proc/cmdline entry and determine the behaviour based on app name.
// Not modifying properties if determined package is of bluestacks, google or android.
/*
 * return 0 if bluestacks/google/android package
 * return 1 otherwise
 */
int bst_check_if_third_party_app(pid_t pid, uid_t uid) {
#define MAX_NAME_LENGTH      64
    int debug = 0;
    int result = 0;
    int package_name_found = 0;

    char app_name[MAX_NAME_LENGTH];

    package_name_found = get_packagname_from_pid(pid,app_name);
    if (!package_name_found)
        return result;

    char bst_pkg_prefix[] = "skcatseulb.moc";
    reverse(bst_pkg_prefix);

    if (uid >= 10000 && !(!strncmp(app_name, bst_pkg_prefix, strlen(bst_pkg_prefix)) ||
                !strncmp(app_name, "com.google.android", strlen("com.google.android")) ||
                !strncmp(app_name, "com.location.provider", strlen("com.location.provider")) ||
                !strncmp(app_name, "com.uncube", strlen("com.uncube")) ||
                !strncmp(app_name, "com.pop.store", strlen("com.pop.store")) ||
                !strncmp(app_name, "com.android", strlen("com.android"))))
        result = 1;

    if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "app name is %s return value is %d\n", app_name, result);
    return result;
}

// This function will return 0 for apps passed in excecption list and if it fails to verify package name,
// or for other apps it will return 1
int hide_property_from_other_apps(pid_t pid, const char *excecptionList[], int size ) {
#define MAX_NAME_LENGTH      64
    int debug = 0;
    int result = 1;
    char app_name[MAX_NAME_LENGTH];

    result = get_packagname_from_pid(pid,app_name);
    if (!result)
        return result;

    for (int i = 0; i < size; i++) {
        if (!strncmp(app_name, excecptionList[i], strlen(excecptionList[i]))) {
            result = 0;
            break;
        }
    }

    if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "app name is %s return value is %d\n", app_name, result);
    return result;
}

// return 0 and empty @dst if fails,
// or it will return pkgname length, fill @dst with pkgname
static inline unsigned bst_get_current_pkgname(char dst[], unsigned dstlen) {
    if (dstlen == 0) return 0;
    const int fd  = TEMP_FAILURE_RETRY(open("/proc/self/cmdline", O_RDONLY));
    if (fd < 0) return 0;
    int len = TEMP_FAILURE_RETRY(read(fd, dst, dstlen - 1));
    close(fd);
    if (len < 0) len = 0;
    dst[len] = 0;
    return len;
}

/*
 * Helper function to read value for @pkgname in @file_path with "pkgname;value" format in lines.
 * If succ: return "value length" and fill parsed @value.
 * If fail: return 0 if it fails to find pkgname or the value is of 0 length,
 */
static const unsigned max_pkgname_len = 64;
static inline int bst_read_custom_value_for_app(const char* pkgname, const char* file_path, char value[PROP_VALUE_MAX]) {
    const bool debug = false;
    char line[max_pkgname_len+PROP_VALUE_MAX+4];
    FILE* fp = fopen(file_path, "r");
    if (fp == nullptr) {
        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "read_custom_value_for_app error opening file [%s] for pkg = %s\n", file_path, pkgname);
        return 0;
    }

    const int name_len = strlen(pkgname);
    // iterate through the file to get the pkgname entries.
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, pkgname, name_len) != 0) continue;

        char* subtoken = strchr(line, ';');
        if (subtoken == nullptr) continue;

        ++subtoken;
        int len = strlen(subtoken);
        if (len > 0 && subtoken[len-1] == '\n') {
            subtoken[--len] = '\0';
        }
        if (len >= PROP_VALUE_MAX) {
            len = PROP_VALUE_MAX - 1;
            subtoken[len] = '\0';
        }
        memcpy(value, subtoken, len + 1);

        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Found matching entry of %s, value: %s\n", pkgname, value);
        fclose(fp);
        return len;
    }

    fclose(fp);
    return 0;
}

// If succ: Return value length and fill @value corresponding to pkgname when success.
// If fail: Return 0 if it fails to find current pkgname in @file_path, or value for current pkgname is empty
static inline int bst_obtain_custom_value_from_path(const char* file_path, char value[PROP_VALUE_MAX]) {
    char pkgname[max_pkgname_len];
    if (bst_get_current_pkgname(pkgname, max_pkgname_len) <= 0) return 0;

    return bst_read_custom_value_for_app(pkgname, file_path, value);
}

int match_uid_helper(const char *path, uid_t val, int buff_length) {
#define MAX_UID_LENGTH     10

  int debug = 0;
  char buff[buff_length];
  unsigned long present_uid = -1;

  FILE* fp = fopen(path, "r");
  if (fp == NULL) {
    if (debug) async_safe_format_log(ANDROID_LOG_WARN, "libc", "match_uid_helper error opening file [%s] for myuid = %u\n", path, val);
    return 0;
  }

  // now we open the marker file and iterate through the file to get the uid entries, and match it with our required value.
  while (fgets(buff, buff_length, fp)) {
    char *p;
    present_uid = strtoul(buff, &p, MAX_UID_LENGTH);
    if (val == present_uid) {
      if (debug) async_safe_format_log(ANDROID_LOG_WARN, "libc", "Found matching entry of %lu\n", present_uid);
      // we have a match, return here itself.
      fclose(fp);
      return 1;
    }
  }

  // we reached here means we have parsed the file and did not get a match, returning 0.
  fclose(fp);
  return 0;
}

/*
 * BS4-11141: ROK tries to set property sys.usb.config to none after which adb disconnects
 * so not allowing 3rd party apps to set this property to none.
 * return 0 - if we don't want the app to set the property
 * return -1 - otherwise.
 *
 */
int bst_hack_system_property_set(const char *key, const char *value) {
    int debug = 0;
    uid_t myuid = getuid();
    pid_t mypid = getpid();
    if (myuid >= 10000
            && ((!strncmp(key, "sys.usb.config", strlen("sys.usb.config")) && !strncmp(value, "none", strlen("none")))
                || (!strncmp(key, "persist.sys.usb.config", strlen("persist.sys.usb.config")) && !strncmp(value, "none", strlen("none"))))
            && bst_check_if_third_party_app(mypid, myuid)) {
        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "uid: %u trying to set %s to %s\n", myuid, key, value);
        return 0;
    }
    return -1;
}

/* Helper function to return modified ro.secure/ro.debuggable system property values if calling app is not of bluestacks/android/google.
 * Bug 7294: Puzzle and Dragons crash on launch as it tries to read ro.debuggable values.
 * Also, if arm apps try to run getprop or read system property for CPU ABI values.
 * For such apps, we will return the ARM ABIs irrespective of actual values.
 * Apps like com.xlcw.hxct.mgdd.m4399,com.lxd.SehzAresunique.m4399 read these values
 */
int bst_hack_system_property(const char *name, char *value) {
#define APP_WITH_ABI2                      "/data/downloads/.tmp/.bstABI2Apps"
#define APP_WITH_ABI2_SHOWDEFAULTCPUABI    "/data/downloads/.tmp/.bstxABIApps"
#define CPU_ABI                            "armeabi-v7a"
#define CPU_ABI_LIST_32                    "armeabi-v7a,armeabi"
#if defined(__LP64__)
#define CPU_ABI_LIST_64                    "arm64-v8a"
#endif
#define MAX_BUFF_LENGTH                    64
#define VALUE_1                            "1"
#define VALUE_0                            "0"
#define VALUE_TRUE                         "true"
#define STOP                               "stopped"
#define CRYPTO_ENCRYPTED                   "encrypted"
#define CRYPTO_BLKDEV                      "/dev/block/dm-1"
#define CRYPTO_TYPE                        "block"
#define USB_STATE_NONE                     "none"
#define TREBLE_ENABLED                     "true"
#define VERITYMODE_ENFORCING               "enforcing"
#define WIFI_INTERFACE_WLAN0               "wlan0"
#define WIFI_DIRECT_INTERFACE              "p2p-dev-wlan0"
#define CONTROL_PRIVAPP_PERMISSION_ENFORCE "enforce"
    int debug = 0;
    int len = 0;
    int is_uid_match = 0, is_show_abi_uid = 0;
    uid_t myuid = getuid();
    pid_t mypid = getpid();

    // If some third party app is trying to read system properties ro.secure/ro.debuggable, then show them the modified values.
    // Apps like puzzle and dragon tries to read ro.debuggable and crashes if does not get user build specific values.
    if (myuid >= 10000
            && name != NULL && value != NULL
            && (!strcmp(name, "ro.secure") || !strcmp(name, "ro.debuggable")
                || !strcmp(name, "ro.allow.mock.location") || !strcmp(name, "ro.crypto.state")
                || !strcmp(name, "ro.adb.secure") || !strncmp(name, "init.svc.bst", strlen("init.svc.bst"))
                || !strcmp(name, "init.svc.imeservice") || !strcmp(name, "init.svc.appstatsd")
                || !strcmp(name, "init.svc.enable_arm_bin") || !strcmp(name, "gsm.sim.bstserial")
                || !strcmp(name, "init.svc.postupgrade") || !strcmp(name, "init.svc.adbd")
                || !strcmp(name, "persist.sys.devId") || !strcmp(name, "persist.sys.pcode")
                || !strcmp(name, "persist.sys.user.email") || !strcmp(name, "persist.sys.abivalue")
                || !strcmp(name, "sys.usb.config") || !strcmp(name, "persist.sys.usb.config")
                || !strcmp(name, "ro.treble.enabled") || !strcmp(name, "init.svc.bindmount")
                || !strcmp(name, "init.svc.mountsf") || !strcmp(name, "ro.crypto.fs_crypto_blkdev")
                || !strcmp(name, "ro.crypto.type") || !strcmp(name, "ro.boot.veritymode")
                || !strcmp(name, "persist.netd.stable_secret") || !strcmp(name, "wifi.interface")
                || !strcmp(name, "ro.dalvik.vm.native.bridge") || !strcmp(name, "ro.control_privapp_permissions")
                || !strcmp(name, "ro.apex.updatable") || !strcmp(name, "ro.crypto.metadata.enabled")
                || !strcmp(name, "wifi.direct.interface"))
            && bst_check_if_third_party_app(mypid, myuid)) {
        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "uid: %u trying to read %s hence returning modifying results\n", myuid, name);
        if (!strcmp(name, "ro.secure")) {
            // changing value as some third party app is reading ro.secure
            len = strlen(VALUE_1);
            memcpy(value, VALUE_1, len+1);
        } else if (!strcmp(name, "ro.debuggable")) {
            // changing value as some third party app is reading ro.debuggable
            len = strlen(VALUE_0);
            memcpy(value, VALUE_0, len+1);
        }
        else if (!strcmp(name, "ro.allow.mock.location")) {
            // changing value as some third party app is reading ro.mock.location
            len = strlen(VALUE_0);
            memcpy(value, VALUE_0, len+1);
        }
        else if (!strcmp(name, "ro.crypto.state")) {
            // changing value as some third party app is reading ro.crypto.state
            len = strlen(CRYPTO_ENCRYPTED);
            memcpy(value, CRYPTO_ENCRYPTED, len+1);
        }
        else if (!strcmp(name, "ro.crypto.fs_crypto_blkdev")) {
            // changing value as some third party app is reading ro.crypto.fs_crypto_blkdev
            len = strlen(CRYPTO_BLKDEV);
            memcpy(value, CRYPTO_BLKDEV, len+1);
        }
        else if (!strcmp(name, "ro.crypto.type")) {
            // changing value as some third party app is reading ro.crypto.type
            len = strlen(CRYPTO_TYPE);
            memcpy(value, CRYPTO_TYPE, len+1);
        }
        else if (!strcmp(name, "ro.adb.secure")) {
            // changing value as some third party app is reading ro.adb.secure
            len = strlen(VALUE_1);
            memcpy(value, VALUE_1, len+1);
        }
        else if (!strcmp(name, "ro.treble.enabled")) {
            // changing value as some third party app is reading ro.treble.enabled
            len = strlen(TREBLE_ENABLED);
            memcpy(value, TREBLE_ENABLED, len+1);
        }
        else if (!strcmp(name, "init.svc.adbd")) {
            // changing value as some third party app is reading init.svc.adbd
            len = strlen(STOP);
            memcpy(value, STOP, len + 1);
        }
        else if (!strcmp(name, "ro.boot.veritymode")) {
            // changing value as some third party app is reading ro.boot.veritymode
            len = strlen(VERITYMODE_ENFORCING);
            memcpy(value, VERITYMODE_ENFORCING, len + 1);
        }
        else if (!strcmp(name, "wifi.interface")) {
            // changing value as some third party app is reading wifi.interface
            len = strlen(WIFI_INTERFACE_WLAN0);
            memcpy(value, WIFI_INTERFACE_WLAN0, len + 1);
        }
        else if (!strcmp(name, "ro.control_privapp_permissions")) {
            // changing value as some third party app is reading ro.control_privapp_permissions
            len = strlen(CONTROL_PRIVAPP_PERMISSION_ENFORCE);
            memcpy(value, CONTROL_PRIVAPP_PERMISSION_ENFORCE, len + 1);
        }
        else if (!strcmp(name, "ro.apex.updatable")) {
            len = strlen(VALUE_TRUE);
            memcpy(value, VALUE_TRUE, len + 1);
        }
        else if (!strcmp(name, "ro.crypto.metadata.enabled")) {
            len = strlen(VALUE_TRUE);
            memcpy(value, VALUE_TRUE, len + 1);
        }
        else if (!strcmp(name, "wifi.direct.interface")) {
            len = strlen(WIFI_DIRECT_INTERFACE);
            memcpy(value, WIFI_DIRECT_INTERFACE, len + 1);
        }
        else if (!strncmp(name, "init.svc.bst", strlen("init.svc.bst"))
                || !strcmp(name, "init.svc.imeservice") || !strcmp(name, "init.svc.appstatsd")
                || !strcmp(name, "init.svc.enable_arm_bin") || !strcmp(name, "gsm.sim.bstserial")
                || !strcmp(name, "init.svc.postupgrade") || !strcmp(name, "persist.sys.devId")
                || !strcmp(name, "persist.sys.pcode") || !strcmp(name, "persist.sys.user.email")
                || !strcmp(name, "persist.sys.abivalue") || !strcmp(name, "init.svc.bindmount")
                || !strcmp(name, "init.svc.mountsf") || !strcmp(name, "persist.netd.stable_secret")
                || !strcmp(name, "ro.dalvik.vm.native.bridge")) {
            // Sending null value for bluestacks specific property
            // Apps like th.co.dcp.townkins try to read properties init.svc.bstfolderd and init.svc.bstsvcmgrtest
            // So sending null for such properties if asked by some third party app.
            len = -1;
            value[0] = 0;
        }
        else if (!strcmp(name, "sys.usb.config") || !strcmp(name, "persist.sys.usb.config")) {
            len = strlen(USB_STATE_NONE);
            memcpy(value, USB_STATE_NONE, len+1);
        }
    } else if(myuid >= 10000 && name != NULL && value != NULL && (strstr(name,"cpu.abi") || strstr(name, "native.bridge") || strstr(name, "ro.arch"))) {
        is_uid_match = match_uid_helper(APP_WITH_ABI2, myuid, MAX_BUFF_LENGTH);

        // Some china apps like com.netease.TCYM.uc; com.youzu.wzqj.ad.baidu; com.zmxyol.union.baidu installed in arm mode
        // crash when we return arm specific cpu.abi values.
        // Hence returning default abi values to such apps based on a marker file under /data/downloads if their Uid entry is present in the same.
        is_show_abi_uid = match_uid_helper(APP_WITH_ABI2_SHOWDEFAULTCPUABI, myuid, MAX_BUFF_LENGTH);

        if (debug) async_safe_format_log(ANDROID_LOG_ERROR,"libc" ,"app uid %u rying to read: %s  is_uid_match:%d  is_show_abi_uid: %d\n", myuid, name, is_uid_match, is_show_abi_uid);

        if (is_uid_match == 1) {
            //Case 14627: Modifying ro.dalvik.vm.native.bridge to arm value '0' for arm apps.
            //This fixes the illegal env detection in security sdk G-presto integrated in this app.
        if (!strcmp(name, "ro.dalvik.vm.native.bridge")) {
        len = strlen(VALUE_0);
        memcpy(value, VALUE_0, len+1);
        } else if (!strcmp(name, "ro.arch")) {
        len = -1;
        value[0] = 0;
        } else if (is_show_abi_uid == 0) {
                if (!strcmp(name, "ro.product.cpu.abi")) {
                    // changing value as arm app is reading ro.product.cpu.abi
                    len = strlen(CPU_ABI);
                    memcpy(value, CPU_ABI, len+1);
                } else if (!strcmp(name, "ro.product.cpu.abilist") || !strcmp(name, "ro.product.cpu.abilist32")) {
                    // changing value as arm app is reading ro.product.cpu.abilist
                    len = strlen(CPU_ABI_LIST_32);
                    memcpy(value, CPU_ABI_LIST_32, len+1);
                }
#if defined(__LP64__)
                else if (!strcmp(name, "ro.product.cpu.abilist64")) {
                    // changing value as arm app is reading ro.product.cpu.abilist64
                    len = strlen(CPU_ABI_LIST_64);
                    memcpy(value, CPU_ABI_LIST_64, len+1);
                }
#endif
                else if (debug) {
                    async_safe_format_log(ANDROID_LOG_ERROR,"libc" ,"trying to read unknown property: %s : %u\n", name, myuid);
                }
            }
        }
    } else if (myuid >= 10000 && name != NULL && value != NULL && !strcmp(name,"ro.csc.sales_code")) {
        // Sending null value for this specific property,as only samsung apps should be able to read this value
#define PKG_1 "com.sec.android.app.samsungapps"
#define PKG_2 "com.sec.android.app.billing"
#define PKG_3 "com.osp.app.signin"
#define PKG_4 "com.samsung.android.mobileservice"

        const char *excecptionList[] = {PKG_1, PKG_2, PKG_3, PKG_4};
        if (hide_property_from_other_apps(mypid, excecptionList, sizeof(excecptionList)/ sizeof(excecptionList[0]))) {
            len = -1;
            value[0] = 0;
        }
    } else if (myuid >= 10000 && name != NULL && value != NULL && !strcmp(name,"ro.product.store")) {
        // Sending null value for this specific property,as only one store apps should be able to read this value
#define PKG_5       "com.skt.skaf.OA00018282"
#define PKG_6       "com.skt.skaf.A000Z00040"

        const char *excecptionList[] = {PKG_5, PKG_6};
        if (hide_property_from_other_apps(mypid, excecptionList, sizeof(excecptionList)/ sizeof(excecptionList[0]))) {
            len = -1;
            value[0] = 0;
        }
    } else if (name != NULL && value != NULL
            && (! strcmp(name, "ro.product.board")
                || !strcmp(name, "ro.product.brand")
                || !strcmp(name, "ro.product.device")
                || !strcmp(name, "ro.product.manufacturer")
                || !strcmp(name, "ro.product.model")
                || !strcmp(name, "ro.product.name")
                || !strcmp(name, "ro.build.fingerprint")
                || !strcmp(name, "ro.build.platform")
                || !strcmp(name, "ro.build.product")
                || !strcmp(name, "ro.build.description")
                || !strcmp(name, "ro.hardware"))) {

        // Return custom model value for some games that use error 70 detection.
        // These games will only run on some x86 devices with certain models on Pie.
        if (myuid >= 10000 && !strcmp(name, "ro.product.model")) {
            len = bst_obtain_custom_value_from_path("/data/downloads/.tmp/.modelProp", value);
            if (len > 0) {
                return len;
            }
        }
        // Return the value of corresponding bst.<prop_name> properties when above properties are read.
        // If returned value is 0 then return the values of original properties i.e. prop_name.
        char prop_name[PROP_NAME_MAX];
        sprintf(prop_name, "bst.%s",name);

        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "uid: %u trying to read %s hence returning results for property %s\n", myuid, name, prop_name);
        int len = __system_property_get(prop_name, value);

        if (debug) async_safe_format_log(ANDROID_LOG_ERROR, "libc", "value is = %s\n", value );
        if (len != 0) {
            return len;
        }
    }
    return len;
}
