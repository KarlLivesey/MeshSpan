// SPDX-License-Identifier: GPL-2.0-only

// Optional local test client only. The installed Samba library is an external
// test prerequisite; this helper binary must never enter MeshSpan artifacts.
// Installed Samba is GPL-3.0-or-later: the locally linked combined binary is
// not distributable as GPL-2.0-only. No Samba implementation source is vendored.
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <libsmbclient.h>

static void authenticate(SMBCCTX *context, const char *server, const char *share,
                         char *domain, int domain_size, char *username,
                         int username_size, char *password, int password_size) {
    (void)server;
    (void)share;
    if (domain_size > 0) snprintf(domain, (size_t)domain_size, "MESHSPAN");
    const char *configured_username = getenv("MESHSPAN_SMB_USERNAME");
    if (configured_username == NULL) configured_username = "Administrator";
    if (username_size > 0)
        snprintf(username, (size_t)username_size, "%s", configured_username);
    if (password_size > 0)
        snprintf(password, (size_t)password_size, "%s",
                 (const char *)smbc_getOptionUserData(context));
}

static int fail(const char *operation) {
    fprintf(stderr, "SMB retained handle: %s failed (errno %d)\n", operation, errno);
    return 1;
}

static int verify_bytes(SMBCCTX *context, SMBCFILE *file, const char *expected) {
    char actual[32] = {0};
    size_t length = strlen(expected);
    if (smbc_getFunctionLseek(context)(context, file, 0, SEEK_SET) != 0)
        return fail("seek");
    if (smbc_getFunctionRead(context)(context, file, actual, length) != (ssize_t)length)
        return fail("read");
    if (memcmp(actual, expected, length) != 0) return fail("verify exact bytes");
    return 0;
}

int main(int argc, char **argv) {
    const char *password = getenv("MESHSPAN_SMB_PASSWORD");
    if (argc != 2 || password == NULL) return fail("configuration");
    SMBCCTX *context = smbc_new_context();
    if (context == NULL) return fail("allocate context");
    smbc_setOptionUserData(context, (void *)password);
    smbc_setFunctionAuthDataWithContext(context, authenticate);
    smbc_setOptionSmbEncryptionLevel(context, SMBC_ENCRYPTLEVEL_REQUIRE);
    smbc_setTimeout(context, 10000);
    if (!smbc_setOptionProtocols(context, "SMB3_11", "SMB3_11"))
        return fail("select SMB3.1.1");
    if (smbc_init_context(context) == NULL) return fail("initialize context");
    SMBCFILE *file = smbc_getFunctionOpen(context)(context, argv[1], O_CREAT | O_RDWR, 0600);
    if (file == NULL) return fail("open");
    const char before[] = "before lease renewal";
    const char after[] = "after lease renewal!";
    if (smbc_getFunctionWrite(context)(context, file, before, sizeof(before) - 1)
        != (ssize_t)(sizeof(before) - 1)) return fail("initial write");
    puts("LEASE_OPEN_ACKNOWLEDGED");
    fflush(stdout);
    // Wait from acknowledged staging on this exact handle, independent of setup.
    struct timespec remaining = {.tv_sec = 65, .tv_nsec = 0};
    while (nanosleep(&remaining, &remaining) != 0)
        if (errno != EINTR) return fail("lease interval");
    if (verify_bytes(context, file, before) != 0) return 1;
    if (smbc_getFunctionLseek(context)(context, file, 0, SEEK_SET) != 0)
        return fail("seek before rewrite");
    if (smbc_getFunctionWrite(context)(context, file, after, sizeof(after) - 1)
        != (ssize_t)(sizeof(after) - 1)) return fail("write after lease");
    if (verify_bytes(context, file, after) != 0) return 1;
    if (smbc_getFunctionClose(context)(context, file) != 0) return fail("publish on close");
    file = smbc_getFunctionOpen(context)(context, argv[1], O_RDONLY, 0);
    if (file == NULL) return fail("reopen published bytes");
    if (verify_bytes(context, file, after) != 0) return 1;
    if (smbc_getFunctionClose(context)(context, file) != 0) return fail("close read handle");
    if (smbc_free_context(context, 1) != 0) return fail("release context");
    puts("RETAINED_HANDLE_READ_WRITE_CLOSE_VERIFIED");
    return 0;
}
