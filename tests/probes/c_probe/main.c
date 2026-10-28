/*
 * OutPost Behavioral Probe - C / ELF Ground Truth Sample
 *
 * Designed exclusively for isolated sandbox baseline tracing and parser validation.
 * Performs deterministic, harmless actions:
 *   1. Writes to file "probe_c.tmp"
 *   2. Chmods "probe_c.tmp" to 0600
 *   3. Renames "probe_c.tmp" -> "probe_c_renamed.tmp"
 *   4. Deletes "probe_c_renamed.tmp"
 *   5. Forks child process and reaps with waitpid
 *   6. Attempts DNS lookup for non-existent domain "probe-c.test.invalid"
 *   7. Attempts TCP connection to TEST-NET-1 IP 192.0.2.1:80 (RFC 5737)
 *   8. Exits cleanly with status 0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

int main(void) {
    printf("=== OutPost C Probe Starting ===\n");
    fflush(stdout);

    /* 1. File write */
    const char *initial_file = "probe_c.tmp";
    int fd = open(initial_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *payload = "OutPost C probe test payload data\n";
        ssize_t written = write(fd, payload, strlen(payload));
        (void)written;
        close(fd);
    }

    /* 2. File chmod to 0600 */
    chmod(initial_file, 0600);

    /* 3. File rename */
    const char *renamed_file = "probe_c_renamed.tmp";
    rename(initial_file, renamed_file);

    /* 4. File delete */
    unlink(renamed_file);

    /* 5. Process spawn via fork */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        printf("--- C Probe Child Process Executing (PID: %d) ---\n", (int)getpid());
        fflush(stdout);
        _exit(0);
    } else if (pid > 0) {
        /* Parent process: wait for child */
        int status = 0;
        waitpid(pid, &status, 0);
    }

    /* 6. DNS lookup attempt (expected to fail in airgap/isolated sandbox) */
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo("probe-c.test.invalid", "80", &hints, &result);
    if (result) {
        freeaddrinfo(result);
    }

    /* 7. TCP socket connect attempt (TEST-NET-1, RFC 5737) */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(80);
        inet_pton(AF_INET, "192.0.2.1", &target.sin_addr);

        /* Set non-blocking or short timeout so probe does not hang */
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100ms */
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        connect(sock, (struct sockaddr *)&target, sizeof(target));
        close(sock);
    }

    printf("=== OutPost C Probe Exiting ===\n");
    fflush(stdout);
    return 0;
}
