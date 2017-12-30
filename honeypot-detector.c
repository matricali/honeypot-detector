#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024

int g_verbose = 0;

void print_error(const char *format, ...)
{
    va_list arg;
    fprintf(stderr, "\t\033[91m[!] ");
    va_start(arg, format);
    vfprintf(stderr, format, arg);
    va_end (arg);
    fprintf(stderr, "\033[0m\n");
}

void print_debug(const char *format, ...)
{
    if (g_verbose != 1) {
        return;
    }
    va_list arg;
    fprintf(stderr, "\033[37m");
    va_start(arg, format);
    vfprintf(stderr, format, arg);
    va_end (arg);
    fprintf(stderr, "\033[0m\n");
}

int probe(char *serverAddr, unsigned int serverPort)
{
    struct sockaddr_in addr;
    int sockfd, ret;
    char buffer[BUF_SIZE];
    char *banner = NULL;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Error creating socket!");
        sockfd = 0;
        return -1;
    }
    print_debug("Socket created.");

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(serverAddr);
    addr.sin_port = htons(serverPort);

    print_debug("\t[-] %s:%d - Connecting...", serverAddr, serverPort);
    ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        print_error("%s:%d - Error connecting to the server!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    print_debug("\t[+] %s:%d - Connected.", serverAddr, serverPort);

    memset(buffer, 0, BUF_SIZE);

    // RECIBIR BANNER
    ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (ret < 0) {
        print_error("%s:%d - Error receiving banner!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    banner = malloc(sizeof(char) * 1024);
    banner = strdup(strtok(buffer, "\n"));
    print_debug("\t[?] %s:%d - %s", serverAddr, serverPort, banner);

    char *pkt1 = "SSH-2.0-OpenSSH_7.5";
    char *pkt2 = "\n";
    char *pkt3 = "asd\n      ";
    char *search = "Protocol mismatch.";

    print_debug("\t[<] %s:%d - Sending pkt1: %s", serverAddr, serverPort, strtok(pkt1, "\n"));
    ret = sendto(sockfd, pkt1, sizeof(pkt1), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt1!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("\t[<] %s:%d - Sending pkt2: %s", serverAddr, serverPort, pkt2);
    ret = sendto(sockfd, pkt2, sizeof(pkt2), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt2!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("\t[<] %s:%d - Sending pkt3: %s", serverAddr, serverPort, pkt3);
    ret = sendto(sockfd, pkt3, sizeof(pkt3), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt3!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("\t[>] %s:%d - Receiving...", serverAddr, serverPort);
    ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (ret < 0) {
        print_error("%s:%d - Error receiving response!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    print_debug("\t[+] %s:%d - Received: %s", serverAddr, serverPort, buffer);

    if (strstr(buffer, search) != NULL) {
        printf("\t[+] %s:%d - %s\n", serverAddr, serverPort, banner);
    } else {
        printf("\t[!] %s:%d - POSSIBLE HONEYPOT!\n", serverAddr, serverPort);
    }

    close(sockfd);
    sockfd = 0;

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
    unsigned int port = 22;

    if (argc < 2) {
        printf("usage: %s <ip address> [port]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (argc >= 3) {
        port = atoi(argv[2]);
    }

    ret = probe(argv[1], port);

    return 0;
}
