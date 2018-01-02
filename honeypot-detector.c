#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define BUF_SIZE 1024
#define HONEYPOT_DETECTOR_VERSION "1.0.1"

int g_verbose = 0;
int g_timeout = 10;
int g_port = 22;
int MAX_FORKS = 1;

void print_error(const char *format, ...)
{
    va_list arg;
    fprintf(stderr, "\033[91m[!] ");
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
    fd_set fdset;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Error creating socket!");
        sockfd = 0;
        return -1;
    }
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    print_debug("Socket created.");

    struct timeval timeout;
    timeout.tv_sec = g_timeout;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(serverAddr);
    addr.sin_port = htons(serverPort);

    print_debug("[-] %s:%d - Connecting...", serverAddr, serverPort);
    ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));

    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);

    if (select(sockfd + 1, NULL, &fdset, NULL, &timeout) == 1) {
        int so_error;
        socklen_t len = sizeof so_error;

        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error < 0) {
            print_error("%s:%d - Error connecting to the server! (%s)", serverAddr, serverPort, strerror(so_error));
            close(sockfd);
            sockfd = 0;
            return -1;
        }
    }

    // Set to blocking mode again...
    if ((ret = fcntl(sockfd, F_GETFL, NULL)) < 0) {
        fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(ret));
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    long arg = 0;
    arg &= (~O_NONBLOCK);
    if ((ret = fcntl(sockfd, F_SETFL, arg)) < 0) {
       fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(ret));
       close(sockfd);
       sockfd = 0;
       return -1;
    }

    print_debug("[+] %s:%d - Connected.", serverAddr, serverPort);

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
    print_debug("[?] %s:%d - %s", serverAddr, serverPort, banner);

    char *pkt1 = "SSH-2.0-OpenSSH_7.5";
    char *pkt2 = "\n";
    char *pkt3 = "asd\n      ";
    char *search = "Protocol mismatch.";

    print_debug("[<] %s:%d - Sending pkt1: %s", serverAddr, serverPort, strtok(pkt1, "\n"));
    ret = sendto(sockfd, pkt1, sizeof(pkt1), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt1!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("[<] %s:%d - Sending pkt2: %s", serverAddr, serverPort, pkt2);
    ret = sendto(sockfd, pkt2, sizeof(pkt2), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt2!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("[<] %s:%d - Sending pkt3: %s", serverAddr, serverPort, pkt3);
    ret = sendto(sockfd, pkt3, sizeof(pkt3), 0, (struct sockaddr *) &addr, sizeof(addr));

    if (ret < 0) {
        print_error("%s:%d - Error sending data pkt3!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }

    print_debug("[>] %s:%d - Receiving...", serverAddr, serverPort);
    ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (ret < 0) {
        print_error("%s:%d - Error receiving response!!", serverAddr, serverPort);
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    print_debug("[+] %s:%d - Received: %s", serverAddr, serverPort, buffer);

    if (strstr(buffer, search) != NULL) {
        printf("[+] %s:%d - %s\n", serverAddr, serverPort, banner);
    } else {
        printf("[!] %s:%d - POSSIBLE HONEYPOT!\n", serverAddr, serverPort);
    }

    close(sockfd);
    sockfd = 0;

    return 0;
}

int main(int argc, char **argv)
{
    int opt = 0;
    int ret = 0;

    char *hosts_filename = NULL;

    while ((opt = getopt(argc, argv, "l:p:j:t:vh")) != -1) {
        switch (opt) {
            case 'v':
                g_verbose = 1;
                break;
            case 'l':
                hosts_filename = optarg;
                break;
            case 'p':
                g_port = atoi(optarg);
                break;
            case 'j':
                MAX_FORKS = atoi(optarg);
                break;
            case 't':
                g_timeout = atoi(optarg);
                break;
            case 'h':
                printf("honeypot-detector v%s - (c) 2017 Jorge Matricali\n", HONEYPOT_DETECTOR_VERSION);
                printf("usage: %s [-l targets.lst] [-p port] [-j threads] [-t timeout] [-vh] [target]\n", argv[0]);
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "\tusage: %s [-l targets.lst] [-p port] [-j threads] [-t timeout] [-vh] [target]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (hosts_filename == NULL) {
        if (optind < argc) {
            ret = probe(argv[optind], g_port);
            return ret;
        } else {
            print_error("No target specified.");
            exit(EXIT_FAILURE);
        }
    }

    // Procesar lista de objetivos
    FILE *input = 0;

    input = fopen(hosts_filename, "r");
    if (input == NULL) {
        print_error("Error opening input file. (%s)", hosts_filename);
        exit(EXIT_FAILURE);
    }

    print_debug("Initializing %d threads...", MAX_FORKS);

    pid_t pid;
    int p = 0;

    ssize_t read;
    char *temp = 0;
    size_t len;

    while ((read = getline(&temp, &len, input)) != -1) {
        strtok(temp, "\n");

        if (p >= MAX_FORKS){
            waitpid(-1, NULL, 0);
            p--;
        }

        pid = fork();

        if (pid) {
            // Parent process
            p++;
        } else if(pid == 0) {
            // Child process
            probe(temp, g_port);
            exit(EXIT_SUCCESS);
        } else {
            print_error("Fork failed!\n");
        }
    }

    pid = 0;
    fclose(input);

    return EXIT_SUCCESS;
}
