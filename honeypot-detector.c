#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    int sockfd, ret;
    char buffer[BUF_SIZE];
    char * serverAddr;

    if (argc < 2) {
        printf("usage: honeypot <ip address>\n");
        exit(1);
    }

    serverAddr = argv[1];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket!\n");
        exit(1);
    }
    // printf("Socket created...\n");

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
    addr.sin_port = htons(22);

    ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        printf("\t[!] %s - Error connecting to the server!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    }
    // printf("Connected to the server...\n");

    memset(buffer, 0, BUF_SIZE);

    // RECIBIR BANNER
    ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (ret < 0) {
        printf("\t[!] %s - Error receiving banner!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    } //else {
        // printf("BANNER:\n%s\n", buffer);
    // }

    char *pkt1 = "SSH-2.0-OpenSSH_7.5";
    char *pkt2 = "\n";
    char *pkt3 = "asd\n      ";
    char *search = "Protocol mismatch.";

    // printf("<< ENVIANDO pkt1\n");
    ret = sendto(sockfd, pkt1, sizeof(pkt1), 0, (struct sockaddr *) &addr, sizeof(addr));
    // printf("-- ENVIADO!\n");
    if (ret < 0) {
        printf("\t[!] %s - Error sending data pkt1!!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    } else {
        // printf(">>PKT1\n");
    }

    // printf("<< ENVIANDO pkt2\n");
    ret = sendto(sockfd, pkt2, sizeof(pkt2), 0, (struct sockaddr *) &addr, sizeof(addr));
    // printf("-- ENVIADO!\n");
    if (ret < 0) {
        printf("\t[!] %s - Error sending data pkt2!!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    } else {
        // printf(">>PKT2\n");
    }

    // printf("<< ENVIANDO pkt3\n");
    ret = sendto(sockfd, pkt3, sizeof(pkt3), 0, (struct sockaddr *) &addr, sizeof(addr));
    // printf("-- ENVIADO!\n");
    if (ret < 0) {
        printf("\t[!] %s - Error sending data pkt3!!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    } else {
        // printf(">>PKT3\n");
    }

    // printf(">> RECIBIENDO...\n");
    ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    // printf("|| RECIBIDO!\n");
    if (ret < 0) {
        printf("\t[!] %s - Error receiving response!!\n", serverAddr);
        close(sockfd);
        sockfd = 0;
        return -1;
    } else {
        // printf("RET:\n%s\n", buffer);
    }

    if (strstr(buffer, search) != NULL) {
        printf("\t[+] %s - OPEN SSH LEGITIMO\n", serverAddr);
    } else {
        printf("\t[!] %s - POSIBLE HONEYPOT!\n", serverAddr);
    }

    // s.send("\n)
    // s.send('asd\n      ')
    // buffer = strdup("SSH-2.0-OpenSSH_7.5")
    // while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    //     ret = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &addr, sizeof(addr));
    //     if (ret < 0) {
    //         printf("Error sending data!\n\t-%s", buffer);
    //     }
    // }

    close(sockfd);
    sockfd = 0;

    return 0;
}
