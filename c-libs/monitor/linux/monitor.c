#include <arpa/inet.h>
#include <errno.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "cJSON/cJSON.h"

/**
 * connect to netlink
 * @return netlink socket fd
 */
static int nl_connect() {
    int netlinkSock;
    struct sockaddr_nl netlinkSockAddr;

    netlinkSock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (netlinkSock == -1) {
        perror("socket");
        return -1;
    }

    netlinkSockAddr.nl_family = AF_NETLINK;
    netlinkSockAddr.nl_groups = CN_IDX_PROC;
    netlinkSockAddr.nl_pid = getpid();

    if (bind(netlinkSock, (struct sockaddr *)&netlinkSockAddr, sizeof(netlinkSockAddr)) == -1) {
        perror("bind");
        close(netlinkSock);
        return -1;
    }

    return netlinkSock;
}

/**
 * set netlink listen
 * @param netlinkSock netlink socket fd
 * @param enable enable or disable
 * @return 0 on success, -1 on error
 */
static int set_proc_ev_listen(int netlinkSock, bool enable) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    if (send(netlinkSock, &nlcn_msg, sizeof(nlcn_msg), 0) == -1) {
        perror("netlink send");
        return -1;
    }

    return 0;
}

/**
 * handle netlink message
 * @param netlinkSock netlink socket fd
 * @param rev_sock udp socket fd for send message to server
 * @param server server address
 * @return 0 on success, -1 on error
 */
static int handle_proc_ev(int netlinkSock, int rev_sock, struct sockaddr_in server) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    char buf[256];
    char sendbuffer[256];
    char *out;
    int recvLen;

    cJSON *root = cJSON_CreateObject();
    cJSON *data = cJSON_CreateObject();

    while (1) {
        recvLen = recv(netlinkSock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (recvLen == 0) {
            return 0;
        } else if (recvLen == -1) {
            if (errno == EINTR) continue;
            perror("netlink recv");
            return -1;
        }

        root = cJSON_CreateObject();
        data = cJSON_CreateObject();
        switch (nlcn_msg.proc_ev.what) {
            case PROC_EVENT_NONE:
                cJSON_AddStringToObject(root, "type", "none");

                out = cJSON_Print(root);
                sprintf(sendbuffer, "%s\n", out);
                sendto(rev_sock, sendbuffer, strlen(sendbuffer), 0, (struct sockaddr *)&server, sizeof(server));
                break;
            case PROC_EVENT_FORK:
                cJSON_AddStringToObject(root, "type", "fork");
                cJSON_AddNumberToObject(data, "pid", nlcn_msg.proc_ev.event_data.fork.child_pid);
                cJSON_AddNumberToObject(data, "tgid", nlcn_msg.proc_ev.event_data.fork.child_tgid);
                cJSON_AddNumberToObject(data, "ppid", nlcn_msg.proc_ev.event_data.fork.parent_pid);
                cJSON_AddNumberToObject(data, "ptgid", nlcn_msg.proc_ev.event_data.fork.parent_tgid);
                cJSON_AddItemToObject(root, "data", data);

                out = cJSON_Print(root);
                sprintf(sendbuffer, "%s\n", out);
                sendto(rev_sock, sendbuffer, strlen(sendbuffer), 0, (struct sockaddr *)&server, sizeof(server));
                break;
            case PROC_EVENT_EXEC:
                cJSON_AddStringToObject(root, "type", "exec");
                cJSON_AddNumberToObject(data, "pid", nlcn_msg.proc_ev.event_data.exec.process_pid);
                cJSON_AddNumberToObject(data, "tgid", nlcn_msg.proc_ev.event_data.exec.process_tgid);
                cJSON_AddItemToObject(root, "data", data);

                out = cJSON_Print(root);
                sprintf(sendbuffer, "%s\n", out);
                sendto(rev_sock, sendbuffer, strlen(sendbuffer), 0, (struct sockaddr *)&server, sizeof(server));
                break;
            case PROC_EVENT_UID:
                break;
            case PROC_EVENT_GID:
                break;
            case PROC_EVENT_EXIT:
                break;
            default:
                break;
        }
    }

    return 0;
}

/**
 * start monitor
 * @param ip server ip
 * @param port server port
 * @return 0 on success, -1 on error
 */
int startMonitor(char *ip, int port) {
    int netlinkSock, rev_sock, recvLen;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &server.sin_addr);
    server.sin_port = htons(port);

    netlinkSock = nl_connect();
    if (netlinkSock == -1)
        return -1;

    if (set_proc_ev_listen(netlinkSock, true) == -1) {
        close(netlinkSock);
        return -1;
    }

    rev_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rev_sock == -1) {
        perror("socket");
        return -1;
    }

    if (handle_proc_ev(netlinkSock, rev_sock, server) == -1) {
        close(netlinkSock);
        return -1;
    }

    set_proc_ev_listen(netlinkSock, false);

    return 1;
}

#ifndef GO_ENV
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        return -1;
    }
    startMonitor(argv[1], atoi(argv[2]));
    return 0;
}
#endif