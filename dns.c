#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h> 

#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <bits/sigaction.h> 
#include <aio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#define PORT 53
#define MAXLINE 4096
#define HEADER_LEN 12

struct Packet 
{
    char* request;
    ssize_t recv_len;

    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    char* full_domain;
    char* authoritative_domain;
    char* domain;
    char* top_level_domain;

    uint16_t q_type;   //1 - A, 28 - AAAA, 5 - CNAME, 2 - NS
    uint16_t q_class;  //1 - IN
};

struct Packet* parse_request_headers(char*, ssize_t);
char* parse_domain(char[], int, int);
struct Packet* get_address_info(struct Packet*);
int free_packet(struct Packet*);
int print_response_headers(struct Packet*);
int log_entry(char*, ssize_t, char*, int);
struct Packet* check_internal(struct Packet*);

int main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    int dns_sock;
    struct sockaddr_in dns_addr;
    socklen_t dns_len = sizeof(dns_addr);

    //dns socket
    if((dns_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("Unable to create socket 80.\n");
        exit(1);
    }

    bzero(&dns_addr, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_addr.s_addr = INADDR_ANY;
    dns_addr.sin_port = htons(PORT);

    int opt = 1;
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) 
    {
        printf("SO_REUSEADDR failed");
        close(dns_sock);
        exit(1);
    }

    if(bind(dns_sock, (struct sockaddr*)&dns_addr, dns_len) < 0)
    {
        printf("Bind failed to port %d\n", PORT);
        
        close(dns_sock);
        exit(1);
    }
    
    printf("Opened on port %d\n", PORT);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    char buffer[MAXLINE];
    while(1)
    {
        bzero(&client_addr, sizeof(client_addr));
        memset(buffer, 0, sizeof(buffer));

        ssize_t recv_len = recvfrom(dns_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
        if(recv_len < 0)
        {
            printf("recvfrom failed\n");
            continue;
        }
        //buffer[recv_len] = '\0';

        struct Packet* pkt = parse_request_headers(buffer, recv_len);
        if(!pkt)
        {
            printf("Incorrect packet header\n");
            continue;
        }

        log_entry(inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), NULL, 0);

        for (ssize_t i = 0; i < pkt->recv_len; i++) 
            printf("%02X ", (unsigned char)pkt->request[i]);
        printf("\n\n");

        struct Packet* answer = check_internal(pkt);
        if(answer)
        {
            printf("internal\n");

            for (ssize_t i = 0; i < answer->recv_len; i++) 
                printf("%02X ", (unsigned char)answer->request[i]);
            printf("\n");

            if(sendto(dns_sock, answer->request, answer->recv_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0)
            {
                printf("failed to send\n");
                continue;
            }

            free_packet(answer);
            free_packet(pkt);
            continue;
        }

        /*
        printf("Transaction ID: 0x%04x\n", pkt->id);
        printf("Flags: 0x%04x\n", pkt->flags);
        printf("Questions: %u\n", pkt->qdcount);
        printf("Answers: %u\n", pkt->ancount);
        printf("Authority RRs: %u\n", pkt->nscount);
        printf("Additional RRs: %u\n", pkt->arcount);
        printf("Auth Domain: %s\n", pkt->authoritative_domain);
        printf("Domain: %s\n", pkt->domain);
        printf("TLD Domain: %s\n", pkt->top_level_domain);
        printf("Full Domain: %s\n", pkt->full_domain);
        printf("qtype: %u\n", pkt->q_type);
        printf("qclass: %u\n", pkt->q_class);
        printf("\n\n");
        */

        //printf("%s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        struct Packet* response = get_address_info(pkt);
        if(!response)
        {
            printf("Response issue\n");
            continue;
        }


        if(sendto(dns_sock, response->request, response->recv_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0)
        {
            printf("failed to send\n");
            continue;
        }

        for (ssize_t i = 0; i < response->recv_len; i++) 
            printf("%02X ", (unsigned char)response->request[i]);
        printf("\n\n");

        if(print_response_headers(response) < 0)
        {
            printf("Issue with response\n");
            free_packet(pkt);
            continue;
        }

        free_packet(pkt);
        free_packet(response);
    }
    close(dns_sock);
    return 0;
}

struct Packet* parse_request_headers(char* buffer, ssize_t recv_len)
{

    struct Packet* pkt = malloc(sizeof(struct Packet));
    if(!pkt)
    {
        printf("Could not initialize memory\n");
        return NULL;
    }

    //printf("%d\n", recv_len);
    pkt->request = malloc(recv_len + 1);
    memcpy(pkt->request, buffer, recv_len);
    pkt->request[recv_len] = '\0';
    pkt->recv_len = recv_len;

    pkt->id = ntohs(*(uint16_t*)(buffer + 0));
    pkt->flags = ntohs(*(uint16_t*)(buffer + 2));
    pkt->qdcount = ntohs(*(uint16_t*)(buffer + 4));
    pkt->ancount = ntohs(*(uint16_t*)(buffer + 6));
    pkt->nscount = ntohs(*(uint16_t*)(buffer + 8));
    pkt->arcount = ntohs(*(uint16_t*)(buffer + 10));

    /*
    for (ssize_t i = 0; i < recv_len; i++) 
    {
        if(buffer[i] == '\n')
            break;
        printf("%02X ", buffer[i]);
    }
    printf("\n");
    */

    char* domain = malloc(MAXLINE);
    memset(domain, 0, MAXLINE);

    int count = HEADER_LEN;
    char size = buffer[count];
    int total = HEADER_LEN + 1;
    while(size != '\0')
    {
        char* ret = parse_domain(buffer, count + 1, size);
        strncat(domain, ret, size);
        
        strcat(domain, ".");

        count += (size + 1);
        total += size + 1;
        size = buffer[count];
        free(ret);
    }
    domain[strlen(domain) - 1] = '\0';
    pkt->full_domain = domain;

    pkt->authoritative_domain = NULL;
    pkt->domain = NULL;
    pkt->top_level_domain = NULL;

    count = 0;
    for(int i = (strlen(domain) - 1); i >= 0; i--)
    {
        if(domain[i] == '.')
        {
            if(!pkt->top_level_domain)
            {
                pkt->top_level_domain = strndup(domain + i + 1, count);
                count = -1;
            }
            else if(!pkt->domain && !pkt->domain)
            {
                pkt->domain = strndup(domain + i + 1, count);
                count = -1;
            }
        }
        count++;
    }

    if(!pkt->domain)
        pkt->domain = strndup(domain, count);
    else
        pkt->authoritative_domain = strndup(domain, count);

    if(!pkt->top_level_domain || !pkt->domain)
    {
        free(domain);
        return NULL;
    }

    pkt->q_type = ntohs(*(uint16_t*)(buffer + total));
    pkt->q_class = ntohs(*(uint16_t*)(buffer + total + 2));

    return pkt;
}

char* parse_domain(char buffer[], int index, int size)
{
    char* domain = malloc(size + 1);
    memset(domain, 0, strlen(domain));

    for(uint8_t i = 0; i < size; i++)
    {
        char c = buffer[index + i];
        memset(domain+i, c, 1);
    }

    memset(domain + size, '\0', 1);
    return domain;
}

struct Packet* get_address_info(struct Packet* pkt)
{
    struct Packet* response = malloc(sizeof(struct Packet));

    response->domain = strdup(pkt->domain);
    response->top_level_domain = strdup(pkt->top_level_domain);

    int question_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (question_sock < 0)
        return NULL;

    struct sockaddr_in question_server;
    question_server.sin_family = AF_INET;
    question_server.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &question_server.sin_addr);

    /*
    // Print the request
    for (ssize_t i = 0; i < pkt->recv_len; i++) 
        printf("%02X ", (unsigned char)pkt->request[i]);
    printf("\n");
    */

    if (sendto(question_sock, pkt->request, pkt->recv_len, 0, (struct sockaddr*)&question_server, sizeof(question_server)) < 0) 
    {
        perror("Send failed");
        close(question_sock);
        return NULL;
    }

    //printf("DNS query sent successfully at %d bytes\n", pkt->recv_len);

    socklen_t server_len = sizeof(question_server);
    response->request = malloc(MAXLINE);
    response->recv_len = recvfrom(question_sock, response->request, MAXLINE, 0, (struct sockaddr*)&question_server, &server_len);

    if (response->recv_len < HEADER_LEN) {
        fprintf(stderr, "Error: DNS response too short (%d bytes)\n", response->recv_len);
        close(question_sock);
        return NULL;
    }
    close(question_sock);
    return response;
}

int free_packet(struct Packet* pkt)
{
    //printf("start:\n");
    if(!pkt)
        return -1;
    
    //printf("freeing request\n");
    if(pkt->request)
    {
        free(pkt->request);
        pkt->request = NULL;    
    }

    //printf("freeing full domain\n");
    if(pkt->full_domain)
    {
        free(pkt->full_domain);
        pkt->full_domain = NULL;
    }

    //printf("freeing auth domain\n");
    if(pkt->authoritative_domain)
    {
        free(pkt->authoritative_domain);
        pkt->authoritative_domain = NULL;
    }

    //printf("freeing domain packet\n");
    if(pkt->domain)
    {
        free(pkt->domain);
        pkt->domain = NULL;
    }

    //printf("freeing tld\n");
    if(pkt->top_level_domain)
    {
        free(pkt->top_level_domain);
        pkt->top_level_domain = NULL;
    }

    //printf("freeing packet\n");
    free(pkt);
    pkt = NULL;

    return 1;
}

int print_response_headers(struct Packet* pkt)
{
    if(!pkt)
        return -1;

    struct Packet* sanitized_input = parse_request_headers(pkt->request, pkt->recv_len);

    //Header + domain + size + . + auth domain + null + 4
    int offset;
    offset = HEADER_LEN + strlen(sanitized_input->domain) + 1 + 1 + strlen(sanitized_input->top_level_domain) + 4 + 1;

    /*
    printf("offset: %d\n", offset); 

    printf("Transaction ID: 0x%04x\n", sanitized_input->id);
    printf("Flags: 0x%04x\n", sanitized_input->flags);
    printf("Questions: %u\n", sanitized_input->qdcount); 
    printf("Answers: %u\n", sanitized_input->ancount);
    printf("Authority RRs: %u\n", sanitized_input->nscount);
    printf("Additional RRs: %u\n", sanitized_input->arcount);
    printf("Auth Domain: %s\n", sanitized_input->authoritative_domain);
    printf("Domain: %s\n", sanitized_input->domain);
    printf("TLD Domain: %s\n", sanitized_input->top_level_domain);
    printf("Full Domain: %s\n", sanitized_input->full_domain);
    printf("qtype: %u\n", sanitized_input->q_type);
    printf("qclass: %u\n", sanitized_input->q_class);
    printf("Answers:\n");
    */

    char* str = malloc(MAXLINE);
    memset(str, 0, MAXLINE);


    int header_len = 0;

    int count = 0;
    while(count < sanitized_input->ancount)
    {
        //uint16_t name = ntohs(*(uint16_t*)(pkt->request + offset));
        uint16_t type = ntohs(*(uint16_t*)(pkt->request + offset + 2));
        //uint16_t class = ntohs(*(uint16_t*)(pkt->request + offset + 4));
        uint32_t ttl = ntohl(*(uint32_t*)(pkt->request + offset + 6));
        //uint16_t len = ntohs(*(uint16_t*)(pkt->request + offset + 10));

        //printf("    Name: ox%04x\n", name);
        //printf("    Type: %u\n", type);
        //printf("    Class: %u\n", class);
        //printf("    TTL: %u\n", ttl);
        //printf("    Data Length: %u\n", len);

        //printf("    ");
        header_len += sprintf(str + header_len, "%s", "    ");

        if(type == 1)
        {
            //printf("%s.%s    %u    IN    A       ", pkt->domain, pkt->top_level_domain, ttl);
            header_len += sprintf(str + header_len, "%s.%s    %u    IN    A       ", sanitized_input->domain, sanitized_input->top_level_domain, ttl);

            for(int i = 0; i < 4; i++)
            {
                uint8_t octet = *(uint8_t*)(pkt->request + offset + 12 + i);
                //printf("%u", octet);
                header_len += sprintf(str + header_len, "%u", octet);

                if(i != 3)
                {
                    //printf(".");
                    header_len += sprintf(str + header_len, ".");
                }
            }
            offset += 16;
            //printf("\n");
            header_len += sprintf(str + header_len, "\n");
        }
        else if(type == 28)
        {
            //printf("%s.%s    %u    IN    AAAA    ", pkt->domain, pkt->top_level_domain, ttl);
            header_len += sprintf(str + header_len, "%s.%s    %u    IN    AAAA    ", sanitized_input->domain, sanitized_input->top_level_domain, ttl);

            for(int i = 0; i < 8; i++)
            {
                uint16_t octet = ntohs(*(uint16_t*)(pkt->request + offset + 12 + (i * 2)));
                //printf("%04x", octet);
                header_len += sprintf(str + header_len, "%04x", octet);

                if(i != 7)
                {
                    //printf(":");
                    header_len += sprintf(str + header_len, ":");
                }
            }
            offset += 28;
            //printf("\n");
            header_len += sprintf(str + header_len, "\n");
        }
        else
        {
            printf("Not Supported\n");
        }

        count++;
    }

    log_entry(NULL, 0, str, header_len);
    free(str);

    /*
    uint8_t root = *(uint8_t*)(pkt->request + offset + 1);
    uint8_t opt = *(uint8_t*)(pkt->request + offset + 2);
    uint16_t udp_size = ntohs(*(uint16_t*)(pkt->request + offset + 3));

    
    printf("Root: 0x%02x\n", root);
    printf("OPT: 0x%02x\n", opt);
    printf("UDP Payload Size: %u\n", udp_size);

    printf("\n\n");
    */

    free_packet(sanitized_input);
    return 0;
}

int log_entry(char* client_ip, ssize_t port, char* resolved_ip, int size)
{
    int fd = open("output.txt", O_CREAT | O_WRONLY | O_APPEND, 0774);
    if(fd < 0)
    {
        printf("Failed to open debug file\n");
        return -1;
    }

    char* str = malloc(MAXLINE);
    if(client_ip)
    {
        sprintf(str, "%s:%d\n", client_ip, port);

        ssize_t len = write(fd, str, strlen(str));
        if(len < 0)
        {
            printf("write failed\n");
            free(str);
            return -1;
        }

        free(str);
    }
    else
    {
        sprintf(str, "    %s", resolved_ip);

        //printf("size of str: %d\n", strlen(str));
        //printf("%s\n", str);

        ssize_t len = write(fd, resolved_ip, size);
        if(len < 0)
        {
            printf("write failed\n");
            free(str);
            return -1;
        }
    }
    return 1;
}

struct Packet* check_internal(struct Packet* request)
{
    char* domain = malloc(MAXLINE);
    memset(domain, 0, MAXLINE);

    if(request->authoritative_domain != NULL)
        sprintf(domain, "%s.%s.%s", request->authoritative_domain, request->domain, request->top_level_domain);
    else
        sprintf(domain, "%s.%s", request->domain, request->top_level_domain);

    if(strcmp(domain, "adoliva.com") == 0)
    {
        struct Packet* pkt = malloc(sizeof(struct Packet));
        printf("Found unique ip\n");
        free(domain);

        char* response = malloc(MAXLINE);
        memset(response, 0, MAXLINE);

        memcpy(response, request->request, 2);

        uint16_t response_flags = 0;
        response_flags |= (1 << 15);  
        response_flags |= (1 << 8);  
        response_flags |= (1 << 7);  
        *(uint16_t*)(response + 2) = htons(response_flags);

        *(uint16_t*)(response + 4) = htons(1);
        *(uint16_t*)(response + 6) = htons(1);  
        *(uint16_t*)(response + 8) = htons(0);  
        *(uint16_t*)(response + 10) = htons(0);

        int pos = HEADER_LEN;
        
        uint8_t domain_length = strlen(request->domain);
        response[pos++] = domain_length;
        memcpy(response + pos, request->domain, domain_length);
        pos += domain_length;
        
        uint8_t tld_length = strlen(request->top_level_domain);
        response[pos++] = tld_length;
        memcpy(response + pos, request->top_level_domain, tld_length);
        pos += tld_length;
        
        response[pos++] = 0;
        
        *(uint16_t*)(response + pos) = htons(1);
        pos += 2;
        
        *(uint16_t*)(response + pos) = htons(1);
        pos += 2;

        int answer_offset = pos;
        
        *(uint16_t*)(response + answer_offset) = htons(0xC00C);
        
        *(uint16_t*)(response + answer_offset + 2) = htons(1);
        
        *(uint16_t*)(response + answer_offset + 4) = htons(1);
        
        *(uint32_t*)(response + answer_offset + 6) = htonl(3600);
        
        *(uint16_t*)(response + answer_offset + 10) = htons(4);
        
        response[answer_offset + 12] = 192;
        response[answer_offset + 13] = 168;
        response[answer_offset + 14] = 1;
        response[answer_offset + 15] = 14;

        pkt->request = response;
        pkt->recv_len = answer_offset + 16;

        return pkt;
    }

    free(domain);
    return NULL;
}