#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DNS_IP "8.8.8.8"
#define DNS_PORT 53

typedef struct DnsPackageHeader
{
        uint16_t id;
        uint16_t flags;
        uint16_t num_questions;
        uint16_t num_answers;
        uint16_t num_authorityRRs;
        uint16_t num_additionalRRs;
} DnsPackageHeader;

void
encode_domain_name(char *dest, const char *domain)
{
        const char *start = domain;
        char *len_ptr = dest;
        dest++;

        while (*domain)
        {
                if (*domain == '.')
                {
                        *len_ptr = domain - start;
                        len_ptr = dest;
                        start = domain + 1;
                }
                else
                {
                        *dest = *domain;
                }
                dest++;
                domain++;
        }
        *len_ptr = domain - start;
        *dest++ = 0;
}

void
print_dns_flags(uint16_t flags)
{
        printf("Flags:\n");
        printf("  Query/Response: %s\n", (flags & 0x8000) ? "Response" : "Query");
        printf("  Opcode: %d\n", (flags >> 11) & 0xF);
        printf("  Authoritative Answer: %s\n", (flags & 0x0400) ? "Yes" : "No");
        printf("  Truncated: %s\n", (flags & 0x0200) ? "Yes" : "No");
        printf("  Recursion Desired: %s\n", (flags & 0x0100) ? "Yes" : "No");
        printf("  Recursion Available: %s\n", (flags & 0x0080) ? "Yes" : "No");
        printf("  Response Code: %d\n", flags & 0xF);
}

void
print_packet(const char *packet, size_t size, const char *direction)
{
        DnsPackageHeader *header = (DnsPackageHeader *) packet;
        printf("\n--- %s ---\n", direction);
        printf("ID: 0x%04X\n", ntohs(header->id));
        print_dns_flags(ntohs(header->flags));
        printf("Questions: %d\n", ntohs(header->num_questions));
        printf("Answers: %d\n", ntohs(header->num_answers));
        printf("Authority RRs: %d\n", ntohs(header->num_authorityRRs));
        printf("Additional RRs: %d\n", ntohs(header->num_additionalRRs));

        printf("Body:\n");
        for (size_t i = sizeof(DnsPackageHeader); i < size; i++)
        {
                printf("%02X ", (unsigned char) packet[i]);
                if ((i + 1) % 16 == 0)
                        printf("\n");
        }
        printf("\n");
}

void
parse_dns_response_short_https(const char *packet, size_t size)
{
        DnsPackageHeader *header = (DnsPackageHeader *) packet;
        const char *ptr = packet + sizeof(DnsPackageHeader);

        for (int i = 0; i < ntohs(header->num_questions); i++)
        {
                while (*ptr != 0)
                        ptr += *ptr + 1;
                ptr += 5;
        }

        for (int i = 0; i < ntohs(header->num_answers); i++)
        {
                if ((*ptr & 0xC0) == 0xC0)
                        ptr += 2;
                else
                {
                        while (*ptr != 0)
                                ptr += *ptr + 1;
                        ptr++;
                }

                uint16_t type = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Tipo
                uint16_t class = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Clase
                uint32_t ttl = ntohl(*(uint32_t *) ptr);
                ptr += 4; // TTL
                uint16_t data_len = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Longitud de datos

                if (type == 1 && class == 1 && data_len == 4)
                {
                        unsigned char ip[4];
                        memcpy(ip, ptr, 4);
                        printf("https://%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
                }

                ptr += data_len;
        }
}
void
parse_dns_response_short(const char *packet, size_t size)
{
        DnsPackageHeader *header = (DnsPackageHeader *) packet;
        const char *ptr = packet + sizeof(DnsPackageHeader);

        for (int i = 0; i < ntohs(header->num_questions); i++)
        {
                while (*ptr != 0)
                        ptr += *ptr + 1;
                ptr += 5;
        }

        for (int i = 0; i < ntohs(header->num_answers); i++)
        {
                if ((*ptr & 0xC0) == 0xC0)
                        ptr += 2;
                else
                {
                        while (*ptr != 0)
                                ptr += *ptr + 1;
                        ptr++;
                }

                uint16_t type = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Tipo
                uint16_t class = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Clase
                uint32_t ttl = ntohl(*(uint32_t *) ptr);
                ptr += 4; // TTL
                uint16_t data_len = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Longitud de datos

                if (type == 1 && class == 1 && data_len == 4)
                {
                        unsigned char ip[4];
                        memcpy(ip, ptr, 4);
                        printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
                }

                ptr += data_len;
        }
}
void
parse_dns_response(const char *packet, size_t size)
{
        DnsPackageHeader *header = (DnsPackageHeader *) packet;

        printf("\n--- DNS RESPONSE ---\n");
        printf("ID: 0x%04X\n", ntohs(header->id));
        printf("Flags: 0x%04X\n", ntohs(header->flags));
        printf("Questions: %d\n", ntohs(header->num_questions));
        printf("Answers: %d\n", ntohs(header->num_answers));

        const char *ptr = packet + sizeof(DnsPackageHeader);

        for (int i = 0; i < ntohs(header->num_questions); i++)
        {
                while (*ptr != 0)
                        ptr += *ptr + 1;
                ptr += 5;
        }

        for (int i = 0; i < ntohs(header->num_answers); i++)
        {
                if ((*ptr & 0xC0) == 0xC0)
                        ptr += 2;
                else
                {
                        while (*ptr != 0)
                                ptr += *ptr + 1;
                        ptr++;
                }

                uint16_t type = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Tipo
                uint16_t class = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Clase
                uint32_t ttl = ntohl(*(uint32_t *) ptr);
                ptr += 4; // TTL
                uint16_t data_len = ntohs(*(uint16_t *) ptr);
                ptr += 2; // Longitud de datos

                if (type == 1 && class == 1 && data_len == 4)
                {
                        unsigned char ip[4];
                        memcpy(ip, ptr, 4);
                        printf("IPv4 Address: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
                }

                ptr += data_len;
        }
}

int
main(int argc, char **argv)
{
        int sock;
        int opts = 0;
        struct sockaddr_in server;
        char buffer[512];

        if (argc < 2 || argc > 3 || argv[1][0] == '-')
        {
                printf("Usage: %s <domain name> -[h|v]\n", argv[0]);
                exit(1);
        }

        if (argc == 3 && argv[2][0] == '-')
                for (char *c = argv[2] + 1; *c; ++c)
                        switch (*c)
                        {
                        case 'h':
                                opts |= 0x1;
                                break;
                        case 'v':
                                opts |= 0x2;
                                break;
                        }


        // Crear el encabezado DNS
        DnsPackageHeader header = {
                .id = htons(0x1234), // ID de la consulta
                .flags = htons(0x0100), // Consulta estándar, recursiva
                .num_questions = htons(1), // Una pregunta
                .num_answers = htons(0), // Sin respuestas
                .num_authorityRRs = htons(0), // Sin registros de autoridad
                .num_additionalRRs = htons(0) // Sin registros adicionales
        };

        // Construir el paquete
        char domain_encoded[256];
        encode_domain_name(domain_encoded, argv[1]);

        uint16_t query_type = htons(1); // Tipo A (IPv4)
        uint16_t query_class = htons(1); // Clase IN (Internet)

        size_t header_size = sizeof(header);
        size_t domain_size = strlen(domain_encoded) + 1;
        size_t packet_size =
        header_size + domain_size + sizeof(query_type) + sizeof(query_class);

        memcpy(buffer, &header, header_size);
        memcpy(buffer + header_size, domain_encoded, domain_size);
        memcpy(buffer + header_size + domain_size, &query_type, sizeof(query_type));
        memcpy(buffer + header_size + domain_size + sizeof(query_type),
               &query_class, sizeof(query_class));

        // Configurar el socket
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
                perror("Error al crear el socket");
                return 1;
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(DNS_PORT);
        inet_pton(AF_INET, DNS_IP, &server.sin_addr);

        // Enviar el paquete
        ssize_t sent = sendto(sock, buffer, packet_size, 0,
                              (struct sockaddr *) &server, sizeof(server));
        if (sent < 0)
        {
                perror("Error al enviar");
                close(sock);
                return 1;
        }

        if (opts & 0x2)
                print_packet(buffer, packet_size, "SENT");

        // Recibir la respuesta
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (received < 0)
        {
                perror("Error al recibir");
                close(sock);
                return 1;
        }

        if (opts & 0x2)
                print_packet(buffer, received, "RECEIVED");

        if (opts & 0x1)
                parse_dns_response_short_https(buffer, received);
        else
                parse_dns_response_short(buffer, received);

        // Cerrar el socket
        close(sock);
        return 0;
}
