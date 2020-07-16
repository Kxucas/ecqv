#include "ecqv_client.h"
#include "cert.h"
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <winsock2.h> 
#include<fstream>
using namespace std;
#pragma comment(lib,"ws2_32.lib")  

#define ECQV_KG_VERSION "0.2 alpha"

#define ECQV_KG_CMD_INFO \
	"ECQV Public/Private Key Pair Generator %s\n" \
	"Create EC key pair with implicit certificate.\n" \
	"Usage: %s [OPTION...] FILE\n" \
	"  -i <arg>                       Identity file, default: STDIN\n" \
	"  -o <arg>                       Output file, default: STDOUT\n" \
	"  -l <arg>                       Log file, default: no logging\n" \
	"  -h <arg>                       Hash function, default: SHA-1\n" \
	"Reads the public key of CA from the certificate PEM file denoted by FILE.\n"

static struct ecqv_opt_t ecqv_opt; // 静态的opt

void print_usage_and_exit(int argc, char *argv[])
{
	if (argc > 0) {
		printf(ECQV_KG_CMD_INFO, ECQV_KG_VERSION, argv[0]);
	}

	exit(EXIT_FAILURE);
}

void parse_cmd_options(int argc, char *argv[])
{
	if (argc < 2) {
		print_usage_and_exit(argc, argv);
	}

	int flag = 1;
	bool end = false;
	do {
		while (flag < argc && argv[flag][0] != '-') flag++;
		if (flag < argc) switch (argv[flag][1])
		{
		case 'i':
			ecqv_opt.in = argv[flag + 1];
			break;
		case 'o':
			ecqv_opt.out = argv[flag + 1];
			break;
		case 'l':
			ecqv_opt.log = argv[flag + 1];
			break;
		case 'h':
			ecqv_opt.hash = argv[flag + 1];
			break;
		default:
			/* If unknown option print info */
			print_usage_and_exit(argc, argv);
			break;
		}
		if (flag >= argc) end = true;
		flag += 2;
	} while (!end);

	/* Get the CA private key file */
	ecqv_opt.certin = argv[argc - 1];
}

// 将EC_POINT编码成用于网络传输的字节流
int encodeECPoint(unsigned char **c, size_t *len, EC_POINT *p, const EC_GROUP *g, BN_CTX *ctx, int type, point_conversion_form_t f = POINT_CONVERSION_UNCOMPRESSED)
{
	unsigned char *buf;
	size_t buf_len;
	EC_POINT *ectest = NULL;

	buf_len = EC_POINT_point2oct(g, p, f, NULL, 0, ctx); //z || x || y
	if (buf_len == 0)
	{
		goto ERR;
	}
	buf = (unsigned char *)OPENSSL_malloc(buf_len + 2);
	//buf = new unsigned char[buf_len + 2];
	buf[0] = (unsigned char) type; //类型标记
	buf[1] = buf_len; //长度标记

	buf_len = EC_POINT_point2oct(g, p, f, buf + 2, buf_len, ctx);
	if (buf_len == 0)
	{
		goto ERR;
	}
	*c = buf;
	*len = buf_len + 2;
	return 0;
ERR:
	return -1;
}

int decodeX509(X509 **x, unsigned char *c, size_t len, int type)
{
	X509 *cert = NULL;
	const unsigned char *uc = c + 3;
	if (c[0] != (unsigned char)type) // 判断type是否正确
	{
		printf("Type ERROR ");
		goto ERR;
	}
	if (*((unsigned short *)(c + 1)) > len)
	{
		printf("Size ERROR ");
		goto ERR;
	}
	cert = X509_new();
	if (d2i_X509(&cert, &uc, *((unsigned short *)(c + 1))) == NULL)
	{
		printf("d2i ERROR ");
		goto ERR;
	}
	*x = cert;
	return 0;
ERR:
	printf("[Client] Decode BYTES to X509 error!\n");
	return -1;
}

int decodeBN(BIGNUM **b, unsigned char *c, size_t len, int type)
{
	BIGNUM *bn = NULL;

	//printf("R: %d\n", c[1]);
	//for (int i = 2; i < c[1]; i++)
	//{
	//	printf("%02x ", c[i]);
	//}
	printf("\n");

	if (c[0] != (unsigned char)type) // 判断type是否正确
	{
		printf("Type ERROR ");
		goto ERR;
	}
	if (c[1] > len)
	{
		printf("Size ERROR ");
		goto ERR;
	}
	bn = BN_new();
	if (BN_bin2bn(c + 2, c[1], bn) == NULL)
	{
		printf("bin2bn ERROR ");
		goto ERR;
	}
	*b = bn;
	return 0;
ERR:
	printf("[Client] Decode BYTES to BIGNUM error!\n");
	return -1;
}

int solve(ecqv_client_t *ecqv_client)
{
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	if (WSAStartup(socketVersion, &wsaData) != 0)
	{
		return -1;
	}
	SOCKET sclient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(6666);
	sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	int len = sizeof(sin);


	ecqv_log_println(ecqv_client->u, "[Client]");
	if (ecqv_client_public_seed(&ecqv_client->Ru, &ecqv_client->a, ecqv_client->u) == -1)
	{
		printf("[Client] Creating public seed (Alpha) failed!\n");
		closesocket(sclient);
		return -1;
	}
	printf("[Client] Step 1 - \"Creating public seed (Alpha)\" finished.\n");


	//1.发送Ru到Server
	size_t buf_len;
	unsigned char* buf = NULL;
	if (encodeECPoint(&buf, &buf_len, ecqv_client->Ru, ecqv_client->u->group, ecqv_client->u->ctx, 1) != 0)
	{
		return -1;
	}
	//printf("Data: %d\n", buf_len);
	//for (int i = 0; i < buf_len; i++)
	//{
	//	printf("%02x ", buf[i]);
	//}
	//printf("\n");
	OPENSSL_free(buf);
	if (sendto(sclient, (char *)buf, buf_len, 0, (sockaddr*)&sin, len) <= 0)
	{
		printf("[Client] Send data to SERVER failed! \n");
		closesocket(sclient);
		return -1;
	}
	printf("[Client] Send data to SERVER success! \n");


	//2.从Server端收到CertU
	size_t recvbuf_len = 1500;
	int recv_len;
	unsigned char *recvbuf = (unsigned char *)OPENSSL_malloc(recvbuf_len);
	if ((recv_len = recvfrom(sclient, (char *)recvbuf, recvbuf_len, 0, (sockaddr*)&sin, &len)) <= 0)
	{
		printf("[Client] Receive data from SERVER failed!\n");
		closesocket(sclient);
		return -1;
	}
	printf("[Client] Receive data from SERVER success\n");
	decodeX509(&ecqv_client->usercert, recvbuf, recv_len, 2);
	decodeBN(&ecqv_client->r, recvbuf + 3 + *(unsigned short *)(recvbuf + 1), recv_len - 3 - *(unsigned short *)(recvbuf + 1), 3);
	


	//3.计算最终公私钥
	ecqv_log_println(ecqv_client->u, "[Client]");
	if (ecqv_create_cert_hash_from_byte(&ecqv_client->e, recvbuf + 3, *(unsigned short *)(recvbuf + 1), ecqv_client->u) == -1)
	{
		printf("[Client] Creating Hash(Cert) failed!\n");
		closesocket(sclient);
		return -1;
	}
	printf("[Client] Step 2 ... finished.\n");
	if (ecqv_client_create_keypair(&ecqv_client->cl_key, ecqv_client->e, ecqv_client->a, ecqv_client->r, ecqv_client->usercert, ecqv_client->u) == -1)
	{
		printf("[Client] Creating public/private key pair failed!\n");
		closesocket(sclient);
		return -1;
	}
	printf("[Client] Step 3 ... finished.\n");

	//4.验证生成的最终公私钥
	if (ecqv_verify_keypair(ecqv_client->cl_key) == -1)
	{
		closesocket(sclient);
		goto ERR;
	}
	printf("Key check... sucesss...\n");
	if (ecqv_export_keypair(ecqv_client->cl_key, ecqv_client->u) == -1)
	{
		closesocket(sclient);
		goto ERR;
	}
	printf("Write keypair... sucesss...\n");
	closesocket(sclient);
	WSACleanup();
	getchar();
	return 0;
ERR:
	return -1;
}

int main(int argc, char *argv[])
{
	ecqv_client_t *ecqv_client = NULL;
	parse_cmd_options(argc, argv);

	
	atexit(ecqv_cleanup); // Clean ECQV resources ata exit
	ecqv_initialize();


	if (ecqv_create_client(&ecqv_client, &ecqv_opt) == -1)
		goto ERR;


	solve(ecqv_client);

	

	
	return EXIT_SUCCESS;

ERR:
	return EXIT_FAILURE;
}


/*
TCP
     User        CA
	  Ru  -----> 
	             xxx();
		  <----- Cert, r
Ru

*/
