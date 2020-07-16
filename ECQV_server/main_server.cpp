#include "ecqv_server.h"
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
	/*"  -i <arg>                       Identity file, default: STDIN\n"*/ \
	/*"  -o <arg>                       Output file, default: STDOUT\n"*/ \
	"  -l <arg>                       Log file, default: no logging\n" \
	"  -h <arg>                       Hash function, default: SHA-1\n" \
	"  -c <arg>                       CA pem file, default: ca_cert.crt\n" \
	"Reads the private key of CA from the PEM file denoted by FILE.\n"

static struct ecqv_opt_t ecqv_opt; // 静态的opt

static void print_usage_and_exit(int argc, char *argv[])
{
	if (argc > 0) {
		printf(ECQV_KG_CMD_INFO, ECQV_KG_VERSION, argv[0]);
	}

	exit(EXIT_FAILURE);
}

static void parse_cmd_options(int argc, char *argv[])
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
		case 'l':
			ecqv_opt.log = argv[flag + 1];
			break;
		case 'h':
			ecqv_opt.hash = argv[flag + 1];
			break;
		case 'c':
			ecqv_opt.certin = argv[flag + 1];
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
	ecqv_opt.key = argv[argc - 1];
}

// 将EC_POINT编码成用于网络传输的字节流
int decodeECPoint(EC_POINT **p, unsigned char *c, size_t len, const EC_GROUP *g, BN_CTX *ctx, int type, point_conversion_form_t f = POINT_CONVERSION_UNCOMPRESSED)
{
	EC_POINT *ep = NULL;
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
	if ((ep = EC_POINT_new(g)) == NULL)
	{
		printf("ec_point_new ERROR ");
		goto ERR;
	}
	if (EC_POINT_oct2point(g, ep, c + 2, len - 2, ctx) == 0)
	{
		printf("oct2point ERROR ");
		goto ERR;
	}

	*p = ep;
	return 0;
ERR:
	return -1;
}

int encodeX509(unsigned char **c, size_t *len, X509 *x, int type)
{
	unsigned char *buf = NULL;
	int buf_len;
	if ((buf_len = i2d_X509(x, &buf)) < 0)
	{
		printf("get length ERROR ");
		goto ERR;
	}
	*c = (unsigned char *)OPENSSL_malloc(buf_len + 3);
	(*c)[0] = type;
	*(unsigned short *)(*c + 1) = (unsigned short)buf_len; // c[1] and c[2] is buf_len
	//printf("%02x c[1]=%02x, c[2]=%02x, c[3] = %02x\n", (*c)[0], (*c)[1], (*c)[2], (*c)[3]);
	memcpy(*c + 3, buf, buf_len);
	//printf("%02x c[1]=%02x, c[2]=%02x, c[3] = %02x\n", (*c)[0], (*c)[1], (*c)[2], (*c)[3]);
	*len = buf_len + 3;
	OPENSSL_free(buf);
	return 0;
ERR:
	if (buf) OPENSSL_free(buf);
	printf("[Client] Decode BYTES to X509 error!\n");
	return -1;
}

int encodeBN(unsigned char **c, size_t *len, BIGNUM *b, int type)
{
	unsigned char *buf = NULL;
	size_t buf_len;
	buf_len = BN_num_bytes(b);
	if (buf_len == 0)
	{
		printf("get length ERROR ");
		goto ERR;
	}
	buf = (unsigned char *)OPENSSL_malloc(buf_len + 2);
	buf[0] = (unsigned char)type; //类型标记
	buf[1] = buf_len; //长度标记

	if (BN_bn2bin(b, buf + 2) <= 0)
	{
		printf("bin2bn ERROR ");
		goto ERR;
	}

	//printf("R: %d\n", buf_len);
	//for (int i = 2; i < 2 + buf_len; i++)
	//{
	//	printf("%02x ", buf[i]);
	//}
	//printf("\n");

	*c = buf;
	*len = buf_len + 2;
	return 0;
ERR:
	if (buf) OPENSSL_free(buf);
	printf("[Client] Decode BYTES to BIGNUM error!\n");
	return -1;
}

int combine2bytearrays(unsigned char **c, size_t *l, unsigned char *c1, size_t l1, unsigned char *c2, size_t l2)
{
	if (l1 < 0 || l2 < 0) return -1;
	int len = l1 + l2;
	unsigned char *ch = NULL;
	ch = (unsigned char *)OPENSSL_malloc(len);
	memcpy(ch, c1, l1);
	memcpy(ch + l1, c2, l2);
	
	*l = len;
	*c = ch;
	OPENSSL_free(c1);
	OPENSSL_free(c2);
	return 0;
}

int solve(ecqv_server_t *ecqv_server)
{
	WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    if (WSAStartup(sockVersion, &wsaData) != 0)
    {
        return -1;
    }
	SOCKET serSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (serSocket == INVALID_SOCKET)
	{
		printf("socket error !");
		return -1;
	}
	sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(6666);
	serAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	if (bind(serSocket, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
	{
		printf("bind error !");
		closesocket(serSocket);
		return -1;
	}

	ecqv_log_println(ecqv_server->u, "[Server]");
	sockaddr_in remoteAddr;
	int nAddrLen = sizeof(remoteAddr);

	int sz = 0;
	while (true)
	{
		//1.收到Ru
		unsigned char recv_buf[255];
		printf("\nReady to receive ... \n");
		int ret = recvfrom(serSocket, (char *)recv_buf, 255, 0, (sockaddr*)&remoteAddr, &nAddrLen);
		sz++;
		if (ret <= 0)
		{
			printf("[%d] Recieve ERROR \n", sz);
			continue;
		}
		if (decodeECPoint(&ecqv_server->Ru, recv_buf, ret, ecqv_server->u->group, ecqv_server->u->ctx, 1) != 0)
		{
			printf("[%d] Decode ECPoint ERROR \n", sz);
			continue;
		}
		
		//2.计算--得到CertU&R
		if (ecqv_server_public_reconstr(&ecqv_server->Pu, &ecqv_server->k, ecqv_server->Ru, ecqv_server->u) == -1)
		{
			printf("[Server %d] Creating public reconstruction data (Pu) failed!\n", sz);
			continue;
		}
		printf("[Server %d] Step 1 ... finished.\n", sz);
		if (createUser(&ecqv_server->usercert, ecqv_server->u->out, ecqv_server->Pu, ecqv_server->u->group, ecqv_server->cacert, ecqv_server->u->ca_key) == -1)
		{
			printf("[Server] Creating certificate failed!\n");
			continue;
		}
		if (ecqv_create_cert_hash(&ecqv_server->e, ecqv_server->usercert, ecqv_server->u) == -1)
		{
			printf("[Server] Creating Hash(Cert || Pu) failed!\n");
			continue;
		}
		printf("[Server] Step 2 ... finished.\n");
		if (ecqv_server_priv_reconstr(&ecqv_server->r, ecqv_server->e, ecqv_server->k, ecqv_server->u->ca_key, ecqv_server->u))
		{
			printf("[Server] Creating private reconstruction data (r) failed!\n");
			continue;
		}
		printf("[Server] Step 3 ... finished.\n");
		

		//3.传递CertU 和 r
		size_t buf1_len, buf2_len, buf_len;
		unsigned char *buf1 = NULL, *buf2 = NULL, *buf = NULL;
		if (encodeX509(&buf1, &buf1_len, ecqv_server->usercert, 2) != 0)
		{
			printf("[Server %d] EncodeX509 failed!\n", sz);
			continue;
		}
		if (encodeBN(&buf2, &buf2_len, ecqv_server->r, 3) != 0)
		{
			printf("[Server %d] EncodeBN failed!\n", sz);
			continue;
		}
		combine2bytearrays(&buf, &buf_len, buf1, buf1_len, buf2, buf2_len);
		//printf("SendMsg: (%d=%d+%d) %02x %02x %02x %02x ...\n", buf_len, buf1_len, buf2_len, buf[0], buf[1], buf[2], buf[3]);
		sendto(serSocket, (char *)buf, buf_len, 0, (sockaddr*)&remoteAddr, nAddrLen);
		printf("[Server %d] Success ! \n\n\n", sz);
	}
	closesocket(serSocket);
	WSACleanup();
	return 0;
ERR:
	return -1;
}

int main(int argc, char *argv[])
{
	ecqv_server_t *ecqv_server = NULL;
	parse_cmd_options(argc, argv);

	atexit(ecqv_cleanup); // Clean ECQV resources ata exit
	ecqv_initialize();

	if (ecqv_create_server(&ecqv_server, &ecqv_opt) == -1)
		goto ERR;
	
	solve(ecqv_server);

	return EXIT_SUCCESS;

ERR:
	return EXIT_FAILURE;
}

