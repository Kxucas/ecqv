#pragma once
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
struct ecqv_opt_t
{
	char *out;
	char *in;
	char *key;
	char *log;
	char *hash;
	char *certin;
};

struct ecqv_gen_t
{
	BN_CTX *ctx;
	BIGNUM *order; // 模数n，随机数范围的右开区间
	EC_GROUP const *group; // 群结构，包括基点等

	EC_KEY *ca_key; // CA的公钥

	EVP_MD const *hash;
	FILE *certin;
	//FILE *in; //实体信息的位置 CTR? 
	FILE *out; // 隐式证书文件的位置
	FILE *key; // CA的公私钥的位置
	FILE *log; // 二进制文件日志的位置
};

struct ecqv_client_t
{
	struct ecqv_gen_t *u; // 通用信息

	EC_KEY *cl_key; // User的公私钥
	X509 *cacert;
	X509 *usercert;

	BIGNUM *a; // 初始私钥 alpha (α)
	EC_POINT *Ru; // 增加：公钥种子
	const EC_POINT *Pu; // 从证书中提取的公钥中间值
	BIGNUM *r; // 私钥重构值
	BIGNUM *e; // 客户端重新计算的Hash值
};

struct ecqv_server_t
{
	struct ecqv_gen_t *u; // 通用信息

	//EC_KEY *ca_key; // CA的公私钥
	EC_KEY *cl_key; // User的公私钥
	X509 *cacert;
	X509 *usercert;

	EC_POINT *Ru; // 从客户端传来的公钥种子
	EC_POINT *Pu; // 存放在证书里的公钥中间值（公钥重构值）
	BIGNUM *r; // 私钥重构值
	BIGNUM *k; // CA生成的随机数
	BIGNUM *e; // CA生成的 证书||Pu 的Hash值
};

void ecqv_cleanup(void);
void ecqv_initialize(void);
void ecqv_log_println(struct ecqv_gen_t *gen, const char *str);

int ecqv_create_client(struct ecqv_client_t **ecqv_server, const struct ecqv_opt_t *opt);
int ecqv_client_public_seed(EC_POINT **Ru, BIGNUM **a, ecqv_gen_t *ecqv_gen);
int ecqv_create_cert_hash_from_byte(BIGNUM **e, unsigned char *cert, int cert_len, ecqv_gen_t *ecqv_gen);
int ecqv_client_create_keypair(EC_KEY **user_key, BIGNUM *e, BIGNUM *a, BIGNUM *r, X509 *user_cert, ecqv_gen_t *ecqv_gen);
int ecqv_verify_keypair(EC_KEY *key);
int ecqv_export_keypair(EC_KEY *key, struct ecqv_gen_t *ecqv_gen);