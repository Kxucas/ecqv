#include "cert.h"
#include <stdio.h>
#include <string.h>
#include "ecqv_server.h"
extern "C"
{
#include <openssl/applink.c>
};



#define ECQV_HASH EVP_sha256() //定义HASH函数为sha1  两边均为openssl的变量，里面定义了函数指针
// 修改成SM3版本则需改为:(openssl，3.0有[evp.h,L801]，需判断对应版本有没有)
// #define ECQV_HASH EVP_sm3()

static void ecqv_log_bn(struct ecqv_gen_t *gen, const char *label, const BIGNUM *bn)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = BN_bn2hex(bn);

	if (!str) {
		printf("Log: error converting bignum to hex.\n");
		return;
	}

	fprintf(gen->log, "BIGNUM (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_point(struct ecqv_gen_t *gen, const char *label, const EC_POINT *point)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = EC_POINT_point2hex(gen->group, point,
		POINT_CONVERSION_UNCOMPRESSED, gen->ctx);

	if (!str) {
		printf("Log: error converting point to hex.\n");
		return;
	}

	fprintf(gen->log, "EC_POINT (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_key(struct ecqv_gen_t *gen, const char *label, const EC_KEY *key)
{
	if (!gen->log) {
		return;
	}

	fprintf(gen->log, "EC_KEY (%s):\n", label);

	if (EC_KEY_print_fp(gen->log, key, 3) == 0) {
		printf("Log: error printing EC key.\n");
		return;
	}

	fflush(gen->log);
}

void ecqv_log_println(struct ecqv_gen_t *gen, const char *str)
{
	if (!str) return;
	fprintf(gen->log, str);
	fprintf(gen->log, "\n");
}

static FILE *ecqv_open_file(const char *name, const char *mode)
{
	FILE *file = fopen(name, mode);

	if (!file) {
		printf("Error opening file '%s'.\n", name);
		return NULL;
	}

	return file;
}

int ecqv_free(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_gen->ctx)	BN_CTX_free(ecqv_gen->ctx);
	if (ecqv_gen->order) BN_free(ecqv_gen->order);
	if (ecqv_gen->ca_key) EC_KEY_free(ecqv_gen->ca_key);
	//if (ecqv_gen->cl_key)  EC_KEY_free(ecqv_gen->cl_key);

	if (ecqv_gen->log) fclose(ecqv_gen->log);
	if (ecqv_gen->key) fclose(ecqv_gen->key);
	//if (ecqv_gen->in)  fclose(ecqv_gen->in);
	if (ecqv_gen->out)  fclose(ecqv_gen->out);

	OPENSSL_free(ecqv_gen);
	return 0;
}

static EC_KEY *ecqv_read_private_key(FILE *file)
{
	EVP_PKEY *pk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	EC_KEY *key;

	//printf("1.3\n");

	if (!pk) {
		printf("Error reading private key file.\n");
		return NULL;
	}

	key = EVP_PKEY_get1_EC_KEY(pk);

	if (!key) {
		printf("Error loading EC private key.\n");
	}

	EVP_PKEY_free(pk);
	return key;
}

static int ecqv_write_private_key(EC_KEY *key, struct ecqv_gen_t *ecqv_gen)
{
	EVP_PKEY *evp_pkey;
	EC_KEY *ec_key;
	evp_pkey = EVP_PKEY_new();

	if (!evp_pkey) {
		return -1;
	}

	ec_key = EC_KEY_dup(key);

	if (!ec_key) {
		return -1;
	}

	if (EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key) == 0) {
		return -1;
	}
	EVP_PKEY_set_alias_type(evp_pkey, EVP_PKEY_EC); // 新加
	if (PEM_write_PrivateKey(ecqv_gen->out, evp_pkey,
		NULL, NULL, 0, 0, NULL) == 0) {
		EVP_PKEY_free(evp_pkey);
		return -1;
	}

	EVP_PKEY_free(evp_pkey);
	return 0;
}

static int ecqv_write_impl_cert(struct ecqv_client_t *ecqv_client)
{
	BIO *b64 = NULL, *bio = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;
	buf_len = EC_POINT_point2oct(ecqv_client->u->group, ecqv_client->Pu,
		POINT_CONVERSION_UNCOMPRESSED,
		NULL, 0, ecqv_client->u->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	buf = (unsigned char *)OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERROR;
	}

	buf_len = EC_POINT_point2oct(ecqv_client->u->group, ecqv_client->Pu,
		POINT_CONVERSION_UNCOMPRESSED,
		buf, buf_len, ecqv_client->u->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, 0);
	bio = BIO_new_fp(ecqv_client->u->out, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	fprintf(ecqv_client->u->out, "-----BEGIN IMPLICIT CERTIFICATE-----\n");
	BIO_write(bio, buf, buf_len);
	(void)BIO_flush(bio);
	fprintf(ecqv_client->u->out, "-----END IMPLICIT CERTIFICATE-----\n");
	OPENSSL_free(buf);
	BIO_free_all(bio);
	return 0;
ERROR:

	if (buf) {
		OPENSSL_free(buf);
	}

	if (bio) {
		BIO_free_all(bio);
	}

	return -1;
}


// server 第一步 - 生成 Pu = Ru + k * G
// 输入：Ru, ecqv_gen, [k]
// 输出：Pu, k
int ecqv_server_public_reconstr(EC_POINT **Pu, BIGNUM **k, EC_POINT *Ru, ecqv_gen_t *ecqv_gen)
{
	EC_POINT *p_kG = NULL;

	ecqv_log_point(ecqv_gen, "alphaG", Ru);

	// 随机生成k
	if (!*k && !(*k = BN_new())) goto ERROR;
	if (BN_rand_range(*k, ecqv_gen->order) == 0) goto ERROR;
	//BN_one(*k); //xx
	ecqv_log_bn(ecqv_gen, "k", *k);

	// 计算kG
	if (!(p_kG = EC_POINT_new(ecqv_gen->group))) goto ERROR;
	if (EC_POINT_mul(ecqv_gen->group, p_kG, *k, NULL, NULL, NULL) == 0) goto ERROR;
	ecqv_log_point(ecqv_gen, "kG", p_kG);

	// 计算中间公钥  Pu = Ru + k * G
	if (!*Pu && !(*Pu = EC_POINT_new(ecqv_gen->group))) goto ERROR;
	if (EC_POINT_add(ecqv_gen->group, *Pu, Ru, p_kG, NULL) == 0)  goto ERROR;
	ecqv_log_point(ecqv_gen, "Pu", *Pu);

	EC_POINT_free(p_kG);
	return 0;
ERROR:
	if (p_kG) EC_POINT_free(p_kG);
	return -1;
}

// server/client 第二步
// 生成e = Hash(Cert）
// 修改时需要把Pu嵌入至Cert里并且只做一次Hash即可
int ecqv_create_cert_hash(BIGNUM **e, X509 *cert, ecqv_gen_t *ecqv_gen)
{
	EVP_MD_CTX *md_ctx = NULL; //上下文（存储中间变量的地方）

	unsigned char md_value[EVP_MAX_MD_SIZE]; //存放Hash的结果
	unsigned int md_len;

	unsigned char *cert_b = NULL; //存放生成的客户证书
	int cert_len;


	// 初始化
	if (!*e && !(*e = BN_new())) return -1;
	if (!(md_ctx = EVP_MD_CTX_new())) return -1;

	// 设置md_ctx以使用 之前设置的hash函数
	if (EVP_DigestInit_ex(md_ctx, ecqv_gen->hash, 0) == 0)  goto ERROR;

	if ((cert_len = i2d_X509(cert, &cert_b)) <= 0) goto ERROR; // 将X509 转换成 字节组
	//printf("cert_len: %d\n", cert_len);
	//for (int i = 0; i < cert_len; i++)
	//	printf("%02x ", cert_b[i]);
	//printf("\n");

	// 将整个证书结构放入Hash输入里
	if (EVP_DigestUpdate(md_ctx, cert_b, cert_len) == 0) goto ERROR;

	// 计算md_value(e) = Hash(cert) ，此时不能再做EVP_DigestUpdate步骤
	if (EVP_DigestFinal_ex(md_ctx, md_value, &md_len) == 0) goto ERROR;
	if (!BN_bin2bn(md_value, md_len, *e)) goto ERROR;
	ecqv_log_bn(ecqv_gen, "e", *e);

	EVP_MD_CTX_destroy(md_ctx);
	return 0;
ERROR:
	if (md_ctx)  EVP_MD_CTX_destroy(md_ctx);
	if (cert_b) OPENSSL_free(cert_b);
	return -1;
}


// server 第三步 - 生成私钥重构值 r = e * k + d_CA
// 输入：e, k, ca_key, ecqv_gen
// 输出：r
int ecqv_server_priv_reconstr(BIGNUM **r, BIGNUM *e, BIGNUM *k, EC_KEY *ca_key, ecqv_gen_t *ecqv_gen)
{
	const BIGNUM *c; //用于存储CA私钥
	BIGNUM *ek; //用于存储e * k中间值

	// 计算ek = e * k
	if (!(ek = BN_new())) return -1;
	if (BN_mul(ek, e, k, ecqv_gen->ctx) == 0) goto ERROR;
	ecqv_log_bn(ecqv_gen, "ek", ek);

	// 生成 r = ek + c
	if (!*r && !(*r = BN_new()))  goto ERROR;
	if (!(c = EC_KEY_get0_private_key(ecqv_gen->ca_key))) goto ERROR; // c为CA私钥
	if (BN_mod_add(*r, ek, c, ecqv_gen->order, ecqv_gen->ctx) == 0)  goto ERROR;
	ecqv_log_bn(ecqv_gen, "r", *r);

	BN_free(ek);
	return 0;
ERROR:
	if (ek)  BN_free(ek);
	return -1;
}

void ecqv_initialize(void)
{
	//CRYPTO_malloc_init(); //OpenSSL 1.1.0以上版本不支持
	OpenSSL_add_all_digests();
}

void ecqv_cleanup(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

// 初始化ECQV   注意拆分时要把CA公钥私钥分开
// 输入：ecqv_gen 指向ECQV结构体指针的地址
// 		ecqv_opt
// 返回：
int ecqv_create(struct ecqv_gen_t **ecqv_gen, const struct ecqv_opt_t *opt)
{
	struct ecqv_gen_t *ecqv;
	const EC_POINT *G;

	// 判断输入参数里是否有CA的公私钥
	if (!opt->key)
	{
		printf("No CA private key given.\n");
		return -1;
	}

	if (!(ecqv = (ecqv_gen_t *)OPENSSL_malloc(sizeof(*ecqv)))) return -1;
	memset(ecqv, 0, sizeof(*ecqv));

	// 如果指定Hash则从对应名字寻找，否则使用默认的 sha1()
	if (opt->hash)
		ecqv->hash = EVP_get_digestbyname(opt->hash);
	else
		ecqv->hash = ECQV_HASH;

	if (!ecqv->hash)
	{
		printf("Hash '%s' not found.\n", opt->hash);
		goto ERROR;
	}

	//打开key文件，读取CA私钥
	if (!(ecqv->key = ecqv_open_file(opt->key, "rb+"))) goto ERROR;

	//printf("1.2\n");

	if (!(ecqv->ca_key = ecqv_read_private_key(ecqv->key))) goto ERROR;

	// 以“二进制读”方式打开输入文件
	//if (!(ecqv->in = (opt->in) ? ecqv_open_file(opt->in, "rb") : stdin)) goto ERROR;
	// 以“二进制写”方式打开日志文件
	if (!(ecqv->log = (opt->log) ? ecqv_open_file(opt->log, "wb") : NULL) && opt->log) goto ERROR;

	// 以“二进制写”方式打开输出文件
	if (!(ecqv->out = (opt->out) ? ecqv_open_file(opt->out, "wb") : stdout)) goto ERROR;

	// 以“读”方式打开CA证书文件
	if (!(ecqv->certin = (opt->certin) ? ecqv_open_file(opt->certin, "r") : ecqv_open_file("ca_cert.crt", "r+"))) goto ERROR;

	// 在日志文件输出CA公私钥 或 公钥
	ecqv_log_key(ecqv, "CA", ecqv->ca_key);
	if (!(ecqv->ctx = BN_CTX_new())) goto ERROR;


	// 从私钥当中获得 群的参数
	//if (!(ecqv->group = EC_KEY_get0_group(ecqv->ca_key))) 
	if (!(ecqv->group = EC_GROUP_new_by_curve_name(NID_secp256k1)))
	{
		printf("Failed to get the group.\n");
		goto ERROR;
	}

	// 从群里获得 基点G
	if (!(G = EC_GROUP_get0_generator(ecqv->group)))
	{
		printf("Failed to get the generator.\n");
		goto ERROR;
	}
	ecqv_log_point(ecqv, "G", G);

	if (!(ecqv->order = BN_new())) goto ERROR;

	// 获得order (n)
	if (EC_GROUP_get_order(ecqv->group, ecqv->order, 0) == 0)
	{
		printf("Failed to get the order.\n");
		goto ERROR;
	}
	ecqv_log_bn(ecqv, "order", ecqv->order);

	*ecqv_gen = ecqv;
	return 0;
ERROR:
	if (ecqv) ecqv_free(ecqv);
	return -1;
}

int ecqv_create_server(struct ecqv_server_t **ecqv_server, const struct ecqv_opt_t *opt)
{
	struct ecqv_server_t * ecqv;
	EVP_PKEY *pk = NULL;
	if (!(ecqv = (ecqv_server_t *)OPENSSL_malloc(sizeof(*ecqv)))) return -1;
	memset(ecqv, 0, sizeof(*ecqv));

	if (ecqv_create(&ecqv->u, opt) == -1) return -1;

	// Read X509 to get CA's PublicKey
	if (PEM_read_X509(ecqv->u->certin, &ecqv->cacert, NULL, NULL) == NULL)
	{
		printf("PEM_read_X509 failed ");
		goto ERR;
	}
	//补充操作：读取公钥并于私钥文件中的公钥相比对（待加）
	pk = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pk, ecqv->u->ca_key);
	printf("Check CA's X509 and PrivateKey: %s\n", X509_check_private_key(ecqv->cacert, pk) == 1 ? "match" : "unmatch");

	*ecqv_server = ecqv;
	return 0;
ERR:
	printf("- ecqv_create_client ERROR\n");
	return -1;
}

int ecqv_client_free(struct ecqv_client_t *ecqv_client)
{
	if (ecqv_client->u) ecqv_free(ecqv_client->u);
	//if (ecqv_client->Pu) EC_POINT_free(ecqv_client->Pu);
	if (ecqv_client->Ru) EC_POINT_free(ecqv_client->Ru);
	if (ecqv_client->r) BN_free(ecqv_client->r);
	if (ecqv_client->a)  BN_free(ecqv_client->a);
	if (ecqv_client->e) BN_free(ecqv_client->e);
	return 0;
}

int ecqv_server_free(struct ecqv_server_t *ecqv_server)
{
	if (ecqv_server->u) ecqv_free(ecqv_server->u);
	//if (Pu) EC_POINT_free(Pu);
	//if (Ru) EC_POINT_free(Ru);
	//if (r) BN_free(r);
	if (ecqv_server->k)  BN_free(ecqv_server->k);
	//if (e) BN_free(e);
	return 0;
}

int ecqv_verify_keypair(EC_KEY *key)
{
	if (EC_KEY_check_key(key) == 0)
	{
		printf("Public key check failed.\n");
		return -1;
	}
	// TODO: verify key as per the ECQV standard
	return 0;
}

int ecqv_export_keypair(EC_KEY *key, struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_write_private_key(key, ecqv_gen) == -1)
	{
		printf("Exporting key pair failed.\n");
		return -1;
	}
	return 0;
}