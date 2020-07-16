#include "cert.h"
#include <stdio.h>
#include <string.h>
#include "ecqv_client.h"
extern "C"
{
#include <openssl/applink.c>
};



#define ECQV_HASH EVP_sha256() //定义HASH函数为sha1  两边均为openssl的变量，里面定义了函数指针
// 修改成SM3版本则需改为:(openssl，3.0有[evp.h,L801]，需判断对应版本有没有)
// #define ECQV_HASH EVP_sm3()

void ecqv_log_bn(struct ecqv_gen_t *gen, const char *label, const BIGNUM *bn)
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

void ecqv_log_point(struct ecqv_gen_t *gen, const char *label, const EC_POINT *point)
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

void ecqv_log_key(struct ecqv_gen_t *gen, const char *label, const EC_KEY *key)
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

	printf("1.3\n");

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

int ecqv_write_private_key(EC_KEY *key, struct ecqv_gen_t *ecqv_gen)
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

int ecqv_write_impl_cert(struct ecqv_client_t *ecqv_client)
{
	BIO *b64 = NULL, *bio = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;
	buf_len = EC_POINT_point2oct(ecqv_client->u->group, ecqv_client->Pu,
		POINT_CONVERSION_UNCOMPRESSED,
		NULL, 0, ecqv_client->u->ctx);

	if (buf_len == 0) {
		goto ERR;
	}

	buf = (unsigned char *)OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERR;
	}

	buf_len = EC_POINT_point2oct(ecqv_client->u->group, ecqv_client->Pu,
		POINT_CONVERSION_UNCOMPRESSED,
		buf, buf_len, ecqv_client->u->ctx);

	if (buf_len == 0) {
		goto ERR;
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
ERR:

	if (buf) {
		OPENSSL_free(buf);
	}

	if (bio) {
		BIO_free_all(bio);
	}

	return -1;
}

// client 第一步 - 生成 Ru = α * G
// 输入：ecqv_gen, [a]
// 输出：Ru, a
int ecqv_client_public_seed(EC_POINT **Ru, BIGNUM **a, ecqv_gen_t *ecqv_gen)
{
	// 随机生成私钥种子 alpha
	if (!*a && !(*a = BN_new()))  goto ERR;
	if (BN_rand_range(*a, ecqv_gen->order) == 0) goto ERR;
	//BN_one(*a); //xx
	ecqv_log_bn(ecqv_gen, "alpha", *a);

	// 计算Ru = α * G
	if (!(*Ru = EC_POINT_new(ecqv_gen->group))) goto ERR;
	if (EC_POINT_mul(ecqv_gen->group, *Ru, *a, NULL, NULL, NULL) == 0) goto ERR;
	ecqv_log_point(ecqv_gen, "alphaG", *Ru);

	return 0;
ERR:
	return -1;
}

// server/client 第二步
// 生成e = Hash(Cert）
// 修改时需要把Pu嵌入至Cert里并且只做一次Hash即可
int ecqv_create_cert_hash_from_byte(BIGNUM **e, unsigned char *cert_b, int cert_len, ecqv_gen_t *ecqv_gen)
{
	EVP_MD_CTX *md_ctx = NULL; //上下文（存储中间变量的地方）

	unsigned char md_value[EVP_MAX_MD_SIZE]; //存放Hash的结果
	unsigned int md_len;


	// 初始化
	if (!*e && !(*e = BN_new())) return -1;
	if (!(md_ctx = EVP_MD_CTX_new())) return -1;

	// 设置md_ctx以使用 之前设置的hash函数
	if (EVP_DigestInit_ex(md_ctx, ecqv_gen->hash, 0) == 0)  goto ERR;

	//printf("cert_len: %d\n", cert_len);
	//for (int i = 0; i < cert_len; i++)
	//	printf("%02x ", cert_b[i]);
	//printf("\n");

	// 将整个证书结构放入Hash输入里
	if (EVP_DigestUpdate(md_ctx, cert_b, cert_len) == 0) goto ERR;

	// 计算md_value(e) = Hash(cert) ，此时不能再做EVP_DigestUpdate步骤
	if (EVP_DigestFinal_ex(md_ctx, md_value, &md_len) == 0) goto ERR;
	if (!BN_bin2bn(md_value, md_len, *e)) goto ERR;
	ecqv_log_bn(ecqv_gen, "e", *e);

	EVP_MD_CTX_destroy(md_ctx);
	return 0;
ERR:
	if (md_ctx)  EVP_MD_CTX_destroy(md_ctx);
	return -1;
}

// client 第三步 - 最终产生公私钥对 a = e * alpha + r; 最终公钥 p_Qa = Pu * e + Q_CA
// 输入：a, r, user_mkey, ecqv_gen[ca_key]
// 输出：user_key
int ecqv_client_create_keypair(EC_KEY **user_key, BIGNUM *e, BIGNUM *a, BIGNUM *r, X509 *user_cert, ecqv_gen_t *ecqv_gen)
{
	EC_POINT *p_efii = NULL, *p_Qa = NULL; //存储 中间值Pu*e 和 最终公钥
	BIGNUM *ealpha = NULL, *qa = NULL; // 存储 中间值e*alpha 和 最终私钥qa
	const EC_POINT *p_Qc = NULL; // 存储CA的公钥
	EVP_PKEY *user_evp_pk = NULL;
	const EC_POINT *Pu = NULL;

	ecqv_log_bn(ecqv_gen, "r", r);

	if (!(user_evp_pk = X509_get_pubkey(user_cert))) goto ERR;
	if (!(Pu = EC_KEY_get0_public_key(EVP_PKEY_get1_EC_KEY(user_evp_pk)))) goto ERR;

	// e_α = e * α
	if (!(ealpha = BN_new())) goto ERR;
	if (BN_mul(ealpha, e, a, ecqv_gen->ctx) == 0) goto ERR;
	ecqv_log_bn(ecqv_gen, "ealpha", ealpha);

	// 最终私钥 a = e * alpha + r
	if (!(qa = BN_new())) goto ERR;
	if (BN_mod_add(qa, ealpha, r, ecqv_gen->order, ecqv_gen->ctx) == 0) goto ERR;
	ecqv_log_bn(ecqv_gen, "qa", qa);

	// p_efii = Pu * e 
	if (!(p_efii = EC_POINT_new(ecqv_gen->group))) goto ERR;
	if (EC_POINT_mul(ecqv_gen->group, p_efii, NULL, Pu, e, NULL) == 0) goto ERR;
	ecqv_log_point(ecqv_gen, "efii", p_efii);

	// 最终公钥 p_Qa = p_efii + p_Qc = Pu * e + Q_CA
	if (!(p_Qa = EC_POINT_new(ecqv_gen->group))) goto ERR;
	if (!(p_Qc = EC_KEY_get0_public_key(ecqv_gen->ca_key))) goto ERR; // 从CA公私钥里提取公钥
	if (EC_POINT_add(ecqv_gen->group, p_Qa, p_efii, p_Qc, 0) == 0) goto ERR;
	ecqv_log_point(ecqv_gen, "Qa", p_Qa);


	if (!(*user_key = EC_KEY_new())) goto ERR;

	// 设置密钥
	if (EC_KEY_set_group(*user_key, ecqv_gen->group) == 0) goto ERR; // 设置群信息
	if (EC_KEY_set_private_key(*user_key, qa) == 0) goto ERR; // 设置私钥
	if (EC_KEY_set_public_key(*user_key, p_Qa) == 0) goto ERR; // 设置公钥
	ecqv_log_key(ecqv_gen, "CLIENT", *user_key);

	EC_POINT_free(p_efii);
	EC_POINT_free(p_Qa);
	BN_free(ealpha);
	BN_free(qa);
	return 0;
ERR:

	if (p_efii) EC_POINT_free(p_efii);
	if (p_Qa) EC_POINT_free(p_Qa);
	if (ealpha) BN_free(ealpha);
	if (qa) BN_free(qa);

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
		goto ERR;
	}

	// 以“二进制写”方式打开日志文件
	if (!(ecqv->log = (opt->log) ? ecqv_open_file(opt->log, "wb") : NULL) && opt->log) goto ERR;

	// 以“二进制写”方式打开输出文件
	if (!(ecqv->out = (opt->out) ? ecqv_open_file(opt->out, "wb") : stdout)) goto ERR;

	// 以“读”方式打开CA证书文件
	if (!(ecqv->certin = (opt->certin) ? ecqv_open_file(opt->certin, "r") : ecqv_open_file("ca_cert.crt", "wb"))) goto ERR;

	// 在日志文件输出CA公私钥 或 公钥
	if (!(ecqv->ctx = BN_CTX_new())) goto ERR;


	// 从私钥当中获得 群的参数
	//if (!(ecqv->group = EC_KEY_get0_group(ecqv->ca_key))) 
	if (!(ecqv->group = EC_GROUP_new_by_curve_name(NID_secp256k1)))
	{
		printf("Failed to get the group.\n");
		goto ERR;
	}

	// 从群里获得 基点G
	if (!(G = EC_GROUP_get0_generator(ecqv->group)))
	{
		printf("Failed to get the generator.\n");
		goto ERR;
	}
	ecqv_log_point(ecqv, "G", G);

	if (!(ecqv->order = BN_new())) goto ERR;

	// 获得order (n)
	if (EC_GROUP_get_order(ecqv->group, ecqv->order, 0) == 0)
	{
		printf("Failed to get the order.\n");
		goto ERR;
	}
	ecqv_log_bn(ecqv, "order", ecqv->order);

	*ecqv_gen = ecqv;
	return 0;
ERR:
	if (ecqv) ecqv_free(ecqv);
	return -1;
}

int ecqv_create_client(struct ecqv_client_t **ecqv_client, const struct ecqv_opt_t *opt)
{
	struct ecqv_client_t * ecqv;
	if (!(ecqv = (ecqv_client_t *)OPENSSL_malloc(sizeof(*ecqv)))) return -1;
	memset(ecqv, 0, sizeof(*ecqv));
	//printf("1.1\n");
	if (ecqv_create(&ecqv->u, opt) == -1) return -1;

	// Read X509 to get CA's PublicKey
	if (PEM_read_X509(ecqv->u->certin, &ecqv->cacert, NULL, NULL) == NULL)
	{
		printf("PEM_read_X509 failed ");
		goto ERR;
	}
	if ((ecqv->u->ca_key = EVP_PKEY_get1_EC_KEY(X509_get_pubkey(ecqv->cacert))) == NULL)
	{
		printf("Get CA's public key failed ");
		goto ERR;
	}
	ecqv_log_key(ecqv->u, "CA", ecqv->u->ca_key);
	*ecqv_client = ecqv;
	return 0;
ERR:
	printf("- ecqv_create_client ERR\n");
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

int ecqv_verify_keypair(EC_KEY *key)
{
	if (EC_KEY_check_key(key) == 0)
	{
		printf("Key-Check... failed.\n");
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

	//if (ecqv_write_impl_cert(ecqv_client) == -1)
	//{
	//	printf( "Exporting certificate failed.\n");
	//	return -1;
	//}

	return 0;
}