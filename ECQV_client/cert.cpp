#include "cert.h"
// 输出：sig, sig_len
int SM2Sign(X509 *x, EVP_PKEY *sk, const EVP_MD *md, unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len)
{
	EVP_MD_CTX *mctx = NULL; //sm2用
	EVP_PKEY_CTX *pctx = NULL; //sm2用
	EVP_PKEY_set_alias_type(sk, EVP_PKEY_SM2); // 默认ECDSA，改为SM2
	mctx = EVP_MD_CTX_new();
	pctx = EVP_PKEY_CTX_new(sk, NULL);
	// EVP_PKEY_CTX_set1_id(pctx, id, id_len); SM2跳过？
	EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
	if (EVP_DigestSignInit(mctx, NULL, md, NULL, sk) != 1) goto ERR;
	EVP_DigestVerifyUpdate(mctx, msg, msg_len);
	EVP_DigestSignFinal(mctx, *sig, sig_len);


	EVP_MD_CTX_free(mctx);
	EVP_PKEY_CTX_free(pctx);
	return 0;
ERR:
	if (mctx) EVP_MD_CTX_free(mctx);
	if (pctx) EVP_PKEY_CTX_free(pctx);
	return -1;
}

int SM2Verify();

int mksm2cert(X509 **x509p, EC_KEY **userpk, EC_KEY **cask, X509_NAME *caname, const char *cn, int bits, int serial, int days)
{
	X509 *x = NULL;
	EVP_PKEY *pk = NULL, *sk = NULL;
	X509_NAME *name = NULL;
	//EVP_MD_CTX *ctx; // 测试


	// 读取/生成user公钥
	if ((pk = EVP_PKEY_new()) == NULL)
		return -1;
	if (userpk && *userpk)
		//if (EVP_PKEY_assign_EC_KEY(pk, *userpk) != 1)
		if (EVP_PKEY_set1_EC_KEY(pk, *userpk) != 1)
			return -1;
	//if (EVP_PKEY_set_alias_type(pk, EVP_PKEY_SM2) != 1)
	//	return -1;

	printf("x\n");

	// 读取/生成X509
	if ((x509p == NULL) || (*x509p == NULL))
	{
		if ((x = X509_new()) == NULL)
			goto ERR;
	}
	else
	{
		x = *x509p;
	}

	// 左边 = 右边
	X509_set_version(x, 2); //版本号
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);

	X509_set_issuer_name(x, (caname) ? caname : name); // 标记name

	// add extensions 待补充

	if ((sk = EVP_PKEY_new()) == NULL)
		goto ERR;
	if (EVP_PKEY_set1_EC_KEY(sk, *cask) != 1) // 将EC_KEY转化为EVP_PKEY
		goto ERR;
	//EVP_PKEY_set_alias_type(sk, EVP_PKEY_SM2);
	//EVP_PKEY_assign_EC_KEY(sk, *cask);

///////////////////// Start Debug ////////////////////////////
#ifdef SSS
	// a_sign.c -> ASN1_item_sign()
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return -1;
	if (!EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, sk))
		return -1;

	// m_sigver.c -> do_sigver_init 

#endif
///////////////////// End Debug ////////////////////////////

	if (!X509_sign(x, sk, EVP_sha256())) //SM3会报错
		goto ERR;
	*x509p = x;
	*userpk = EVP_PKEY_get0_EC_KEY(pk);

	return 0;
ERR:
	if (pk) EVP_PKEY_free(pk);
	return -1;
}

int createCA(X509 **cert, FILE *fp)
{
	//EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(ecdh);
	//EVP_PKEY *evk = EVP_PKEY_new();
	//EVP_PKEY_set1_EC_KEY(evk, ecdh);
	X509 *x509 = NULL;
	if (mksm2cert(&x509, &ecdh, &ecdh, 0, "Openssl Group", 256, 2345, 3650) == -1) return -1;
	*cert = x509;

	// write cert
	PEM_write_X509(fp, x509);
	return 0;
}

int createUser(X509 **cert, FILE *fp, EC_POINT *Pu, const EC_GROUP *g, X509 *cacert, EC_KEY *cakey)
{
	EC_KEY *pk = EC_KEY_new();
	X509 *x509 = NULL;
	X509_NAME *caname = X509_get_subject_name(cacert);

	if (pk == NULL) return -1;
	if (EC_KEY_set_group(pk, g) == 0) goto ERR;
	if (EC_KEY_set_public_key(pk, Pu) == 0) goto ERR;

	cakey = EVP_PKEY_get1_EC_KEY(X509_get0_pubkey(cacert));

	if (mksm2cert(&x509, &pk, &cakey, caname, "test.com", 256, 2345, 3650) == -1) goto ERR;
	*cert = x509;

	PEM_write_X509(fp, x509);
	return 0;
ERR:
	if (pk) EC_KEY_free(pk);
	return -1;
}