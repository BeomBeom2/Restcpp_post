//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <openssl/ec.h>
//#include <openssl/ecdh.h>
///*NID_X9_62_prime256v1*/
//#include <openssl/evp.h>
//
///*Nice little macro to save a few lines.*/
//void die(const char* reason)
//{
//	fprintf(stderr, reason);
//	fflush(stderr);
//	exit(1);
//}
//
///*Elliptic Curve Diffie-Hellman function*/
//int EC_DH(unsigned char** secret, EC_KEY* key, const EC_POINT* pPub)
//{
//	int secretLen;
//
//	secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(key));
//	secretLen = (secretLen + 7) / 8;
//
//	printf("key len : %d\n", secretLen);
//
//	*secret = (unsigned char*)malloc(secretLen);
//	if (!(*secret))
//		die("Failed to allocate memory for secret.\n");
//	secretLen = ECDH_compute_key(*secret, secretLen, pPub, key, NULL);
//
//	printf("secret key len : %d\n", secretLen);
//
//	return secretLen;
//}
//
///*Key generation function for throwaway keys.*/
//EC_KEY* gen_key(void)
//{
//	EC_KEY* key;
//
//	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//	if (key == NULL)
//		die("Failed to create lKey object.\n");
//
//	if (!EC_KEY_generate_key(key))
//		die("Failed to generate EC key.\n");
//
//	return key;
//}
//
//int main(int argc, char** argv)
//{
//	EC_KEY* CPublic_Key, * SPublic_Key, * tmp_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//	EC_KEY* tmp_key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//	int CSecretLen, SSecretLen;
//	unsigned char* CSecret, * SSecret;
//
//	unsigned char* tmp = NULL;
//	unsigned char* tmp2 = NULL;
//	CPublic_Key = gen_key();
//	int size = EC_KEY_key2buf(CPublic_Key, EC_KEY_get_conv_form(CPublic_Key), &tmp, nullptr); //키를 버퍼에 담음
//	int size1 = EC_KEY_oct2key(tmp_key, tmp, size, nullptr); //버퍼에 담긴 키를 oct string로 반환(=key)
//
//	SPublic_Key = gen_key();
//	size = EC_KEY_key2buf(SPublic_Key, EC_KEY_get_conv_form(SPublic_Key), &tmp2, nullptr);
//
//	size1 = EC_KEY_oct2key(tmp_key2, tmp2, size, nullptr);
//
//	CSecretLen = EC_DH(&CSecret, CPublic_Key, EC_KEY_get0_public_key(tmp_key2));
//	SSecretLen = EC_DH(&SSecret, SPublic_Key, EC_KEY_get0_public_key(tmp_key));
//	if (CSecretLen != SSecretLen)
//		die("SecretLen mismatch.\n");
//
//	if (memcmp(CSecret, SSecret, CSecretLen))
//		die("Secrets don't match.\n");
//
//	printf("lSecret : ");
//	for (int i = 0; i < CSecretLen; i++)
//		printf(" %c", CSecret[i]);
//
//	printf("\n");
//	printf("pSecret : ");
//	for (int i = 0; i < SSecretLen; i++)
//		printf(" %c", SSecret[i]);
//	printf("\n");
//
//	free(CSecret);
//	free(SSecret);
//	OPENSSL_free(tmp);
//	OPENSSL_free(tmp2);
//
//	EC_KEY_free(CPublic_Key);
//	EC_KEY_free(SPublic_Key);
//	CRYPTO_cleanup_all_ex_data();
//
//	return 0;
//}