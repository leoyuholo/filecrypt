#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define READ_BLOCK_SIZE 1024 * 1024

/* with reference to Patrick's example code: 
 * http://www.cse.cuhk.edu.hk/csci5470/notes/files/openssl_pclee.tar.gz
 */

unsigned char* endian_swap(unsigned int x){
    
	unsigned char* ret_buf = (unsigned char*)malloc(sizeof(unsigned int));
	
	ret_buf[0] = (unsigned char)(x >> 24);
	ret_buf[1] = (unsigned char)(x >> 16);
	ret_buf[2] = (unsigned char)(x >> 8);
	ret_buf[3] = (unsigned char)(x);
	
	return ret_buf;
}

// compute k and signature
void cal_k_and_sign(FILE* ifp, DSA* dsa, unsigned char** k, unsigned char** signature){
	
	// move to end of file
	fseek(ifp, 0, SEEK_END);
	// get file size
	unsigned int file_size = (unsigned int)ftell(ifp);
	// move to begin of file
	rewind(ifp);
	
	// endian swapping for file size
	unsigned char* buf_ptr = endian_swap(file_size);
	
	// init SHA256 (first hash)
	SHA256_CTX hash_1_ctx;
	SHA256_Init(&hash_1_ctx);
	
	// init SHA1
	SHA_CTX sha1_ctx;
	SHA_Init(&sha1_ctx);
	
	// digest file size
	SHA256_Update(&hash_1_ctx, buf_ptr, sizeof(unsigned int));
	
	// free memory
	free(buf_ptr);
	
	// digest file content
	int read_pos = 0;
	int read_cnt = 0;
	
	buf_ptr = (unsigned char*)malloc(READ_BLOCK_SIZE);
	
	while(1){
		read_cnt = fread(buf_ptr, 1, READ_BLOCK_SIZE, ifp);
		
		SHA256_Update(&hash_1_ctx, buf_ptr, read_cnt);
		SHA_Update(&sha1_ctx, buf_ptr, read_cnt);
		
		read_pos += read_cnt;
		if(read_pos >= file_size){
			break;
		}
	}
	
	// free memory
	free(buf_ptr);
	
	// get result of first hash
	unsigned char* hash_1 = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
	SHA256_Final(hash_1, &hash_1_ctx);
	
	// get result of sha1
	unsigned char* sha1 = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	SHA_Final(sha1, &sha1_ctx);
	
// printf("sha1:[");
// for(int i = 0;i < SHA_DIGEST_LENGTH;i++)	printf("%x", sha1[i]);
// printf("]\n");
	
	// init SHA256 (second hash)
	SHA256_CTX hash_2_ctx;
	SHA256_Init(&hash_2_ctx);
	
	// digest result of first hash
	SHA256_Update(&hash_2_ctx, hash_1, SHA256_DIGEST_LENGTH);
	
	// free memory
	free(hash_1);
	
	// if(*k != NULL)	free(*k);
	
	// get result of second hash
	*k = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
	SHA256_Final(*k, &hash_2_ctx);
	
	// if(*signature != NULL)	free(*signature);
	
	unsigned int dsa_size = DSA_size(dsa);
	*signature = (unsigned char*)malloc(dsa_size);
	DSA_sign(0, sha1, SHA_DIGEST_LENGTH, *signature, &dsa_size, dsa);
	
// printf("signature:[");
// for(int i = 0;i < dsa_size;i++)	printf("%x", (*signature)[i]);
// printf("]len[%d]\n", dsa_size);
	
	return;
}

void encrypt_k_and_file_size(RSA* rsa, unsigned char* k, FILE* ifp, FILE* ofp){
	
	// move to end of file
	fseek(ifp, 0, SEEK_END);
	// get file size
	unsigned int file_size = (unsigned int)ftell(ifp);
	// move to begin of file
	rewind(ifp);
	
	// endian swapping for file size
	unsigned char* buf_ptr = endian_swap(file_size);
	
	unsigned char* encrypt_buf = (unsigned char*)malloc(36);	//256bit = 32byte, then add 4byte
	
	memcpy(encrypt_buf, k, 32);
	memcpy(encrypt_buf + 32, buf_ptr, 4);
	
	unsigned int rsa_size = RSA_size(rsa);
	unsigned char* encrypt_result = (unsigned char*)malloc(rsa_size);
	
	RSA_public_encrypt(36, encrypt_buf, encrypt_result, rsa, RSA_PKCS1_OAEP_PADDING);
	
// printf("encrypt_result:[");
// for(int i = 0;i < rsa_size;i++)	printf("%x", encrypt_result[i]);
// printf("]\n");
	
	fwrite(encrypt_result, 1, rsa_size, ofp);
	
	return;
}

void encrypt_file_content_and_signature(AES_KEY* aes, unsigned char* signature, FILE* ifp, FILE* ofp){
	
	// move to end of file
	fseek(ifp, 0, SEEK_END);
	// get file size
	unsigned int file_size = (unsigned int)ftell(ifp);
	// move to begin of file
	rewind(ifp);
	
	// init iv
	unsigned char* iv = (unsigned char*)calloc(1, AES_BLOCK_SIZE);
	
	// encrypt
	int read_pos = 0;
	int read_cnt = 0;
	
	unsigned char* encrypt_buf = (unsigned char*)malloc(16);	// 128bit = 16byte
	unsigned char* encrypt_result = (unsigned char*)malloc(16);	// 128bit = 16byte
	
	// encrypt content
	while(1){
		read_cnt = fread(encrypt_buf, 1, 16, ifp);
		
		if(read_cnt != 16){
			break;
		}
		
		AES_cbc_encrypt(encrypt_buf, encrypt_result, read_cnt, aes, iv, AES_ENCRYPT);
		
		fwrite(encrypt_result, 1, 16, ofp);
		
		read_pos += read_cnt;
		if(read_pos >= file_size){
			read_cnt = 0;
			break;
		}
	}
	
	// encrypt remaining content and part of signature
	int tmp_int = read_cnt + 48;
	
	unsigned char* buf_ptr = (unsigned char*)malloc(tmp_int);
	memcpy(buf_ptr, encrypt_buf, read_cnt);
	memcpy(buf_ptr + read_cnt, signature, 48);
	
// printf("tmp_int[%d]\n", tmp_int);
	
	int i;
	for(i = 0;i < (tmp_int - 16);i += 16){
		
		memcpy(encrypt_buf, buf_ptr + i, 16);
		
		AES_cbc_encrypt(encrypt_buf, encrypt_result, 16, aes, iv, AES_ENCRYPT);
		
// printf("buf:[");
// for(int k = 0;k < 16;k++)	printf("%x", encrypt_result[k]);
// printf("]\n");
		
		fwrite(encrypt_result, 1, 16, ofp);
		
	}
	
	// encrypt remaining signature with padding
	
	if((tmp_int % 16) != 0){
		
		memset(encrypt_buf, 0, 16);
		
		memcpy(encrypt_buf, buf_ptr + i, tmp_int % 16);
		
		AES_cbc_encrypt(encrypt_buf, encrypt_result, read_cnt, aes, iv, AES_ENCRYPT);
		
// printf("buf:[");
// for(int k = 0;k < 16;k++)	printf("%x", encrypt_result[k]);
// printf("]\n");
		
		fwrite(encrypt_result, 1, 16, ofp);
		
	}
	
	free(buf_ptr);
	free(iv);
	free(encrypt_buf);
	free(encrypt_result);
	
	return;
}

void encrypt(char* input_file, char* dsa_priv_key_file, char* rsa_pub_key_file, char* passphrase){
	
// printf("enc[%s] [%s] [%s] [%s]\n", input_file, dsa_priv_key_file, rsa_pub_key_file, passphrase);
	
	int input_file_strlen = strlen(input_file);
	
	if(!strcmp(input_file + (input_file_strlen - 4), ".enc")){
		printf("is .enc file\n");
		return;
	}
	
	FILE* ifp;
	if((ifp = fopen(input_file, "rb")) == NULL){
		fprintf(stderr, "Unable to open input file\n");
		exit(-1);
	}
	
	FILE* dsa_priv_key_fp;
	if((dsa_priv_key_fp = fopen(dsa_priv_key_file, "r")) == NULL){
		fprintf(stderr, "Unable to open private key file\n");
		exit(-1);
	}
	
	DSA* dsa = NULL;
	PEM_read_DSAPrivateKey(dsa_priv_key_fp, &dsa, NULL, passphrase);
	fclose(dsa_priv_key_fp);
	
	// step1 & 2: compute K and signature
	unsigned char* k = NULL;
	unsigned char* signature = NULL;
	cal_k_and_sign(ifp, dsa, &k, &signature);
	
	// step3: encrypt k and file size
	FILE* rsa_pub_key_fp;
	if((rsa_pub_key_fp = fopen(rsa_pub_key_file, "r")) == NULL){
		fprintf(stderr, "Unable to open public key file\n");
		exit(-1);
	}
	
	RSA* rsa;
	PEM_read_RSA_PUBKEY(rsa_pub_key_fp, &rsa, NULL, NULL);
	fclose(rsa_pub_key_fp);
	// RSA_print_fp(stdout, rsa, 0);
	
	FILE* ofp;
	char* output_file = (char*)malloc(strlen(input_file) + 5);
	sprintf(output_file, "%s.enc", input_file);
	if((ofp = fopen(output_file, "w")) == NULL){
		fprintf(stderr, "Unable to open output file\n");
		exit(-1);
	}
	
	encrypt_k_and_file_size(rsa, k, ifp, ofp);
	
	// step4: encrypt file content and signature
	AES_KEY aes;
	
	AES_set_encrypt_key(k, 256, &aes);
	
	encrypt_file_content_and_signature(&aes, signature, ifp, ofp);
	
	fclose(ifp);
	fclose(ofp);
	
	return;
}

void decrypt_k_and_file_size(FILE* ifp, RSA* rsa, unsigned char** k, unsigned int* file_size){
	
	unsigned int rsa_size = RSA_size(rsa);
	
	unsigned char* buf_ptr = (unsigned char*)malloc(rsa_size);
	
	fread(buf_ptr, 1, 128, ifp);
	
	unsigned char* decrypt_result = (unsigned char*)malloc(rsa_size);
	
	RSA_private_decrypt(rsa_size, buf_ptr, decrypt_result, rsa, RSA_PKCS1_OAEP_PADDING);
	
	*k = (unsigned char*)malloc(32);
	
	memcpy(*k, decrypt_result, 32);
	
	free(buf_ptr);
	buf_ptr = endian_swap(*((unsigned int*)(decrypt_result + 32)));
	
	*file_size = *(unsigned int*)buf_ptr;
	free(buf_ptr);
	
	return;
}

unsigned char* decrypt_file_content_and_signature(AES_KEY* aes, unsigned int file_size, unsigned char** signature, FILE* ifp, FILE* ofp){
	
	// init SHA1
	SHA_CTX sha1_ctx;
	SHA_Init(&sha1_ctx);
	
	fseek(ifp, 128, SEEK_SET);
	rewind(ofp);
	
	unsigned char* buf_ptr = (unsigned char*)calloc(1, 16);
	unsigned char* decrypt_result = (unsigned char*)calloc(1, 16);
	unsigned char* iv = (unsigned char*)calloc(1, 16);
	
	unsigned int write_pos = 0;
	unsigned int write_cnt = 0;
	
	while(1){
		write_cnt = fread(buf_ptr, 1, 16, ifp);
		write_pos += write_cnt;
		
		AES_cbc_encrypt(buf_ptr, decrypt_result, 16, aes, iv, AES_DECRYPT);
		
		fwrite(decrypt_result, 1, 16, ofp);
		
		SHA_Update(&sha1_ctx, decrypt_result, 16);
		
		if(write_pos > (file_size - 16)){
			break;
		}
	}
	
	unsigned int remain_byte = file_size - write_pos;
	fread(buf_ptr, 1, 16, ifp);
// printf("buf:[");
// for(int i = 0;i < 16;i++)	printf("%x", buf_ptr[i]);
// printf("]\n");
	AES_cbc_encrypt(buf_ptr, decrypt_result, 16, aes, iv, AES_DECRYPT);
	fwrite(decrypt_result, 1, remain_byte, ofp);
		
	SHA_Update(&sha1_ctx, decrypt_result, remain_byte);
	// get result of sha1
	unsigned char* sha1 = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	SHA_Final(sha1, &sha1_ctx);
	
	*signature = (unsigned char*)calloc(1, 48);
	unsigned int signature_pos = 0;
	
	memcpy(*signature, decrypt_result + remain_byte, (16 - remain_byte));
	signature_pos += (16 - remain_byte);
	
// printf("remain_byte[%d]\n", remain_byte);
	
	while(signature_pos <= 48){
		
		fread(buf_ptr, 1, 16, ifp);
// printf("buf:[");
// for(int i = 0;i < 16;i++)	printf("%x", buf_ptr[i]);
// printf("]\n");
		AES_cbc_encrypt(buf_ptr, decrypt_result, 16, aes, iv, AES_DECRYPT);
		
		memcpy(*signature + signature_pos, decrypt_result, 48 > (signature_pos + 16) ? 16 : (48 - signature_pos));
		signature_pos += 16;
	}
	
// printf("sha1:[");
// for(int i = 0;i < SHA_DIGEST_LENGTH;i++)	printf("%x", sha1[i]);
// printf("]\n");
	
// printf("signature:[");
// for(int i = 0;i < 48;i++)	printf("%x", (*signature)[i]);
// printf("]\n");
	
	free(buf_ptr);
	free(decrypt_result);
	free(iv);
	
	return sha1;
}

void decrypt(char* input_file, char* dsa_cert_file, char* rsa_priv_key_file, char* passphrase){
	
// printf("dec[%s] [%s] [%s] [%s]\n", input_file, dsa_cert_file, rsa_priv_key_file, passphrase);
	
	int input_file_strlen = strlen(input_file);
	
	if(strcmp(input_file + (input_file_strlen - 4), ".enc")){
		printf("not .enc file\n");
		return;
	}
	
	FILE* ifp;
	if((ifp = fopen(input_file, "rb")) == NULL){
		fprintf(stderr, "Unable to open input file\n");
		exit(-1);
	}
	
	// load rsa private key
	FILE* rsa_priv_key_fp;
	if((rsa_priv_key_fp = fopen(rsa_priv_key_file, "r")) == NULL){
		fprintf(stderr, "Unable to open private key file\n");
		exit(-1);
	}
	
	RSA* rsa = NULL;
	PEM_read_RSAPrivateKey(rsa_priv_key_fp, &rsa, NULL, passphrase);
	
	fclose(rsa_priv_key_fp);
	
	// RSA_print_fp(stdout, rsa, 0);
	
	// step 1: decrypt k and file size
	unsigned char* k = NULL;
	unsigned int file_size = 0;
	decrypt_k_and_file_size(ifp, rsa, &k, &file_size);
	
	// step 2: decrypt file content and signature
	FILE* ofp;
	char* output_file = (char*)malloc(input_file_strlen - 3);
	memcpy(output_file, input_file, input_file_strlen - 3);
	output_file[input_file_strlen - 4] = '\0';
	if((ofp = fopen(output_file, "w")) == NULL){
		fprintf(stderr, "Unable to open output file\n");
		exit(-1);
	}
	
	AES_KEY aes;
	
	AES_set_decrypt_key(k, 256, &aes);
	
	unsigned char* signature = NULL;
	unsigned char* sha1 = NULL;
	sha1 = decrypt_file_content_and_signature(&aes, file_size, &signature, ifp, ofp);
	
	// step 3: verify signature
	// load dsa public key
	FILE* dsa_cert_fp;
	if((dsa_cert_fp = fopen(dsa_cert_file, "r")) == NULL){
		fprintf(stderr, "Unable to open certificate file\n");
		exit(-1);
	}
	
	X509* cert;
	if((cert = PEM_read_X509(dsa_cert_fp, NULL, NULL, NULL)) == NULL){
		fprintf(stderr, "cannot read cert file\n");
		exit(-1);
	}
	
	EVP_PKEY* pub_key;
	if((pub_key = X509_get_pubkey(cert)) == NULL){
		fprintf(stderr, "cannot read x509's public key\n");
		exit(-1);                                      
	}
	
	fclose(dsa_cert_fp);
	
	// verify signature and input_string
	DSA* dsa = EVP_PKEY_get1_DSA(pub_key);
	int is_valid_signature;
	is_valid_signature = DSA_verify(0, sha1, SHA_DIGEST_LENGTH, signature, 48, dsa);
	
// printf("is_valid_signature? = %d\n", is_valid_signature);
	
	if(is_valid_signature != 1){
		printf("invalid signature for file: %s\n", input_file);
	}
	
	return;
}

void do_dir(void func(char*, char*, char*, char*), char* input_file, char* dsa_key_file, char* rsa_key_file, char* passphrase){
	
	struct stat statbuf;
	struct dirent* dp;
	DIR* dfd;
	char str_buf[200];
	
	stat(input_file, &statbuf);
	
	if(S_ISDIR(statbuf.st_mode)){
		// printf("%s is dir\n", input_file);
		dfd = opendir(input_file);
		while((dp = readdir(dfd)) != NULL){
			if(dp->d_name[0] != '.'){
				sprintf(str_buf, "%s/%s", input_file, dp->d_name);
				do_dir(func, str_buf, dsa_key_file, rsa_key_file, passphrase);
			}
		}
		closedir(dfd);
	}else{
		func(input_file, dsa_key_file, rsa_key_file, passphrase);
	}
	
	return;
}

int main(int argc, char** argv){
	
	if(argc != 10){
		printf("%s -e -f file.pdf -lpri lpri.pem -spub spub.pem -lp 5470.\n", argv[0]);
		printf("OR\n");
		printf("%s -d -f file.pdf.enc -cert cert.pem -spri spri.pem -sp 0745.\n", argv[0]);
		return 0;
	}
		
	OpenSSL_add_all_algorithms();
	
	SSL_load_error_strings();
	
	if(!strcmp(argv[1], "-e")){
		do_dir(encrypt, argv[3], argv[5], argv[7], argv[9]);
	}else if(!strcmp(argv[1], "-d")){
		do_dir(decrypt, argv[3], argv[5], argv[7], argv[9]);
	}
	
	return 0;
	
}