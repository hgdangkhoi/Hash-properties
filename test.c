#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";

void hash(char * hashAlgo, char *message, unsigned char *md_value) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;	
	int md_len, i;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashAlgo);
	if(md == NULL) {
		printf("Unknown message digest %s\n", hashAlgo);
		exit(1);
	}
	//adapt from https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit.html
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	
}

void randomString(char *message) {
	int i;
	for (i=0;i<sizeof(message);i++){
		int index = rand() / (RAND_MAX / (sizeof(charset)-1));
		message[i] = charset[index];
	}
}

int crackOneWayHash(char * hashAlgo) {
	char message1[7], message2[7];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	
	int count=0, i;
	randomString(message1);    	
	hash(hashAlgo, message1, digt1);
	// run the crack
	do {    		
		randomString(message2);
		hash(hashAlgo, message2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);	
	printf("cracked after %d tries! same digest ", count, message1, message2);
	for(i = 0; i < 12; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

int crackCollisionHash(char * hashAlgo) {
	char message1[7], message2[7];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];	
	int count=0, i;
	// run the crack
	do {    	
		randomString(message1);
		hash(hashAlgo, message1, digt1);
		randomString(message2);
		hash(hashAlgo, message2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);
	printf("cracked after %d tries! same digest ", count);
	for(i = 0; i < 12; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{
	char *hashAlgo;
	hashAlgo = argv[1];
	//srand((int)time(0));	// init random seed
	int i,count;
	for (i=0,count=0;i<9;i++)
		count+=crackCollisionHash(hashAlgo);
	printf("average time cracking collision-free: %d \n", count/9);
	for (i=0,count=0;i<5;i++)
		count+=crackOneWayHash(hashAlgo);
	printf("average time cracking one-way: %d \n", count/5);
}