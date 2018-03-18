// Khoi Hoang
// CSC 250 - lab 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

void hashFunction(char * hashAlgo, char *message, unsigned char *md_value) {
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

int oneWayProperty(char * hashAlgo) {
	char message1[7], message2[7];
	unsigned char hashValue1[EVP_MAX_MD_SIZE], hashValue2[EVP_MAX_MD_SIZE];
	
	int count=0, i;
	randomString(message1);    	
	hashFunction(hashAlgo, message1, hashValue1);
	
	do {    		
		randomString(message2);
		hashFunction(hashAlgo, message2, hashValue2);
		count++;
	} while (strncmp(hashValue1, hashValue2, 3)!=0);	//compare 3 byte character, which is 24 bits 
	printf("Cracked one way property after %d trials", count);
	printf("Message 1: %s, hash: ", message1);
	for(i = 0; i < 12; i++) {
		printf("%02x", hashValue1[i]);
	}
	printf("\n");
	printf("Message 2: %s, hash: ", message2);
	for(i = 0; i < 12; i++) {
		printf("%02x", hashValue2[i]);
	}
	return count;
}

int collisionFreeProperty(char * hashAlgo) {
	char message1[7], message2[7];
	unsigned char hashValue1[EVP_MAX_MD_SIZE], hashValue2[EVP_MAX_MD_SIZE];	
	int count=0, i;
	
	do {    	
		randomString(message1);
		hashFunction(hashAlgo, message1, hashValue1);
		randomString(message2);
		hashFunction(hashAlgo, message2, hashValue2);
		count++;
	} while (strncmp(hashValue1, hashValue2, 3)!=0);
	printf("Cracked collision free property after %d trials\n", count);
	printf("Message 1: %s, hash: ", message1);
	for(i = 0; i < 12; i++) {
		printf("%02x", hashValue1[i]);
	}
	printf("\n");
	printf("Message 2: %s, hash: ", message2);
	for(i = 0; i < 12; i++) {
		printf("%02x", hashValue2[i]);
	}
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{
	char *hashAlgo;
	hashAlgo = argv[1];
	
	int i,count;
	for (i=0,count=0;i<9;i++){
		count+=collisionFreeProperty(hashAlgo);
	}
	printf("Average time to crack collision free property: %d \n", count/9);
	for (i=0,count=0;i<5;i++){
		count+=oneWayProperty(hashAlgo);
	}
	printf("Average time to crack one way property: %d \n", count/5);
}