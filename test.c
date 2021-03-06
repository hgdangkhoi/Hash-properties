// Khoi Hoang
// CSC 250 - lab 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <time.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

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
	for (i=0;i<3;i++){
		int index = rand() % (int)(sizeof(charset)-1);
		message[i] = charset[index];
	}
}

int oneWayProperty(char * hashAlgo) {
	char message1[4] = {0};
	char message2[4] = {0};
	unsigned char hashValue1[EVP_MAX_MD_SIZE], hashValue2[EVP_MAX_MD_SIZE];
	
	int count=0, i;
	randomString(message1);    	
	hashFunction(hashAlgo, message1, hashValue1); //generate a random hash value
	
	do {//find message2 so that hash value of message2 = hashValue1
		randomString(message2);
		hashFunction(hashAlgo, message2, hashValue2);
		count++;
	} while (memcmp(hashValue1, hashValue2, 3)!=0);	//compare 3 byte character, which is 24 bits 
	printf("Cracked one way property after %d trials\n", count);
	printf("Message 1: %s, hash: ", message1);
	for(i = 0; i < 3; i++) {
		printf("%02x", hashValue1[i]);
	}
	printf("\n");
	printf("Message 2: %s, hash: ", message2);
	for(i = 0; i < 3; i++) {
		printf("%02x", hashValue2[i]);
	}
	printf("\n");
	return count;
}

int collisionFreeProperty(char * hashAlgo) {
	char message1[4] = {0};
	char message2[4] = {0};
	unsigned char hashValue1[EVP_MAX_MD_SIZE], hashValue2[EVP_MAX_MD_SIZE];	
	int count=0, i;
	
	do {    	
		randomString(message1);
		randomString(message2);
		if (strncmp(message1, message2, 4)==0) continue;
		hashFunction(hashAlgo, message1, hashValue1);
		hashFunction(hashAlgo, message2, hashValue2);
		count++;
	} while (memcmp(hashValue1, hashValue2, 3)!=0);
	printf("Cracked collision free property after %d trials\n", count);
	printf("Message 1: %s, hash: ", message1);
	for(i = 0; i < 3; i++) {
		printf("%02x", hashValue1[i]);
	}
	printf("\n");
	printf("Message 2: %s, hash: ", message2);
	for(i = 0; i < 3; i++) {
		printf("%02x", hashValue2[i]);
	}
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{	
	srand(time(0)); //use current time for random generator
	char *hashAlgo;
	hashAlgo = argv[1];
	clock_t start, end;
	int i,count;
	double time_taken = 0;
	start = clock();
	for (i=0,count=0;i<5;i++){
		count+=collisionFreeProperty(hashAlgo);
	}
	end = clock();
	time_taken = ((double)(end - start))/CLOCKS_PER_SEC;
	printf("Average trials to crack collision free property: %d \n", count/5);
	printf("Elapsed time: %f seconds\n", time_taken);
	time_taken = 0.0;
	start = clock();
	for (i=0,count=0;i<5;i++){
		count+=oneWayProperty(hashAlgo);
	}
	end = clock();
	time_taken = ((double)(end - start))/CLOCKS_PER_SEC;
	printf("Average trials to crack one way property: %d \n", count/5);
	printf("Elapsed time: %f seconds\n", time_taken);
}
