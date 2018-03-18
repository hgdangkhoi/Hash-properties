#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void getHash(char * hashAlgo, char *message, unsigned char *md_value) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char value[EVP_MAX_MD_SIZE];
	int md_len, i;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashAlgo);
	if(!md) {
		printf("Unknown message digest %s\n", hashAlgo);
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	
	#strncpy(md_value, value, 12);
}

void setRndStr(char *message) {
	int i;
	for (i=0;i<strlen(message);i++)
		message[i] = rand()%256-128;
}

int crackOneWayHash(char * hashAlgo) {
	char message1[12], message2[12];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	
	int count=0, i;
	setRndStr(message1);
    
	getHash(hashAlgo, message1, digt1);
	// run the crack
	do {
    	
		setRndStr(message2);
		getHash(hashAlgo, message2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 12)!=0);
	
	printf("cracked after %d tries! same digest ", count, message1, message2);
	for(i = 0; i < 12; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

int crackCollisionHash(char * hashAlgo) {
	char message1[12], message2[12];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	
	int count=0, i;
	
	do {
		setRndStr(message1);
		getHash(hashAlgo, message1, digt1);
		setRndStr(message2);
		getHash(hashAlgo, message2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 12)!=0);
	printf("cracked after %d tries! same digest ", count);
	for(i = 0; i < 12; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{
	char *hashAlgo;
	if(!argv[1])
		// set to md5 by default
		hashAlgo = "md5";
	else
		hashAlgo = argv[1];
	srand((int)time(0));	// init random seed
	int i,count;
	for (i=0,count=0;i<7;i++)
		count+=crackCollisionHash(hashAlgo);
	printf("average time cracking collision-free: %d \n", count/7);
	for (i=0,count=0;i<7;i++)
		count+=crackOneWayHash(hashAlgo);
	printf("average time cracking one-way: %d \n", count/7);
}