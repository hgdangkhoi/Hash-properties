#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void getHash(char * hashname, char *msg, unsigned char *md_value) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	//unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashname);
	if(!md) {
		printf("Unknown message digest %s\n", hashname);
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, strlen(msg));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	// shrink the digest's length to 24 (3 words)
	//strncpy( digt, md_value, 3);
}

void setRndStr(char *msg) {
	int i;
	for (i=0;i<11;i++)
		msg[i] = rand()%256-128;
}

int crackOneWayHash(char * hashname) {
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	// we do not need to generate words, instead generating number only
	int count=0, i;
	setRndStr(msg1);
    	//sprintf(msg1, "%d", rand());	// convert to string
	// get an initial message
	getHash(hashname, msg1, digt1);
	// run the crack
	do {
    		//sprintf(msg2, "%d", rand());	// convert to string
		setRndStr(msg2);
		getHash(hashname, msg2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);
	//printf("\n cracked after %d tries! %s and %s has same digest ", count, msg1, msg2);
	printf("cracked after %d tries! same digest ", count, msg1, msg2);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

int crackCollisionHash(char * hashname) {
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	// we do not need to generate words, instead generating number only
	int count=0, i;
	// run the crack
	do {
    		//sprintf(msg1, "%d", rand());	// convert to string
		setRndStr(msg1);
		getHash(hashname, msg1, digt1);
    		//sprintf(msg2, "%d", rand());	// convert to string
		setRndStr(msg2);
		getHash(hashname, msg2, digt2);
		count++;
	} while (strncmp(digt1, digt2, 3)!=0);
	//printf("\n cracked after %d tries! %s and %s has same digest ", count, msg1, msg2);
	printf("cracked after %d tries! same digest ", count);
	for(i = 0; i < 3; i++) printf("%02x", digt1[i]);
	printf("\n");
	return count;
}

main(int argc, char *argv[])
{
	char *hashname;
	if(!argv[1])
		// set to md5 by default
		hashname = "md5";
	else
		hashname = argv[1];
	srand((int)time(0));	// init random seed
	int i,count;
	for (i=0,count=0;i<15;i++)
		count+=crackCollisionHash(hashname);
	printf("average time cracking collision-free: %d \n", count/15);
	for (i=0,count=0;i<5;i++)
		count+=crackOneWayHash(hashname);
	printf("average time cracking one-way: %d \n", count/5);
}