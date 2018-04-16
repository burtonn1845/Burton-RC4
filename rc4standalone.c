#include <openssl/evp.h>
/*#include "rc4.h"
#include "rc4_enc.c"
#include "rc4_locl.h"
#include "rc4_skey.c"*/
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stdbool.h>
//xor test case
char *xorTest(char *buf,int bytesRead)
{	
	//xor test
	
	for(int i = 0; i<bytesRead;i++)
	{
		buf[i] = buf[i] ^ 0x0011;
	}
	return buf;
}

void main(int argc, char *argv[])
{
   
   const EVP_CIPHER *type = EVP_rc4();
    EVP_CIPHER_CTX *ctx;
    const EVP_MD *digest = EVP_sha256();
    int infd,outfd,bytesRead,bytesWritten,keyBytes,evpBytesRead;
    unsigned char buf[4096];
    const char magic[] = "Salted__";
    const char salt[] = "12345678";
    bool eof=false;
    unsigned char hexkey[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char returnBuf[4096+EVP_MAX_BLOCK_LENGTH];

    if(argc != 5)
    {
        printf("not enough arguments\nUsage:./rc4standalone.out <password> <infile> <outfile> <e/d>\n");
        return;
    }
    const unsigned char *pw = argv[1];
    char *inpath = argv[2];
    char *outpath = argv[3];
    int tool;
    int pwLength = strlen(pw);
    printf("entered pw : %s\tlength : %d\n",pw,pwLength);
   	
	//check for encrypt or decrypt
	if(strcmp(argv[4],"e") == 0)
	{
		tool = 1;
		printf("set to encrypt.\n");
	}
	else 
	{
		tool = 0;
		printf("set to decrypt.\n");
	}
	//open in file
	if(( infd = open(inpath,O_RDWR) ) == -1)
	{
		printf("failed to open file.\n");
		return;
	}
	//create out file
	if((outfd = creat(outpath,S_IRWXU)) == -1)
	{
		printf("outfile creation failed.\n");
		return;
	}
	//use password to create a key
	if((keyBytes=EVP_BytesToKey(type, digest, salt,pw,pwLength,1,hexkey,NULL)) == 0)
	{
		printf("EVP_BytesToKey has failed.\n");
		return;
	}
	//print key
	printf("keyBytes: %d\n",keyBytes);
	 if (keyBytes > 0) {
                printf("key=");
                for (int i = 0; i < keyBytes; i++)
                    printf("%02X", hexkey[i]);
                printf("\n");
	}
	//initialzie cipher context
    	ctx = EVP_CIPHER_CTX_new();
	//populate cipher context with needed information
   	EVP_CipherInit_ex(ctx,EVP_rc4(),NULL,hexkey,NULL,tool);
	
  	printf("Preparing to read bytes...\n");
	
	//write salt and header information to out file if encrypting
	if(tool == 1){  	
	write(outfd,magic,8);
	write(outfd,salt,8);
	}//seek past header and salt information if decrypting
	else if(tool == 0){
	lseek(infd,16,SEEK_SET);
	}
	
	//loop while not at eof
	while(eof == false){
		//read up to 4096 bytes into buffer
		if(( bytesRead = read(infd,buf,4096)) == -1)
		{
			printf("failed to read file.\n");
			return;
		}
		//check if at eof
		else if (bytesRead <= 0)
		{
			eof=true;
		}
		printf("bytesRead: %d\n",bytesRead);

		//xor test case to verify read/write/creation is functional 
		//returnBuf = xorTest(buf,bytesRead);
		
		//use either update or final evp function depending on file location
		if(eof==false)
		{
			EVP_CipherUpdate(ctx,returnBuf,&evpBytesRead,buf,bytesRead);
		}
		else if(eof == true)
		{
			EVP_CipherFinal_ex(ctx,returnBuf,&evpBytesRead);
			printf("Finalizing...\n");
		}
	//	printf("evpbytesread: %d\n",evpBytesRead);
		
		//write bytes to file
		if((bytesWritten = write(outfd,returnBuf,evpBytesRead)) == -1)
		{
			printf("failed to write to file\n");
			return;
		}
	}    
	//EVP_CIPHER_CTX_cleanup(ctx);	
    	close(infd);
	close(outfd);
}
