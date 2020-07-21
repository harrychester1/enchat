//refrencing:
//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//https://www.openssl.org/docs/man1.1.0/man3/SHA256_Init.html
//https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html

#include <stdio.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void encryptionerror()          //is called on error with encryption (for future error handling and testing)
{
    //printf("encryption failed\n");
}

void decryptionerror()          //is called on error with decryption (for future error handling and testing)
{
    //printf("decryption failed\n");
}

void getiv(unsigned char *iv)   //generates 16 cryptographically pseudo random bytes 
{
    unsigned char temp;
    for (int i = 0; i < 16; i++)        //as it needs 16 bytes so loops 16 times
    {
        do
        {
            RAND_bytes(&temp, 1);       //gets a random byte
        } while (isalnum(temp) == 0);   //checks if it is an alpanumeric
        *(iv + i) = temp;
    }
    *(iv + 16) = '\0';                  //appends a null character
}

int decrypt(unsigned char *key, char *msgrecieved, char **output)   //extracts the ciphertext from the message sent and decrypts it using the passed in key and iv taken from the message sent
{
    EVP_CIPHER_CTX *ctx;
    int len, plainlen, cipherlen, i = 0;
    unsigned char ciphertext[3000], initvector[17];
    char temp[5];
    unsigned char *plaintextp;
    unsigned char plaintext[2048];
    for (i = 0; i < 4; i++)                 //retrieves the ciphertext lenth from the message recieved
        temp[i] = *(msgrecieved + i);
    cipherlen = strtol(temp, NULL, 10);
    for (i = 0; i < 16; i++)                //retrieves the initialisation vector from the message recieved
    {
        initvector[i] = *(msgrecieved + 4 + i);
    }
    initvector[16] = '\0';
    i = 0;
    for (int n = 0; n <= cipherlen; n++)    //retrieves the ciphertext from the message recieved
    {
        ciphertext[n] = *(msgrecieved + n + 20);
    }
    ciphertext[cipherlen] = '\0';
    if (!(ctx = EVP_CIPHER_CTX_new()))
        decryptionerror();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initvector))
        decryptionerror();
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen))    //adds the cipertext to the decryption proccess
        decryptionerror();
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    plainlen = len;
    if (1 != EVP_DecryptFinal_ex(ctx, &plaintext[len], &len))                   //decrypts the ciphertext
    {
        printf("password wrong\n"); //ERR_print_errors_fp(stderr);
        return 0;
    }
    plainlen += len;
    *(plaintext + plainlen + 1) = '\0';
    EVP_CIPHER_CTX_free(ctx);                   //garbage collection
    plaintextp = malloc(plainlen + 1);          
    memcpy(plaintextp, plaintext, plainlen);
    plaintextp[plainlen] = '\0';
    *output = plaintextp;
    return plainlen + 1;                        //returns a the size of the decrypted plaintext
}

int encrypt(char *plaintext, unsigned char *key, char **output)     //encrypts the plaintext passed into it and builds the message that will be sent over the network
{
    EVP_CIPHER_CTX *ctx;
    int len, clen;
    char temp[5], plaintexttemp[2048], msgtosend[2568];
    unsigned char initvector[17], ciphertext[2500];
    memset(ciphertext, '\0', 2500);
    char *msgtosendp;
    char *decrypted;
    do
    {
        getiv(initvector);                  //gets an initialisation vector 
        if (!(ctx = EVP_CIPHER_CTX_new()))
            encryptionerror();
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initvector))
            encryptionerror();
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext)))    //adds plaintext to the encryption proccess
            encryptionerror();
        clen = len;
        EVP_CIPHER_CTX_set_padding(ctx, 1);                         //makes sure padding is added
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  //encrypts the plaintext
            encryptionerror();
        clen += len;
        EVP_CIPHER_CTX_free(ctx);       //garbage collection
        sprintf(temp, "%04d", clen);    //}
        strcpy(msgtosend, temp);        //}
        strcat(msgtosend, initvector);  //}
        strcat(msgtosend, ciphertext);  //}builds the message to be sent
    } while (strlen(ciphertext) % 16 != 0 || decrypt(key, msgtosend, &decrypted) == 0); //calls decrypt to make sure it is able to be decrypted
    msgtosendp = malloc(clen + 21);
    memcpy(msgtosendp, msgtosend, clen + 21);
    *output = msgtosendp;
    return clen + 21;       //returns the size of the message to be send
}

unsigned char *hashpword(char password[32])                         //generates a sha256 of the string passed in
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *hashp;
    size_t length = strlen(password);
    SHA256(password, strlen(password), hash);   //hashes the password
    hashp = malloc(SHA256_DIGEST_LENGTH);
    memcpy(hashp, hash, SHA256_DIGEST_LENGTH);
    return hashp;                               //returns a pointer to the hashed password
}

//  int main()
//  {
//      unsigned char hash[SHA256_DIGEST_LENGTH], ciphertext[128];
//      char *msgtosend;
//      char password[32] = "password", plaintext[2048] = "11223344556677889900", *decryptedtext;
//      hashpword(password);
//      int cipherlen;
//      encrypt(plaintext, hash, &msgtosend);
//     decrypt(hash, msgtosend, &decryptedtext);
//      printf("%s\n",decryptedtext);
//      return 0;
//  }
