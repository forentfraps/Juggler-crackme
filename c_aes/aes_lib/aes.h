#ifndef _AES_HOMEMADE_
#define _AES_HOMEMADE_

void Encrypt(unsigned char* block, unsigned char* KeyList);
void Decrypt(unsigned char* block, unsigned char* KeyList);
void KeyScheduler(unsigned char* MasterKey, unsigned char* dest);

#endif
