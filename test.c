/*  
 
 Copyright (c) 1987, 1991, 2021 Dirk-Willem van Gulik <dirkx(at)webweaving(dot)org>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/

#include <stdlib.h>
#include <stdio.h>

#include "tiny-AES-c/aes.c"
#include "crc24.c"

int main(int argc, char ** argv) {
	struct AES_ctx ctx;
	uint8_t iv[16] = { 1, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15 };
	uint8_t key[16] = { 1, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15 };

// Plaintext is a message.
// To make string printing easy - we add the \0.

	char message[16+1] = "Ok to pay 1.00 !\0";
	printf("Original msg   : %s\n", message);

// ENCRYPT
	AES_init_ctx_iv(&ctx,key,iv);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)message, 16);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)message+16, 16);

// Start of the attack
// tweak the message; change the dot into a 0 to increase
// the approved amount.
//
	message[ 11 ] ^= ('.' ^ '0');

        printf("\n *** attack - changed char 8 into a '0'\n\n");
// end of the attack.

// DECRYPT
	AES_init_ctx_iv(&ctx,key,iv);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)message, 16);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)message+16, 16);

	printf("Decoded msg    : %s\n", message);

	exit(0);
};
