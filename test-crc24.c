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

// Plaintext is a message; terminated by a CRC.
// the CRC is part of the message (and thus encrypted).
// To make string printing easy - we out a \0 just
// before the CRC.

	char plaintext[2*16+1] = "Pay me 1.00 now ! please!!!\0CRC\0";

  	uint32_t crc;
	crc  = crc24_calc((uint8_t *)plaintext,32-3);

	printf("Original msg   : %s\n", plaintext);
	printf("Original CRC24 : %02x.%02x.%02x\n",
		(uint8_t)plaintext[29], 
		(uint8_t)plaintext[30], 
		(uint8_t)plaintext[31]);

        plaintext[31 - 0] = (crc >> 16) & 0xFF;
        plaintext[31 - 1] = (crc >>  8) & 0xFF;
        plaintext[31 - 2] = (crc >>  0) & 0xFF;

	AES_init_ctx_iv(&ctx,key,iv);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)plaintext, 16);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)plaintext+16, 16);

// Start of the attack
//
	uint32_t cypher_crc  = crc24_calc((uint8_t *)plaintext,32-3);

// tweak the plaintext.
//
	plaintext[ 8 ] ^= ('.' ^ '0');

// make sure the crc gets tweaked too
	uint32_t post_cypher_crc  = crc24_calc((uint8_t *)plaintext,32-3);
	uint32_t crc_flip = cypher_crc ^ post_cypher_crc;
	
        plaintext[31 - 0] ^= (crc_flip >> 16) & 0xFF;
        plaintext[31 - 1] ^= (crc_flip >>  8) & 0xFF;
        plaintext[31 - 2] ^= (crc_flip >>  0) & 0xFF;

        printf("\n *** attack - changed char 8 into a '0'\n\n");
// end of the attack.

	AES_init_ctx_iv(&ctx,key,iv);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)plaintext, 16);
	AES_CTR_xcrypt_buffer(&ctx,(uint8_t *)plaintext+16, 16);

	crc  = crc24_calc((uint8_t *)plaintext,32-3);

	printf("Decoded msg    : %s\n", plaintext);
	printf("Final CRC24    : %02x.%02x.%02x and is ",
		(uint8_t)plaintext[29], 
		(uint8_t)plaintext[30], 
		(uint8_t)plaintext[31]);

	if (
		((uint8_t)plaintext[31 - 0] == ((crc >> 16) & 0xFF)) &&
		((uint8_t)plaintext[31 - 1] == ((crc >>  8) & 0xFF)) &&
		((uint8_t)plaintext[31 - 2] == ((crc >>  0) & 0xFF)) 
	) printf("OK (matches decoded cleartext)\n"); else printf("CRC spotted the error!");

	exit(0);
};
