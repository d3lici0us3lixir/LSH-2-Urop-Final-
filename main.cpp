#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <cstdlib>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include "ARIA.h"
#include "BLOWFISH.h"
#include "CAMELLIA.h"
#include "GIFT.h"
#include "hash.h"
#include "LEA.h"
#include "PRESENT.h"
#include "SEED.h"
#include "Shingle.h"
#include "LSH.h"
#include "Simon.h"
#include "sm4.h"
using namespace std;


string make_plain_8(const uint8_t PLAIN[], int len) {
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < len; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(PLAIN[i]);

	}
	ori_str += ss.str();
	return ori_str;
}

string make_plain_32(const uint32_t PLAIN[], int len) {
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < len; i++) {
		// Convert each element to a two-digit hexadecimal string
		ss << std::hex << std::setw(8) << std::setfill('0') << static_cast<int>(PLAIN[i]);

	}
	ori_str += ss.str();
	return ori_str;
}

int main() {

	//cipher
	uint8_t Plain[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	uint32_t Plain2[2] = { 0x00112233, 0x44556677 };
	uint32_t Plain4[4] = { 0x00112233, 0x44556677,0x8899aabb, 0xccddeeff };
	uint8_t Plain10[10] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };
	uint8_t Key[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	uint32_t Key4[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
	uint8_t Key8[8] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
	uint8_t Key10[10] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09 };
	uint8_t Cipher[16] = { 0, };


	string plain_8 = make_plain_8(Plain, 16);
	string plain_32 = make_plain_32(Plain2,2);
	string plain_4 = make_plain_32(Plain4, 4);
	string plain_10 = make_plain_8(Plain10, 10);
	vector<vector<string>> minHashSignatures;
	vector<string> tmp;

	//LSH
	int shingleing_size = 5; // shingleing size
	const int number_of_input = 6;
	vector<string> LSH_input[number_of_input];//lsh test vector
	int num_permutation = 200; //b*r
	int num_bands = 10;//b
	int band_size = num_permutation / num_bands;//r
	const int test_size = 100;//lsh test vector
	string ROUND_CT;
	
	//cipher object
	ARIA aria(Plain, Cipher, Key);
	BLOWFISH blowfish(Plain2, Key8, 8);
	CAMELLIA camellia(Plain, Key);
	GIFT gift(Plain, Key);
	LEA lea(Plain, Key);
	PRESENT present(Plain10, Key10);
	SEED seed(Plain4, Key4);
	SM4 sm4(Plain, Key);


	//bit로 표현해보기 유사한 것 끼리


	vector<string> round_enc_text[10];
	/*
	0 : plain
	1 : ARIA
	2 : BLOWFISH -> different oupput size
	3 : SEED
	4 : LEA
	5 : CAMELLIA
	6 : GIFT
	7 : PRESENT
	8 : SM4
	
	*/
	int cnt = 0;
	for (int round = 0; round < 12; round++) {
		cnt = 0;
		cout << "Round " << round << endl;
		ROUND_CT = plain_8;
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = aria.ARIA_EnCrypt(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = blowfish.ROUND_Blowfish_Enc(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = seed.SEED_Enc(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = lea.LEA_Round_Encrypt(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = camellia.camelia_encrypt(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = gift.giftb128_8(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT = present.PRESENT_ENC(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		ROUND_CT =sm4.round(round);
		round_enc_text[cnt] = string_shingle(ROUND_CT, shingleing_size);
		sort(round_enc_text[cnt].begin(), round_enc_text[cnt].end());
		round_enc_text[cnt].erase(unique(round_enc_text[cnt].begin(), round_enc_text[cnt].end()), round_enc_text[cnt].end());
		cnt++;

		
		HashFunction hash_function(num_permutation);
		vector<vector<string>> minHashSignatures;
		vector<string> tmp;
		for (int j = 0; j < 8; j++) {
			tmp = hash_function.ComputeSignature(round_enc_text[j]);
			minHashSignatures.push_back(tmp);

		}
		bucket_hash(minHashSignatures, num_bands, band_size);

		minHashSignatures.clear();
		tmp.clear();



	}

	return 0;
}
