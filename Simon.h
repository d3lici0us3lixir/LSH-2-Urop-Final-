#pragma once
#ifndef SIMON_H
#define SIMON_H

#define WORD_SIZE 16
#define KEY_SIZE 32
#define NUM_ROUNDS 32

#include<stdint.h>
#include <stdio.h>
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
using namespace std;

class SIMON {
public:
	SIMON(uint64_t* plain, uint64_t* key);
	void simon_key_schedule(uint64_t* key, uint64_t* round_keys);
	string make_return_str(uint64_t x, uint64_t u);
	string simon_encrypt(int round);
	uint64_t round_keys[NUM_ROUNDS + 1];
	uint64_t x;
	uint64_t y;
	uint64_t pt[2] = {0,};
	const uint64_t z[5] = { 0b0001100111000011010100100010111110110011100001101010010001011111,
						0b0001011010000110010011111011100010101101000011001001111101110001,
						0b0011001101101001111110001000010100011001001011000000111011110101,
						0b0011110000101100111001010001001000000111101001100011010111011011,
						0b0011110111001001010011000011101000000100011011010110011110001011 };
};
#endif
