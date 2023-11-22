#ifndef PRESENT_H
#define PRESENT_H

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

class PRESENT {
public:
	PRESENT(uint8_t* STATE, uint8_t* KEY);
	string PRESENT_ENC(int round);
	string make_return_str(volatile uint8_t* state);
	const uint8_t sBox4[16] = { 0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2 };
	volatile uint8_t state[8];
	uint8_t key[10];
	uint8_t i = 0;
	//	pLayer variables
	uint8_t position = 0;
	uint8_t element_source = 0;
	uint8_t bit_source = 0;
	uint8_t element_destination = 0;
	uint8_t bit_destination = 0;
	uint8_t temp_pLayer[8] = { 0 };
	//	Key scheduling variables
	uint8_t round = 0;
	uint8_t save1 = 0;
	uint8_t save2 = 0;

};
#endif
