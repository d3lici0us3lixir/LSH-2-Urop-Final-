#ifndef LEA_H
#define LEA_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
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
#define LEA_BLOCKLEN 16
#define ROR(w,mv) ((w>>mv)|(w<<(32-mv))) 
#define ROL(w,mv) ((w<<mv)|(w>>(32-mv)))


class LEA {
public:
	LEA(uint8_t* input, uint8_t* key);
	string LEA_Round_Encrypt(int i);
	void LEA_Keyschedule(const uint8_t key[16]);
	uint32_t Plain[4] = { 0x00, };
	uint32_t ct[4] = { 0x00, };
	const uint32_t keyschedule_con[8] = { 0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957 };
	uint32_t rk[24][6] = { 0x00, };
	string ori_str;
	


};
#endif
