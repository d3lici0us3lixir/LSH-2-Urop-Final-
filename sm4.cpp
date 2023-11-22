#include "sm4.h"



SM4::SM4(uint8_t* key, uint8_t pt[16]) {
	key_expanding(key);
	for (int i = 0; i < 4; i++) {
		state[i][0] = pt[4 * i];
		state[i][1] = pt[4 * i + 1];
		state[i][2] = pt[4 * i + 2];
		state[i][3] = pt[4 * i + 3];
	}
}

void SM4::left_shift(uint8_t pt[4], uint8_t result[4], int num) {
	int div = num / 8;
	int mod = num % 8;

	uint8_t temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = pt[(i + div) % 4];
	}

	result[3] = (temp[3] << mod) + (temp[0] >> (8 - mod));

	for (int i = 0; i < 3; i++) {
		result[i] = ((temp[i] << mod) + (temp[i + 1] >> (8 - mod)));
	}
}

void SM4::L(uint8_t pt[4], uint8_t ct[4]) {
	uint8_t c1[4], c2[4], c3[4], c4[4];
	left_shift(pt, c1, 2);
	left_shift(pt, c2, 10);
	left_shift(pt, c3, 18);
	left_shift(pt, c4, 24);

	ct[0] = pt[0] ^ c1[0] ^ c2[0] ^ c3[0] ^ c4[0];
	ct[1] = pt[1] ^ c1[1] ^ c2[1] ^ c3[1] ^ c4[1];
	ct[2] = pt[2] ^ c1[2] ^ c2[2] ^ c3[2] ^ c4[2];
	ct[3] = pt[3] ^ c1[3] ^ c2[3] ^ c3[3] ^ c4[3];
}

void SM4::T(uint8_t pt[4], uint8_t ct[4]) {
	uint8_t state[4];
	state[0] = sbox[pt[0]];
	state[1] = sbox[pt[1]];
	state[2] = sbox[pt[2]];
	state[3] = sbox[pt[3]];
	L(state, ct);
}

void SM4::F(uint8_t pt[16], uint8_t key[4], uint8_t ct[4]) {
	uint8_t state[4], state2[4];
	state[0] = pt[4] ^ pt[8] ^ pt[12] ^ key[0];
	state[1] = pt[5] ^ pt[9] ^ pt[13] ^ key[1];
	state[2] = pt[6] ^ pt[10] ^ pt[14] ^ key[2];
	state[3] = pt[7] ^ pt[11] ^ pt[15] ^ key[3];
	T(state, state2);
	ct[0] = state2[0] ^ pt[0];
	ct[1] = state2[1] ^ pt[1];
	ct[2] = state2[2] ^ pt[2];
	ct[3] = state2[3] ^ pt[3];
}

void SM4::L1(uint8_t pt[4], uint8_t ct[4]) {
	uint8_t state[4], state2[4];
	left_shift(pt, state, 13);
	left_shift(pt, state2, 23);

	ct[0] = pt[0] ^ state[0] ^ state2[0];
	ct[1] = pt[1] ^ state[1] ^ state2[1];
	ct[2] = pt[2] ^ state[2] ^ state2[2];
	ct[3] = pt[3] ^ state[3] ^ state2[3];
}

void SM4::T1(uint8_t pt[4], uint8_t ct[4]) {
	uint8_t state[4];
	state[0] = sbox[pt[0]];
	state[1] = sbox[pt[1]];
	state[2] = sbox[pt[2]];
	state[3] = sbox[pt[3]];
	L1(state, ct);
}

void SM4::key_expanding(uint8_t* key) {
	int i;
	uint8_t state[36][4];
	uint8_t state2[4], state3[4];

	for (i = 0; i < 4; i++) {
		state[0][i] = key[i] ^ fk[i];
		state[1][i] = key[i + 4] ^ fk[i + 4];
		state[2][i] = key[i + 8] ^ fk[i + 8];
		state[3][i] = key[i + 12] ^ fk[i + 12];
	}

	for (i = 0; i < 32; i++) {
		state2[0] = state[i + 1][0] ^ state[i + 2][0] ^ state[i + 3][0] ^ ck[i * 4];
		state2[1] = state[i + 1][1] ^ state[i + 2][1] ^ state[i + 3][1] ^ ck[i * 4 + 1];
		state2[2] = state[i + 1][2] ^ state[i + 2][2] ^ state[i + 3][2] ^ ck[i * 4 + 2];
		state2[3] = state[i + 1][3] ^ state[i + 2][3] ^ state[i + 3][3] ^ ck[i * 4 + 3];
		T1(state2, state3);
		state[i + 4][0] = state3[0] ^ state[i][0];
		state[i + 4][1] = state3[1] ^ state[i][1];
		state[i + 4][2] = state3[2] ^ state[i][2];
		state[i + 4][3] = state3[3] ^ state[i][3];
		key_ex[i][0] = state[i + 4][0];
		key_ex[i][1] = state[i + 4][1];
		key_ex[i][2] = state[i + 4][2];
		key_ex[i][3] = state[i + 4][3];
	}
}

string SM4::make_return_str() {
	ostringstream ss;
	for (int i = 0; i < 16; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << hex << setw(2) << setfill('0') << static_cast<int>(ct[i]);

	}
	string ori_str = "";
	ori_str += ss.str();
	return ori_str;
}


string SM4::round(uint8_t rounding) {
	int i = rounding;
	state2[0] = state[i][0];
	state2[1] = state[i][1];
	state2[2] = state[i][2];
	state2[3] = state[i][3];
	state2[4] = state[i + 1][0];
	state2[5] = state[i + 1][1];
	state2[6] = state[i + 1][2];
	state2[7] = state[i + 1][3];
	state2[8] = state[i + 2][0];
	state2[9] = state[i + 2][1];
	state2[10] = state[i + 2][2];
	state2[11] = state[i + 2][3];
	state2[12] = state[i + 3][0];
	state2[13] = state[i + 3][1];
	state2[14] = state[i + 3][2];
	state2[15] = state[i + 3][3];
	F(state2, key_ex[i], state3);
	state[i + 4][0] = state3[0];
	state[i + 4][1] = state3[1];
	state[i + 4][2] = state3[2];
	state[i + 4][3] = state3[3];
	ct[0] = state[rounding + 3][0];
	ct[1] = state[rounding + 3][1];
	ct[2] = state[rounding + 3][2];
	ct[3] = state[rounding + 3][3];

	ct[4] = state[rounding + 2][0];
	ct[5] = state[rounding + 2][1];
	ct[6] = state[rounding + 2][2];
	ct[7] = state[rounding + 2][3];

	ct[8] = state[rounding + 1][0];
	ct[9] = state[rounding + 1][1];
	ct[10] = state[rounding + 1][2];
	ct[11] = state[rounding + 1][3];

	ct[12] = state[rounding][0];
	ct[13] = state[rounding][1];
	ct[14] = state[rounding][2];
	ct[15] = state[rounding][3];

	string return_str = make_return_str();
	return return_str;

}


/*
int main() {
	uint8_t pt[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	SM4 sm4(key, pt);
	string t;
	for (int i = 0; i < 32; i++) {
		t = sm4.round(i);
		cout << "ROUND : " << t << endl;
	}


	return 0;
}
*/