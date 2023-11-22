#include "CAMELLIA.h"
typedef unsigned char uint8_t;
typedef unsigned int  uint32_t;

#define KL 0
#define KR 4
#define KA 8
#define KB 12
#define L  0
#define R  64




CAMELLIA::CAMELLIA(uint8_t* PT, uint8_t* KEY) {
	copy(PT, PT + 16, pt);

}

void CAMELLIA::p_function(uint8_t pt[8], uint8_t result[8]) {
	result[0] = pt[0] ^ pt[2] ^ pt[3] ^ pt[5] ^ pt[6] ^ pt[7];
	result[1] = pt[0] ^ pt[1] ^ pt[3] ^ pt[4] ^ pt[6] ^ pt[7];
	result[2] = pt[0] ^ pt[1] ^ pt[2] ^ pt[4] ^ pt[5] ^ pt[7];
	result[3] = pt[1] ^ pt[2] ^ pt[3] ^ pt[4] ^ pt[5] ^ pt[6];
	result[4] = pt[0] ^ pt[1] ^ pt[5] ^ pt[6] ^ pt[7];
	result[5] = pt[1] ^ pt[2] ^ pt[4] ^ pt[6] ^ pt[7];
	result[6] = pt[2] ^ pt[3] ^ pt[4] ^ pt[5] ^ pt[7];
	result[7] = pt[0] ^ pt[3] ^ pt[4] ^ pt[5] ^ pt[6];
}

void CAMELLIA::s_function(uint8_t pt[8], uint8_t result[8]) {
	result[0] = sbox1[pt[0]];
	result[1] = sbox2[pt[1]];
	result[2] = sbox3[pt[2]];
	result[3] = sbox4[pt[3]];
	result[4] = sbox2[pt[4]];
	result[5] = sbox3[pt[5]];
	result[6] = sbox4[pt[6]];
	result[7] = sbox1[pt[7]];
}

void CAMELLIA::f_function(uint8_t pt[8], uint8_t key[8], uint8_t result[8]) {
	uint8_t state[8] = { 0, };
	uint8_t state2[8] = { 0, };
	for (int i = 0; i < 8; i++) {
		state[i] = pt[i] ^ key[i];
	}
	s_function(state, state2);
	p_function(state2, result);
}

void CAMELLIA::left_shift(uint8_t pt[16], uint8_t result[16], int num) {
	int div = num / 8;
	int mod = num % 8;

	uint8_t temp[16];
	for (int i = 0; i < 16; i++) {
		temp[i] = pt[(i + div) % 16];
	}

	result[15] = (temp[15] << mod) + (temp[0] >> (8 - mod));

	for (int i = 0; i < 15; i++) {
		result[i] = ((temp[i] << mod) + (temp[i + 1] >> (8 - mod)));
	}



}

void CAMELLIA::left_shift_for4(uint8_t pt[4], uint8_t result[4], int num) {
	int div = num / 8;
	int mod = num % 8;

	uint8_t temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = pt[(i + div) % 16];
	}

	result[3] = (temp[3] << mod) + (temp[0] >> (8 - mod));

	for (int i = 0; i < 3; i++) {
		result[i] = ((temp[i] << mod) + (temp[i + 1] >> (8 - mod)));
	}



}

void CAMELLIA::make_keyAB(uint8_t key[16], uint8_t ka[16]) {
	uint8_t left[8];
	uint8_t right[8];
	uint8_t state[8];
	uint8_t state2[8];
	uint8_t state3[8];
	int i;
	for (i = 0; i < 8; i++) {
		left[i] = key[i];
		right[i] = key[i + 8];
	}

	f_function(left, sigma[0], state);
	for (i = 0; i < 8; i++) {
		state[i] ^= right[i];
	}

	f_function(state, sigma[1], state2);
	for (i = 0; i < 8; i++) {
		state2[i] ^= (left[i] ^ left[i]);
		state[i] ^= (right[i]);
	}

	f_function(state2, sigma[2], state3);
	for (i = 0; i < 8; i++) {
		state3[i] ^= state[i];
	}

	f_function(state3, sigma[3], state);
	for (i = 0; i < 8; i++) {
		state[i] ^= state2[i];
		ka[i] = state[i];
		ka[i + 8] = state3[i];
	}
}

void CAMELLIA::FL(uint8_t pt[8], uint8_t key[8], uint8_t result[8]) {
	uint8_t left[4];
	uint8_t right[4];
	uint8_t state[4], state2[4], state3[4];

	for (int i = 0; i < 4; i++) {
		left[i] = pt[i];
		right[i] = pt[i + 4];
	}

	for (int i = 0; i < 4; i++) {
		state[i] = left[i] & key[i];
	}

	left_shift_for4(state, state2, 1);

	for (int i = 0; i < 4; i++) {
		result[i] = ((state2[i] ^ right[i]) | key[i + 4]) ^ left[i];
		result[i + 4] = state2[i] ^ right[i];
	}
}

void CAMELLIA::FL_inverse(uint8_t pt[8], uint8_t key[8], uint8_t result[8]) {
	uint8_t left[4];
	uint8_t right[4];
	uint8_t state[4], state2[4], state3[4];

	for (int i = 0; i < 4; i++) {
		left[i] = pt[i];
		right[i] = pt[i + 4];
	}

	for (int i = 0; i < 4; i++) {
		result[i] = (right[i] | key[i + 4]) ^ left[i];
		state[i] = result[i] & key[i];
	}


	left_shift_for4(state, state2, 1);
	for (int i = 0; i < 4; i++) {

		result[i + 4] = pt[i + 4] ^ state2[i];
	}
}


void CAMELLIA::key_schedule(uint8_t* key) {
	int i;
	uint8_t ka[16];
	make_keyAB(key, ka);
	uint8_t state[16], state2[16];
	left_shift(ka, state, 111);

	for (i = 0; i < 8; i++) {
		kw[0][i] = key[i];
		kw[1][i] = key[i + 8];
		kw[2][i] = state[i];
		kw[3][i] = state[i + 8];
	}

	left_shift(key, state, 15);
	left_shift(ka, state2, 15);
	for (i = 0; i < 8; i++) {
		k[0][i] = ka[i];
		k[1][i] = ka[i + 8];
		k[2][i] = state[i];
		k[3][i] = state[i + 8];
		k[4][i] = state2[i];
		k[5][i] = state2[i + 8];
	}

	left_shift(key, state, 45);
	left_shift(ka, state2, 45);

	for (i = 0; i < 8; i++) {
		k[6][i] = state[i];
		k[7][i] = state[i + 8];
		k[8][i] = state2[i];
	}

	left_shift(key, state, 60);
	left_shift(ka, state2, 60);

	for (i = 0; i < 8; i++) {
		k[9][i] = state[i + 8];
		k[10][i] = state2[i];
		k[11][i] = state2[i + 8];
	}

	left_shift(key, state, 94);
	left_shift(ka, state2, 94);

	for (i = 0; i < 8; i++) {
		k[12][i] = state[i];
		k[13][i] = state[i + 8];
		k[14][i] = state2[i];
		k[15][i] = state2[i + 8];
	}

	left_shift(key, state, 111);

	for (i = 0; i < 8; i++) {
		k[16][i] = state[i];
		k[17][i] = state[i + 8];
	}

	left_shift(ka, state, 30);
	left_shift(key, state2, 77);
	for (i = 0; i < 8; i++) {
		kl[0][i] = state[i];
		kl[1][i] = state[i + 8];
		kl[2][i] = state2[i];
		kl[3][i] = state2[i + 8];
	}

}

void CAMELLIA::camelia_round(uint8_t pt[16], uint8_t key[8], uint8_t result[16]) {
	uint8_t left[8];
	uint8_t right[8];
	uint8_t state[8];

	for (int i = 0; i < 8; i++) {
		left[i] = pt[i];
		right[i] = pt[i + 8];
	}

	f_function(left, key, state);

	for (int i = 0; i < 8; i++) {
		result[i] = state[i] ^ right[i];
		result[i + 8] = left[i];
	}

}

string CAMELLIA::camelia_encrypt(int round) {
	string return_str;

	if (round < 6 && round == 0) {

		for (int i = 0; i < 8; i++) {
			state[i] = kw[0][i] ^ pt[i];
			state[i + 8] = kw[1][i] ^ pt[i + 8];
		}


		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];
		}
		return_str = make_return_str(state2);
		return return_str;

	}
	else if (round < 6 && round>0) {
		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];
		}
		return_str = make_return_str(state2);
		return return_str;
	}


	else if (round < 12 && round == 6) {
		for (int i = 0; i < 8; i++) {
			left[i] = state[i];
			right[i] = state[i + 8];
		}

		FL(left, kl[0], left2);
		FL_inverse(right, kl[1], right2);

		for (int i = 0; i < 8; i++) {
			state[i] = left2[i];
			state[i + 8] = right2[i];
		}


		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];

		}
		return_str = make_return_str(state2);
		return return_str;
	}
	else if (round < 12 && round <= 6) {
		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];
		}
		return_str = make_return_str(state2);
		return return_str;
	}

	else if (round < 18 && round == 12) {
		for (int i = 0; i < 8; i++) {
			left[i] = state[i];
			right[i] = state[i + 8];
		}

		FL(left, kl[2], left2);
		FL_inverse(right, kl[3], right2);

		for (int i = 0; i < 8; i++) {
			state[i] = left2[i];
			state[i + 8] = right2[i];
		}


		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];

		}
		return_str = make_return_str(state2);
		return return_str;
	}
	else if (round < 18) {
		camelia_round(state, k[round], state2);
		for (int j = 0; j < 16; j++) {
			state[j] = state2[j];

		}
		return_str = make_return_str(state2);
		return return_str;
	}
	else if (round == 17) {
		for (int i = 0; i < 8; i++) {
			left[i] = state[i];
			right[i] = state[i + 8];
		}

		for (int i = 0; i < 8; i++) {
			left2[i] = right[i] ^ kw[2][i];
			right2[i] = left[i] ^ kw[3][i];
		}

		for (int i = 0; i < 8; i++) {
			result[i] = left2[i];
			result[i + 8] = right2[i];
		}
		return_str = make_return_str(result);
		return return_str;
	}

}

string CAMELLIA::make_return_str(uint8_t* state) {
	vector<string> connect_str;
	connect_str.clear();
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < 16; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(state[i]);

	}
	ori_str += ss.str();

	return ori_str;
}


/*

int main()
{
	uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	uint8_t pt[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	uint8_t ct[16];

	CAMELLIA camellia(pt, key);
	camellia.key_schedule(key);
	string round_str;
	for (int round = 0; round < 16; round++)
	{
		round_str = camellia.camelia_encrypt(round);
		cout << round_str << endl;
	}

}
*/
