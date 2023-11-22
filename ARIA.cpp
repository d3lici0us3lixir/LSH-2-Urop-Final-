#include "ARIA.h"

#define BLOCKLEN 16

ARIA::ARIA(uint8_t* pt, uint8_t* ct, uint8_t* key) {

	std::copy(pt, pt + 16, PT);
	std::copy(key, key + 16, KEY);
	std::copy(ct, ct + 16, CT);
	Enc_KEY_Expansion(key, rk);
	memcpy(copy_pt, pt, BLOCKLEN * sizeof(uint8_t));

}

void ARIA::Add_SubstOdd_Layer(uint8_t* input, uint8_t* key) {
	input[0] = ARIA_S1[input[0] ^ key[0]];
	input[1] = ARIA_S2[input[1] ^ key[1]];
	input[2] = ARIA_RS1[input[2] ^ key[2]];
	input[3] = ARIA_RS2[input[3] ^ key[3]];
	input[4] = ARIA_S1[input[4] ^ key[4]];
	input[5] = ARIA_S2[input[5] ^ key[5]];
	input[6] = ARIA_RS1[input[6] ^ key[6]];
	input[7] = ARIA_RS2[input[7] ^ key[7]];
	input[8] = ARIA_S1[input[8] ^ key[8]];
	input[9] = ARIA_S2[input[9] ^ key[9]];
	input[10] = ARIA_RS1[input[10] ^ key[10]];
	input[11] = ARIA_RS2[input[11] ^ key[11]];
	input[12] = ARIA_S1[input[12] ^ key[12]];
	input[13] = ARIA_S2[input[13] ^ key[13]];
	input[14] = ARIA_RS1[input[14] ^ key[14]];
	input[15] = ARIA_RS2[input[15] ^ key[15]];
}

void ARIA::Add_SubstEven_Layer(uint8_t* input, uint8_t* key) {
	input[0] = ARIA_RS1[input[0] ^ key[0]];
	input[1] = ARIA_RS2[input[1] ^ key[1]];
	input[2] = ARIA_S1[input[2] ^ key[2]];
	input[3] = ARIA_S2[input[3] ^ key[3]];
	input[4] = ARIA_RS1[input[4] ^ key[4]];
	input[5] = ARIA_RS2[input[5] ^ key[5]];
	input[6] = ARIA_S1[input[6] ^ key[6]];
	input[7] = ARIA_S2[input[7] ^ key[7]];
	input[8] = ARIA_RS1[input[8] ^ key[8]];
	input[9] = ARIA_RS2[input[9] ^ key[9]];
	input[10] = ARIA_S1[input[10] ^ key[10]];
	input[11] = ARIA_S2[input[11] ^ key[11]];
	input[12] = ARIA_RS1[input[12] ^ key[12]];
	input[13] = ARIA_RS2[input[13] ^ key[13]];
	input[14] = ARIA_S1[input[14] ^ key[14]];
	input[15] = ARIA_S2[input[15] ^ key[15]];
}

void ARIA::DiffLayer(uint8_t* input) {
	uint8_t temp[16] = { 0x00, };

	temp[0] = input[3] ^ input[4] ^ input[6] ^ input[8] ^ input[9] ^ input[13] ^ input[14];
	temp[1] = input[2] ^ input[5] ^ input[7] ^ input[8] ^ input[9] ^ input[12] ^ input[15];
	temp[2] = input[1] ^ input[4] ^ input[6] ^ input[10] ^ input[11] ^ input[12] ^ input[15];
	temp[3] = input[0] ^ input[5] ^ input[7] ^ input[10] ^ input[11] ^ input[13] ^ input[14];
	temp[4] = input[0] ^ input[2] ^ input[5] ^ input[8] ^ input[11] ^ input[14] ^ input[15];
	temp[5] = input[1] ^ input[3] ^ input[4] ^ input[9] ^ input[10] ^ input[14] ^ input[15];
	temp[6] = input[0] ^ input[2] ^ input[7] ^ input[9] ^ input[10] ^ input[12] ^ input[13];
	temp[7] = input[1] ^ input[3] ^ input[6] ^ input[8] ^ input[11] ^ input[12] ^ input[13];
	temp[8] = input[0] ^ input[1] ^ input[4] ^ input[7] ^ input[10] ^ input[13] ^ input[15];
	temp[9] = input[0] ^ input[1] ^ input[5] ^ input[6] ^ input[11] ^ input[12] ^ input[14];
	temp[10] = input[2] ^ input[3] ^ input[5] ^ input[6] ^ input[8] ^ input[13] ^ input[15];
	temp[11] = input[2] ^ input[3] ^ input[4] ^ input[7] ^ input[9] ^ input[12] ^ input[14];
	temp[12] = input[1] ^ input[2] ^ input[6] ^ input[7] ^ input[9] ^ input[11] ^ input[12];
	temp[13] = input[0] ^ input[3] ^ input[6] ^ input[7] ^ input[8] ^ input[10] ^ input[13];
	temp[14] = input[0] ^ input[3] ^ input[4] ^ input[5] ^ input[9] ^ input[11] ^ input[14];
	temp[15] = input[1] ^ input[2] ^ input[4] ^ input[5] ^ input[8] ^ input[10] ^ input[15];

	memcpy(input, temp, 16 * sizeof(uint8_t));
}

void ARIA::Round_odd(uint8_t* input, uint8_t* rk) {
	Add_SubstOdd_Layer(input, rk);
	DiffLayer(input);
}

void ARIA::Round_even(uint8_t* input, uint8_t* rk) {
	Add_SubstEven_Layer(input, rk);
	DiffLayer(input);
}

void ARIA::Final_Round(uint8_t* input, uint8_t* key12, uint8_t* key13) {
	Add_SubstEven_Layer(input, key12);

	input[0] ^= key13[0];
	input[1] ^= key13[1];
	input[2] ^= key13[2];
	input[3] ^= key13[3];
	input[4] ^= key13[4];
	input[5] ^= key13[5];
	input[6] ^= key13[6];
	input[7] ^= key13[7];
	input[8] ^= key13[8];
	input[9] ^= key13[9];
	input[10] ^= key13[10];
	input[11] ^= key13[11];
	input[12] ^= key13[12];
	input[13] ^= key13[13];
	input[14] ^= key13[14];
	input[15] ^= key13[15];
}

void ARIA::Rot_L(uint8_t* input, uint8_t* output, int num) {
	uint8_t copy_input[16] = { 0x00, };
	memcpy(copy_input, input, 16 * sizeof(uint8_t));
	int r = num % 8;
	int q = num >> 3;
	uint8_t temp[16] = { 0x00, };
	memcpy(temp, input, 16 * sizeof(uint8_t));
	if (r == 0) {
		copy_input[0] = temp[(0 + q) % BLOCKLEN];
		copy_input[1] = temp[(1 + q) % BLOCKLEN];
		copy_input[2] = temp[(2 + q) % BLOCKLEN];
		copy_input[3] = temp[(3 + q) % BLOCKLEN];
		copy_input[4] = temp[(4 + q) % BLOCKLEN];
		copy_input[5] = temp[(5 + q) % BLOCKLEN];
		copy_input[6] = temp[(6 + q) % BLOCKLEN];
		copy_input[7] = temp[(7 + q) % BLOCKLEN];
		copy_input[8] = temp[(8 + q) % BLOCKLEN];
		copy_input[9] = temp[(9 + q) % BLOCKLEN];
		copy_input[10] = temp[(10 + q) % BLOCKLEN];
		copy_input[11] = temp[(11 + q) % BLOCKLEN];
		copy_input[12] = temp[(12 + q) % BLOCKLEN];
		copy_input[13] = temp[(13 + q) % BLOCKLEN];
		copy_input[14] = temp[(14 + q) % BLOCKLEN];
		copy_input[15] = temp[(15 + q) % BLOCKLEN];
	}
	else {
		copy_input[0] = (temp[(0 + q) % BLOCKLEN] << r) | (temp[(0 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[1] = (temp[(1 + q) % BLOCKLEN] << r) | (temp[(1 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[2] = (temp[(2 + q) % BLOCKLEN] << r) | (temp[(2 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[3] = (temp[(3 + q) % BLOCKLEN] << r) | (temp[(3 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[4] = (temp[(4 + q) % BLOCKLEN] << r) | (temp[(4 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[5] = (temp[(5 + q) % BLOCKLEN] << r) | (temp[(5 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[6] = (temp[(6 + q) % BLOCKLEN] << r) | (temp[(6 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[7] = (temp[(7 + q) % BLOCKLEN] << r) | (temp[(7 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[8] = (temp[(8 + q) % BLOCKLEN] << r) | (temp[(8 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[9] = (temp[(9 + q) % BLOCKLEN] << r) | (temp[(9 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[10] = (temp[(10 + q) % BLOCKLEN] << r) | (temp[(10 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[11] = (temp[(11 + q) % BLOCKLEN] << r) | (temp[(11 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[12] = (temp[(12 + q) % BLOCKLEN] << r) | (temp[(12 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[13] = (temp[(13 + q) % BLOCKLEN] << r) | (temp[(13 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[14] = (temp[(14 + q) % BLOCKLEN] << r) | (temp[(14 + q + 1) % BLOCKLEN] >> (8 - r));
		copy_input[15] = (temp[(15 + q) % BLOCKLEN] << r) | (temp[(15 + q + 1) % BLOCKLEN] >> (8 - r));
	}
	memcpy(output, copy_input, BLOCKLEN * sizeof(uint8_t));
}

void ARIA::ROT_XOR(uint8_t* input, uint8_t* op, uint8_t* output, int num) {
	uint8_t temp[16] = { 0x00, };
	Rot_L(input, temp, num);
	output[0] = temp[0] ^ op[0];
	output[1] = temp[1] ^ op[1];
	output[2] = temp[2] ^ op[2];
	output[3] = temp[3] ^ op[3];
	output[4] = temp[4] ^ op[4];
	output[5] = temp[5] ^ op[5];
	output[6] = temp[6] ^ op[6];
	output[7] = temp[7] ^ op[7];
	output[8] = temp[8] ^ op[8];
	output[9] = temp[9] ^ op[9];
	output[10] = temp[10] ^ op[10];
	output[11] = temp[11] ^ op[11];
	output[12] = temp[12] ^ op[12];
	output[13] = temp[13] ^ op[13];
	output[14] = temp[14] ^ op[14];
	output[15] = temp[15] ^ op[15];
}

void ARIA::Enc_KEY_Expansion(uint8_t* mk, uint8_t rk[13][16]) {
	uint8_t KL[16] = { 0x00, };
	memcpy(KL, mk, 16 * sizeof(uint8_t));
	uint8_t KR[16] = { 0X00, };

	uint8_t CK1[16] = { 0x51,0x7c,0xc1,0xb7,0x27,0x22,0x0a,0x94,0xfe,0x13,0xab,0xe8,0xfa,0x9a,0x6e,0xe0 };
	uint8_t CK2[16] = { 0x6d,0xb1,0x4a,0xcc,0x9e,0x21,0xc8,0x20,0xff,0x28,0xb1,0xd5,0xef,0x5d,0xe2,0xb0 };
	uint8_t CK3[16] = { 0xdb,0x92,0x37,0x1d,0x21,0x26,0xe9,0x70,0x03,0x24,0x97,0x75,0x04,0xe8,0xc9,0x0e };

	//W0
	uint8_t W0[16] = { 0x00, };
	memcpy(W0, KL, 16 * sizeof(uint8_t));
	//W1
	uint8_t copy_W0[16] = { 0x00, };
	memcpy(copy_W0, W0, 16 * sizeof(uint8_t));
	uint8_t W1[16] = { 0x00, };
	Round_odd(copy_W0, CK1);
	memcpy(W1, copy_W0, 16 * sizeof(uint8_t));
	//W2
	uint8_t W2[16] = { 0x00, };
	uint8_t copy_W1[16] = { 0x00, };
	memcpy(copy_W1, W1, 16 * sizeof(uint8_t));
	Round_even(copy_W1, CK2);
	W2[0] = copy_W1[0] ^ W0[0];
	W2[1] = copy_W1[1] ^ W0[1];
	W2[2] = copy_W1[2] ^ W0[2];
	W2[3] = copy_W1[3] ^ W0[3];
	W2[4] = copy_W1[4] ^ W0[4];
	W2[5] = copy_W1[5] ^ W0[5];
	W2[6] = copy_W1[6] ^ W0[6];
	W2[7] = copy_W1[7] ^ W0[7];
	W2[8] = copy_W1[8] ^ W0[8];
	W2[9] = copy_W1[9] ^ W0[9];
	W2[10] = copy_W1[10] ^ W0[10];
	W2[11] = copy_W1[11] ^ W0[11];
	W2[12] = copy_W1[12] ^ W0[12];
	W2[13] = copy_W1[13] ^ W0[13];
	W2[14] = copy_W1[14] ^ W0[14];
	W2[15] = copy_W1[15] ^ W0[15];
	//W3
	uint8_t W3[16] = { 0x00, };
	uint8_t copy_W2[16] = { 0x00, };
	memcpy(copy_W2, W2, 16 * sizeof(uint8_t));
	Round_odd(copy_W2, CK3);
	W3[0] = copy_W2[0] ^ W1[0];
	W3[1] = copy_W2[1] ^ W1[1];
	W3[2] = copy_W2[2] ^ W1[2];
	W3[3] = copy_W2[3] ^ W1[3];
	W3[4] = copy_W2[4] ^ W1[4];
	W3[5] = copy_W2[5] ^ W1[5];
	W3[6] = copy_W2[6] ^ W1[6];
	W3[7] = copy_W2[7] ^ W1[7];
	W3[8] = copy_W2[8] ^ W1[8];
	W3[9] = copy_W2[9] ^ W1[9];
	W3[10] = copy_W2[10] ^ W1[10];
	W3[11] = copy_W2[11] ^ W1[11];
	W3[12] = copy_W2[12] ^ W1[12];
	W3[13] = copy_W2[13] ^ W1[13];
	W3[14] = copy_W2[14] ^ W1[14];
	W3[15] = copy_W2[15] ^ W1[15];

	ROT_XOR(W1, W0, rk[0], 128 - 19);
	ROT_XOR(W2, W1, rk[1], 128 - 19);
	ROT_XOR(W3, W2, rk[2], 128 - 19);
	ROT_XOR(W0, W3, rk[3], 128 - 19);
	ROT_XOR(W1, W0, rk[4], 128 - 31);
	ROT_XOR(W2, W1, rk[5], 128 - 31);
	ROT_XOR(W3, W2, rk[6], 128 - 31);
	ROT_XOR(W0, W3, rk[7], 128 - 31);
	ROT_XOR(W1, W0, rk[8], 61);
	ROT_XOR(W2, W1, rk[9], 61);
	ROT_XOR(W3, W2, rk[10], 61);
	ROT_XOR(W0, W3, rk[11], 61);
	ROT_XOR(W1, W0, rk[12], 31);
}

string ARIA::ARIA_EnCrypt(int round) {


	if (round % 2 == 0) {
		Round_odd(copy_pt, rk[round]);
	}
	else if (round % 2 == 1) {
		Round_even(copy_pt, rk[round]);;
	}
	else if (round == 11) {
		Final_Round(copy_pt, rk[11], rk[12]);
	}


	memcpy(CT, copy_pt, BLOCKLEN * sizeof(uint8_t));
	vector<string> connect_str;
	connect_str.clear();
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < 16; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(copy_pt[i]);

	}
	ori_str += ss.str();
	return ori_str;
}





/*
int main() {
	//바이트배열_CTR 암호화
	uint8_t Plain[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	uint8_t Key[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	uint8_t Cipher[16] = { 0, };
	string round_ct;
	ARIA aria(Plain, Key, Cipher);
	for (int round = 0; round < 12; round++) {
		round_ct = aria.ARIA_EnCrypt(round);
		cout << "round: ";
		cout << round<<endl;

	}

	return 0;
}
*/