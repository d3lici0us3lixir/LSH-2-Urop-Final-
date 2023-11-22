#include "BLOWFISH.h"

#define RN 16

BLOWFISH::BLOWFISH(uint32_t* PT, uint8_t* key, int keyLen) {
	Blowfish_Init(key, keyLen);
	copy(PT, PT + 2, pt);
	RN_left = pt[0]; // store x_l in left
	RN_right = pt[1]; // store x_r in right

}

uint32_t BLOWFISH::BF_F(uint32_t(*s)[256], uint32_t x)
{
	unsigned short s1, s2, s3, s4;
	uint32_t  y;

	// step 1: Divide x into 8-bit segments s1, s2, s3, and s4.
	s4 = (unsigned short)(x & 0xFF); // Extract the lowest 8 bits
	x >>= 8;
	s3 = (unsigned short)(x & 0xFF); // Extract the next 8 bits
	x >>= 8;
	s2 = (unsigned short)(x & 0xFF); // Extract the next 8 bits
	x >>= 8;
	s1 = (unsigned short)(x & 0xFF); // Extract the highest 8 bits

	// step 2: Put s1, s2, s3, s4 into the S-box and get y.
	y = s[0][s1] + s[1][s2];
	y = y ^ s[2][s3];
	y = y + s[3][s4];

	return y;
}

void BLOWFISH::Blowfish_Enc(uint32_t* p, uint32_t(*s)[256], uint32_t* pt, uint32_t* ct)
{


	left = pt[0]; // store x_l in left
	right = pt[1]; // store x_r in right

	for (int i = 0; i < RN; ++i) {
		// step 1: Perform XOR between left and i-th element of P-array
		left = left ^ p[i];

		// step 2: Put the result of step 1 into the Blowfish F function
		// step 3: Perform XOR between the result of step 2 and right
		//         Store the result of step 3 in right
		right = BF_F(s, left) ^ right;

		// step 4: Swap left and right
		temp = left;
		left = right;
		right = temp;
	} // step 5: Repeat RN times (16 times)

	// step 6: Swap left and right
	temp = left;
	left = right;
	right = temp;

	// step 7: Perform XOR between right and 17-th element of P-array
	//         Store the result of step 7 in right
	right = right ^ p[RN];

	// step 8: Perform XOR between left and 18-th element of P-array
	//         Store the result of step 8 in left
	left = left ^ p[RN + 1];

	// store left and right in x_l and x_r
	ct[0] = left;
	ct[1] = right;
}

string BLOWFISH::make_return_str(uint32_t RN_right, uint32_t RN_left) {


	ostringstream ss;
	ss << hex << setw(4) << setfill('0') << RN_right << setw(4) << setfill('0') << RN_left;
	return ss.str();
}

string BLOWFISH::ROUND_Blowfish_Enc(int round)
{
	if (round < RN) {

		RN_left = RN_left ^ NP[round];
		RN_right = BF_F(NS, RN_left) ^ RN_right;
		temp = RN_left;
		RN_left = RN_right;
		RN_right = temp;
		round_Str = make_return_str(RN_right, RN_left);
		return round_Str;

	}
	else {
		// step 6: Swap left and right
		temp = RN_left;
		RN_left = RN_right;
		RN_right = temp;

		// step 7: Perform XOR between right and 17-th element of P-array
		//         Store the result of step 7 in right
		RN_right = RN_right ^ NP[RN];

		// step 8: Perform XOR between left and 18-th element of P-array
		//         Store the result of step 8 in left
		RN_left = RN_left ^ NP[RN + 1];

		// store left and right in x_l and x_r
		// ct[0] = left;
		// ct[1] = right;
		round_Str = make_return_str(RN_left, RN_right);
		return round_Str;
	}
}

void BLOWFISH::Blowfish_Init(uint8_t* key, int keyLen)
{
	int i, j, k;
	// Initialize S-boxes
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j++)
			NS[i][j] = o_s[i][j];
	}

	// Initialize P-array
	j = 0;
	for (i = 0; i < RN + 2; ++i) {
		input = 0x00000000; // 32-bit initialization key to used for each block

		// Divide the key into 4-byte blocks to create a round key
		for (k = 0; k < 4; ++k) {
			input = (input << 8) | key[j]; //get 8-bit of key and store in input
			j = j + 1;
			// if exceed the length of key, start from the beginning
			if (j >= keyLen) j = 0;
		}
		// Store the result of XOR operation between o_p and input in P-array
		NP[i] = o_p[i] ^ input;
	}

	// Shuffle the P-array using the Blowfish algorithm
	for (i = 0; i < RN + 2; i += 2) {
		Blowfish_Enc(NP, NS, init, init);
		NP[i] = init[0];
		NP[i + 1] = init[1];
	}

	// Shuffle the S-boxes using the Blowfish algorithm
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 256; j += 2) {
			Blowfish_Enc(NP, NS, init, init);
			NS[i][j] = init[0];
			NS[i][j + 1] = init[1];
		}
	}
}

/*
int main() {
	uint32_t text[2] = { 0xffffffffL, 0xffffffffL }; // plain text
	uint8_t key[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // user's key
	uint32_t enc_text[2]; // cipher text
	BLOWFISH blowfish(text, key, 8);
	string round_ct;
	for (int i = 0; i < RN; ++i) {
		round_ct = blowfish.ROUND_Blowfish_Enc(i);
		cout << round_ct<<endl;
	}


}
*/