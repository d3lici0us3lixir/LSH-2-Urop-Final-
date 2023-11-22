#include "SEED.h"


	SEED::SEED(uint32_t* Plaintext, uint32_t* Key) {
		state[0] = Plaintext[0];
		state[1] = Plaintext[1];
		state[2] = Plaintext[2];
		state[3] = Plaintext[3];

		Key_gen(Key);

	}

	void SEED::int2byte(uint32_t* input, uint8_t* output) {
		*(output + 0) = *(input + 0) >> 24;
		*(output + 1) = ((*(input + 0)) >> 16) & 0xff;
		*(output + 2) = ((*(input + 0)) >> 8) & 0xff;
		*(output + 3) = (*(input + 0)) & 0xff;

		*(output + 4) = (*(input + 1)) >> 24;
		*(output + 5) = ((*(input + 1)) >> 16) & 0xff;
		*(output + 6) = ((*(input + 1)) >> 8) & 0xff;
		*(output + 7) = (*(input + 1)) & 0xff;

		*(output + 8) = (*(input + 2)) >> 24;
		*(output + 9) = ((*(input + 2)) >> 16) & 0xff;
		*(output + 10) = ((*(input + 2)) >> 8) & 0xff;
		*(output + 11) = (*(input + 2)) & 0xff;

		*(output + 12) = (*(input + 3)) >> 24;
		*(output + 13) = ((*(input + 3)) >> 16) & 0xff;
		*(output + 14) = ((*(input + 3)) >> 8) & 0xff;
		*(output + 15) = (*(input + 3)) & 0xff;
	}

	uint32_t SEED::G_fun(uint32_t x) {

		uint32_t y[4] = { 0, };
		uint32_t z[4] = { 0, };
		uint32_t m[4] = { 0xfc, 0xf3, 0xcf, 0x3f };


		y[0] = S1[((x) & 0xff)];
		y[1] = S2[((x) >> 8) & 0xff];
		y[2] = S1[((x) >> 16) & 0xff];
		y[3] = S2[((x) >> 24) & 0xff];

		z[3] = (y[0] & m[3]) ^ (y[1] & m[0]) ^ (y[2] & m[1]) ^ (y[3] & m[2]);
		z[2] = (y[0] & m[2]) ^ (y[1] & m[3]) ^ (y[2] & m[0]) ^ (y[3] & m[1]);
		z[1] = (y[0] & m[1]) ^ (y[1] & m[2]) ^ (y[2] & m[3]) ^ (y[3] & m[0]);
		z[0] = (y[0] & m[0]) ^ (y[1] & m[1]) ^ (y[2] & m[2]) ^ (y[3] & m[3]);

		return (z[0] | (z[1] << 8) | (z[2] << 16) | (z[3] << 24));
	}

	void SEED::Key_gen(uint32_t* Key) {

		uint32_t A, B;
		const uint32_t KC[16] = { 0x9e3779b9, 0x3c6ef373 ,0x78dde6e6 ,0xf1bbcdcc , 0xe3779b99 ,0xc6ef3733 ,0x8dde6e67 ,0x1bbcdccf ,0x3779b99e ,0x6ef3733c ,0xdde6e678 ,0xbbcdccf1 ,0x779b99e3 ,0xef3733c6 ,0xde6e678d,0xbcdccf1b };

		for (int i = 0; i < 16; i++) {

			A = Key[0] + Key[2] - KC[i];
			B = Key[1] - Key[3] + KC[i];

			A = G_fun(A);
			B = G_fun(B);

			RK[i][0] = A;
			RK[i][1] = B;

			if (i % 2 == 0) {
				A = Key[0];
				Key[0] = (Key[0] >> 8) | (Key[1] << 24);
				Key[1] = (Key[1] >> 8) | (A << 24);

			}
			else {
				A = Key[2];
				Key[2] = (Key[2] << 8) | (Key[3] >> 24);
				Key[3] = (Key[3] << 8) | (A >> 24);

			}
		}
	}

	void SEED::F_fun(uint32_t C, uint32_t D, uint32_t K0, uint32_t K1, uint32_t* E, uint32_t* F) {

		uint32_t First = 0;
		uint32_t Second = 0;

		First = (C ^ K0) ^ (D ^ K1);
		First = G_fun(First);
		Second = First;
		First = (First + (C ^ K0));
		First = G_fun(First);
		Second = (Second + First);
		Second = G_fun(Second);
		*F = Second;
		*E = (First + Second);

	}

	string SEED::make_return_str(uint32_t* state) {
		string ori_str;
		ostringstream ss;
		for (int i = 0; i < 4; i++) {
			// Convert each element to a two-digit hexadecimal string

			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(state[i]);

		}
		ori_str = "";
		ori_str += ss.str();
		return ori_str;
	}

	string SEED::SEED_Enc(int i) {

		string return_str;
		if (i < 15) {
			
				C = state[2];
				D = state[3];

				F_fun(state[2], state[3], RK[i][0], RK[i][1], &A, &B);
				state[2] = A ^ state[0];
				state[3] = B ^ state[1];
				state[0] = C;
				state[1] = D;
				return_str = make_return_str(state);
				return return_str;
		}

		else {
			Ciphertext[2] = state[2];
			Ciphertext[3] = state[3];
			F_fun(state[2], state[3], RK[15][0], RK[15][1], &A, &B);
			Ciphertext[0] = A ^ state[0];
			Ciphertext[1] = B ^ state[1];
			return_str = make_return_str(Ciphertext);
			return return_str;
		}
	}




	/*
int main() {
	uint32_t Key[4] = { 0, };
	uint32_t Plaintext[4] = { 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F };
	SEED seed(Plaintext, Key);
	string ROUND_CT;
	for (int i = 0; i < 16; i++) {
		ROUND_CT = seed.SEED_Enc(i);
		cout << ROUND_CT << endl;
	}

}

*/