#include "LEA.h"
typedef unsigned int word;
typedef unsigned char byte;
	LEA::LEA(uint8_t* input, uint8_t* key) {

		memcpy(Plain + 0, (unsigned int*)input + 0, 4 * sizeof(unsigned char));
		memcpy(Plain + 1, (unsigned int*)input + 1, 4 * sizeof(unsigned char));
		memcpy(Plain + 2, (unsigned int*)input + 2, 4 * sizeof(unsigned char));
		memcpy(Plain + 3, (unsigned int*)input + 3, 4 * sizeof(unsigned char));
		LEA_Keyschedule(key);
	}

	string LEA::LEA_Round_Encrypt(int i)
	{

		ct[0] = ROL(((Plain[0] ^ rk[i][0]) + (Plain[1] ^ rk[i][1])), 9);
		ct[1] = ROR(((Plain[1] ^ rk[i][2]) + (Plain[2] ^ rk[i][3])), 5);
		ct[2] = ROR(((Plain[2] ^ rk[i][4]) + (Plain[3] ^ rk[i][5])), 3);
		ct[3] = Plain[0];

		for (int j = 0; j < 4; j++) {
			Plain[j] = ct[j];
		}
		ostringstream ss;
		for (int i = 0; i < 4; i++) {
			// Convert each element to a two-digit hexadecimal string

			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ct[i]);

		}
		ori_str = "";
		ori_str += ss.str();
		return ori_str;


	}

	void LEA::LEA_Keyschedule(const uint8_t key[16]) {
		uint32_t state[4] = { 0x00, };
		memcpy(state, (uint32_t*)key, 16 * sizeof(unsigned char));
		for (uint32_t i = 0; i < 24; i++) {
			
			state[0] = ROL(state[0] + ROL(keyschedule_con[i % 4], (i + 0)), 1);
			state[1] = ROL(state[1] + ROL(keyschedule_con[i % 4], (i + 1)), 3);
			state[2] = ROL(state[2] + ROL(keyschedule_con[i % 4], (i + 2)), 6);
			state[3] = ROL(state[3] + ROL(keyschedule_con[i % 4], (i + 3)), 11);

			//각 라운드 키 세팅
			rk[i][0] = state[0];
			rk[i][1] = state[1];
			rk[i][2] = state[2];
			rk[i][3] = state[1];
			rk[i][4] = state[3];
			rk[i][5] = state[1];
		}
		
	}



/*
int main()
{
	uint8_t PT[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	uint8_t key[16] = { 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0 };
	string ROUND_CT;
	LEA lea(PT, key);

	for (int i = 0; i < 24; i++) {
		ROUND_CT = lea.LEA_Round_Encrypt(i);
		cout << i<<": " << ROUND_CT << endl;
	}


	//ECB_암호화


	return 0;
}
*/