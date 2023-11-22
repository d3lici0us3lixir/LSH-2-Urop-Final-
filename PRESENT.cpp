#include "PRESENT.h"


PRESENT::PRESENT(uint8_t* STATE, uint8_t* KEY) {
	copy(STATE, STATE + 8, state);
	copy(KEY, KEY + 10, key);
}

string PRESENT::PRESENT_ENC(int round) {
	int i = 0;
	string return_str;
	if (round < 31) {

		//	****************** addRoundkey *************************
		i = 0;
		do
		{
			state[i] = state[i] ^ key[i + 2];
			i++;
		} while (i <= 7);
		//	****************** sBox ********************************
		do
		{
			i--;
			state[i] = sBox4[state[i] >> 4] << 4 | sBox4[state[i] & 0xF];
		} while (i > 0);
		//	****************** pLayer ******************************
		for (i = 0; i < 8; i++)
		{
			temp_pLayer[i] = 0;
		}
		for (i = 0; i < 64; i++)
		{
			position = (16 * i) % 63;						//Artithmetic calculation of the pLayer
			if (i == 63)									//exception for bit 63
				position = 63;
			element_source = i / 8;
			bit_source = i % 8;
			element_destination = position / 8;
			bit_destination = position % 8;
			temp_pLayer[element_destination] |= ((state[element_source] >> bit_source) & 0x1) << bit_destination;
		}
		for (i = 0; i <= 7; i++)
		{
			state[i] = temp_pLayer[i];
		}
		//	****************** End pLayer **************************
		//	****************** Key Scheduling **********************
		save1 = key[0];
		save2 = key[1];
		i = 0;
		do
		{
			key[i] = key[i + 2];
			i++;
		} while (i < 8);
		key[8] = save1;
		key[9] = save2;
		i = 0;
		save1 = key[0] & 7;								//61-bit left shift
		do
		{
			key[i] = key[i] >> 3 | key[i + 1] << 5;
			i++;
		} while (i < 9);
		key[9] = key[9] >> 3 | save1 << 5;

		key[9] = sBox4[key[9] >> 4] << 4 | (key[9] & 0xF);	//S-Box application

		if ((round + 1) % 2 == 1)							//round counter addition
			key[1] ^= 128;
		key[2] = ((((round + 1) >> 1) ^ (key[2] & 15)) | (key[2] & 240));
		//	****************** End Key Scheduling ******************
		return_str = make_return_str(state);
		return return_str;
	}


	//	****************** addRoundkey *************************
	else if (round == 31) {
		i = 0;
		do										//final key XOR
		{
			state[i] = state[i] ^ key[i + 2];
			i++;
		} while (i <= 7);
		return_str = make_return_str(state);
		return return_str;
	}

}

string PRESENT::make_return_str(volatile uint8_t* state) {
	vector<string> connect_str;
	connect_str.clear();
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < 8; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(state[i]);

	}
	ori_str += ss.str();
	return ori_str;
}



/*
int main(void)
{
	uint8_t KEY[10] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uint8_t STATE[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	PRESENT present(STATE, KEY);
	string round_ct;
	for (int i = 0; i < 32; i++) {
		round_ct = present.PRESENT_ENC(i);
		cout << round_ct << endl;
	}


}

*/

