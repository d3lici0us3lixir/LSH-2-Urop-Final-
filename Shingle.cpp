#include "Shingle.h"

vector<string> shingle(uint8_t input_string[], int size, int arrsize)
{
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < arrsize; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(input_string[i]);

	}
	ori_str += ss.str();
	vector<string> connect_str;

	for (int i = 0; i < ori_str.length() - size + 1; i++)
	{
		connect_str.push_back(ori_str.substr(i, size));
	}

	return connect_str;
}

vector<string> string_shingle(string input_str, int size) {
	vector<string> connect_str;
	for (int i = 0; i < input_str.length() - size + 1; i++)
	{
		connect_str.push_back(input_str.substr(i, size));
	}
	return connect_str;
}

vector<string> shingle_len8(uint8_t input_string[], int size, int arrsize)
{
	string ori_str = "";
	std::ostringstream ss;
	for (int i = 0; i < arrsize; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(input_string[i]);

	}
	ori_str += ss.str();
	vector<string> connect_str;

	for (int i = 0; i < ori_str.length() - size + 1; i++)
	{
		connect_str.push_back(ori_str.substr(i, size));
	}

	return connect_str;
}

void int2byte(uint32_t* input, uint8_t* output) {
	int j = 0;
	for (int i = 0; i < sizeof(input); i++) {
		*(output + j) = *(input + i) >> 24;
		*(output + j + 1) = (*(input + i) >> 16) & 0xff;
		*(output + j + 2) = (*(input + i) >> 8) & 0xff;
		*(output + j + 3) = (*(input + i)) & 0xff;
		j = j + 4;
	}

}


vector<string> shingle(uint32_t input_string[], int size, int arrsize)
{
	string ori_str;
	int vector_counter = 0;
	int hash_value = 0;
	uint8_t uint8_string[16];
	int2byte(input_string, uint8_string);
	std::ostringstream ss;
	for (int i = 0; i < 16; i++) {
		// Convert each element to a two-digit hexadecimal string

		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(uint8_string[i]);

	}
	ori_str += ss.str();
	vector<string> connect_str;

	for (int i = 0; i < ori_str.length() - size + 1; i++)
	{
		connect_str.push_back(ori_str.substr(i, size));
	}


	return connect_str;
}


/*
int main()
{
	//uint8_t input_string[8] = {0x73, 0x61, 0x65, 0x36, 0x31, 0x35, 0x39, 0x37};
	uint32_t Plaintext[4] = { 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F };
	uint8_t input_string[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	int size = 5;
	//vector<string> ret = shingle8(input_string, size, sizeof(input_string));
	vector<string> ret = shingle(Plaintext, size, sizeof(Plaintext));

	for (int i = 0; i < ret.size(); i++) {

		cout << ret[i] << endl;

	}
	return 0;
}
*/