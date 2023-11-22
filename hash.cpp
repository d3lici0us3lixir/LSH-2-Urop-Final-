#include <iostream>
#include <cstdlib>
#include <vector>
#include <unordered_map>
#include "hash.h"
using namespace std;

/*
0 : plain
1 : ARIA
2 : BLOWFISH -> different oupput size
3 : SEED
4 : LEA
5 : CAMELLIA
6 : GIFT
7 : PRESENT
8 : SM4

*/


int javahash(uint8_t input_string[])
{
    int hash_value = 0;
    for (int i = 0; i < sizeof(input_string); i++)
    {
        hash_value = 31 * hash_value + (input_string[i] & 0xff);
    }
    return hash_value;
}



void bucket_hash(vector<vector<string>> minHashSignatures, int num_bands, int band_size) {
    string cipher_name[9] = { "Plain", "ARIA", "BLOWFISH","SEED","LEA", "CAMELLIA", "GIFT,", "PRESENT", "SM4" };
    unordered_map<unsigned int, vector<int>> bucket;
    unordered_map<unsigned int, vector<int>>::iterator iter;
    unsigned int hash_val;
    string tmp = "";
    int max_col;
    for (int band = 0; band < num_bands; band++) {

        cout << "band number is " << band << endl;
        for (int set_num = 0; set_num < minHashSignatures.size(); set_num++) {
            int j = band * band_size - 1;
            if (j < 0) j = 0;
            tmp = "";
            max_col = band_size * band;
            if (max_col == 0) max_col = band_size;
            for (; j < max_col; j++) {

                tmp = tmp + minHashSignatures[set_num][j];
            }
            hash_val = hash<string>()(tmp);
            iter = bucket.find(hash_val);
            if (iter != bucket.end()) { //found hash
                bucket[hash_val].push_back(set_num);

            }
            else {
                bucket[hash_val].push_back(set_num);
            }

        }

        for (const auto& pair : bucket) {
            if (pair.second.size() >= 2) {
                cout << "Key: " << pair.first << ", Value: ";
                for (const int& value : pair.second) {
                    cout << cipher_name[value] << ", ";
                }
                cout << endl;

            }


        }

        bucket.clear();
    }
}