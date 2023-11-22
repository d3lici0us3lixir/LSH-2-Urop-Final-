#include "Simon.h"



SIMON::SIMON(uint64_t* plain, uint64_t* key) {
    simon_key_schedule(key, round_keys);
    copy(plain, plain+2, pt);


}
void SIMON::simon_key_schedule(uint64_t* key, uint64_t* round_keys) {
    round_keys[0] = key[0];
    round_keys[1] = key[1];

    for (int i = 2; i <= NUM_ROUNDS; i++) {
        uint64_t temp = round_keys[i - 1];
        uint64_t rotated = temp >> (WORD_SIZE - 3);
        round_keys[i] = (round_keys[i - 2] ^ rotated ^ temp) ^ ((0xC9 << 2) ^ (0x3ULL << 62));
    }
}

string SIMON::make_return_str(uint64_t x, uint64_t y) {


    ostringstream ss;
    ss << hex << setw(8) << setfill('0') << x << setw(4) << setfill('0') << y;
    return ss.str();
}


string SIMON::simon_encrypt(int round) {

    uint64_t temp = x;
    x = (y ^ ((x & 0xFFFFFFFFFFFFFFFEULL) << 1) ^ (z[round % 5]) ^ round_keys[round]);
    y = temp;
    string round_str = make_return_str(x, y);
    return round_str;
    

}



/*
int main() {
    uint64_t key[2] = { 0x1918111009080100ULL, 0 }; // 예제 키
    uint64_t plain[2] = { 0x6565687700000000ULL, 0 }; // 평문 블록
    SIMON simon(plain, key);
    string t;
    for (int i = 0; i < 32; i++) {
        t = simon.simon_encrypt(i+1);
        cout << t << endl;
   }


    cout << "cipher: " << t << endl;

    return 0;
}
*/