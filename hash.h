#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include <vector>
#include <string>
#include <unordered_map>

int javahash(uint8_t input_string[]);
void bucket_hash(std::vector<std::vector<std::string>> minHashSignatures, int num_bands, int band_size);


#endif 
