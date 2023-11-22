#ifndef SHINGLE_H
#define SHINGLE_H

#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>
#include <stdio.h>
#include <sstream>
#include <iomanip>
using namespace std;

vector<string> shingle(uint8_t input_string[], int size, int arrsize);
vector<string> shingle_len8(uint8_t input_string[], int size, int arrsize);
vector<string> string_shingle(string input_str, int size);
void int2byte(uint32_t* input, uint8_t* output);
vector<string> shingle(uint32_t input_string[], int size, int arrsize);
#endif
