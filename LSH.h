#ifndef LSH_H
#define LSH_H

#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <unordered_map>
#include "Shingle.h"
#include "hash.h"
using namespace std;

class HashFunction {
public:
	HashFunction(int num_permutations);
	vector<string> ComputeSignature(const vector<string> set);


	int priv_num_permutations;
	vector<int> coefficients_;
	set<string> row_name;

};

double JaccardSimilarity(const set<string>& set1, const set<string>& set2);

#endif
