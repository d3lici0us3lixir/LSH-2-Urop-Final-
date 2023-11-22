#include "LSH.h"


HashFunction::HashFunction(int num_permutations) : priv_num_permutations(num_permutations) {
	srand(static_cast<unsigned>(time(0)));
	coefficients_.resize(num_permutations);
	for (int i = 0; i < num_permutations; ++i) {
		coefficients_[i] = rand() % 10000000;
	}
}

vector<string>HashFunction::ComputeSignature(const vector<string> set) {
	vector<unsigned int> signature(priv_num_permutations, INT16_MAX);
	vector<string> str_signature(priv_num_permutations);

	for (const string element : set) {
		for (int i = 0; i < priv_num_permutations; ++i) {
			unsigned int hash_val = hash<string>()(element);
			unsigned int permuted_hash = (coefficients_[i] * hash_val) % INT16_MAX;
			signature[i] = min(signature[i], permuted_hash);
		}
	}
	int i = 0;
	for (const int sign : signature) {
		str_signature[i] = to_string(signature[i]);
		i++;
	}

	return str_signature;
}



double JaccardSimilarity(const set<string>& set1, const set<string>& set2) {
	set<string> intersection;
	set_intersection(set1.begin(), set1.end(), set2.begin(), set2.end(), inserter(intersection, intersection.begin()));
	int intersection_size = intersection.size();
	int union_size = set1.size() + set2.size() - intersection_size;
	return static_cast<double>(intersection_size) / union_size;
}