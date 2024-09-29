#pragma once
#include <vector>
#include <string>
#include <map>

using namespace std;

class modCipher {
    private:
        int key;
    public:
        modCipher()=delete;
        modCipher(int skey);
        string encrypt(string &text);
        string decrypt(string &text);
};
