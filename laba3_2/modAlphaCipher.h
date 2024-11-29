#include <cmath>
#include <cctype>
#include <locale>
#include <codecvt>
#include <iostream>
#include <string>

class CipherError : public std::invalid_argument
{
public:
    explicit CipherError(const std::wstring& what_arg)
        : std::invalid_argument(wstring_to_string(what_arg))
    {}

private:
    static std::wstring string_to_wstring(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.from_bytes(str);
    }

    static std::string wstring_to_string(const std::wstring& wstr) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.to_bytes(wstr);
    }
};

class RouteCipher
{
public:
    static int getValidColumns(int columns);
    static std::wstring encrypt(const std::wstring& plaintext, int columns);
    static std::wstring decrypt(const std::wstring& ciphertext, int columns);
    static std::wstring getValidPlainText(const std::wstring& s);
    static std::wstring getValidCipherText(const std::wstring& s);

private:
    static std::wstring string_to_wstring(const std::string& str);
    static std::string wstring_to_string(const std::wstring& wstr);
};
