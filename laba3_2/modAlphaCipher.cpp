#include "modAlphaCipher.h"
#include <cmath>
#include <cctype>
#include <locale>
#include <codecvt>
#include <iostream>
#include <string>

std::wstring RouteCipher::encrypt(const std::wstring& plaintext, int columns)
{
    columns = getValidColumns(columns);
    std::wstring validatedPlainText = getValidPlainText(plaintext);
    int rows = (validatedPlainText.length() + columns - 1) / columns;
    std::wstring encryptedText;

    for (int i = columns - 1; i >= 0; --i) {
        for (int j = 0; j < rows; ++j) {
            std::wstring::size_type index = j * columns + i;

            if (index < validatedPlainText.length()) {
                encryptedText += validatedPlainText[index];
            }
        }
    }
    return encryptedText;
}

std::wstring RouteCipher::decrypt(const std::wstring& ciphertext, int columns)
{
    columns = getValidColumns(columns);
    std::wstring validatedCipherText = getValidCipherText(ciphertext);
    int rows = static_cast<int>(std::ceil(static_cast<double>(validatedCipherText.length()) / columns));
    std::wstring decryptedText;

    for (int i = rows - 1; i >= 0; --i) {
        for (int j = columns - 1; j >= 0; --j) {
            std::wstring::size_type index = j * rows + (rows - i - 1);

            if (index < validatedCipherText.length()) {
                decryptedText += validatedCipherText[index];
            }
        }
    }
    return decryptedText;
}

int RouteCipher::getValidColumns(int columns)
{
    if (columns <= 0)
        throw CipherError(L"Invalid number of columns");
    return columns;
}

std::wstring RouteCipher::getValidPlainText(const std::wstring & s)
{
    for (auto c : s) {
        if (std::iswdigit(c)) {
            throw CipherError(L"Digits are not allowed in plaintext");
        }
    }

    std::wstring tmp;
    for (auto c : s) {
        if (std::iswalpha(c)) {
            tmp.push_back(std::towupper(c));
        } else {
            throw CipherError(L"Invalid character in plaintext");
        }
    }

    if (tmp.empty())
        throw CipherError(L"Empty plaintext");
    
    return tmp;
}

std::wstring RouteCipher::getValidCipherText(const std::wstring & s)
{
    for (auto c : s) {
        if (std::iswdigit(c)) {
            throw CipherError(L"Digits are not allowed in ciphertext");
        }
    }

    std::wstring tmp;
    for (auto c : s) {
        if (std::iswalpha(c) && std::iswupper(c)) {
            tmp.push_back(c);
        } else {
            throw CipherError(L"Invalid character in ciphertext");
        }
    }

    if (tmp.empty())
        throw CipherError(L"Empty ciphertext");
    
    return tmp;
}

std::wstring RouteCipher::string_to_wstring(const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::string RouteCipher::wstring_to_string(const std::wstring& wstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}
