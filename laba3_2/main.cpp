#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <locale>
#include <iostream>
#include <codecvt>

std::string wstring_to_string(const std::wstring& wstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

SUITE(RouteCipherTest)
{
    TEST(ValidEncryptionAndDecryption)
    {
        CHECK_EQUAL(wstring_to_string(L"ОРНВИАДЗ"), wstring_to_string(RouteCipher::encrypt(L"ДИНОЗАВР", 4)));
        CHECK_EQUAL(wstring_to_string(L"ДИНОЗАВР"), wstring_to_string(RouteCipher::decrypt(L"ОРНВИАДЗ", 4)));
    }

    TEST(LowCaseString)
    {
        CHECK_EQUAL(wstring_to_string(L"УАЕНКМРВЙИ"), wstring_to_string(RouteCipher::encrypt(L"муравейник", 2)));
        CHECK_EQUAL(wstring_to_string(L"МУРАВЕЙНИК"), wstring_to_string(RouteCipher::decrypt(L"УАЕНКМРВЙИ", 2)));
    }

    TEST(EmptyTextEncryptionAndDecryption)
    {
        CHECK_THROW(RouteCipher::encrypt(L"", 5), CipherError);
        CHECK_THROW(RouteCipher::decrypt(L"", 5), CipherError);
    }

    TEST(StringWithWhitespaceAndPunct)
    {
        CHECK_EQUAL(wstring_to_string(L"ОРНВИАДЗ"), wstring_to_string(RouteCipher::encrypt(L"ДИНОЗАВР", 4)));
        CHECK_EQUAL(wstring_to_string(L"ДИНОЗАВР"), wstring_to_string(RouteCipher::decrypt(L"ОРНВИАДЗ", 4)));
    }

    TEST(NegativeColumnsEncryptionAndZeroColumnsDecryption)
    {
        CHECK_THROW(RouteCipher::encrypt(L"текст", -2), CipherError);
        CHECK_THROW(RouteCipher::decrypt(L"Текст", 0), CipherError);
    }

    TEST(StringWithNumbers)
    {
        CHECK_THROW(RouteCipher::encrypt(L"Пр1в3т", 4), CipherError);
        CHECK_THROW(RouteCipher::decrypt(L"ПР1В3Т", 4), CipherError);
    }

    TEST(InvalidPlaintextAndCiphertext)
    {
        CHECK_THROW(RouteCipher::encrypt(L"7782", 4), CipherError);
        CHECK_THROW(RouteCipher::encrypt(L"*%:)", 4), CipherError);
        CHECK_THROW(RouteCipher::decrypt(L"*%:)", 4), CipherError);
        CHECK_THROW(RouteCipher::decrypt(L"7782", 4), CipherError);
    }

    TEST(MaximumColumnsEncryptionAndDecryption)
    {
        CHECK_EQUAL(wstring_to_string(L"ДИНОЗАВР"), wstring_to_string(RouteCipher::encrypt(L"ДИНОЗАВР", 1)));
        CHECK_EQUAL(wstring_to_string(L"ДИНОЗАВР"), wstring_to_string(RouteCipher::decrypt(L"ДИНОЗАВР", 1)));
        CHECK_EQUAL(wstring_to_string(L"РВАЗОНИД"), wstring_to_string(RouteCipher::encrypt(L"ДИНОЗАВР", 8)));
        CHECK_EQUAL(wstring_to_string(L"ДИНОЗАВР"), wstring_to_string(RouteCipher::decrypt(L"РВАЗОНИД", 8)));
    }
}

int main(int argc, char **argv)
{
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
