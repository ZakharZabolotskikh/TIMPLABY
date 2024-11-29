#include <iostream>
#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>

SUITE(KeyTest)
{
    TEST(ValidKey)
    {
        CHECK_EQUAL("BCDBC", modAlphaCipher("BCD").encrypt("AAA AA"));
    }
    
    TEST(LongKey)
    {
        CHECK_EQUAL("BCDEF", modAlphaCipher("BCDEFGHIJK").encrypt("AAAAA"));
    }
    
    TEST(LowCaseKey)
    {
        CHECK_EQUAL("BCDBC", modAlphaCipher("bcd").encrypt("AAA AA"));
    }
    
    TEST(DigitsInKey)
    {
        CHECK_THROW(modAlphaCipher cp("B1"), cipher_error);
    }
    
    TEST(PunctuationInKey)
    {
        CHECK_THROW(modAlphaCipher cp("B,C"), cipher_error);
    }
    
    TEST(WhitespaceInKey)
    {
        CHECK_THROW(modAlphaCipher cp("B C"), cipher_error);
    }
    
    TEST(EmptyKey)
    {
        CHECK_THROW(modAlphaCipher cp(""), cipher_error);
    }
    
    TEST(WeakKey)
    {
        CHECK_THROW(modAlphaCipher cp("AAA"), cipher_error);
    }
}

struct KeyB_fixture
{
    modAlphaCipher * p;
    
    KeyB_fixture()
    {
        p = new modAlphaCipher("B");
    }
    
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString)
    {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH", p->encrypt("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"));
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString)
    {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH", p->encrypt("thequickbrownfoxjumpsoverthelazydog"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct)
    {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH", p->encrypt("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG))"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers)
    {
        CHECK_EQUAL("IBQQZOFXZFBS", p->encrypt("Happy New 2025 Year"));
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString)
    {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoAlphaString)
    {
        CHECK_THROW(p->encrypt("88005553535"), cipher_error);
    }
    
    TEST(MaxShiftKey)
    {
        CHECK_EQUAL("SGDPTHBJAQNVMENWITLORNUDQSGDKZYXCNF",
                     modAlphaCipher("Z").encrypt("THEQUICKBROWNFOXJUMPSOVER THELAZYDOG"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString)
    {
        CHECK_EQUAL("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", p->decrypt("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH"));
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString)
    {
        CHECK_THROW(p->decrypt("uifRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, WhitespaceString)
    {
        CHECK_THROW(p->decrypt("UIF RVJDL CSPXO GPY KVNQT PWFS UIFMBAZ EPH"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, DigitsString)
    {
        CHECK_THROW(p->decrypt("IBQQZOFX2019ZFBS"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, PunctString)
    {
        CHECK_THROW(p->decrypt("IFMMP,XPSME"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString)
    {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    
    TEST(MaxShiftKey)
    {
        CHECK_EQUAL("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
                     modAlphaCipher("Z").decrypt("SGDPTHBJAQNVMENWITLORNUDQ SGDKZYXCNF"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
