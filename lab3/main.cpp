#include <UnitTest++/UnitTest++.h>
#include </home/23pt108@ibst.psu/lab3/modAlphaCipher.h>

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("ГРАГР",modAlphaCipher("ГРА").encrypt("ААААА"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("ГРАДУ",modAlphaCipher("ГРАДУС").encrypt("ААААА"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("ГРАГР",modAlphaCipher("гра").encrypt("ААААА"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("Г1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("Г,Р"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("Г Р А"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ААА"),cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("Г");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ШСЪЦДСОЯЫЗЖЗРЗЁ", p->encrypt("ХОЧУБОЛЬШЕДЕНЕГ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ШСЪЦДСОЯЫЗЖЗРЗЁ", p->encrypt("хочубольшеденег"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("ШСЪЦДСОЯЫЗЖЗРЗЁ", p->encrypt("ХОЧУ БОЛЬШЕ ДЕНЕГ!"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("ДСОЯЫЗЖЗРЗЁ", p->encrypt("55БОЛЬШЕДЕНЕГ"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("3*3=9?"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ФНЦТАНКЫЧДГДМДВ", modAlphaCipher("Я").encrypt("ХОЧУБОЛЬШЕДЕНЕГ"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ХОЧУБОЛЬШЕДЕНЕГ", p->decrypt("ШСЪЦДСОЯЫЗЖЗРЗЁ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("шсъЦДСОЯЫЗЖЗРЗЁ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("ШСЪЦД СОЯЫЗЖЗРЗЁ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("55ДСОЯЫЗЖЗРЗЁ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("ШСЪЦДСОЯЫЗЖЗРЗЁ!"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ХОЧУБОЛЬШЕДЕНЕГ", modAlphaCipher("Я").decrypt("ФНЦТАНКЫЧДГДМДВ"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
