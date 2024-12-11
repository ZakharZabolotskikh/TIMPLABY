#include <iostream>
#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>

SUITE(KeyTest)
{
    TEST(ValidKey)
    {
        CHECK_EQUAL("БВГБВ", modAlphaCipher("БВГ").encrypt("ААА АА"));
    }
    
    TEST(LongKey)
    {
        CHECK_EQUAL("БВГДЕ", modAlphaCipher("БВГДЕЖЗИЙК").encrypt("ААААА"));
    }
    
    TEST(LowCaseKey)
    {
        CHECK_EQUAL("БВГБВ", modAlphaCipher("бвг").encrypt("ААА АА"));
    }
    
    TEST(DigitsInKey)
    {
        CHECK_THROW(modAlphaCipher cp("Б1"), cipher_error);
    }
    
    TEST(PunctuationInKey)
    {
        CHECK_THROW(modAlphaCipher cp("Б,В"), cipher_error);
    }
    
    TEST(WhitespaceInKey)
    {
        CHECK_THROW(modAlphaCipher cp("Б В"), cipher_error);
    }
    
    TEST(EmptyKey)
    {
        CHECK_THROW(modAlphaCipher cp(""), cipher_error);
    }
    
    TEST(WeakKey)
    {
        CHECK_THROW(modAlphaCipher cp("ААА"), cipher_error);
    }
}

struct KeyB_fixture
{
    modAlphaCipher * p;
    
    KeyB_fixture()
    {
        p = new modAlphaCipher("Б");
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
        CHECK_EQUAL("УЙГРЙЕОКДСЗОГПРЕЛМОЦРХУЙФМУЛБЕЯЖХЕА",
                    p->encrypt("СКОРОБУДЕТНОВЫЙГОД"));
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString)
    {
        CHECK_EQUAL("УЙГРЙЕОКДСЗОГПРЕЛМОЦРХУЙФМУЛБЕЯЖХЕА",
                    p->encrypt("скоро будет новый год"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithWhitespaceAndPunct)
    {
        CHECK_EQUAL("УЙГРЙЕО КДСЗОГ ПРЕЛМОЦРХ УЙФМУЛБЕ ЯЖХЕА",
                    p->encrypt("СКОРО БУДЕТ НОВЫЙ ГОД!!"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers)
    {
        CHECK_THROW(p->encrypt("СЧАСТЛИВОГО2025ГОДА"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString)
    {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoAlphaString)
    {
        CHECK_THROW(p->encrypt("123456"), cipher_error);
    }
    
    TEST(MaxShiftKey)
    {
        CHECK_EQUAL("РЙНПСАТДГЗЕОГУКДЗБКЩЙМПРОЖЗРЯШХФЧДЗ",
                     modAlphaCipher("Я").encrypt("СКОРОБЫДЕТНОВЫЙГОД"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString)
    {
        CHECK_EQUAL("СКОРОБУДЕТНОВЫЙГОД", p->decrypt("ТЛПЛСПУЁИАЙСКЩБЧОЩПСЗФЛШЮГКЪДМЗЖДГБ"));
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString)
    {
        CHECK_THROW(p->decrypt("тлплспУЁИАЙСКЩБЧОЩПСЗФЛШЮГКЪДМЗЖДГБ"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, WhitespaceString)
    {
        CHECK_THROW(p->decrypt("ТЛПЛ СП УЁИАЙСК ЩБЧОЩПСЗФ ЛШЮГКЪДМ ЗЖДГБ"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, DigitsString)
    {
        CHECK_THROW(p->decrypt("ТЛПЛС2025ПУЁИА"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, PunctString)
    {
        CHECK_THROW(p->decrypt("ТЛПЛ,СПУЁИА"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString)
    {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    
    TEST(MaxShiftKey)
    {
        CHECK_EQUAL("СКОРОБУДЕТНОВЫЙГОД",
                     modAlphaCipher("Я").decrypt("РЙНПСАТДГЗЕОГУКДЗБКЩЙМПРОЖЗРЯШХФЧДЗ"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
