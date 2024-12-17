#include <UnitTest++/UnitTest++.h>
#include "code.h"
#include <string>

std::string s = "VALORANT";

SUITE(KeyTest) {
    TEST(ValidKey) {
        code cipher(4, "VALORANT");
        CHECK_EQUAL("OTLNAAVR", cipher.encryption(s));
    }
    TEST(LongKey) {
        CHECK_THROW(code(1, "VALORANT"), cipher_error);
    }
}

struct KeyB_fixture {
    code * t;
    KeyB_fixture() {
        t = new code(4, "VALORANT");
    }
    ~KeyB_fixture() {
        delete t;
    }
};

SUITE(EncryptTest) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input = "VALORANT";
        CHECK_EQUAL("OTLNAAVR", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input = "valorant";
        CHECK_EQUAL("otlnaavr", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        std::string input = "VALO RANT";
        CHECK_EQUAL("OTLNAAVR", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        std::string input = "VALO4ANT";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input = "";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        std::string input = "2*2=5?";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "VALORANT");
        std::string input1 = "TNAROLAV";
        std::string input2 = "VALORANT";
        CHECK_EQUAL("VALORANT", cipher.transcript(input1, input2));
    }
}

SUITE(DecryptText) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input1 = "OTLNAAVR";
        std::string input2 = "VALORANT";
        CHECK_EQUAL("VALORANT", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input1 = "otlnaavr";
        std::string input2 = "valorant";
        CHECK_EQUAL("valorant", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        std::string input1 = "VALORANT";
        std::string input2 = "VALO RANT";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        std::string input1 = "VALO4ANT";
        std::string input2 = "VALO4ANT";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        std::string input1 = "VALORANT!";
        std::string input2 = "VALORANT!";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input1 = "";
        std::string input2 = "";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "Serafime");
        std::string input1 = "TNAROLAV";
        std::string input2 = "VALORANT";
        CHECK_EQUAL("VALORANT", cipher.transcript(input1, input2));
    }
}

int main(int argc, char **argv) {
    return UnitTest::RunAllTests();
}

