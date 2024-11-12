#include <iostream>
#include "Cipher.h"

void check(string Text, int key) {
    try {
        Cipher cipher(key, Text);
        string cipherText = cipher.encryption(Text);
        string decryptedText = cipher.transcript(cipherText, Text);

        cout << "Ключ = " << key << endl;
        cout << "Исходный текст: " << Text << endl;
        cout << "Зашифрованный текст: " << cipherText << endl;
        cout << "Расшифрованный текст: " << decryptedText << endl;

    } catch (const cipher_error & e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
}

int main() {
    check("Lexalada", 4);
    return 0;
}
