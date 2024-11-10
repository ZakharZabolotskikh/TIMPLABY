#include "modAlphaCipher.h"

#include <cctype>
#include <iostream>
#include <locale>
#include <codecvt>

using namespace std;

void check(const string& Text, const string& key, const bool destructCipherText = false)
{
    try {
        string cipherText;
        string decryptedText;
        modAlphaCipher cipher(key);
        
        // Проверяем кодировку входного текста
        if (Text.empty() || key.empty()) {
            throw cipher_error("Текст или ключ не могут быть пустыми.");
        }

        cipherText = cipher.encrypt(Text);
        
        if (destructCipherText && cipherText.length() > 1) {
            cipherText[1] += 32; // Пример изменения второго символа
        }

        decryptedText = cipher.decrypt(cipherText);
        
        cout << "Ключ = " << key << endl;
        cout << "Исходный текст: " << Text << endl;
        cout << "Зашифрованный текст: " << cipherText << endl;
        cout << "Расшифрованный текст: " << decryptedText << endl;
    } catch (const cipher_error& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
    } catch (const std::exception& e) {
        cerr << "Общая ошибка: " << e.what() << endl;
    }
}

int main()
{
    check("ЛАДАГРАНТА", "КЛЮЧ");
    check("ЛАДАГРАНТА", "Ключ");
    check("ЛАДАГРАНТА", "");
    check("ЛАДАГРАНТА", "Клю4");
    check("Лада гранта", "КЛЮЧ");
    check("123", "КЛЮЧ");
    check("Лада гранта", "КЛЮЧ", true);
    
    return 0;
}
