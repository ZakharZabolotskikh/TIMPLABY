/**
* @file Cipher.h
* @author Заболотских З.В.
* @version 1.0
* @brief Описание класса cipher_error
* @date 29.11.2024
*/
#pragma once
#include <map>
#include <string>
#include <vector>
#include <stdexcept>

using namespace std;

/**
 * @class cipher_error
 * @brief Исключение для обработки ошибок шифрования.
 *
 * Этот класс наследует от std::invalid_argument и используется для генерации
 * исключений, связанных с ошибками в процессе шифрования.
 */
class cipher_error : public invalid_argument {
public:
    /**
     * @brief Конструктор для создания исключения с сообщением.
     * @param what_arg Сообщение об ошибке.
     */
    explicit cipher_error(const string& what_arg)
        : invalid_argument(what_arg) {}

    /**
     * @brief Конструктор для создания исключения с сообщением.
     * @param what_arg Сообщение об ошибке в виде C-строки.
     */
    explicit cipher_error(const char* what_arg)
        : invalid_argument(what_arg) {}
};

/**
 * @class Cipher
 * @brief Класс для шифрования и дешифрования текста с использованием симметричного шифра.
 *
 * Этот класс реализует симметричный шифр, который позволяет шифровать и дешифровать текст
 * на основе заданного ключа.
 */
class Cipher {
private:
    int key; ///< Ключ для шифрования/дешифрования.

    /**
     * @brief Проверяет и возвращает допустимый ключ.
     * @param key Исходный ключ.
     * @param Text Исходный текст для проверки.
     * @return Допустимый ключ.
     */
    inline int getValidKey(int key, const string& Text);

    /**
     * @brief Проверяет и возвращает допустимый открытый текст.
     * @param s Открытый текст для проверки.
     * @return Допустимый открытый текст.
     */
    inline string getValidOpenText(string& s);

    /**
     * @brief Проверяет и возвращает допустимый зашифрованный текст.
     * @param s Зашифрованный текст для проверки.
     * @param open_text Открытый текст для сравнения.
     * @return Допустимый зашифрованный текст.
     */
    inline string getValidCipherText(string& s, string& open_text);

public:
    /**
     * @brief Конструктор по умолчанию удален.
     *
     * Запрещает создание объекта без ключа и текста.
     */
    Cipher() = delete;

    /**
     * @brief Конструктор класса Cipher.
     * @param skey Целочисленный ключ для шифрования/дешифрования.
     * @param text Исходный текст, который будет использоваться для шифрования/дешифрования.
     */
    Cipher(int skey, string text);

    /**
     * @brief Шифрует открытый текст с использованием заданного ключа.
     * @param text Открытый текст, который нужно зашифровать.
     * @return Зашифрованный текст.
     */
    string encryption(string& text);

    /**
     * @brief Дешифрует зашифрованный текст с использованием заданного ключа.
     * @param text Зашифрованный текст, который нужно расшифровать.
     * @param open_text Открытый текст для сравнения (при необходимости).
     * @return Дешифрованный текст (открытый текст).
     */
    string transcript(string& text, string& open_text);
};
