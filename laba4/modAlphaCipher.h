/**
* @file modAlphaCipher.h
* @author Заболотских З.В.
* @version 1.0
* @brief Описание класса modAlphaCipher
* @date 29.11.2024
*/
#pragma once
#include <vector>
#include <string>
#include <map>
#include <stdexcept>
#include <locale>

using namespace std;

/**
 * @class modAlphaCipher
 * @brief Класс для шифрования и дешифрования текста с использованием модульного алфавитного шифра.
 *
 * Этот класс реализует модульный алфавитный шифр, который позволяет шифровать и дешифровать текст
 * на основе заданного ключа, используя кириллический алфавит.
 */
class modAlphaCipher {
private:
    wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"; ///< Кириллический алфавит.
    map<wchar_t, int> alphaNum; ///< Сопоставление символов алфавита с их индексами.
    vector<int> key; ///< Вектор ключа для шифрования/дешифрования.

    /**
     * @brief Преобразует строку в вектор целых чисел на основе индексов символов.
     * @param s Строка для преобразования.
     * @return Вектор целых чисел, представляющий индексы символов.
     */
    vector<int> convert(const wstring& s);

    /**
     * @brief Преобразует вектор целых чисел обратно в строку.
     * @param v Вектор целых чисел для преобразования.
     * @return Строка, представляющая символы по индексам.
     */
    wstring convert(const vector<int>& v);

    /**
     * @brief Проверяет, является ли строка допустимой для шифрования.
     * @param s Строка для проверки.
     * @return true, если строка допустима; false в противном случае.
     */
    bool isValid(const wstring &s); // Объявление функции проверки

public:
    /**
     * @brief Конструктор по умолчанию удален.
     *
     * Запрещает создание объекта без ключа.
     */
    modAlphaCipher() = delete;

    /**
     * @brief Конструктор класса modAlphaCipher.
     * @param skey Строка-ключ для шифрования/дешифрования. Должна содержать только допустимые символы.
     * @throw invalid_argument Если ключ содержит недопустимые символы.
     */
    modAlphaCipher(const wstring& skey);

    /**
     * @brief Шифрует открытый текст с использованием заданного ключа.
     * @param open_text Открытый текст, который нужно зашифровать.
     * @return Зашифрованный текст.
     * @throw invalid_argument Если открытый текст содержит недопустимые символы.
     */
    wstring encrypt(const wstring& open_text);

    /**
     * @brief Дешифрует зашифрованный текст с использованием заданного ключа.
     * @param cipher_text Зашифрованный текст, который нужно расшифровать.
     * @return Открытый текст.
     * @throw invalid_argument Если зашифрованный текст содержит недопустимые символы.
     */
    wstring decrypt(const wstring& cipher_text);
};
