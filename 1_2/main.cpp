#include <iostream>
#include <string>
#include "modCipher.h"

bool isValid(const int k, string &text) {
    int razm=text.size();
    if (k>razm)
        return false;
    return true;
}

int main() {
    string text;
    int key;
    unsigned vibor;
    cout << "Введите текcт: ";
    cin >> text;
    cout << "Введите кол-во столбцов: ";
    cin >> key;
    if (!isValid(key, text)) {
        cout << "Ключ не корректен\n";
        return 1;
    }
    cout<<"Ключ загружен\n";
    modCipher shifr(key);
    do {
        cout << "Шифратор готов. Выберите опрецию (Выход-0, Шифрока-1, Расшифровка-2): ";
        cin >> vibor;
        if (vibor > 2) {
            cout << "Неверная операция!\n" << endl;
        } else if (vibor > 0) {
            if (vibor == 1)
                cout << shifr.encrypt(text) << endl;
            else
                cout << shifr.decrypt(text) << endl;
        }
    } while (vibor != 0);
    return 0;
}
