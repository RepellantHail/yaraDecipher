#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::string;
using std::vector;

class RC4 {
public:
    RC4(const vector<unsigned char>& key) {
        keySchedulingAlgorithm(key);
    }

    vector<unsigned char> process(const vector<unsigned char>& inputText) {
        vector<unsigned char> outputText;
        outputText.reserve(inputText.size());

        for (size_t n = 0; n < inputText.size(); ++n) {
            unsigned char k = pseudoRandomGeneration();
            outputText.push_back(inputText[n] ^ k); 
        }

        return outputText;
    }

private:
    unsigned char S[256];
    int i = 0, j = 0;

    void keySchedulingAlgorithm(const vector<unsigned char>& key) {
        int keyLen = key.size();
        unsigned char T[256];

        // Paso 1: Inicializar S y T
        for (int i = 0; i < 256; i++) {
            S[i] = i;
            T[i] = key[i % keyLen];
        }

        // Paso 2: Permutar S usando T
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) % 256;
            std::swap(S[i], S[j]);
        }
    }

    unsigned char pseudoRandomGeneration() {
        // PRGA - Genera un flujo de clave byte por byte
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        int t = (S[i] + S[j]) % 256;
        return S[t];
    }
};

vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, std::ios::binary);
    return { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
}

void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

vector<unsigned char> passphraseToKey(const string& passphrase) {
    return vector<unsigned char>(passphrase.begin(), passphrase.end());
}

int main() {
    int choice;
    cout << "Elige una opción:\n";
    cout << "1. Cifrar un archivo\n";
    cout << "2. Descifrar un archivo\n";
    cout << "Ingresa tu elección (1 o 2): ";
    cin >> choice;
    cin.ignore();  // Ignorar el carácter de nueva línea que queda en el búfer de entrada

    // Pedir la frase de paso
    string passphrase;
    cout << "Introduce la frase de paso: ";
    std::getline(cin, passphrase);

    // Convertir la frase de paso a un vector de clave
    vector<unsigned char> key = passphraseToKey(passphrase);
    RC4 rc4(key);

    if (choice == 1) {
        // Cifrado
        vector<unsigned char> plaintext = readFile("sample.txt");
        vector<unsigned char> ciphertext = rc4.process(plaintext);
        writeFile("ciphered.txt", ciphertext);
        cout << "Cifrado completo. Texto cifrado escrito en ciphered.txt" << endl;
    } else if (choice == 2) {
        // Descifrado
        vector<unsigned char> ciphertext = readFile("ciphered.txt");
        vector<unsigned char> plaintext = rc4.process(ciphertext);
        writeFile("deciphered.txt", plaintext);
        cout << "Descifrado completo. Texto plano escrito en deciphered.txt" << endl;
    } else {
        cout << "Elección inválida. Por favor selecciona 1 o 2." << endl;
    }

    return 0;
}
