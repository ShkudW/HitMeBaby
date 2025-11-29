#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <wincrypt.h>
#include <fstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;


const unsigned char XOR_KEY[] = {
    0x4D, 0x61, 0x6E, 0x75, 0x73, 0x52, 0x65, 0x64,
    0x54, 0x65, 0x61, 0x6D, 0x32, 0x30, 0x32, 0x35
};

const size_t KEY_LENGTH = sizeof(XOR_KEY);


vector<unsigned char> XorEncrypt(const string& plaintext) {
    vector<unsigned char> encrypted(plaintext.size());

    for (size_t i = 0; i < plaintext.size(); i++) {
        encrypted[i] = plaintext[i] ^ XOR_KEY[i % KEY_LENGTH];
    }

    return encrypted;
}


string Base64Encode(const vector<unsigned char>& data) {
    DWORD base64Len = 0;
    DWORD dataSize = static_cast<DWORD>(data.size());

    // Get required buffer size
    if (!CryptBinaryToStringA(data.data(), dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL, &base64Len)) {
        cerr << "[-] CryptBinaryToStringA (size) failed: " << GetLastError() << endl;
        return "";
    }

    // Allocate buffer
    char* base64Buffer = new char[base64Len];

    // Encode
    if (!CryptBinaryToStringA(data.data(), dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        base64Buffer, &base64Len)) {
        cerr << "[-] CryptBinaryToStringA (encode) failed: " << GetLastError() << endl;
        delete[] base64Buffer;
        return "";
    }

    string result(base64Buffer, base64Len - 1);
    delete[] base64Buffer;

    return result;
}


string EncryptArguments(const string& arguments) {
    cout << "[*] Encrypting arguments..." << endl;
    cout << "[+] Original: " << arguments << endl;


    vector<unsigned char> encrypted = XorEncrypt(arguments);
    cout << "[+] XOR encrypted: " << encrypted.size() << " bytes" << endl;

    string base64 = Base64Encode(encrypted);
    cout << "[+] Base64 encoded: " << base64.length() << " characters" << endl;

    return base64;
}


int main(int argc, char* argv[]) {


    if (argc < 2) {
        cout << "Usage: ArgEncryptor.exe <arguments>" << endl;
        return 1;
    }

    // Combine all arguments into one string
    string arguments;
    for (int i = 1; i < argc; i++) {
        if (i > 1) arguments += " ";
        arguments += argv[i];
    }

    // Encrypt
    string encrypted = EncryptArguments(arguments);

    if (encrypted.empty()) {
        cerr << "[-] Encryption failed!" << endl;
        return 1;
    }

    cout << encrypted << endl;
    cout << endl;

    string outputFile = "encrypted_args.txt";
    ofstream out(outputFile);
    if (out.is_open()) {
        out << encrypted;
        out.close();
        cout << "[+] Saved to: " << outputFile << endl;
    }

    cout << endl;
    cout << "========================================" << endl;
    cout << "              Usage Example            " << endl;
    cout << "========================================" << endl;
    cout << endl;
    cout << "HitMeBaby.exe config.txt --encrypted \"" << encrypted << "\"" << endl;
    cout << endl;
    cout << "Or from file:" << endl;
    cout << "HitMeBaby.exe config.txt --encrypted-file encrypted_args.txt" << endl;
    cout << endl;

    return 0;
}