#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <wincrypt.h>
#include <fstream>

#pragma comment(lib, "crypt32.lib")

using namespace std;


const unsigned char ARG_XOR_KEY[] = {
    0x4D, 0x61, 0x6E, 0x75, 0x73, 0x52, 0x65, 0x64,
    0x54, 0x65, 0x61, 0x6D, 0x32, 0x30, 0x32, 0x35
};

const size_t ARG_KEY_LENGTH = sizeof(ARG_XOR_KEY);


string NormalizeBase64(const string& base64) {
    string normalized = base64;

    normalized.erase(remove_if(normalized.begin(), normalized.end(), ::isspace), normalized.end());

    while (normalized.length() % 4 != 0) {
        normalized += '=';
    }

    return normalized;
}


vector<unsigned char> Base64DecodeArg(const string& base64) {

    string normalized = NormalizeBase64(base64);

    DWORD binaryLen = 0;
    DWORD base64Len = static_cast<DWORD>(normalized.length());

    if (!CryptStringToBinaryA(normalized.c_str(), base64Len,
        CRYPT_STRING_BASE64,
        NULL, &binaryLen, NULL, NULL)) {
        printf("[-] Base64 decode failed (size): %d\n", GetLastError());
        printf("[-] Input: %s\n", normalized.c_str());
        return vector<unsigned char>();
    }

    vector<unsigned char> binary(binaryLen);

    if (!CryptStringToBinaryA(normalized.c_str(), base64Len,
        CRYPT_STRING_BASE64,
        binary.data(), &binaryLen, NULL, NULL)) {
        printf("[-] Base64 decode failed (decode): %d\n", GetLastError());
        return vector<unsigned char>();
    }

    binary.resize(binaryLen);
    return binary;
}


string XorDecryptArg(const vector<unsigned char>& encrypted) {
    string decrypted(encrypted.size(), '\0');

    for (size_t i = 0; i < encrypted.size(); i++) {
        decrypted[i] = encrypted[i] ^ ARG_XOR_KEY[i % ARG_KEY_LENGTH];
    }

    return decrypted;
}


string DecryptArguments(const string& encryptedBase64) {
    vector<unsigned char> encrypted = Base64DecodeArg(encryptedBase64);
    if (encrypted.empty()) {
        printf("[-] Base64 decode returned empty\n");
        return "";
    }

    string decrypted = XorDecryptArg(encrypted);

    return decrypted;
}


bool ParseEncryptedArgs(int argc, char* argv[], string& decryptedArgs) {
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];


        if (arg == "--encrypted" && i + 1 < argc) {
            string encrypted = argv[i + 1];

            printf("[DEBUG] Received encrypted: %s\n", encrypted.c_str());

            decryptedArgs = DecryptArguments(encrypted);

            if (decryptedArgs.empty()) {
                printf("[-] Failed to decrypt arguments!\n");
                printf("[-] Encrypted input: %s\n", encrypted.c_str());
                return false;
            }

            printf("[+] Decrypted arguments: %s\n", decryptedArgs.c_str());
            return true;
        }

        if (arg == "--encrypted-file" && i + 1 < argc) {
            string filename = argv[i + 1];


            ifstream file(filename);
            if (!file.is_open()) {
                printf("[-] Failed to open file: %s\n", filename.c_str());
                return false;
            }

            string encrypted;
            getline(file, encrypted);
            file.close();

            printf("[DEBUG] Read from file: %s\n", encrypted.c_str());

            decryptedArgs = DecryptArguments(encrypted);

            if (decryptedArgs.empty()) {
                printf("[-] Failed to decrypt arguments from file!\n");
                return false;
            }

            printf("[+] Decrypted arguments from file: %s\n", decryptedArgs.c_str());
            return true;
        }
    }

    return false;
}


void ParseDecryptedArgsToArray(const string& decryptedArgs, vector<char*>& argvArray) {
    string current;
    bool inQuotes = false;

    for (size_t i = 0; i < decryptedArgs.length(); i++) {
        char c = decryptedArgs[i];

        if (c == '"') {
            inQuotes = !inQuotes;
        }
        else if (c == ' ' && !inQuotes) {
            if (!current.empty()) {
                char* arg = new char[current.length() + 1];
                strcpy_s(arg, current.length() + 1, current.c_str());
                argvArray.push_back(arg);
                current.clear();
            }
        }
        else {
            current += c;
        }
    }

    if (!current.empty()) {
        char* arg = new char[current.length() + 1];
        strcpy_s(arg, current.length() + 1, current.c_str());
        argvArray.push_back(arg);
    }
}


void CleanupArgArray(vector<char*>& argvArray) {
    for (char* arg : argvArray) {
        delete[] arg;
    }
    argvArray.clear();
}