#include <cstring>
#include <openssl/evp.h>
#include <iostream>
#include <string>
#include <fstream>
#include <queue>

using namespace std;

// Another Spaghetti
int main(int argc, char *argv[]) {
    const char cipherECB[] = "aes-128-ecb";
    const char cipherCBC[] = "aes-128-cbc";
    unsigned char key[EVP_MAX_KEY_LENGTH] = "thisIsMyKeyOogaBooga";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "apesStrongToget";
    const EVP_CIPHER *evpCipher;
    unsigned char buffer[1030];
    unsigned char result[2048];
    bool cipher;
    bool ecb;
    char c;
    vector<char> toCopy;
    ifstream input;
    ofstream output;

    // Reading the arguments
    if (argc != 4) {
        printf("Missing arguments!\n");
        return -1;
    }
    if (strcmp(argv[1], "-e") == 0) {
        cipher = true;
    } else if (strcmp(argv[1], "-d") == 0) {
        cipher = false;
    } else {
        printf("Invalid argument - only -e or -d allowed!\n");
        return -2;
    }
    if (strcmp(argv[2], "ecb") == 0) {
        ecb = true;
    } else if (strcmp(argv[2], "cbc") == 0) {
        ecb = false;
    } else {
        printf("Invalid argument - only ecb or cbc allowed!\n");
        return -3;
    }
    string fileName = argv[3];

    // Header information extraction
    input.open(fileName, ios::in | ios::binary);
    input.seekg(0, ios::end);
    uint64_t fileSize = input.tellg();
    input.seekg(0, ios::beg);
    if (!input.is_open()) {
        input.close();
        printf("Invalid argument - file does not exist!\n");
        return -4;
    }
    for (int i = 0; i < 18; ++i) {
        if (!input.is_open()) {
            input.close();
            printf("Problem with input file!\n");
            return -5;
        }
        if (!input.get(c).good()) {
            input.close();
            printf("Problem with input file - Header too short!\n");
            return -6;
        }
        toCopy.push_back(c);
    }

    uint16_t imgIDLen = toCopy[0];
    uint16_t mapLen = (toCopy[6] << 8) | (toCopy[5]);
    uint16_t mapDepth = toCopy[7];
    uint64_t mapSizeTotal = (mapDepth / 8) * mapLen;

    if (mapSizeTotal + imgIDLen > fileSize - 18) {
        input.close();
        printf("Problem with input file - ID + Map length is greater than the file size!\n");
        return -7;
    }

    // Copying the imdID & mapData
    for (uint64_t i = 0; i < imgIDLen + mapSizeTotal; ++i) {
        if (!input.is_open()) {
            input.close();
            printf("Problem with input file! (1)\n");
            return -8;
        }
        if (!input.get(c).good()) {
            input.close();
            printf("Problem with input file! (2)\n");
            return -9;
        }
        toCopy.push_back(c);
    }

    // Setting correct cipher
    OpenSSL_add_all_ciphers();
    evpCipher = EVP_get_cipherbyname(ecb ? cipherECB : cipherCBC);
    if (!evpCipher) {
        printf("Sifra %s neexistuje!\n", cipherECB);
        return -10;
    }
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return -11;

    string outFileName = fileName.substr(0, fileName.length() - 4);
    int tmpLen = 0;
    int read;

    if (cipher) {
        outFileName.append(ecb ? "_ecb.tga" : "_cbc.tga");
        if (!EVP_EncryptInit_ex(ctx, evpCipher, nullptr, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return -12;
        }
        output.open(outFileName, ios::out | ios::app | ios::binary);
        if (!output.is_open()) {
            EVP_CIPHER_CTX_free(ctx);
            printf("Failed to create a file!\n");
            return -14;
        }
        // Copy header
        for (char i : toCopy) {
            output.put(i);
        }
        while (true) {
            input.read((char *) buffer, 1024);
            read = input.gcount();
            if (input.fail() && !input.eof()) {
                EVP_CIPHER_CTX_free(ctx);
                printf("Found a bad bit!\n");
                return -14;
            }
            if (!EVP_EncryptUpdate(ctx, result, &tmpLen, buffer, read)) {
                EVP_CIPHER_CTX_free(ctx);
                return -15;
            }
            output.write(reinterpret_cast<const char *>(result), tmpLen);

            if (read < 1024)
                break;
        }
        if (!EVP_EncryptFinal_ex(ctx, result, &tmpLen)) {
            EVP_CIPHER_CTX_free(ctx);
            return -16;
        }
        output.write(reinterpret_cast<const char *>(result), tmpLen);
    } else {
        outFileName.append("_dec.tga");
        if (!EVP_DecryptInit_ex(ctx, evpCipher, nullptr, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return -17;
        }
        output.open(outFileName, ios::out | ios::app | ios::binary);
        if (!output.is_open()) {
            EVP_CIPHER_CTX_free(ctx);
            printf("Failed to create a file!\n");
            return -18;
        }
        // Copy header
        for (char i : toCopy) {
            output.put(i);
        }
        while (true) {
            input.read((char *) buffer, 1024);
            read = input.gcount();
            if (input.fail() && !input.eof()) {
                EVP_CIPHER_CTX_free(ctx);
                printf("Found a bad bit!\n");
                return -19;
            }
            if (!EVP_DecryptUpdate(ctx, result, &tmpLen, buffer, read)) {
                EVP_CIPHER_CTX_free(ctx);
                return -20;
            }
            output.write(reinterpret_cast<const char *>(result), tmpLen);
            if (read < 1024)
                break;
        }
        if (!EVP_DecryptFinal_ex(ctx, result, &tmpLen)) {
            EVP_CIPHER_CTX_free(ctx);
            return -21;
        }
        output.write(reinterpret_cast<const char *>(result), tmpLen);
    }
    EVP_CIPHER_CTX_free(ctx);
    input.close();
    output.close();
    return 0;
}