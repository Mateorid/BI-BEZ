#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <openssl/evp.h>
#include <random>
#include <string>
#include <cstring>
#include <chrono>

char hashFunction[] = "sha384";  //Selected hash function ("sha1", "md5", ...)

//from: https://stackoverflow.com/questions/1640258/need-a-fast-random-generator-for-c/1640402#1640402
uint64_t xorshf96(uint64_t &x, uint64_t &y, uint64_t &z) {
    uint64_t t;
    x ^= x << 16;
    x ^= x >> 5;
    x ^= x << 1;

    t = x;
    x = y;
    y = z;
    z = t ^ x ^ y;

    return z;
}

/* Returns the number of 0 bits in a row */
int bitCheck(char byte) {
    int i;
    int tmp, tmp2 = 0;
    for (i = 7; 0 <= i; i--) {
        tmp = ((byte >> i) & 0x01);
        if (tmp == 0)
            tmp2++;
        if (tmp != 0)
            break;
    }
    return tmp2;
}

//Spaghetti code because why not
int main(int argc, char *argv[]) {
    //Setting up PRNG
    std::random_device rd;
    std::mt19937::result_type seed = rd() ^(
            (std::mt19937::result_type)
                    std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()
                    ).count() +
            (std::mt19937::result_type)
                    std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::high_resolution_clock::now().time_since_epoch()
                    ).count());

    std::mt19937 gen(seed);
    std::uniform_int_distribution<unsigned> distrib(100000000, 999999999);
    static uint64_t x = distrib(gen), y = distrib(gen), z = distrib(gen);

    //Argument handling
    int zeroBits;
    if (argc != 2) {
        printf("Invalid argument!");
        return -1;
    }
    if (strcmp(argv[1], "0") == 0) {
        zeroBits = 0;
    } else {
        zeroBits = atoi(argv[1]);
        if (zeroBits <= 0 || zeroBits > 384) {
            printf("Invalid argument!");
            return -1;
        }
    }

    // Hashing stuff
    EVP_MD_CTX *ctx;
    const EVP_MD *type;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length;
    bool end = false;
    int tmp, totalZeros = 0;
    std::string text;

    OpenSSL_add_all_digests();
    type = EVP_get_digestbyname(hashFunction);
    if (!type) {
        printf("Hash %s neexistuje.\n", hashFunction);
        return 1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return 2;

    while (!end) {
        /* Hash the text */
        if (!EVP_DigestInit_ex(ctx, type, nullptr)) { // context setup for our hash type
            EVP_MD_CTX_free(ctx);
            return 3;
        }
        text = std::to_string(xorshf96(x, y, z));
        if (!EVP_DigestUpdate(ctx, text.data(), text.size())) { // feed the message in
            EVP_MD_CTX_free(ctx);
            return 4;
        }
        if (!EVP_DigestFinal_ex(ctx, hash, &length)) { // get the hash
            EVP_MD_CTX_free(ctx);
            return 5;
        }

        // Check if first n bits are "0"
        for (uint i = 0; i < length; ++i) {
            tmp = bitCheck(hash[i]);
            totalZeros += tmp;
            if (tmp != 8) {
                if (totalZeros >= zeroBits) {
                    end = true;
                    break;
                } else {
                    break;
                }
            }
        }
        totalZeros = 0;
    }
    EVP_MD_CTX_free(ctx);

    // Printing the hash
    for (unsigned int i = 0; i < text.length(); i++)
        printf("%02x", text.c_str()[i]);
    std::cout << " ";
    for (unsigned int i = 0; i < length; i++)
        printf("%02x", hash[i]);
    return 0;
}