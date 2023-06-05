#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>

#define WORD_SIZE 32

// first 32 bits of the fractional parts of the square roots of the first 8 primes, eg. (sqrt(x) - 1)
uint32_t IVHashes[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// first 32 bits of the fractional parts of the cube roots of the first 64 primes eg. (cbrt(x) - 1):
uint32_t IVConstants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void printByteBinary(uint8_t byte) {
    for (int i = 8 - 1; i >= 0; i--) {
        std::cout << ((byte >> i) & 1);
    }
    std::cout << " ";
}

uint8_t intToHex(int number) {
    if (number < 0 || number > 255) {
        std::cerr << "error: input needs to have a between 0 & 255 bits!" << std::endl;
        return 0;
    }

    return static_cast<uint8_t>(number & 0xFF);
}

void printWordBinary(uint32_t word) {
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        std::cout << ((word >> i) & 1);
        if (i % 8 == 0) {
            std::cout << " ";
        }
    }
    std::cout << std::endl;
}

// bitwise right rotation
uint32_t rotr(uint32_t word, int amount) {
    return (word >> amount) | (word << ((WORD_SIZE - amount)));
}

uint32_t sigma(uint32_t input, int firstRotation, int secondRotation, int bitShift) {
    return (rotr(input, firstRotation) ^ rotr(input, secondRotation) ^ input >> bitShift);
};

std::string sha256(std::string input) {
    /*
        init a 512 bit array
        NOTE: input size is only supported for less than 30 bytes (due to single byte int > hex conversion)
    */
    uint8_t msgBytes[64] = {0b00000000};

    auto start = std::chrono::high_resolution_clock::now();

    // load the input into a byte array
    for (int i = 0; i < input.length(); i++) {
        msgBytes[i] = input[i];
    }

    msgBytes[input.length()] = 0b10000000; // append a 1 bit to the end of the input

    // append the input size to the end of the byte array
    msgBytes[64 - 1] = intToHex(input.length() * 8);

    // create a schedule array of 32 bit words with length 64
    uint32_t w[64] = {0b00000000};

    // load the first 16 words from input byte array into the schedule array
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(msgBytes[i * 4]) << 24) | (uint32_t(msgBytes[(i * 4) + 1]) << 16) | (uint32_t(msgBytes[(i * 4) + 2]) << 8) | uint32_t(msgBytes[(i * 4) + 3]);
    }

    // calculate the rest of the words in the schedule array (64-16 words)
    for (int i = 16; i < 64; i++) {
        w[i] = w[i - 16] + sigma(w[i - 15], 7, 18, 3) + w[i - 7] + sigma(w[i - 2], 17, 19, 10);
    }

    // store the initialisation vectores in local variables
    int a = IVHashes[0];
    int b = IVHashes[1];
    int c = IVHashes[2];
    int d = IVHashes[3];
    int e = IVHashes[4];
    int f = IVHashes[5];
    int g = IVHashes[6];
    int h = IVHashes[7];

    // compression function main loop
    for (int i = 0; i < 64; i++) {
        int s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        int ch = (e & f) ^ (~e & g);
        int temp1 = h + s1 + ch + IVConstants[i] + w[i];
        int s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        int maj = (a & b) ^ (a & c) ^ (b & c);
        int temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    int z[8];

    // add the compressed chunk (currently only 1 chunk) to the final hash
    z[0] = a + IVHashes[0];
    z[1] = b + IVHashes[1];
    z[2] = c + IVHashes[2];
    z[3] = d + IVHashes[3];
    z[4] = e + IVHashes[4];
    z[5] = f + IVHashes[5];
    z[6] = g + IVHashes[6];
    z[7] = h + IVHashes[7];

    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double milliseconds = duration.count() / 1000.0;
    std::cout << "execution time: " << milliseconds << " ms" << std::endl;

    std::stringstream hash;

    for (int i = 0; i < 8; i++) {
        hash << std::hex << std::setw(8) << std::setfill('0') << z[i];
    };

    return hash.str();
};

int main() {
    std::string input = "TestString@123"; // 18d0e7e10ee48e7b0bcfef80f0711df9822c78fc098ef7ace5dc9290e73c6fc5
    std::string expectedHash = "18d0e7e10ee48e7b0bcfef80f0711df9822c78fc098ef7ace5dc9290e73c6fc5";

    std::string hash = sha256(input);

    std::cout << "expected hash: " << expectedHash << std::endl;
    std::cout << "generated hash: " << hash << std::endl;
    std::cout << "matches: " << (bool)(hash == expectedHash) << std::endl;

    return 0;
}