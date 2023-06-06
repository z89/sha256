#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>

using namespace std;

// first 32 bits of the fractional parts of the cube roots of the first 64 primes eg. (cbrt(x) - 1):
uint32_t cubeConstants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void printBits(uint64_t value) {
    const uint64_t mask = 1ULL << 63; // Mask to extract the leftmost bit

    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (value & (mask >> i)) >> (63 - i);
        cout << bit;
    }

    cout << endl;
}

void printByte(uint8_t byte) {
    for (int i = 8 - 1; i >= 0; i--) {
        cout << ((byte >> i) & 1);
    }
    cout << " ";
}

void printWord(uint32_t word) {
    for (int i = 32 - 1; i >= 0; i--) {
        cout << ((word >> i) & 1);
        if (i % 8 == 0) {
            cout << " ";
        }
    }
    cout << endl;
}

// bitwise right rotation
uint32_t rotr(uint32_t word, int amount) {
    return (word >> amount) | (word << ((32 - amount)));
}

uint32_t sigma(uint32_t input, int firstRotation, int secondRotation, int bitShift) {
    return (rotr(input, firstRotation) ^ rotr(input, secondRotation) ^ input >> bitShift);
};

void sha256(uint8_t *input, uint8_t size, uint8_t *output) {
    // first 32 bits of the fractional parts of the square roots of the first 8 primes, eg. (sqrt(x) - 1)
    uint32_t hashValues[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint64_t multiple = 512;            // size of each chunk in bits
    uint64_t inputBitLength = size * 8; // size of input in bits

    // calculate chunks needed to store input
    while (multiple < inputBitLength + (1 + 64)) {
        multiple += 512;
    }

    int totalBytes = multiple / 8;           // total bytes for input byte array
    uint8_t inputBytes[totalBytes] = {0x00}; // initialize input into unsigned 8 bit array

    // load the input into a byte array
    for (uint32_t i = 0; i < size; i++) {
        inputBytes[i] = input[i];
    }

    // append a 1 bit to the end of the input
    inputBytes[inputBitLength / 8] = 0b10000000;

    // append the input size to the end of the byte array
    uint64_t tmp = __builtin_bswap64(inputBitLength);
    memcpy(&inputBytes[totalBytes - 8], &tmp, sizeof(tmp));

    for (uint64_t chunk = 0; chunk < multiple / 512; chunk++) {
        // create a schedule array of 32 bit words with length 64
        uint32_t w[64] = {0b00000000};

        // load the first 16 words from input chunk into the schedule array
        for (uint8_t i = 0; i < 16; i++) {
            w[i] = (uint32_t(inputBytes[chunk * 64 + i * 4]) << 24) | (uint32_t(inputBytes[chunk * 64 + i * 4 + 1]) << 16) | (uint32_t(inputBytes[chunk * 64 + i * 4 + 2]) << 8) | (uint32_t(inputBytes[chunk * 64 + i * 4 + 3]));
        }

        // calculate the rest of the words in the schedule array (64-16 words)
        for (uint8_t i = 16; i < 64; i++) {
            w[i] = w[i - 16] + sigma(w[i - 15], 7, 18, 3) + w[i - 7] + sigma(w[i - 2], 17, 19, 10);
        }

        // store the initialisation values
        uint32_t a = hashValues[0];
        uint32_t b = hashValues[1];
        uint32_t c = hashValues[2];
        uint32_t d = hashValues[3];
        uint32_t e = hashValues[4];
        uint32_t f = hashValues[5];
        uint32_t g = hashValues[6];
        uint32_t h = hashValues[7];

        // compression function loop
        for (uint8_t i = 0; i < 64; i++) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s1 + ch + cubeConstants[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // add the compressed chunk to the current hash values
        hashValues[0] += a;
        hashValues[1] += b;
        hashValues[2] += c;
        hashValues[3] += d;
        hashValues[4] += e;
        hashValues[5] += f;
        hashValues[6] += g;
        hashValues[7] += h;
    }

    // convert the uint32 hash values to uint8 bytes
    for (int i = 0; i < 8; ++i) {
        output[i * 4 + 0] = (hashValues[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (hashValues[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (hashValues[i] >> 8) & 0xFF;
        output[i * 4 + 3] = hashValues[i] & 0xFF;
    }
};

int main(int argc, char *argv[]) {
    string str;
    bool custom = false;

    if (argc > 1) {
        if (argc > 2) {
            cout << "Please only enter one string to hash" << endl;
            return 0;
        }

        str = argv[1];
        custom = true;
    } else {
        str = "TestString@123";
    }

    string expectedHashA = "18d0e7e10ee48e7b0bcfef80f0711df9822c78fc098ef7ace5dc9290e73c6fc5";
    string expectedHashB = "214d44942de22b965668c7bb6c45928781aefe21e4ecdaa34f10da776ee91c2d";

    uint8_t hashesA[32];
    uint8_t hashesB[32];

    uint8_t *inputBytes = new uint8_t[str.length()];
    std::memcpy(inputBytes, str.c_str(), str.length());

    auto hashAStart = chrono::high_resolution_clock::now();
    sha256(inputBytes, str.length(), hashesA);
    auto hashAEnd = chrono::high_resolution_clock::now();

    auto hashBStart = chrono::high_resolution_clock::now();
    sha256(hashesA, 32, hashesB);
    auto hashBEnd = chrono::high_resolution_clock::now();

    stringstream hashA, hashB;

    for (size_t i = 0; i < 32; ++i) {
        hashA << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashesA[i]);
        hashB << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashesB[i]);
    }

    auto durationA = chrono::duration_cast<chrono::microseconds>(hashAEnd - hashAStart);
    auto durationB = chrono::duration_cast<chrono::microseconds>(hashBEnd - hashBStart);
    auto totalDuration = chrono::duration_cast<chrono::microseconds>(hashBEnd - hashAStart);

    if (custom) {
        cout << "input:           " << str << endl;
        cout << endl;

        cout << "hashA:           " << hashA.str() << endl;
        cout << "execution time:  " << durationA.count() / 1000.0 << " ms" << endl;
        cout << endl;
        cout << "hash doubling..." << endl;
        cout << endl;

        cout << "hashB:           " << hashB.str() << endl;
        cout << "execution time:  " << durationB.count() / 1000.0 << " ms" << endl;
        cout << endl;

    } else {
        cout << "input:           " << str << endl;
        cout << endl;

        cout << "hashA:           " << hashA.str() << endl;
        cout << "expectedHashA :  " << expectedHashA << endl;
        cout << "match:           " << (hashA.str() == expectedHashA ? "true" : "false") << endl;
        cout << "execution time:  " << durationA.count() / 1000.0 << " ms" << endl;
        cout << endl;
        cout << "hash doubling..." << endl;
        cout << endl;

        cout << "hashB:           " << hashB.str() << endl;
        cout << "expectedHashB :  " << expectedHashB << endl;
        cout << "match:           " << (hashB.str() == expectedHashB ? "true" : "false") << endl;
        cout << "execution time:  " << durationB.count() / 1000.0 << " ms" << endl;
        cout << endl;
    }

    cout << "total execution time:  " << totalDuration.count() / 1000.0 << " ms" << endl;
    cout << endl;

    return 0;
}