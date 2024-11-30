// header file inclusions
#include "kernel/types.h"    // provides basic type definitions e.g.: uint
#include "kernel/stat.h"     // file status structures and constants (dev, ino, type, nlink, size)
#include "user/user.h"       // user-space function declerations

// SHA-256 Constants
#define CHUNK_SIZE 64        // SHA-256 processes data in standard 64-byte (512-bit) blocks
#define WORD_SIZE 4          // each chunk will be divided into words of 4 bytes (32 bits)
#define SHA256_BLOCK_SIZE 32 // the final hash size, 32 bytes (256 bits)
#define MAX_INPUT_SIZE 1024  // If MAX_INPUT_SIZE is too large, could cause buffer and stack overflow therefore it is limited 1024 bytes

// Define our own uint32 and uint64 since xv6 doesn't have standard C header stdint.h which provides fixed-width integer types
typedef unsigned int uint32;    // Works because xv6 runs on x86, where int is 32 bits
typedef unsigned long uint64;   // Works because long is 64 bits on xv6's x86

// Standard SHA-256 initial hash values
// first 32 bits of the fractional parts of the square roots of the first 8 primes
static uint32 h0 = 0x6a09e667;    // 0x6a09e667 is first 32 bits of fractional part of √2
static uint32 h1 = 0xbb67ae85;    // ... √3
static uint32 h2 = 0x3c6ef372;    // ... √5
static uint32 h3 = 0xa54ff53a;    // ... √7
static uint32 h4 = 0x510e527f;    // ... √11
static uint32 h5 = 0x9b05688c;    // ... √13
static uint32 h6 = 0x1f83d9ab;    // ... √17
static uint32 h7 = 0x5be0cd19;    // ... √19

// k array contains 64 constants derived from cube roots of first 64 primes
static const uint32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// Helper functions, core operations used in sha-256

// Rotate Right function - circular right rotation of bits
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32-(bits))))
// Choose function - selects bits from y or z based on x
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
// Majority function - outputs 1 if majority of inputs are 1
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
// Upper case sigma functions for message schedule
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
// Lower case sigma functions for compression
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// Custom string to hex function for xv6. To convert each byte of the final hash state into its hexadecimal string representation.
void byte_to_hex(unsigned char byte, char str[3]) {    // Input is in binary form (as an 8-bit unsigned char)
    const char hex_chars[] = "0123456789abcdef";    // lookup table containing hexadecimal digits from 0-9 and a-f
    str[0] = hex_chars[byte >> 4];    // shifts the byte 4 bits to the right, extracting the high 4 bits (first hexadecimal digit)
    str[1] = hex_chars[byte & 0xf];    // bitwise AND with 15 (0x0F), extracting the low 4 bits (second hexadecimal digit)
    str[2] = '\0';    // Null terminator
}

#define SCHEDULE_SIZE 64    // number of words in message schedule
#define ROUNDS 64           // number of processing rounds

// The core transformation function
void sha256_transform(uint32 state[8], const unsigned char data[CHUNK_SIZE]) {
    uint32 a, b, c, d, e, f, g, h, i, t1, t2, m[SCHEDULE_SIZE];

    // Create message schedule
    for (i = 0; i < CHUNK_SIZE/WORD_SIZE; ++i) {    // 64/4 = 16 words
        m[i] = ((uint32)data[i*WORD_SIZE] << 24) |
               ((uint32)data[i*WORD_SIZE+1] << 16) |
               ((uint32)data[i*WORD_SIZE+2] << 8) |
               ((uint32)data[i*WORD_SIZE+3]);
    }

    // Expand 16 words to 64 words
    for (; i < SCHEDULE_SIZE; ++i) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // 64 rounds of processing
    for (i = 0; i < ROUNDS; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
     state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_hash(const char* input, char output[65]) {
    uint32 state[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    uint32 datalen = 0;
    uint32 bitlen[2] = {0, 0};  // Using array for 64-bit length
    unsigned char data[64];
    uint32 i;

    // Get input length
    uint32 inputlen = strlen(input);

    // Process each byte of input
    for (i = 0; i < inputlen; ++i) {
        data[datalen] = input[i];
        datalen++;
        if (datalen == 64) {
            sha256_transform(state, data);
            // Update bitlen
            bitlen[0] += 512;
            if (bitlen[0] < 512) bitlen[1]++;
            datalen = 0;
        }
    }

    // Pad the data
    i = datalen;
    if (datalen < 56) {
        data[i++] = 0x80;
        while (i < 56)
            data[i++] = 0x00;
    } else {
        data[i++] = 0x80;
         while (i < 64)
            data[i++] = 0x00;
        sha256_transform(state, data);
        memset(data, 0, 56);
    }

    // Append length
    uint32 total_bits[2];
    total_bits[1] = bitlen[1];
    total_bits[0] = bitlen[0] + (datalen * 8);
    if (total_bits[0] < (datalen * 8)) total_bits[1]++;

    for (i = 0; i < 8; i++) {
        data[63-i] = total_bits[0] & 0xFF;
        total_bits[0] >>= 8;
    }
    sha256_transform(state, data);

    // Convert hash to string
    char hex[3];
    for (i = 0; i < 8; i++) {
        byte_to_hex((state[i] >> 24) & 0xFF, hex);
        output[i*8] = hex[0];
        output[i*8 + 1] = hex[1];
        byte_to_hex((state[i] >> 16) & 0xFF, hex);
        output[i*8 + 2] = hex[0];
        output[i*8 + 3] = hex[1];
        byte_to_hex((state[i] >> 8) & 0xFF, hex);
        output[i*8 + 4] = hex[0];
        output[i*8 + 5] = hex[1];
        byte_to_hex(state[i] & 0xFF, hex);
        output[i*8 + 6] = hex[0];
        output[i*8 + 7] = hex[1];
    }
    output[64] = '\0';
}


// Function to safely read input from console
void get_input(char *buffer, int max_size) {
    int i = 0;
    char c;

    while (i < max_size - 1) {
        if (read(0, &c, 1) <= 0 || c == '\n') {
            break;
        }
        buffer[i++] = c;
    }
    printf("\n");
    buffer[i] = '\0';
}


int main(void) {
    char input[MAX_INPUT_SIZE];
    char hash[65];

    while(1) {
        printf("\nSHA-256 Hash Calculator\n");
        printf("Enter string to hash (or 'exit' to quit): ");

        // Get input from user
        memset(input, 0, MAX_INPUT_SIZE);
        get_input(input, MAX_INPUT_SIZE);

        // Check if user wants to exit
        if(strcmp(input, "exit") == 0) {
            printf("Exiting...\n");
            break;
        }

        // Calculate and display hash
        sha256_hash(input, hash);
        printf("\nInput string: %s\n", input);
        printf("SHA-256 hash: %s\n", hash);
    }

    exit(0);
}