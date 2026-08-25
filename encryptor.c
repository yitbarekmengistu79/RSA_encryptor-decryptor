#include <stdio.h>
#include <stdlib.h>
#include <time.h>
unsigned long long power_mod(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) result = (__int128)result * base % mod;
        base = (__int128)base * base % mod;
        exp /= 2;
    }
    return result;
}
void rc4_init(unsigned char *S, unsigned char *key, int key_len) {
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}
void rc4_crypt(unsigned char *S, unsigned char *data, size_t len) {
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        unsigned char K = S[(S[i] + S[j]) % 256];
        data[n] ^= K;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    unsigned long long e = 65537, n = 3233;
    FILE *fp = fopen(filename, "rb");
    if (!fp) { perror("Failed to open file"); return 1; }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *plaintext = malloc(size);
    if (!plaintext) { fclose(fp); return 1; }
    fread(plaintext, 1, size, fp);
    fclose(fp);
    srand((unsigned int)time(NULL));
    unsigned char stream_key[4];
    unsigned long long encrypted_key[4];
    for (int i = 0; i < 4; i++) {
        stream_key[i] = rand() % 256;
        encrypted_key[i] = power_mod((unsigned long long)stream_key[i], e, n);
    }
    unsigned char S[256];
    rc4_init(S, stream_key, 4);
    rc4_crypt(S, plaintext, size);
    fp = fopen(filename, "wb");
    if (!fp) { free(plaintext); return 1; }

    fwrite(encrypted_key, sizeof(unsigned long long), 4, fp);
    fwrite(plaintext, 1, size, fp);

    fclose(fp);
    free(plaintext);
    printf("Successfully encrypted: %s\n", filename);
    return 0;
}
