#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_SIZE 256

void rc4_init(unsigned char *S, const unsigned char *key, size_t key_len) {
    for (int i = 0; i < STATE_SIZE; i++) {
        S[i] = (unsigned char)i;
    }
    int j = 0;
    for (int i = 0; i < STATE_SIZE; i++) {
        j = (j + S[i] + key[i % key_len]) % STATE_SIZE;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}
void rc4_decrypt(const unsigned char *key, size_t key_len, unsigned char *data, size_t data_len) {
    unsigned char S[STATE_SIZE];
    rc4_init(S, key, key_len);

    int i = 0, j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % STATE_SIZE;
        j + (j + S[i]) % STATE_SIZE;

        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        unsigned char keystream_byte = S[(S[i] + S[j]) % STATE_SIZE];
        data[k] ^= keystream_byte;
    }
}
int decrypt_file(const char *input_path, const char *output_path, const unsigned char *key, size_t key_len) {
    FILE *infile = fopen(input_path, "rb");
    if (!infile) {
        perror("error opening encrypted file");
        return -1;
    }
    fseek(infile, 0, SEEK_END);
    long file_size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    if (file_size <= 0) {
        printf("file is empty. nothing to decrypt\n");
        fclose(infile);
        return 0;
    }
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if(!buffer) {
        perror("memory allocation error");
        fclose(infile);
        return -1;
    }
    fread(buffer, 1, file_size, infile);
    fclose(infile);
    rc4_decrypt(key, key_len, buffer, file_size);
    FILE *outfile = fopen(output_path, "wb");
    if(!infile) {
        perror("error opening output file");
        free(buffer);
        return -1;
    }
    fwrite(buffer, 1, file_size, outfile);
    free(buffer);
    fclose(outfile);
    return 0;
}
int main(int argc, char *argv[]) {
    const char *input_file = "file.txt.enc";
    const char *output_file = "file_decrypted.txt";
    const unsigned char key[] = "yitbarek's secret key";
    size_t key_len = strlen((const char *)key);

    printf("starting decryption...\n");
    if(decrypt_file(input_file, output_file, key, key_len) == 0) {
        printf("file succesfully decrypted: %s -> %s\n", input_file, output_file);
    } else {
        printf("decryption failed.\n");
        return 1;
    }
    return 0;
}