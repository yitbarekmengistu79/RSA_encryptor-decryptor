#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_SIZE 256

void rc4_init(unsigned char *S, const unsigned char *key, size_t key_len) {
    if (!S || !key || key_len == 0) return;

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

void rc4_encrypt(const unsigned char *key, size_t key_len, unsigned char *data, size_t data_len) {
    if (!key || !data || data_len == 0) return;

    unsigned char S[STATE_SIZE];
    rc4_init(S, key, key_len);
    
    int i = 0, j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % STATE_SIZE;
        j = (j + S[i]) % STATE_SIZE;
        
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
        unsigned char keystream_byte = S[(S[i] + S[j]) % STATE_SIZE];
        data[k] ^= keystream_byte;
    }
}

int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key, size_t key_len) {
    if (!input_path || !output_path || !key) {
        fprintf(stderr, "[-] Invalid argument pointers.\n");
        return -1;
    }

    FILE *infile = fopen(input_path, "rb");
    if (!infile) {
        perror("[-] Error opening input file");
        return -1;
    }

    // Determine file size safely
    if (fseek(infile, 0, SEEK_END) != 0) {
        perror("[-] Failed to seek end of file");
        fclose(infile);
        return -1;
    }
    
    long file_size = ftell(infile);
    if (file_size < 0) {
        perror("[-] Failed to get file size");
        fclose(infile);
        return -1;
    }
    
    rewind(infile);

    if (file_size == 0) {
        printf("[!] File is empty. Nothing to encrypt.\n");
        fclose(infile);
        return 0;
    }

    // Allocate memory and check pointer validity
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if (!buffer) {
        fprintf(stderr, "[-] Memory allocation failed for size: %ld\n", file_size);
        fclose(infile);
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, file_size, infile);
    fclose(infile);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "[-] Failed to read complete file contents.\n");
        free(buffer);
        return -1;
    }

    // Encrypt contents
    rc4_encrypt(key, key_len, buffer, file_size);

    // Write to output file
    FILE *outfile = fopen(output_path, "wb");
    if (!outfile) {
        perror("[-] Error opening output file");
        free(buffer);
        return -1;
    }

    fwrite(buffer, 1, file_size, outfile);

    free(buffer);
    fclose(outfile);
    return 0;
}

int main(void) {
    const char *input_file = "file.txt";
    const char *output_file = "file.txt.enc";
    const unsigned char key[] = "MySecretKey123";
    size_t key_len = strlen((const char *)key);

    printf("[*] Starting Encryption...\n");
    if (encrypt_file(input_file, output_file, key, key_len) == 0) {
        printf("[+] File successfully encrypted: %s -> %s\n", input_file, output_file);
    } else {
        printf("[-] Encryption failed.\n");
        return 1;
    }

    return 0;
}