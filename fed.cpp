#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Function to generate a random key and IV
void generateKeyandIV(unsigned char* key, unsigned char* iv) {
    if (!RAND_bytes(key, 32)) {
        std::cerr << "Error generating key" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating IV" << std::endl;
        exit(EXIT_FAILURE);
    }
}

// Function to save the key and IV to a file
void saveKeyAndIV(const std::string& filename, const unsigned char* key, const unsigned char* iv) {
    std::ofstream out(filename, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "Unable to open key file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }
    out.write(reinterpret_cast<const char*>(key), 32);
    out.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    out.close();
}

// Function to load the key and IV from a file
void loadKeyAndIV(const std::string& filename, unsigned char* key, unsigned char* iv) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "Unable to open key file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }
    in.read(reinterpret_cast<char*>(key), 32);
    in.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    in.close();
}

// Function to encrypt a file
bool encrypt_file(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, const unsigned char* key, const unsigned char* iv) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in.is_open()) {
        std::cerr << "Unable to open input file: " << inputFile << std::endl;
        return false;
    }
    if (!out.is_open()) {
        std::cerr << "Unable to open output file: " << outputFile << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create context." << std::endl;
        return false;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        std::cerr << "Failed to initialize encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[1024];
    unsigned char ciphertext[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int ciphertext_len;

    while (in.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        bytesRead = static_cast<int>(in.gcount());
        if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, bytesRead)) {
            std::cerr << "Encryption failed during update." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write(reinterpret_cast<char*>(ciphertext), ciphertext_len);
    }

    if (!EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len)) {
        std::cerr << "Encryption failed during finalization." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write(reinterpret_cast<char*>(ciphertext), ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    // Save the key and IV to a file
    saveKeyAndIV(keyFile, key, iv);

    return true;
}

// Function to decrypt a file
bool decrypt_file(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, unsigned char* key, unsigned char* iv) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in.is_open()) {
        std::cerr << "Unable to open input file: " << inputFile << std::endl;
        return false;
    }
    if (!out.is_open()) {
        std::cerr << "Unable to open output file: " << outputFile << std::endl;
        return false;
    }

    // Load the key and IV from the file
    loadKeyAndIV(keyFile, key, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create context." << std::endl;
        return false;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        std::cerr << "Failed to initialize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[1024];
    unsigned char plaintext[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int plaintext_len;

    while (in.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        bytesRead = static_cast<int>(in.gcount());
        if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, bytesRead)) {
            std::cerr << "Decryption failed during update." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write(reinterpret_cast<char*>(plaintext), plaintext_len);
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len)) {
        std::cerr << "Decryption failed during finalization." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write(reinterpret_cast<char*>(plaintext), plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input_file> <output_file>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string keyFile = "key_and_iv.bin";

    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];

    if (mode == "encrypt") {
        generateKeyandIV(key, iv);
        if (encrypt_file(inputFile, outputFile, keyFile, key, iv)) {
            std::cout << "File encrypted successfully" << std::endl;
        }
        else {
            std::cerr << "File encryption failed" << std::endl;
        }
    }
    else if (mode == "decrypt") {
        if (decrypt_file(inputFile, outputFile, keyFile, key, iv)) {
            std::cout << "File decrypted successfully" << std::endl;
        }
        else {
            std::cerr << "File decryption failed" << std::endl;
        }
    }
    else {
        std::cerr << "Invalid mode specified. Use 'encrypt' or 'decrypt'" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
