#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>
#include <shlobj.h>  // Для получения пути к рабочему столу

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define SALT_SIZE 16

void GeneratePassword(char* password, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    srand((unsigned int)time(NULL));

    for (int i = 0; i < length; i++) {
        password[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    password[length] = '\0';
}

void PBKDF2_HMAC_SHA256(const char* password, uint8_t* salt, uint8_t* key) {
    for (int i = 0; i < KEY_SIZE; i++) {
        key[i] = password[i % strlen(password)] ^ salt[i % SALT_SIZE];
    }
}

void EncryptBlock(uint8_t* block, uint8_t* key, int size) {
    for (int i = 0; i < size; i++) {
        block[i] ^= key[i % KEY_SIZE];
    }
}

void AddPadding(uint8_t* data, int* size) {
    int paddingSize = AES_BLOCK_SIZE - (*size % AES_BLOCK_SIZE);
    for (int i = 0; i < paddingSize; i++) {
        data[*size + i] = rand() % 256;
    }
    *size += paddingSize;
}

int EncryptFile(const char* inputFile, const char* outputFile, const char* password) {
    FILE* in;
    fopen_s(&in, inputFile, "rb");
    if (!in) {
        printf("Error: file not found!\n");
        return -1;
    }

    fseek(in, 0, SEEK_END);
    int fileSize = (int)ftell(in);
    fseek(in, 0, SEEK_SET);

    uint8_t* fileData = (uint8_t*)malloc(fileSize + AES_BLOCK_SIZE);
    if (!fileData) {
        printf("Error: not enough memory!\n");
        fclose(in);
        return -1;
    }

    fread(fileData, 1, fileSize, in);
    fclose(in);

    uint8_t salt[SALT_SIZE], key[KEY_SIZE];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < SALT_SIZE; i++) salt[i] = rand() % 256;

    PBKDF2_HMAC_SHA256(password, salt, key);
    AddPadding(fileData, &fileSize);

    for (int i = 0; i < fileSize; i += AES_BLOCK_SIZE) {
        EncryptBlock(&fileData[i], key, AES_BLOCK_SIZE);
    }

    FILE* out;
    fopen_s(&out, outputFile, "wb");
    if (!out) {
        printf("Error: could not create file!\n");
        free(fileData);
        return -1;
    }

    fwrite(salt, 1, SALT_SIZE, out);
    fwrite(fileData, 1, fileSize, out);
    fclose(out);
    free(fileData);

    printf("File encrypted: %s\n", outputFile);
    return 0;
}

int DecryptFile(const char* inputFile, const char* outputFile, const char* password) {
    FILE* in;
    fopen_s(&in, inputFile, "rb");
    if (!in) {
        printf("Error: file not found!\n");
        return -1;
    }

    fseek(in, 0, SEEK_END);
    int fileSize = (int)ftell(in) - SALT_SIZE;
    fseek(in, 0, SEEK_SET);

    uint8_t salt[SALT_SIZE], key[KEY_SIZE];
    fread(salt, 1, SALT_SIZE, in);

    uint8_t* fileData = (uint8_t*)malloc(fileSize);
    if (!fileData) {
        printf("Error: not enough memory!\n");
        fclose(in);
        return -1;
    }

    fread(fileData, 1, fileSize, in);
    fclose(in);

    PBKDF2_HMAC_SHA256(password, salt, key);

    for (int i = 0; i < fileSize; i += AES_BLOCK_SIZE) {
        EncryptBlock(&fileData[i], key, AES_BLOCK_SIZE);
    }

    FILE* out;
    fopen_s(&out, outputFile, "wb");
    if (!out) {
        printf("Error: could not create file!\n");
        free(fileData);
        return -1;
    }

    fwrite(fileData, 1, fileSize, out);
    fclose(out);
    free(fileData);

    printf("File decrypted: %s\n", outputFile);
    return 0;
}

void CreateDirectoryForDesktop(char* folderPath) {
    // Получаем путь к рабочему столу на Windows
    char desktopPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath) == S_OK) {
        printf("Desktop path: %s\n", desktopPath);
        snprintf(folderPath, MAX_PATH, "%s\\Encrypted_Files", desktopPath);

        // Создаем папку, если она не существует
        if (CreateDirectoryA(folderPath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            printf("Directory created at: %s\n", folderPath);
        }
        else {
            printf("Error creating directory!\n");
        }
    }
    else {
        printf("Error retrieving Desktop path!\n");
    }
}

int main() {
    char inputFile[256], outputFile[256], password[33], folderPath[256];

    // Создаем папку на рабочем столе
    CreateDirectoryForDesktop(folderPath);

    // Меню
    int choice;
    printf("Select function:\n");
    printf("1. Encrypt file\n");
    printf("2. Decrypt file\n");
    printf("Enter your choice: ");
    if (scanf_s("%d", &choice) != 1) {
        printf("Invalid input!\n");
        return -1;
    }

    if (choice == 1) {
        // Шифрование
        printf("Enter the path of the file to encrypt: ");
        if (scanf_s("%255s", inputFile, (unsigned int)sizeof(inputFile)) != 1) {
            printf("Invalid input for file path!\n");
            return -1;
        }

        GeneratePassword(password, 32);  // Генерируем случайный пароль
        snprintf(outputFile, sizeof(outputFile), "%s\\encrypted.enc", folderPath);

        if (EncryptFile(inputFile, outputFile, password) != 0) {
            return -1;
        }

        // Сохраняем пароль в той же папке
        FILE* pf;
        char passwordFilePath[512];
        snprintf(passwordFilePath, sizeof(passwordFilePath), "%s\\password.txt", folderPath);
        fopen_s(&pf, passwordFilePath, "w");
        if (pf) {
            fprintf(pf, "%s", password);
            fclose(pf);
            printf("Password saved at: %s\n", passwordFilePath);
        }
        else {
            printf("Error saving password!\n");
        }

    }
    else if (choice == 2) {
        // Расшифровка
        printf("Enter the path of the encrypted file: ");
        if (scanf_s("%255s", inputFile, (unsigned int)sizeof(inputFile)) != 1) {
            printf("Invalid input for file path!\n");
            return -1;
        }

        printf("Enter the password: ");
        if (scanf_s("%32s", password, (unsigned int)sizeof(password)) != 1) {
            printf("Invalid input for password!\n");
            return -1;
        }

        snprintf(outputFile, sizeof(outputFile), "%s\\decrypted.zip", folderPath);  // Изменено на .zip
        if (DecryptFile(inputFile, outputFile, password) != 0) {
            return -1;
        }

        printf("Decrypted file saved to: %s\n", outputFile);
    }
    else {
        printf("Invalid choice!\n");
        return -1;
    }

    return 0;
}
