#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <chrono>
#include <vector>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <conio.h> // For _getch()
#define PLATFORM_NAME "Windows"
#elif defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#define PLATFORM_NAME "macOS"
#endif

const int SECOND = 1;
const int MINUTE = 60 * SECOND;
const int HOUR = 60 * MINUTE;
const int DAY = 24 * HOUR;
const int MONTH = 30 * DAY;
const int YEAR = 365 * DAY;

using json = nlohmann::json;
using namespace std;

const int MOD_BITS = 128, AES_BITS = 256, SPEED = 1500000;
const int BUFFER_SIZE = 1024;

std::string to_hex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string get_password() {
    std::string password, confirm_password;
    char ch;

#ifdef _WIN32
    do {
        std::cout << "Enter password: ";
        password.clear();
        while ((ch = _getch()) != '\r') { // '\r' is carriage return
            if (ch == '\b' && !password.empty()) { // Handle backspace
                password.pop_back();
                std::cout << "\b \b"; // Move cursor back, print space to delete, move back again
            } else if (ch != '\b') {
                password.push_back(ch);
                std::cout << '*'; // Echo asterisk for each character
            }
        }
        std::cout << "\nConfirm password: ";
        confirm_password.clear();
        while ((ch = _getch()) != '\r') {
            if (ch == '\b' && !confirm_password.empty()) {
                confirm_password.pop_back();
                std::cout << "\b \b";
            } else if (ch != '\b') {
                confirm_password.push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << std::endl;
        if (password != confirm_password) {
            std::cout << "Passwords do not match. Please try again.\n";
        }
    } while (password != confirm_password);
#elif defined(__APPLE__)
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // Get terminal settings
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Turn echo off
    do {
        std::cout << "Enter password: ";
        password.clear();
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        while ((ch = getchar()) != '\n') {
            password += ch;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\nConfirm password: ";
        confirm_password.clear();
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        while ((ch = getchar()) != '\n') {
            confirm_password += ch;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        if (password != confirm_password) {
            std::cout << "Passwords do not match. Please try again.\n";
        }
    } while (password != confirm_password);
#endif

    // Securely zero out the confirm_password memory
    std::memset(&confirm_password[0], 0, confirm_password.size());
    confirm_password.clear();

    return password;
}

BIGNUM* generate_prime(int bits) {
    BIGNUM* prime = BN_new();
    BN_generate_prime_ex(prime, bits, 0, nullptr, nullptr, nullptr);
    return prime;
}

BIGNUM* generate_random_number(int bits) {
    BIGNUM* num = BN_new();
    BN_rand(num, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    return num;
}

#define AES_BLOCK_SIZE 16

void aes_encrypt(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, vector<unsigned char>& ciphertext, vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption");
    }

    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to encrypt");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
}

vector<unsigned char> aes_decrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    vector<unsigned char> plaintext(ciphertext.size());

    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to decrypt");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

json make_puzzle(int t_seconds, const string& password) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = generate_prime(MOD_BITS / 2);
    BIGNUM* q = generate_prime(MOD_BITS / 2);
    BIGNUM* N = BN_new();
    BN_mul(N, p, q, ctx);

    BIGNUM* a = BN_new();
    BN_rand(a, MOD_BITS, -1, 0);

    BIGNUM* cipher_value = BN_dup(a);
    unsigned long long exponent = static_cast<unsigned long long>(t_seconds) * SPEED;
    auto start_time = chrono::high_resolution_clock::now();

    for (unsigned long long i = 0; i < exponent; i++) {
        BN_sqr(cipher_value, cipher_value, ctx);
        BN_mod(cipher_value, cipher_value, N, ctx);

        if (i % (exponent / 100) == 0) {  // Report progress every 1%
            auto now = chrono::high_resolution_clock::now();
            double elapsed = chrono::duration_cast<chrono::seconds>(now - start_time).count();
            double percent = 100.0 * i / exponent;
            cout << fixed << "Progress: " << setprecision(2) << percent << "%, Elapsed Time: " << elapsed << " seconds" << endl;
        }
    }

    unsigned char key_bytes[AES_BITS / 8] = { 0 };
    if (BN_bn2binpad(cipher_value, key_bytes, AES_BITS / 8) < 0) {
        cerr << "Failed to convert BIGNUM to binary." << endl;
        BN_free(p);
        BN_free(q);
        BN_free(N);
        BN_free(a);
        BN_free(cipher_value);
        BN_CTX_free(ctx);
        return nullptr;
    }

    string actual_pw = get_password();
    vector<unsigned char> key_vect(key_bytes, key_bytes + AES_BITS / 8);
    vector<unsigned char> plaintext(actual_pw.begin(), actual_pw.end());
    vector<unsigned char> ciphertext, iv;

    aes_encrypt(plaintext, key_vect, ciphertext, iv);

    char* N_dec = BN_bn2dec(N);
    char* a_dec = BN_bn2dec(a);

    json puzzle = {
        {"N", string(N_dec)},
        {"a", string(a_dec)},
        {"exponent", std::to_string(exponent)},
        {"ciphertext", to_hex(ciphertext)},
        {"iv", to_hex(iv)}
    };

    OPENSSL_free(N_dec);
    OPENSSL_free(a_dec);
    BN_free(p);
    BN_free(q);
    BN_free(N);
    BN_free(a);
    BN_free(cipher_value);
    BN_CTX_free(ctx);

    return puzzle;
}

string solve_puzzle(const json& puzzle) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = BN_new();
    BIGNUM* a = BN_new();
    BN_dec2bn(&N, puzzle["N"].get<string>().c_str());
    BN_dec2bn(&a, puzzle["a"].get<string>().c_str());
    unsigned long long exponent = std::stoull(puzzle["exponent"].get<string>());
    auto start_time = chrono::high_resolution_clock::now();

    BIGNUM* result = BN_dup(a);
    for (unsigned long long i = 0; i < exponent; i++) {
        BN_sqr(result, result, ctx);
        BN_mod(result, result, N, ctx);

        if (i % (exponent / 100) == 0) {  // Report progress every 1%
            auto now = chrono::high_resolution_clock::now();
            double elapsed = chrono::duration_cast<chrono::seconds>(now - start_time).count();
            double percent = 100.0 * i / exponent;
            cout << fixed << "Progress: " << setprecision(2) << percent << "%, Elapsed Time: " << elapsed << " seconds" << endl;
        }
    }

    unsigned char key_bytes[AES_BITS / 8] = { 0 };
    if (BN_bn2binpad(result, key_bytes, AES_BITS / 8) < 0) {
        cerr << "Failed to convert BIGNUM to binary." << endl;
        BN_free(N);
        BN_free(a);
        BN_free(result);
        BN_CTX_free(ctx);
        return "Error: BIGNUM conversion failed.";
    }

    vector<unsigned char> key_vect(key_bytes, key_bytes + AES_BITS / 8);
    vector<unsigned char> ciphertext = from_hex(puzzle["ciphertext"].get<string>());
    vector<unsigned char> iv = from_hex(puzzle["iv"].get<string>());
    vector<unsigned char> decrypted_msg;

    decrypted_msg = aes_decrypt(ciphertext, key_vect, iv);

    BN_free(N);
    BN_free(a);
    BN_free(result);
    BN_CTX_free(ctx);

    return string(decrypted_msg.begin(), decrypted_msg.end());
}

void backup_file(const string& filename) {
    time_t now = time(0);
    tm* ltm = localtime(&now);
    char date[20];
    strftime(date, sizeof(date), "%Y-%m-%d-%H-%M-%S", ltm);
    string backup_folder = "backups";
    string backup_filename = backup_folder + "/" + filename + "-" + date + ".json";
    ifstream src(filename, ios::binary);
    ofstream dst(backup_filename, ios::binary);
    dst << src.rdbuf();
    cout << "Backup saved as " << backup_filename << endl;
}

int main() {
    cout << R"(
        _  __                                    __   __
       | |/ /                                    \ \ / /
       | ' /  __ _  _ __  _ __ ___    __ _  ______\ V / 
       |  <  / _` || '__|| '_ ` _ \  / _` ||______|> <  
       | . \| (_| || |   | | | | | || (_| |       / . \ 
       |_|\_\\__,_||_|   |_| |_| |_| \__,_|      /_/ \_\


                      www.karma-x.io

                        TimeCapsule
            )" << endl;
    json puzzle;
    string filename = "puzzle.json";
    ifstream file_in;
    ofstream file_out;
    string choice;

    while (true) {
        cout << "Options:\n1. Create a new puzzle\n2. Solve the current puzzle\n3. Exit\nEnter your choice (1, 2, or 3): ";
        cin >> choice;

        if (choice == "1") {
            cout << "\033[1;31mWarning: Creating a puzzle takes just as long as solving one. Tread carefully.\033[0m\n";
            cout << "Select the desired time to solve the puzzle:\n";
            cout << "0. 2 seconds\n1. 30 seconds\n2. 30 minutes\n3. 24 hours\n4. 12 days\n5. 30 days\n6. 90 days\n7. 180 days\n8. 360 days\n";
            string time_choice;
            cin >> time_choice;
            vector<int> time_options = { 2 * SECOND, 30 * SECOND, 30 * MINUTE, 24 * HOUR, 12 * DAY, 30 * DAY, 90 * DAY, 180 * DAY, 360 * DAY };

            int time_index = stoi(time_choice);
            if (time_index < 0 || time_index >= time_options.size()) {
                cout << "Invalid time choice. Please try again.\n";
                continue;
            }
            int t_seconds = time_options[time_index];

            string dummy_password = get_password();

            file_in.open(filename);
            if (file_in) {
                string overwrite;
                cout << "A puzzle already exists. Do you want to overwrite it? (y/n): ";
                cin >> overwrite;
                if (overwrite != "y") {
                    cout << "Operation cancelled.\n";
                    file_in.close();
                    continue;
                }
                file_in.close();
                backup_file(filename);  // Backup the existing puzzle
            }

            puzzle = make_puzzle(t_seconds, dummy_password);
            std::fill(dummy_password.begin(), dummy_password.end(), '\0');
            dummy_password.clear();
            file_out.open(filename);
            file_out << puzzle.dump(4);
            file_out.close();
            cout << "Puzzle created and saved.\n";
        } else if (choice == "2") {
            file_in.open(filename);
            if (!file_in) {
                cout << "Error: Puzzle file '" << filename << "' not found.\n";
                continue;
            }
            file_in >> puzzle;
            file_in.close();

            cout << "Solving the puzzle...\n";
            string result = solve_puzzle(puzzle);
            cout << "Solution: " << result << endl;
        } else if (choice == "3") {
            cout << "Exiting...\n";
            break;
        } else {
            cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0;
}

