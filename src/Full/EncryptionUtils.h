#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <string>
#include <vector>
#include <chrono>

#define AS_PORT 8080
#define TGS_PORT 8081
#define SERVICE_PORT 8082
#define MAX_BUFFER 1048576

const std::string clientSecretKey = "clientsecretkey11223";
const std::string tgsID = "ticketgrantingserviceID"; 
const std::string tgsSecretKey = "ticketseeeeeeKEY";
const std::string serviceSecretKey = "servicesecretkey";

int strToInt(const std::string& str){
    int ans = 0;
    for(int i=0; i<str.length(); i++){
        if(str[i] > '9' || str[i] < '0'){
            printf("Error strToInt.\n");
            return -1;
        }
        ans = ans*10 + str[i] - '0';
    }
    return ans;
}

std::int64_t Timestamp(){
    return std::chrono::duration_cast<std::chrono::seconds>
    (std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string encrypt(const std::string &plaintext, const std::string &key) {
    std::string encrypted;
    for (size_t i = 0; i < plaintext.length(); ++i) {
        char keyChar = key[i % key.length()]; // Cycle through key characters
        char encChar = (plaintext[i] + keyChar) % 128; // Use % 128 to stay within ASCII
        encrypted.push_back(encChar);
    }
    return encrypted;
}

std::string decrypt(const std::string &ciphertext, const std::string &key) {
    std::string decrypted;
    for (size_t i = 0; i < ciphertext.length(); ++i) {
        char keyChar = key[i % key.length()];
        char decChar = (ciphertext[i] - keyChar + 128) % 128; // Use +128 to avoid negative numbers
        decrypted.push_back(decChar);
    }
    return decrypted;
}

std::vector<std::string> extractData(std::string str){
    std::string temp_str = "";
	std::vector<std::string> data;
	for(int i=0; i<str.length(); i++){
		if(str[i] == ','){
			data.push_back(temp_str);
            temp_str = "";
		}
        else{
            temp_str += (char) str[i];
        }
	}
	if(temp_str!="")
        data.push_back(temp_str);
	return data;
}

#endif