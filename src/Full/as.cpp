// C++ program to show the example of server application in 
// socket programming 
#include <cstring> 
#include <iostream> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h> 
#include <ctime>
#include <random>
#include "EncryptionUtils.h"

std::string genRandKey(int length) {
    // define characters for the service session key
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    // seed the random number generator
    std::random_device rd;
    std::mt19937 generator(rd());

    // define a distribution for selecting characters
    std::uniform_int_distribution<int> distribution(0, charset.size() - 1);

    // generate the service session key
    std::string key;
    for (int i = 0; i < length; i++) {
        key += charset[distribution(generator)];
    }

    return key;
}

int listen_port(int serverSocket, int port){
    // specifying the address 
	sockaddr_in serverAddress; 
	serverAddress.sin_family = AF_INET; 
	serverAddress.sin_port = htons(port); 
	serverAddress.sin_addr.s_addr = INADDR_ANY; 

	// binding socket. 
	if(bind(serverSocket, (struct sockaddr*)&serverAddress, 
		sizeof(serverAddress)) != 0)
		printf("AS: Bind error.\n");

	// listening to the assigned socket 
	listen(serverSocket, 5); 

	// accepting connection request 
	int clientSocket 
		= accept(serverSocket, nullptr, nullptr); 
    
    return clientSocket;
}

class asReply{
	public:

	std::string tgsID;
	int timestamp = time_t(0);
	int tgtLifetime;
	std::string tgsSessionKey;

	std::string convert_message(){
        std::string temp = tgsID + "," + std::to_string(timestamp) + "," 
            + std::to_string(tgtLifetime) + "," + tgsSessionKey;
        return temp;
    }
};

class TGT{ //Ticket-granting Ticket
public:
	std::string userID;
	std::string tgsID;
	int timestamp = time_t(0);
	int userPort;
	int tgtLifetime;
	std::string tgsSessionKey;

	std::string convert_message(){
        std::string temp = userID + "," + tgsID + "," + std::to_string(timestamp) + "," 
            + std::to_string(userPort) + "," + std::to_string(tgtLifetime)
			+ "," + tgsSessionKey;
        return temp;
    }
};

bool TGTReq_check(std::vector<std::string> data){
	// check expected size 4
	if(data.size() != 4)
		return false;

	// check userID non null

	// check if serviceID exists in server (we don't implement that here)

	// check userPort non null

	// check TGT lifetime requested
	float time = std::stoi(data[3]);
	if(time <= 0 && time >= 900){
		printf("TGT time requested too short or long: %f", time);
		return false;
	}
	return true;
}

int main(){
	// 1. Get request from user

	// creating sockets
	int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

	// check error
	if(serverSocket == -1){
		printf("Socket creation error.\n");
	}
    
	// set port
	int serverPort = AS_PORT;
    int clientSocket = listen_port(serverSocket, serverPort);

	// receive data
	char buffer[MAX_BUFFER] = { 0 }; 
	recv(clientSocket, buffer, MAX_BUFFER, 0); 
	std::cout << "Message received: " << buffer << std::endl; 

	// extract data
	std::vector<std::string> tgtReqData = extractData(std::string(buffer));

	// check data
	if(!TGTReq_check(tgtReqData)){
		printf("Data check failed.\n");
		close(serverSocket);
		return 0;
	}
	std::cout << "TGT request accepted" << std::endl;
	TGT tgt;
	asReply rep;

	// construct AS_reply
	rep.tgsID = tgsID;
	rep.tgtLifetime = std::stoi(tgtReqData[2]);
	//rep.tgsSessionKey = genRandKey(32);
	rep.tgsSessionKey = "thisisthesessionkey";
	std::cout << "AS reply: " << rep.convert_message() << std::endl;

	std::string rep_en = encrypt(rep.convert_message(), clientSecretKey);

	// construct TGT
	tgt.tgsID = tgsID;
	tgt.tgsSessionKey = rep.tgsSessionKey;
	tgt.tgtLifetime = rep.tgtLifetime;
	tgt.userID = tgtReqData[0];
	tgt.userPort = std::stoi(tgtReqData[2]);

	std::cout << "TGT: " << tgt.convert_message() << std::endl;
	
	std::string tgt_en = encrypt(tgt.convert_message(), tgsSecretKey);

	// send packages
	int length = rep_en.length();
	send(clientSocket, &length, sizeof(int)/sizeof(char), 0);
	send(clientSocket, rep_en.data(), rep_en.length(), 0);
	send(clientSocket, tgt_en.data(), tgt_en.length(), 0); 
}