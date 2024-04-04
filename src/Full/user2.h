#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "EncryptionUtils.h"
#include <vector>
#include <sstream>

using namespace std;

class tgsReq {
public:
    string serviceID;
    int ticketLifetime;
    string convertMessage() {
        return serviceID + "," + to_string(ticketLifetime);
    }
};

class UA{
private:
    int timestamp = Timestamp();
public:
    string userID;

    void setnewTimestamp(){
        this->timestamp = Timestamp();
    }

    string convertMessage(){
        return userID + "," + to_string(timestamp);
    }
};

vector<string> splitFields(const string& str) {
    vector<string> fields;
    stringstream ss(str);
    string field;
    while (getline(ss, field, ','))
    {
        fields.push_back(field);
    }
    return fields;
}

void sendMsgToTGS(const string &tgt, tgsReq &req, const string &ua, string &tgsReply, string& serviceTicket) {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    // specifying address 
	sockaddr_in serverAddress; 
	serverAddress.sin_family = AF_INET; 
	serverAddress.sin_port = htons(TGS_PORT); 
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

	// sending connection request 
	if(connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connect failed\n";
    }
    else {
        cout << "Connect successfully\n";
    }

    // Convert TGS request to string message
    const string requestMessage = req.convertMessage();

    // test encrypt data
    // TGT message and UA message is encrypted in previous step, this encryption here is just the testing
    //string tgtCipherText = encrypt(tgt, "tgtsecretkey");
    //string uaCipherText = encrypt(ua, "tgssessionkey");
    
    // Send data
    send(clientSocket, tgt.c_str(), tgt.length(), 0);
    sleep(1);
    send(clientSocket, requestMessage.c_str(), requestMessage.length(), 0);
    sleep(1);
    send(clientSocket, ua.c_str(), ua.length(), 0);
    
    // // Receive data
    char tgsReply_Buffer[1024] = {0}, serviceTicket_Buffer[1024] = {0};
    recv(clientSocket, tgsReply_Buffer, 1024, 0);
    recv(clientSocket, serviceTicket_Buffer, 1024, 0);

    // cout << resBuffer << "\n";
    // cout << stBuffer << "\n";

    //string resMsg = decrypt(string(tgsReply_Buffer), TGSsessionkey); //replace by tgs session key in AS

    // cout << resMsg << "\n";
    // cout << stBuffer << "\n";
    tgsReply = string(tgsReply_Buffer);
    serviceTicket = string(serviceTicket_Buffer);

    close(clientSocket);
    
}
