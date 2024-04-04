// C++ program to illustrate the client application in the 
// socket programming 
#include <cstring> 
#include <iostream> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include "EncryptionUtils.h"
#include <vector>

#include "user2.h"

using namespace std;

void connect_port(int otherSocket, int port){
    // specifying address 
	sockaddr_in otherAddress; 
	otherAddress.sin_family = AF_INET; 
	otherAddress.sin_port = htons(port); 
	otherAddress.sin_addr.s_addr = INADDR_ANY; 

	// sending connection request 
	int return_code = connect(otherSocket, (struct sockaddr*)&otherAddress, 
			sizeof(otherAddress)); 
	if(return_code == -1){
        printf("Port connection error.\n");
    }
}

class tgtReq{
    public:

	string userID;
	string serviceID;
	size_t userPort; //IPv4
	size_t tgtLifetime;

    string convert_message(){
        string temp = userID + "," + serviceID + "," 
            + std::to_string(userPort) + "," + std::to_string(tgtLifetime);
        return temp;
    }
};

class clientInfo{
    public:
    string userID;
    string userPass;
    string serviceID;
    int userSocket;
    string clientSecretKey(){
        return encrypt(userID + userPass, "12346789123456789");
        //return encrypt(userID + userPass, key);
    }
    clientInfo(){
        this->userSocket = socket(AF_INET, SOCK_STREAM, 0);
        
        if(this->userSocket == -1)
            printf("Socket creation error.\n");
    }
    ~clientInfo(){
        close(userSocket);
    }
} user;

void sendTGTticketReq(){
    // TGT Ticket request construct
    tgtReq user_tgt;
    user_tgt.userID = user.userID;
    user_tgt.serviceID = user.serviceID;
    user_tgt.userPort = AS_PORT;
    user_tgt.tgtLifetime = 60;

	// send TGT Ticket request 
    string temp_msg = user_tgt.convert_message();
    printf("User TGT request: %s \n", temp_msg.data());
	if(send(user.userSocket, temp_msg.data(), temp_msg.length(), 0) == -1) 
        printf("Send failed.\n");
}

vector<string> getASreply(int serverSocket){
    // get data
    int length;
    if(recv(serverSocket, &length, sizeof(int)/sizeof(char), 0) == -1)
        printf("Receive error: int.\n");
    char buffer[MAX_BUFFER] = { 0 };
	if(length >= MAX_BUFFER || recv(serverSocket, buffer, length, 0) == -1) // AS reply
        printf("Receive error.\n");
    string ASreply_en = string(buffer);
    //std::cout << ASreply_en << std::endl;
    
    // decrypt and extract reply
    string ASrep_msg = decrypt(ASreply_en, "clientsecretkey11223");
    vector<string> ASreply = extractData(ASrep_msg);

    std::cout << "AS reply: " << ASrep_msg << std::endl;

    return ASreply;
}

string getTGT_en(int serverSocket){
    //get data
    char buffer[MAX_BUFFER] = {0};
    if(recv(serverSocket, buffer, sizeof(buffer), 0) == -1) // TGT ticket
        printf("Receive error.\n");
    string TGT_en = string(buffer);

    return TGT_en;
}

vector<string> extract_tgsReply(string tgsReply){
    int num_of_content = 4;
    vector<string> data = extractData(tgsReply);
    if(data.size()!=4){
        printf("tgsReply returned false: %s\n", tgsReply.c_str());
        return vector<string>();
    }
    return data;
}

void sendMsgToService(string serviceTicket_en, string UA_en, string& serviceReply){
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    // specifying address 
	sockaddr_in serverAddress; 
	serverAddress.sin_family = AF_INET; 
	serverAddress.sin_port = htons(SERVICE_PORT); 
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

	// sending connection request 
	if(connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connect failed\n";
    }
    else {
        cout << "Connect successfully";
    }


    // send
    int serviceTicket_len = serviceTicket_en.length();
    int UA_len = UA_en.length();
    send(clientSocket, &serviceTicket_len, sizeof(int)/sizeof(char), 0);
    send(clientSocket, serviceTicket_en.data(), serviceTicket_len, 0);
    send(clientSocket, &UA_len, sizeof(int)/sizeof(char), 0);
    send(clientSocket, UA_en.data(), UA_len, 0);

    //reply
    char buffer[MAX_BUFFER] = {0};
    recv(clientSocket, buffer, MAX_BUFFER, 0);
    serviceReply = string(buffer);

    close(clientSocket);
}

int main() 
{
    printf("\n\nPhase 1: Request Ticket-granting Ticket from KDC: Authentication Server.\n\n");
    sleep(3);

    // user credentials
    user.userID = "USERID1234567";
    user.userPass = "cake8888";
    user.serviceID = "serviceID";
    //std::cout << "CSK: " << user.clientSecretKey() << std::endl;

    // connect ports
    connect_port(user.userSocket, AS_PORT);

    // 1. Send request for TGT ticket --------------------------
    sendTGTticketReq();

    // 2. Get AS reply & TGT ticket -------------------------
    vector<string> ASrep = getASreply(user.userSocket);
    string TGT_en = getTGT_en(user.userSocket);
    close(user.userSocket);

    printf("\n\nPhase 2: Request Service Ticket from KDC: Ticket-granting Server.\n\n");
    sleep(3);

    // 3 + 4. Send (en)TGT + tgsReq + UA ticket to TGS, 
    // returning encrypted TGS reply with Service Ticket
    string TGSSessionKey = ASrep[3];
    tgsReq tgsREQ;
    tgsREQ.serviceID = ASrep[0];
    tgsREQ.ticketLifetime = 120;
    UA ua; // user authenticator
    ua.userID = user.userID;
    string UA_en = encrypt(ua.convertMessage(), TGSSessionKey);
    
    string tgsReply, serviceTicket;
    sendMsgToTGS(TGT_en, tgsREQ, UA_en, tgsReply, serviceTicket);
    
    printf("tgsReply, de: %s\n", decrypt(tgsReply, TGSSessionKey).data());
    printf("serviceTicket, de: %s\n", decrypt(serviceTicket, serviceSecretKey).data());
    
    printf("\n\nPhase 3: Request service session.\n\n");
    sleep(3);

    // 5. User sends E(SerivceSecretKey, ServiceTicket) and E(ServiceSessionKey, 
    // UserAuthenticator), get service Reply
    vector<string> tgsReply_data = extract_tgsReply(decrypt(tgsReply, TGSSessionKey));
    string serviceSessionKey = tgsReply_data[3];

    ua.setnewTimestamp();
    UA_en = encrypt(ua.convertMessage(), serviceSessionKey);
    string serviceReply_en;
    sendMsgToService(serviceTicket, UA_en, serviceReply_en);

    // 6. check service
    vector<string> serviceReply_data = extractData(decrypt(serviceReply_en, serviceSessionKey));
    string serviceReply_serviceID = serviceReply_data[0];
    if(serviceReply_serviceID == user.serviceID){
        printf("Yay!!! Got the service!\n");
    }
    else{
        printf("No service.\n");
    }

    return 0; 
}
