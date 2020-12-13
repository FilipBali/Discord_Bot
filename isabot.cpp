/**
 * @author Filip Bali
 * Project name: Discord bot
 * School subject: ISA
 * School: VUT FIT BRNO
 */


/**
 * Project libraries
 */
#include <iostream>
#include <cstring>
#include <utility>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <map>
#include <regex>
#include <vector>
#include <unistd.h>
#include <cmath>
#include <fstream>

using namespace std;

//Multiple options how program could ends.
#define SUCCESSFULL_EXIT 0
#define ERROR_EXIT -1
#define ERROR_INTERNAL_EXIT -2

/**
 * CParams
 * Description: Handle program parameters
 */
class CParams {
    /*
     * isabot [-h|--help] [-v|--verbose] -t <bot_access_token>
     *
     * Pořadí parametrů je libovolné. Popis parametrů:
     *
     * Spuštění programu bez parametrů zobrazí nápovědu.
     * -h|--help : Vypíše nápovědu na standardní výstup.
     * -v|--verbose : Bude zobrazovat zprávy, na které bot reaguje na standardní výstup ve formátu "<channel> - <username>: <message>".
     * -t <bot_access_token> : Zde je nutno zadat autentizační token pro přístup bota na Discord.
     */

    private:
        //If a program parameter is set -> true, default false
        bool help = false;
        bool verbose = false;
        bool access_token = false;

        //Discord API token
        string access_token_string;

        /**
         * Load all program parameters
         * @param argc Number of arguments
         * @param argv Arg char*
         */
        void getParams(int argc, char *argv[]){
            if ( argc == 1 ){   //in case of 0 arguments
                this->printHelpMsg();
            }

            for (int i = 1; i < argc; i++) {
                this->checkArgument(&i, argc, argv);
            }
        };

        /**
         * Print help message to stdout
         */
        void printHelpMsg(){
            printf("-----------------------------------------------------------------------------------------\n");
            printf("                                   HELP MESSAGE                                          \n");
            printf("                                                                                         \n");
            printf("Description: This is Echo Bot for Discord software.                                      \n");
            printf("             Implementation using C/C++ programming languages.                           \n");
            printf("             Purpose of this bot is repeating every message in #isa-bot channel          \n");
            printf("             from other Discord users.                                                   \n");
            printf("                                                                                         \n");
            printf("             Messages from other Bots will NOT be repeated!                              \n");
            printf("             Bot user is classified as user who has in Discord nickname a word \"bot\".  \n");
            printf("             (Checking is case sensitive!)                                               \n");
            printf("             Example: ----------------------                                             \n");
            printf("                      | Nickname | Is Bot? |                                             \n");
            printf("                      ----------------------                                             \n");
            printf("                      |  Robot   |   YES   |                                             \n");
            printf("                      |  ROBOT   |   NO    |                                             \n");
            printf("                      |  RO_bot  |   YES   |                                             \n");
            printf("                      |  Bottle  |   No    |                                             \n");
            printf("                      |  bottle  |   YES   |                                             \n");
            printf("                      |  isa_bot |   YES   |                                             \n");
            printf("                      ----------------------                                             \n");
            printf("                                                                                         \n");
            printf("Usage: ./isabot [-h|--help] [-v|--verbose] -t <bot_access_token>                         \n");
            printf("                                                                                         \n");
            printf(" -> Where: Arguments in [] brackets are optional.                                        \n");
            printf("           Arguments in WITHOUT brackets are required.                                   \n");
            printf("                                                                                         \n");
            printf("    [-h|--help] -> Prints help message and program will be terminated.                   \n");
            printf("    [-v|--verbose] -> Prints details about every repeated message to stdout.             \n");
            printf("    -t <bot_access_token> -> Discord Bot token which specified which Discord Bot is used.\n");
            printf("                             Can be found at https://discord.com/developers/applications \n");
            printf("                                                                                         \n");
            printf("                                                                                         \n");
            printf("            !!! WARNING: IMPLEMENTATION IS LIMITED TO ONE SERVER !!!                     \n");
            printf("-----------------------------------------------------------------------------------------\n");
            exit(SUCCESSFULL_EXIT);
        }

        /**
         *
         * @param ArgNum Parameter position. Which parameter is processed
         * @param argc Number of parameters
         * @param argv Arg char*
         */
        void checkArgument(int *ArgNum ,int argc, char *argv[]) {
            if (strcmp("-h", argv[*ArgNum]) == 0 or
                strcmp("--help", argv[*ArgNum]) == 0) {
                    this->printHelpMsg();

            } else if(strcmp("-v", argv[*ArgNum]) == 0 or
                      strcmp("--verbose", argv[*ArgNum]) == 0) {
                    this->verbose = true;

            } else if(strcmp("-t", argv[*ArgNum]) == 0) {
                    this->access_token = true;
                    if (*ArgNum < argc - 1){
                        this->access_token_string = argv[(*ArgNum)+1];
                        *ArgNum = (*ArgNum) + 1;
                    } else { // No <bot_access_token>
                        printf("No access token specified while, program will be terminated.");
                        exit(ERROR_EXIT);
                    }
            } else {
                printf("Unknown program parameter, program will be terminated.");
                exit(ERROR_EXIT);
            }
        }

    public:
        //Constructor
        CParams(int argc, char *argv[]){
            this->getParams(argc, argv);

            if (this->access_token_string.length() == 0){
                printf("Discord Bot Access Token is not set, please, specify it if in program argument with"
                       "parameter -v or check help message with parameter -h."
                       "Program na will be terminated.");
                exit(ERROR_EXIT);
            }
        }

        /**
         * Check if parameter is set.
         * @param param Which parameter want to check in string format like "-h"
         * @return True if parameter is set, otherwise false.
         */
        bool getParamBool(const string &param){
            if ("-h" == param){
                return this->help;
            } else if ("-v" == param){
                return  this->verbose;
            } else if ("-t" == param){
                return this->access_token;
            }
            printf("Internal Error, getParamBool");
            exit(ERROR_INTERNAL_EXIT);
        }

        /**
         * Return access token from private variable
         * @return Acess token as std::string.
         */
        string getAccessToken(){
            return this->access_token_string;
        }
};

/**
 * class CJSON
 * Description: Process json response from Discord API calls.
 */
class CJSON {

    private:
        std::vector<std::vector<std::string>> array_of_values;
        std::vector<std::string> vector_json_split_messages;

    public:
       /**
         * If there are more messages to repeat, this function split messages from one json
         * to several "subjsons" and store them separately to vector one by one.
         * @param json Messages in json as response from Discord API call.
         */
        void split_json_messages_into_vector(std::string json){
            //Inspiration https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c

            //Split by }, {
            std::string delimiter = "}, {";

            size_t pos = 0;
            std::string token;
            while ((pos = json.find(delimiter)) != std::string::npos) {
                token = json.substr(0, pos);

                //Store message
                this->vector_json_split_messages.push_back(token);

                //Processed message is deleted from string
                json.erase(0, pos + delimiter.length());
            }
            this->vector_json_split_messages.push_back(json);
        }

        /**
         * If there is value which is need to be extracted from json (info about server id, message content etc.),
         * this function could be used.
         * @param regex Regex expression to extract data
         * @param string String with JSON from witch the data will be extracted.
         * @return Extracted value in string format
         */
        std::string JSON_filter(std::string regex, std::string string){
            //Inspiration: https://stackoverflow.com/questions/11627440/regex-c-extract-substring

            const std::string& s = string;

            std::regex rgx(regex);
            std::smatch match;

            if (std::regex_search(s.begin(), s.end(), match, rgx))
                return match[1];
            return "";
        }

        /**
         * This method is used to extract and store important message data from message to std::vector.
         * Processed messages are stored in vector "split_json_messages_into_vector" as class private variable.
         * @return Vector which contains extracted message data (later used in POST request )
         */
        std::vector<std::vector<std::string>> load_values_from_json(){
                for(const std::string& message : vector_json_split_messages) {

                    std::vector<std::string> values;

                    // Regular expression to extract id value of message
                    std::string id = this->JSON_filter(R"(\"id\": \"(\w+)\", \"type\".*)", message);
                    values.push_back(id);

                    // Regular expression to extract content value of message
                    std::string content = this->JSON_filter(R"(\"content\": \"(.*)\", \"channel_id\".*)", message);
                    values.push_back(content);


                    // Regular expression to extract USERNAME of message
                    std::string nickname = this->JSON_filter(R"(\"username\": \"(.*)\", \"avatar\".*)", message);
                    values.push_back(nickname);

                    // Regular expression to extract TTS value of message
                    std::string tts = this->JSON_filter(R"(\"tts\": (\w+), \"timestamp\".*)", message);
                    values.push_back(tts);

                    // Regular expression to extract ID of sender of message
                    std::string sender_id = this->JSON_filter(R"(\"author\".*\"id\": \"(\w+)\", \"username\":.*)", message);
                    values.push_back(sender_id);

                    //Save all extracted values to vector
                    this->array_of_values.push_back(values);
                }
                return this->array_of_values;
            }
};


/**
 * Class CConnection
 * Description: Provides communication with Discord through their API,
 *              Init/Send/Receive SSL messages
 */
class CConnection {
    private:
        //Instance of class CParams
        CParams &Params;

        //SSL socket
        SSL *ssl_sock{};


    /**
     * Timers, limiters, checkers of connection
     */
    std::string timeLimitReset_get_request;
    std::string HTTP_STATUS_get_request;

    std::string remaining_post_request;
    std::string timeLimitReset_post_request;


    /**
         * There are stored data about Discord Server and Server channel
         * Data are mapped to identifiers
         *
         * Server identifiers:
         * - id (important)
         * - name (important)
         * - icon
         * - owner
         * - permissions
         *
         * Channel identifiers:
         * - id (important)
         */
        std::map<std::string, std::string> mapServerJSON;
        std::map<std::string, std::string> mapServerGuildsJSON;

        // ID of last message which was repeated
        std::string last_message_ID;

        // ID of this bot
        std::string bot_ID;

        /**
         * In case of first run of while loop
         * is needed to receive last message id of channel.
         * Then just fetch new messages from time of last API call.
         */
        bool first_run = true;


        void MainProcess(){
            this->Connect();
        }

        /**
         * Main methon of program, contains endless loop send/receive
         */
        void Connect(){

            this->init_ssl_resources();

            //Get servers where the bot is connected
            std::string dc_json_response = this->send_GET_request("/users/@me");
            this->bot_ID = this->JSON_filter(R"(\"id\": \"(\w+)\", \"username\":.*)", dc_json_response);

            dc_json_response = this->send_GET_request("/users/@me/guilds");

            // Parse server JSON response
            std::string value = this->JSON_filter(R"(.*"id": "(\w+)\".*)", dc_json_response);

            this->mapServerJSON.insert(std::make_pair("id",value));

            value = this->JSON_filter(R"(.*"name": "(\w+)\".*)", dc_json_response);
            this->mapServerJSON.insert(std::make_pair("name",value));

            value = this->JSON_filter(R"(.*"icon": "(\w+)\".*)", dc_json_response);
            this->mapServerJSON.insert(std::make_pair("icon",value));

            value = this->JSON_filter(R"(.*"owner": "(\w+)\".*)", dc_json_response);
            this->mapServerJSON.insert(std::make_pair("owner",value));

            value = this->JSON_filter(R"(.*"permissions": "(\w+)\".*)", dc_json_response);
            this->mapServerJSON.insert(std::make_pair("permissions",value));


            // Get channels which server has.
            dc_json_response = this->send_GET_request(std::string("/guilds/") + std::string(this->mapServerJSON.find("id")->second) + std::string("/channels"));


            std::string delimiter = R"("name": "isa-bot")";
            std::string token = dc_json_response.substr(0, dc_json_response.find(delimiter));

            //Find server which is called isa-bot
            std::string last_element(token.substr(token.rfind("\"id\"") + 4));
            value = this->JSON_filter(R"(: "(\w+)\".*)", last_element);

            // Store id of isa-bot channel
            this->mapServerGuildsJSON.insert(std::make_pair("id",value));

            while(true) {

                if (first_run) {
                    //If first run get last message id of channel
                    dc_json_response = this->send_GET_request(std::string("/channels/") + std::string(this->mapServerGuildsJSON["id"]));
                    this->last_message_ID = this->JSON_filter(R"(\"last_message_id\": \"(\w+)\", \"type\".*)", dc_json_response);

                    this->first_run = false;
                    continue;
                } else {
                    // Get last message id of channel
                    dc_json_response = this->send_GET_request(std::string("/channels/") + std::string(this->mapServerGuildsJSON["id"]));

                    if (dc_json_response == "FALSE_ERROR_JSON"){
                        continue;
                    }

                    //Extract last message id and name(nickname of sender)
                    std::string last_channel_message_id = this->JSON_filter(R"(\"last_message_id\": \"(\w+)\", \"type\".*)", dc_json_response);


                    //Check last messages with message id of last message that was processed
                    if (this->last_message_ID != last_channel_message_id) {
                        dc_json_response = this->send_GET_request(std::string("/channels/") + std::string(this->mapServerGuildsJSON["id"]) + std::string("/messages"),
                                                                  std::string("?after=") +
                                                                  std::string(this->last_message_ID));
                        if (dc_json_response == "FALSE_ERROR_JSON"){
                            continue;
                        }

                    } else {
                        continue;
                    }
                }

                class CJSON parser;
                parser.split_json_messages_into_vector(dc_json_response);
                std::vector<std::vector<std::string>> messages = parser.load_values_from_json();

                //Save ID of last message
                if (messages.size() >= 1) {
                    this->last_message_ID = messages[0][0];

                    //Reverse messages, because older one need to be repeated first
                    std::reverse(messages.begin(),messages.end());

                    for (std::vector<std::string> message : messages) {

                        //If nickname contains "BOT" then ignore this message (do not repeat this message), otherwise repeat
                        if (message[2].find("bot") == std::string::npos && message[4] != this->bot_ID ) {
                            std::string POST_STRING = std::string(R"({"content": ")") +
                                    std::string("echo: ") + std::string(message[2])+ std::string(" - ") + std::string(message[1]) +
                                    std::string(R"(", "tts": false})");
                            dc_json_response = this->send_POST_request(std::string("/channels/") + std::string(this->mapServerGuildsJSON.find("id")->second) + std::string("/messages"), POST_STRING);

                            //If -v program parameter is set, then print additional info to stdout
                            if(Params.getParamBool("-v"))
                                cout << "isa-bot" << " - " << std::string(message[2]) << ": " << std::string(message[1]) << "\n";
                        }
                    }
                }
            }
        }

        /**
         * Initialize all required resources to provide SSL communication.
         */
        void init_ssl_resources(){
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                printf("Internal Error, opening socket, Connect");
                exit(ERROR_INTERNAL_EXIT);
            }


            struct hostent * server = gethostbyname("discord.com");
            if (server == NULL) {
                printf("Internal Error, no host, Connect");
                exit(ERROR_INTERNAL_EXIT);
            }


            struct sockaddr_in serv_addr{};

            bzero((char *) &serv_addr, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            bcopy((char *)server->h_addr,
                  (char *)&serv_addr.sin_addr.s_addr,
                  server->h_length);
            serv_addr.sin_port = htons(443);
            if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
                printf("Internal Error, not connecting, Connect");
                exit(ERROR_INTERNAL_EXIT);
            }

            BIO *outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

            // Initialize OpenSSL
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            ERR_load_BIO_strings();



             // Initialize SSL
            if(SSL_library_init() < 0)
                BIO_printf(outbio, "Internal Error, SSL initializing has failed!\n");

            // Create SSL structure
            SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method ());
            if (ssl_ctx == NULL)
                BIO_printf(outbio, "Internal Error, Creating of SSL structure has failed.\n");


            // Disable SSLv2
            // Allow only TSLv1 and TSLv3
            SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

            // Create SSL connection
            (this->ssl_sock) = SSL_new(ssl_ctx);

            //Attach to the descriptor
            SSL_set_fd(this->ssl_sock , sockfd);

            //SSL handshake
            int err = SSL_connect(this->ssl_sock );
            if (err != 1){
                printf("Internal Error, SSL_connect error, Connect");
                exit(ERROR_INTERNAL_EXIT);
            }
        }

        /**
         * Make GET request to Discord server.
         * @param api_call Contains request string after /api/v8
         * @param snowflake (Optional) Get messages after certain date
         * @return JSON response
         */
        std::string send_GET_request(std::string api_call, std::string snowflake = ""){
            std::string request = std::string("GET /api/v8") + std::string((api_call)) + std::string(snowflake) + std::string(" HTTP/1.1\r\n") +
                                 std::string("Host: discord.com\r\n") +
                                 std::string("Authorization: Bot ") + std::string(Params.getAccessToken()) + std::string("\r\n") +
                                 std::string("\r\n");


            int ret = SSL_write(this->ssl_sock , request.c_str(), strlen(request.c_str()));
            ret = SSL_get_error(this->ssl_sock , ret);


            char buffer[1024] = "";
            int received = 0;
            int TotalReceived = 0;

            std::string conData;
            std::string myString;
            std::string jsonString;
            bool is_json = false;
            while(1){

                received = SSL_read(this->ssl_sock , buffer, sizeof(buffer));
                if (received > 0)
                {
                    TotalReceived += received;

                    myString.append(buffer, received);

                    this->HTTP_STATUS_get_request = this->JSON_filter(R"(HTTP/1.1 (\w+) .*)", myString);
                    this->timeLimitReset_get_request = this->JSON_filter(R"(\"retry_after\": (\w+).)", myString);

                    // Detect just JSON and delete HTTP header of received message
                    char ch = '\0';
                    for(int i = 0; i < received; i++){
                        if ((ch == '\n' and (buffer[i] == '[' or buffer[i] == '{')) or is_json){
                            conData += buffer[i];
                            is_json = true;
                        }
                        ch = buffer[i];
                    }

                    if (this->HTTP_STATUS_get_request.length() > 0 && this->HTTP_STATUS_get_request != "200"){

                        if (this->HTTP_STATUS_get_request == "429"){
                            if (this->timeLimitReset_get_request.length() > 0) {
                                sleep(((int) std::round(stod(this->timeLimitReset_get_request))) + 2);
                            } else {
                                continue;
                            }
                        }

                        return "FALSE_ERROR_JSON";
                    }

                    if (is_json and (conData[conData.length()-3] == ']' or conData[conData.length()-3] == '}')) {
                        return conData;
                    }

                }else{
                    this->init_ssl_resources();
                    return "FALSE_ERROR_JSON";
                }
            }

            return "FALSE_ERROR_JSON";
        }

        /**
        * Make POST request to Discord server.
        * @param api_call Contains request string
        * @param content JSON which is send to Discord server
        * @return JSON response
        */
        std::string send_POST_request(std::string api_call, std::string content){

            if (this->remaining_post_request == "0"){
                sleep(((int)std::round(stod(this->timeLimitReset_post_request)))+1);
            }

            std::string POST_API_CALL = std::string("/channels/") + std::string(this->mapServerGuildsJSON.find("id")->second) + std::string("/messages");
            std::string request = std::string("POST /api/v8") + std::string(api_call) + std::string(" HTTP/1.1\r\n") +
                                  std::string("Host: discord.com\r\n") +
                                  std::string("Authorization: Bot ") + std::string(Params.getAccessToken()) + std::string("\r\n") +
                                  std::string("Content-Type: application/json\r\n") +
                                  std::string("Content-Length: ") + std::string(std::to_string(content.length())) + std::string("\r\n\r\n") +
                                  std::string(content);


            int ret2 = SSL_write(this->ssl_sock , request.c_str(), strlen(request.c_str()));
            ret2 = SSL_get_error(this->ssl_sock , ret2);

            char buffer[1024] = "";
            int received;
            std::string conData;
            int TotalReceived = 0;
            bool is_json = false;

            std::string myString;

            while(1) {
                received = SSL_read(this->ssl_sock, buffer, sizeof(buffer));
                if (received > 0) {
                    TotalReceived += received;

                    myString.append(buffer, received);


                    this->remaining_post_request = this->JSON_filter(R"(x-ratelimit-remaining: (\w+)\r\nx-ratelimit-reset.*)", myString);
                    this->timeLimitReset_post_request = this->JSON_filter(R"(x-ratelimit-reset-after: (\w.+)\r\nx-envoy-upstream-service-time.*)", myString);

                    char ch = '\0';
                    for(int i = 0; i < received; i++){
                        if ((ch == '\n' and (buffer[i] == '[' or buffer[i] == '{')) or is_json){
                            conData += buffer[i];
                            is_json = true;
                        }
                        ch = buffer[i];
                    }
                    if (is_json and (conData[conData.length()-3] == ']' or conData[conData.length()-3] == '}')) {
                        return conData;
                    }
                }
            }
        }

        /**
         * If there is value which is need to be extracted from json (info about server id, message content etc.),
         * this function could be used.
         * @param regex Regex expression to extract data
         * @param string String with JSON from witch the data will be extracted.
         * @return Extracted value in string format
         */
        std::string JSON_filter(std::string regex, std::string string){
            //Inspiration: https://stackoverflow.com/questions/11627440/regex-c-extract-substring

            const std::string& s = string;

            std::regex rgx(regex);
            std::smatch match;

            if (std::regex_search(s.begin(), s.end(), match, rgx))
                return match[1];
            return "";
        }

    public:
        explicit CConnection(CParams &Params ) : Params(Params) {
            this->MainProcess();
        }
};

int main(int argc, char* argv[] ) {

    CParams Params(argc, argv);
    CConnection Connection(Params);

    return SUCCESSFULL_EXIT;
}
