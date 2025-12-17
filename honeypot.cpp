#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <fstream>

#define PORT 22 // Эмулируем SSH порт
#define LOG_FILE "honeypot.log"

void log_connection(const char* ip, int port) {
    std::ofstream logfile(LOG_FILE, std::ios::app);
    if (logfile.is_open()) {
        time_t now = time(0);
        char* dt = ctime(&now);
        dt[strlen(dt)-1] = '\0'; // Убираем символ новой строки
        logfile << "[" << dt << "] Connection attempt from: " << ip << " to port: " << port << std::endl;
        logfile.close();
    }
    std::cout << "Alert! Connection from: " << ip << " to port: " << port << std::endl;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Создание сокета
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Прикрепляем сокет к порту
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::cout << "Honeypot started. Listening on port " << PORT << "..." << std::endl;

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);

        // Логируем атаку
        log_connection(client_ip, PORT);

        // (Опционально) Можно отправить фальшивый баннер
        const char* banner = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\n";
        send(new_socket, banner, strlen(banner), 0);

        // Закрываем соединение
        close(new_socket);
    }
    close(server_fd);
    return 0;
}
