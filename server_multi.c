#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pthread.h> //thread library
#include <time.h>
#include <openssl/evp.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define LOG_FILE "server.log"
#define MAX_REQUESTS_PER_SEC 5

#define VALID_USERNAME "shahar"
#define SALT "c3k9_CyberSec2026!$"
// SHA256(password + SALT)
#define VALID_PASSWORD_HASH "d2447d916f9f2228fcff669ff3a52d4fb090751202233e2c8d20cc533c8d8cef"

#define MAX_FAILED_ATTEMPTS 3
#define LOCKOUT_TIME_SEC 30
#define MAX_TRACKED_IPS 256

// per-IP brute-force tracking (one attacker can't lock out other users)
typedef struct {
        char ip[INET_ADDRSTRLEN];
        int failed_attempts;
        time_t lockout_start_time;
} ip_record_t;

ip_record_t ip_table[MAX_TRACKED_IPS];
int ip_count = 0;
int next_slot = 0; //when table is full, oldest slot is reused
pthread_mutex_t auth_lock_mutex = PTHREAD_MUTEX_INITIALIZER;

// info passed to each client thread
typedef struct {
        int sock;
        char ip[INET_ADDRSTRLEN];
        int port;
} client_info_t;

SSL_CTX *ssl_ctx = NULL;

void compute_sha256_with_salt(const char *password, const char *salt, char output_hex[65]){
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;

        char salted_input[256] = {0};//buffer to put the salt

        snprintf(salted_input, sizeof(salted_input), "%s%s", password, salt);

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx,salted_input, strlen(salted_input));

        EVP_DigestFinal_ex(ctx, hash,&hash_len);
        EVP_MD_CTX_free(ctx);

        for (unsigned int i=0; i< hash_len; i++) {
                sprintf(output_hex + (i*2), "%02x", hash[i]);
        }
        output_hex[64] = '\0';
}

// find the record of an IP, or create one. caller must hold auth_lock_mutex
ip_record_t *get_ip_record(const char *ip){
        for (int i = 0; i < ip_count; i++){
                if (strcmp(ip_table[i].ip, ip) == 0){
                        return &ip_table[i];
                }
        }
        ip_record_t *rec;
        if (ip_count < MAX_TRACKED_IPS){
                rec = &ip_table[ip_count++];
        } else {
                rec = &ip_table[next_slot];
                next_slot = (next_slot + 1) % MAX_TRACKED_IPS;
        }
        snprintf(rec->ip, sizeof(rec->ip), "%s", ip);
        rec->failed_attempts = 0;
        rec->lockout_start_time = 0;
        return rec;
}

int active_clients = 0; //COUNTING CLIENTS
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER; //lock safe for threads
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

//log function for thread
void log_event(const char *level, const char *message){
        time_t now = time(NULL);
        struct tm t;
        localtime_r(&now, &t); //thread safe version of localtime
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &t);

        pthread_mutex_lock(&log_mutex);
//print to screen
        printf("[%s] [%s] %s\n", time_str, level,message);
//create and open file
        FILE *f = fopen(LOG_FILE, "a");
        if (f !=NULL){
                fprintf(f, "[%s] [%s] %s\n", time_str, level,message);
                fclose(f);
        }
        pthread_mutex_unlock(&log_mutex);
}

// function to create SSL context
SSL_CTX *create_ssl_context(){
        const SSL_METHOD *method = TLS_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
                perror("Unable to create SSL context");
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
        //refuse old insecure protocols (SSLv3, TLS 1.0, TLS 1.1)
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        return ctx;
}
//server.crt server.key
void configure_ssl_context(SSL_CTX *ctx){
        //public certificate of server
        if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0){
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
        //private key of server
        if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0){
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
}


void *handle_client(void *client_info_ptr){
        client_info_t info = *(client_info_t *)client_info_ptr;
        free(client_info_ptr); //free memory for client info
        int new_socket = info.sock;

        char peer[64]; //"ip:port" of the client, used in every log line
        snprintf(peer, sizeof(peer), "%s:%d", info.ip, info.port);

        char buffer[BUFFER_SIZE] = {0};
        char log_buff[512];

        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, new_socket);
        //encrypted hand shake
        if (SSL_accept(ssl) <= 0){
                ERR_print_errors_fp(stderr);
                snprintf(log_buff, sizeof(log_buff), "TLS handshake failed with client %s", peer);
                log_event("WARNING", log_buff);
                SSL_free(ssl);
                close(new_socket);
                return NULL;
        }

        int message_count = 0;
        time_t window_start = time(NULL);

        int is_authenticated = 0;

//updates when client connects
        pthread_mutex_lock(&clients_mutex);
        active_clients++;
        snprintf(log_buff, sizeof(log_buff), "[Thread %lu] Secure TLS client %s connected on sock %d. Active clients: %d",
                 (unsigned long)pthread_self(), peer, new_socket, active_clients);
        log_event("INFO", log_buff);
        pthread_mutex_unlock(&clients_mutex);
        char *welcome_msg = "Welcome to server! \nPlease LOGIN to continue. Usage: LOGIN <username> <password>\n";
        SSL_write(ssl, welcome_msg, strlen(welcome_msg));

//conversation loop with bot

        while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

                if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
//check rate limiting
                time_t current_time = time(NULL);

                if (current_time - window_start >= 1){
//if more than 1 second
                        window_start = current_time;
                        message_count = 1;
                }else{
                        message_count++;
                        if (message_count > MAX_REQUESTS_PER_SEC){
                                snprintf(log_buff, sizeof(log_buff), "SECURITY ALERT: Client %s exceeded rate limit (%d requests/sec). Connection dropped.",
                                         peer, message_count);
                                log_event("WARNING", log_buff);

                                char *err_msg = "HTTP/1.1 429 Too Many Requests\nRate limit exceeded. Connection closed.\n";
                                SSL_write(ssl, err_msg, strlen(err_msg));
                                break;
                        }
                }
//command login

                if (strncmp(buffer, "LOGIN ", 6) == 0){
                        char username[64] = {0};
                        char password[64] = {0};

                        pthread_mutex_lock(&auth_lock_mutex);
                        ip_record_t *rec = get_ip_record(info.ip);
                        time_t now = time(NULL); //getting current time
                        //checking max tries for this IP
                        if(rec->failed_attempts >= MAX_FAILED_ATTEMPTS){
                                //calc how many seconds left out of 30
                                double seconds_left = LOCKOUT_TIME_SEC - difftime(now, rec->lockout_start_time);

                                if (seconds_left > 0){
                                        pthread_mutex_unlock(&auth_lock_mutex);
                                        char reply[128];
                                        snprintf(reply, sizeof(reply), "Account locked due to multiple failed attempts. Try again in %.0f seconds.\n",
                                                 seconds_left);
                                        SSL_write(ssl, reply, strlen(reply));

                                        snprintf(log_buff, sizeof(log_buff), "SECURITY ALERT: Rejected login from %s - source is LOCKED", peer);
                                        log_event("WARNING", log_buff);

                                        continue;
                                }else{
                                // after 30 seconds- reset
                                rec->failed_attempts = 0;
                                rec->lockout_start_time = 0;
                                snprintf(log_buff, sizeof(log_buff), "Lockout period expired for %s. Login unlocked", info.ip);
                                log_event("INFO", log_buff);
                                }
                        }
                        pthread_mutex_unlock(&auth_lock_mutex);

                        if (sscanf(buffer + 6, "%63s %63s", username, password) == 2) {
                                password[strcspn(password, "\r\n")] = 0;
                                username[strcspn(username, "\r\n")] = 0;

                                char computed_hash[65] = {0};
                                compute_sha256_with_salt(password, SALT, computed_hash);

                                if (strcmp(username, VALID_USERNAME) == 0 && strcmp(computed_hash, VALID_PASSWORD_HASH) == 0){
                                        //reset when login succeeded
                                        pthread_mutex_lock(&auth_lock_mutex);
                                        get_ip_record(info.ip)->failed_attempts = 0;
                                        pthread_mutex_unlock(&auth_lock_mutex);

                                        is_authenticated = 1;
                                        char *reply = "200 SUCCESS: Authenticated successfully!\n";
                                        SSL_write(ssl, reply, strlen(reply));

                                        snprintf(log_buff, sizeof(log_buff), "User '%s' authenticated successfully from %s", username, peer);
                                        log_event("INFO", log_buff);
                                }else{
                                        // dealing with failed attempts
                                        pthread_mutex_lock(&auth_lock_mutex);
                                        ip_record_t *r = get_ip_record(info.ip);
                                        r->failed_attempts++;
                                        int attempts = r->failed_attempts;

                                        //check if lock
                                        if (attempts >= MAX_FAILED_ATTEMPTS){
                                                r->lockout_start_time = time(NULL);
                                                snprintf(log_buff, sizeof(log_buff), "SECURITY ALERT: %d failed login attempts from %s (last user '%s'). Source LOCKED for %d seconds",
                                                         MAX_FAILED_ATTEMPTS, peer, username, LOCKOUT_TIME_SEC);
                                                log_event("WARNING", log_buff);
                                        }else{
                                        snprintf(log_buff,sizeof(log_buff),"SECURITY WARNING: Failed login attempt (%d/%d) for user '%s' from %s",
                                                         attempts, MAX_FAILED_ATTEMPTS, username, peer);
                                        log_event("WARNING", log_buff);
                                        }
                                        pthread_mutex_unlock(&auth_lock_mutex);

                                        is_authenticated = 0;
                                        char reply[128];
                                        //showing how many attempts
                                        snprintf(reply, sizeof(reply), "401 UNAUTHORIZED: Invalid credentials! Attempt %d/%d\n",
                                                         attempts, MAX_FAILED_ATTEMPTS);
                                        SSL_write(ssl, reply, strlen(reply));
                                }
                        } else{
                                char *reply = "401 UNAUTHORIZED: Invalid credentials!\n";
                                SSL_write(ssl, reply, strlen(reply));

                        }

            }else if (strncmp(buffer, "PING", 4) == 0) {
                if (!is_authenticated){
                        char *reply = "FORBIDDEN: Please LOGIN first\n";
                         SSL_write(ssl, reply, strlen(reply));
                }else{
                char *reply = "PONG!\n";
                SSL_write(ssl, reply, strlen(reply));
                }

            } else if (strncmp(buffer, "TIME", 4) == 0) {
                if (!is_authenticated){
                        char *reply = "FORBIDDEN: Please LOGIN first\n";
                         SSL_write(ssl, reply, strlen(reply));
                }else{
                        char *reply = "Server time: Active Multi-Threaded Session!\n";
                        SSL_write(ssl, reply, strlen(reply));
                }

            } else if (strncmp(buffer, "EXIT", 4) == 0) {
                char *reply = "Goodbye!\n";
                SSL_write(ssl, reply, strlen(reply));
                snprintf(log_buff, sizeof(log_buff), "Client %s sent EXIT. Closing connection", peer);
                log_event("INFO", log_buff);
                break;

            } else {
                char *reply = "Unknown command. Try PING, TIME, or EXIT.\n";
                SSL_write(ssl, reply, strlen(reply));
            }

        } else if (bytes_read == 0) {
                snprintf(log_buff, sizeof(log_buff),"Client %s disconnected gracefully.", peer);
                log_event("INFO", log_buff);
                break;
        } else {
            snprintf(log_buff, sizeof(log_buff), "Connection error with client %s", peer);
            log_event("WARNING", log_buff);
            break;
        }
    }
//updates when client disconnect
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
        pthread_mutex_lock(&clients_mutex);
        active_clients--;
        snprintf(log_buff, sizeof(log_buff),"[-] [Thread %lu] Client %s disconnected. Active clients: %d",
                 (unsigned long)pthread_self(), peer, active_clients);
        log_event("INFO", log_buff);
        pthread_mutex_unlock(&clients_mutex);

        return NULL;
}

int main(){
        int server_fd;
        struct sockaddr_in address;
        //a client that disconnects mid-write must not kill the whole server
        signal(SIGPIPE, SIG_IGN);
        log_event("INFO", "Starting Multi-Thread Secure SSL/TLS Cyber Server...");

        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        ssl_ctx = create_ssl_context();
        configure_ssl_context(ssl_ctx);

// create the socket
        server_fd = socket(AF_INET, SOCK_STREAM,0);
        if (server_fd < 0){
                perror("Socket failed");
                exit(EXIT_FAILURE);
        }

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET ,SO_REUSEADDR, &opt, sizeof(opt));

//bind
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) <0 ){
                perror("Bind failed");
                close(server_fd);
                exit(EXIT_FAILURE);
        }

// Listen
        if (listen(server_fd, 10) < 0) {
                perror("Listen failed");
                close(server_fd);
                exit(EXIT_FAILURE);
        }
        char start_log[128];
        snprintf(start_log, sizeof(start_log), "Multi-threaded server listening on port %d...", PORT);
        log_event("INFO", start_log);

//CREATING THREADS LOOP
        while (1){
                struct sockaddr_in client_addr; //separate struct so the server address is not overwritten
                socklen_t addrlen = sizeof(client_addr);
                int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
                if (new_socket < 0){
                        perror("Accept failed");
                        continue;//keep listen after no connect
                }

//pass socket + client IP/port to the thread
                client_info_t *info = malloc(sizeof(client_info_t));
                if (info == NULL){
                        close(new_socket);
                        continue;
                }
                info->sock = new_socket;
                inet_ntop(AF_INET, &client_addr.sin_addr, info->ip, sizeof(info->ip));
                info->port = ntohs(client_addr.sin_port);

                pthread_t thread_id;
                //pthread_create returns 0 on success, an error number otherwise
                if (pthread_create(&thread_id, NULL, handle_client, (void*) info) != 0){
                        perror("Could not create thread");
                        free(info);
                        close(new_socket);
                        continue;
                }

                pthread_detach(thread_id);
        }
close(server_fd);
SSL_CTX_free(ssl_ctx);

return 0;

}
