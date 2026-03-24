/*
 * Claude for NeXTSTEP
 * A native Claude AI console client for NeXTSTEP 3.3
 *
 * Connects directly to api.anthropic.com over TLS 1.2
 * using Crypto Ancienne (cryanc) by Cameron Kaiser.
 *
 * Build: cc -O -o claude claude.c
 * Usage: ./claude
 *
 * (c) 2026 ARNLTony & Claude. MIT License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* Crypto Ancienne TLS library */
#include "cryanc.c"

/* --- Configuration --- */

#define API_HOST      "api.anthropic.com"
#define API_PORT      443
#define API_VERSION   "2023-06-01"
#define DEFAULT_MODEL "claude-3-haiku-20240307"
#define MAX_TOKENS    1024
#define KEY_FILE      ".claude_api_key"
#define MODEL_FILE    ".claude_model"

#define INPUT_BUF     4096
#define RESPONSE_BUF  65536
#define HISTORY_BUF   32768
#define HTTP_BUF      4096
#define WRAP_WIDTH    72

/* --- Globals --- */

static char api_key[256];
static char model[128];
static char history[HISTORY_BUF];
static int history_len = 0;
static int running = 1;

/* --- TLS helpers (from carl.c pattern) --- */

int https_send_pending(sockfd, context)
int sockfd;
struct TLSContext *context;
{
    unsigned int out_buffer_len = 0;
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    const unsigned char *out_buffer;

    out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    while (out_buffer && out_buffer_len > 0) {
        int res = send(sockfd, (char *)&out_buffer[out_buffer_index],
                       out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int validate_certificate(context, certificate_chain, len)
struct TLSContext *context;
struct TLSCertificate **certificate_chain;
int len;
{
    return no_error;
}

/* --- JSON helpers (minimal, hand-rolled) --- */

/*
 * Find a JSON string value by key. Returns pointer to the start
 * of the value string (after the opening quote), or NULL.
 * Sets *out_len to the length of the value.
 */
char *json_find_string(json, key, out_len)
char *json;
char *key;
int *out_len;
{
    char pattern[256];
    char *p, *start, *search;

    sprintf(pattern, "\"%s\"", key);
    search = json;

    while (1) {
        p = strstr(search, pattern);
        if (!p) return NULL;

        /* skip past "key" */
        p += strlen(pattern);

        /* skip whitespace */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        /* must be followed by colon (this is a key, not a value) */
        if (*p != ':') {
            search = p;
            continue;
        }
        p++; /* skip colon */

        /* skip whitespace after colon */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p != '"') {
            search = p;
            continue;
        }
        p++; /* skip opening quote */
        start = p;

        /* find closing quote, handling escapes */
        while (*p && !(*p == '"' && *(p-1) != '\\'))
            p++;

        *out_len = p - start;
        return start;
    }
}

/*
 * Extract the text content from a Claude API response.
 * Looks for "text" field inside the content array.
 */
void extract_response_text(json, out, out_size)
char *json;
char *out;
int out_size;
{
    char *text;
    int len;
    int i, j;

    text = json_find_string(json, "text", &len);
    if (!text) {
        /* Try to find error message */
        text = json_find_string(json, "message", &len);
        if (text) {
            if (len >= out_size) len = out_size - 1;
            strncpy(out, text, len);
            out[len] = '\0';
            return;
        }
        strcpy(out, "(Could not parse response)");
        return;
    }

    /* Copy with JSON unescape */
    j = 0;
    for (i = 0; i < len && j < out_size - 1; i++) {
        if (text[i] == '\\' && i + 1 < len) {
            i++;
            switch (text[i]) {
                case 'n':  out[j++] = '\n'; break;
                case 't':  out[j++] = '\t'; break;
                case '"':  out[j++] = '"';  break;
                case '\\': out[j++] = '\\'; break;
                case '/':  out[j++] = '/';  break;
                default:   out[j++] = text[i]; break;
            }
        } else {
            out[j++] = text[i];
        }
    }
    out[j] = '\0';
}

/* --- Display helpers --- */

void print_wrapped(prefix, text, width)
char *prefix;
char *text;
int width;
{
    int col, prefix_len, i;
    char *p;

    prefix_len = strlen(prefix);
    printf("%s", prefix);
    col = prefix_len;

    p = text;
    while (*p) {
        if (*p == '\n') {
            putchar('\n');
            /* indent continuation lines */
            for (i = 0; i < prefix_len; i++) putchar(' ');
            col = prefix_len;
            p++;
            continue;
        }

        /* Word wrapping */
        if (col >= width && *p == ' ') {
            putchar('\n');
            for (i = 0; i < prefix_len; i++) putchar(' ');
            col = prefix_len;
            p++;
            continue;
        }

        putchar(*p);
        col++;
        p++;
    }
    putchar('\n');
}

void print_banner()
{
    printf("\n");
    printf("  Claude for NeXTSTEP\n");
    printf("  Model: %s\n", model);
    printf("  Type 'quit' to exit.\n");
    printf("\n");
}

/* --- History management --- */

/*
 * Append a message to the conversation history JSON array.
 * History format: {"role":"user","content":"..."},{"role":"assistant","content":"..."},...
 */
void history_append(role, content)
char *role;
char *content;
{
    char *p;
    int needed;
    int i;

    /* Estimate space needed (content + escaping overhead + JSON wrapper) */
    needed = strlen(content) * 2 + 64;
    if (history_len + needed >= HISTORY_BUF - 100) {
        /* History full, reset to keep things working */
        history_len = 0;
        history[0] = '\0';
        printf("  (conversation history cleared — memory full)\n\n");
        return;
    }

    if (history_len > 0) {
        history[history_len++] = ',';
    }

    /* Build JSON message object with escaped content */
    history_len += sprintf(history + history_len,
        "{\"role\":\"%s\",\"content\":\"", role);

    /* Escape the content */
    for (i = 0; content[i]; i++) {
        if (history_len >= HISTORY_BUF - 100) break;
        switch (content[i]) {
            case '"':  history[history_len++] = '\\';
                       history[history_len++] = '"';  break;
            case '\\': history[history_len++] = '\\';
                       history[history_len++] = '\\'; break;
            case '\n': history[history_len++] = '\\';
                       history[history_len++] = 'n';  break;
            case '\t': history[history_len++] = '\\';
                       history[history_len++] = 't';  break;
            default:   history[history_len++] = content[i]; break;
        }
    }

    history_len += sprintf(history + history_len, "\"}");
    history[history_len] = '\0';
}

/* --- Network / API --- */

/*
 * Send a message to Claude and get a response.
 * Returns 0 on success, -1 on error.
 */
int claude_send(user_message, response, response_size)
char *user_message;
char *response;
int response_size;
{
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    struct TLSContext *context;
    char *body, *http_request;
    int body_len, req_len;
    char recv_buf[HTTP_BUF];
    char *resp_data;
    int resp_len, resp_cap;
    int read_size;
    int sent;
    int header_done;
    char *body_start;
    unsigned char tls_buf[HTTP_BUF];

    /* Add user message to history */
    history_append("user", user_message);

    /* Build JSON request body */
    body = (char *)malloc(HISTORY_BUF + 512);
    if (!body) { strcpy(response, "Out of memory"); return -1; }

    sprintf(body,
        "{\"model\":\"%s\","
        "\"max_tokens\":%d,"
        "\"messages\":[%s]}",
        model, MAX_TOKENS, history);
    body_len = strlen(body);

    /* Build HTTP request */
    http_request = (char *)malloc(body_len + 1024);
    if (!http_request) { free(body); strcpy(response, "Out of memory"); return -1; }

    sprintf(http_request,
        "POST /v1/messages HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "X-API-Key: %s\r\n"
        "Anthropic-Version: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        API_HOST, api_key, API_VERSION, body_len, body);
    req_len = strlen(http_request);
    free(body);

    /* Resolve hostname */
    printf("  Connecting...\n");
    fflush(stdout);

    server = gethostbyname(API_HOST);
    if (!server) {
        free(http_request);
        strcpy(response, "DNS lookup failed");
        return -1;
    }

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        free(http_request);
        strcpy(response, "Socket creation failed");
        return -1;
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr,
           (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(API_PORT);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        free(http_request);
        close(sockfd);
        strcpy(response, "Connection failed");
        return -1;
    }

    /* TLS handshake */
    printf("  TLS handshake...\n");
    fflush(stdout);

    context = tls_create_context(0, TLS_V12);
    if (!context || !tls_sni_set(context, API_HOST)) {
        free(http_request);
        close(sockfd);
        strcpy(response, "TLS setup failed");
        return -1;
    }
    tls_client_connect(context);
    https_send_pending(sockfd, context);

    /* Complete handshake and send request */
    sent = 0;
    resp_data = (char *)malloc(response_size);
    if (!resp_data) {
        free(http_request);
        tls_destroy_context(context);
        close(sockfd);
        strcpy(response, "Out of memory");
        return -1;
    }
    resp_len = 0;
    header_done = 0;

    while (1) {
        read_size = recv(sockfd, (char *)tls_buf, sizeof(tls_buf), 0);
        if (read_size <= 0) break;

        tls_consume_stream(context, tls_buf, read_size,
                           validate_certificate);
        https_send_pending(sockfd, context);

        if (!tls_established(context))
            continue;

        /* Send HTTP request once TLS is up */
        if (!sent) {
            printf("  Thinking...\n");
            fflush(stdout);
            tls_write(context, (unsigned char *)http_request, req_len);
            https_send_pending(sockfd, context);
            sent = 1;
        }

        /* Read decrypted response */
        while ((read_size = tls_read(context, tls_buf, sizeof(tls_buf) - 1)) > 0) {
            if (resp_len + read_size < response_size - 1) {
                memcpy(resp_data + resp_len, tls_buf, read_size);
                resp_len += read_size;
            }
        }
    }

    resp_data[resp_len] = '\0';
    free(http_request);
    tls_destroy_context(context);
    close(sockfd);

    /* Skip HTTP headers */
    body_start = strstr(resp_data, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        extract_response_text(body_start, response, response_size);
    } else {
        strncpy(response, resp_data, response_size - 1);
        response[response_size - 1] = '\0';
    }

    free(resp_data);
    return 0;
}

/* --- API key loading --- */

int load_api_key()
{
    FILE *fp;
    int len;
    char path[512];
    char *home;

    /* Try current directory first */
    fp = fopen(KEY_FILE, "r");
    if (!fp) {
        /* Try home directory */
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, KEY_FILE);
            fp = fopen(path, "r");
        }
    }

    if (!fp) return -1;

    if (fgets(api_key, sizeof(api_key), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Strip newline */
    len = strlen(api_key);
    while (len > 0 && (api_key[len-1] == '\n' || api_key[len-1] == '\r'))
        api_key[--len] = '\0';

    return (len > 0) ? 0 : -1;
}

/* --- Model loading --- */

void load_model()
{
    FILE *fp;
    int len;
    char path[512];
    char *home;

    /* Default */
    strncpy(model, DEFAULT_MODEL, sizeof(model) - 1);

    /* Try current directory first */
    fp = fopen(MODEL_FILE, "r");
    if (!fp) {
        /* Try home directory */
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, MODEL_FILE);
            fp = fopen(path, "r");
        }
    }

    if (!fp) return;

    if (fgets(model, sizeof(model), fp) != NULL) {
        len = strlen(model);
        while (len > 0 && (model[len-1] == '\n' || model[len-1] == '\r'))
            model[--len] = '\0';
    }
    fclose(fp);
}

/* --- Signal handler --- */

void handle_sigint(sig)
int sig;
{
    printf("\n\n  Goodbye!\n\n");
    running = 0;
}

/* --- Main --- */

int main(argc, argv)
int argc;
char **argv;
{
    char input[INPUT_BUF];
    char response[RESPONSE_BUF];
    int result;

    signal(SIGINT, handle_sigint);

    /* Load API key */
    if (argc > 1 && strncmp(argv[1], "sk-", 3) == 0) {
        strncpy(api_key, argv[1], sizeof(api_key) - 1);
    } else if (load_api_key() != 0) {
        printf("\n  Claude for NeXTSTEP\n\n");
        printf("  API key not found. Create a file called '%s'\n", KEY_FILE);
        printf("  containing your Anthropic API key, or pass it as an argument:\n\n");
        printf("    ./claude sk-ant-...\n\n");
        return 1;
    }

    /* Load model (from .claude_model file or default) */
    load_model();

    /* Initialize */
    history[0] = '\0';
    history_len = 0;

    print_banner();

    /* Main conversation loop */
    while (running) {
        printf("you> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL)
            break;

        /* Strip newline */
        input[strlen(input) - 1] = '\0';

        /* Skip empty input */
        if (input[0] == '\0')
            continue;

        /* Commands */
        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0)
            break;

        if (strcmp(input, "clear") == 0) {
            history[0] = '\0';
            history_len = 0;
            printf("  (conversation cleared)\n\n");
            continue;
        }

        /* Send to Claude */
        printf("\n");
        response[0] = '\0';
        result = claude_send(input, response, sizeof(response));

        if (result == 0 && response[0]) {
            history_append("assistant", response);
            printf("\n");
            print_wrapped("claude> ", response, WRAP_WIDTH);
        } else {
            printf("  Error: %s\n", response);
        }
        printf("\n");
    }

    printf("\n  Goodbye!\n\n");
    return 0;
}
