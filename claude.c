/*
 * Claude for NeXTSTEP
 * A native Claude AI console client for NeXTSTEP 3.3
 *
 * Connects directly to api.anthropic.com over TLS 1.2
 * using Crypto Ancienne (cryanc) by Cameron Kaiser.
 *
 * Build: cc -O -o claude claude.c
 * Usage: ./claude [--dangerously-skip-permissions] [sk-ant-...]
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

/* Crypto Ancienne TLS library - linked separately via cryanc.o */
#include "cryanc.h"

/* --- Configuration --- */

#define API_HOST      "api.anthropic.com"
#define API_PORT      443
#define API_VERSION   "2023-06-01"
#define DEFAULT_MODEL "claude-haiku-4-5-20251001"
#define MAX_TOKENS    1024
#define KEY_FILE      ".claude_api_key"
#define MODEL_FILE    ".claude_model"
#define MODELS_FILE   ".claude_models"
#define MAX_MODELS    16
#define VERSION       "1.1"

#define INPUT_BUF     4096
#define RESPONSE_BUF  65536
#define HISTORY_BUF   32768
#define HTTP_BUF      4096
#define WRAP_WIDTH    72

#define CMD_TAG_OPEN  "<cmd>"
#define CMD_TAG_CLOSE "</cmd>"
#define MAX_CMD_LEN   512
#define CMD_OUTPUT_BUF 4096
#define MAX_CMD_LOOPS  5
#define DENY_FILE     ".claude_deny"
#define ALLOW_FILE    ".claude_allow"
#define MAX_RULES     64
#define MAX_RULE_LEN  64

/* --- Globals --- */

static char api_key[256];
static char model[128];
static char models[MAX_MODELS][128];
static int model_count = 0;
static char history[HISTORY_BUF];
static int history_len = 0;
static int msg_count = 0;
static int running = 1;
static float temperature = 1.0;
static char platform_prompt[2048];
static char user_prompt[1024];
static char system_prompt[4096];
static int last_input_tokens = 0;
static int last_output_tokens = 0;

/* Command execution */
static int auto_execute = 0;
static char cwd[512];
static char deny_list[MAX_RULES][MAX_RULE_LEN];
static int deny_count = 0;
static char allow_list[MAX_RULES][MAX_RULE_LEN];
static int allow_count = 0;
static FILE *logfp = NULL;

/* Hardcoded deny list - always enforced */
static char *builtin_deny[] = {
    "rm", "mv", "cp", "dd",
    "mkfs", "newfs", "fdisk", "format",
    "chmod", "chown", "mknod",
    "halt", "reboot", "shutdown",
    NULL
};

/* --- Logging --- */

void log_msg(msg)
char *msg;
{
    if (logfp) {
        fprintf(logfp, "%s\n", msg);
        fflush(logfp);
    }
}

void log_fmt2(fmt, a, b)
char *fmt;
char *a;
char *b;
{
    if (logfp) {
        fprintf(logfp, fmt, a, b);
        fprintf(logfp, "\n");
        fflush(logfp);
    }
}

void open_log()
{
    logfp = fopen("claude.log", "a");
    if (logfp) {
        fprintf(logfp, "\n=== Session started ===\n");
        fflush(logfp);
    }
}

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
 * Find a JSON integer value by key. Returns the value, or -1 if not found.
 */
int json_find_int(json, key)
char *json;
char *key;
{
    char pattern[256];
    char *p, *search;

    sprintf(pattern, "\"%s\"", key);
    search = json;

    while (1) {
        p = strstr(search, pattern);
        if (!p) return -1;

        p += strlen(pattern);
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p != ':') { search = p; continue; }
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

        if (*p >= '0' && *p <= '9')
            return atoi(p);
        search = p;
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
    printf("  Claude for NeXTSTEP v%s\n", VERSION);
    printf("  Model: %s\n", model);
    if (auto_execute)
        printf("  Command mode: auto-execute\n");
    printf("  Type '/help' for commands.\n");
    printf("\n");
}

/* --- Command safety --- */

/*
 * Load a rule list from a config file (one prefix per line).
 * Tries cwd first, then home directory.
 */
int load_rule_file(filename, list, max_rules)
char *filename;
char list[][MAX_RULE_LEN];
int max_rules;
{
    FILE *fp;
    char path[512];
    char *home;
    char line[MAX_RULE_LEN];
    int count = 0;
    int len;

    fp = fopen(filename, "r");
    if (!fp) {
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, filename);
            fp = fopen(path, "r");
        }
    }

    if (!fp) return 0;

    while (count < max_rules && fgets(line, sizeof(line), fp)) {
        len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len > 0 && line[0] != '#') {
            strncpy(list[count], line, MAX_RULE_LEN - 1);
            list[count][MAX_RULE_LEN - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    return count;
}

void load_cmd_rules()
{
    deny_count = load_rule_file(DENY_FILE, deny_list, MAX_RULES);
    allow_count = load_rule_file(ALLOW_FILE, allow_list, MAX_RULES);
    log_fmt2("Loaded %s deny, %s allow rules",
        deny_count ? "custom" : "0", allow_count ? "custom" : "0");
}

/*
 * Extract the first word (command name) from a command string.
 */
void get_cmd_name(cmd, name, name_size)
char *cmd;
char *name;
int name_size;
{
    int i = 0;

    /* Skip leading whitespace */
    while (*cmd == ' ' || *cmd == '\t') cmd++;

    while (*cmd && *cmd != ' ' && *cmd != '\t' && i < name_size - 1) {
        name[i++] = *cmd++;
    }
    name[i] = '\0';
}

/*
 * Check if a command matches any entry in a rule list.
 * Matches by command name prefix.
 */
int matches_list(cmd, list, count)
char *cmd;
char list[][MAX_RULE_LEN];
int count;
{
    char name[MAX_RULE_LEN];
    int i;

    get_cmd_name(cmd, name, sizeof(name));

    for (i = 0; i < count; i++) {
        if (strcmp(name, list[i]) == 0)
            return 1;
    }
    return 0;
}

/*
 * Check if a command matches the hardcoded deny list.
 */
int matches_builtin_deny(cmd)
char *cmd;
{
    char name[MAX_RULE_LEN];
    int i;

    get_cmd_name(cmd, name, sizeof(name));

    for (i = 0; builtin_deny[i] != NULL; i++) {
        if (strcmp(name, builtin_deny[i]) == 0)
            return 1;
    }
    return 0;
}

/*
 * Check if a command tries to escape the working directory.
 * Blocks ".." traversal and absolute paths outside cwd.
 */
int path_is_safe(cmd)
char *cmd;
{
    /* Block .. traversal */
    if (strstr(cmd, ".."))
        return 0;

    /* Check for absolute paths - scan for / followed by a path */
    {
        char *p = cmd;
        while (*p) {
            if (*p == '/' && p != cmd && *(p-1) == ' ') {
                /* Found an absolute path argument */
                if (strncmp(p, cwd, strlen(cwd)) != 0)
                    return 0;
            }
            p++;
        }
    }

    return 1;
}

/*
 * Check command safety. Returns:
 *  0 = denied (blocked)
 *  1 = allowed (pre-approved or auto-execute)
 *  2 = ask user
 */
int check_cmd_safety(cmd)
char *cmd;
{
    /* 1. Hardcoded deny - always enforced */
    if (matches_builtin_deny(cmd))
        return 0;

    /* 2. User deny list - always enforced */
    if (matches_list(cmd, deny_list, deny_count))
        return 0;

    /* 3. Path safety */
    if (!path_is_safe(cmd))
        return 0;

    /* 4. User allow list */
    if (matches_list(cmd, allow_list, allow_count))
        return 1;

    /* 5. Auto-execute mode */
    if (auto_execute)
        return 1;

    /* 6. Ask user */
    return 2;
}

/* --- Command execution --- */

/*
 * Find <cmd>...</cmd> in response text.
 * Returns pointer to command string (static buffer), or NULL.
 */
char *find_cmd_tag(text)
char *text;
{
    static char cmd_buf[MAX_CMD_LEN];
    char *start, *end;
    int len;

    start = strstr(text, CMD_TAG_OPEN);
    if (!start) return NULL;

    start += strlen(CMD_TAG_OPEN);
    end = strstr(start, CMD_TAG_CLOSE);
    if (!end) return NULL;

    len = end - start;
    if (len <= 0 || len >= MAX_CMD_LEN) return NULL;

    strncpy(cmd_buf, start, len);
    cmd_buf[len] = '\0';
    return cmd_buf;
}

/*
 * Remove all <cmd>...</cmd> tags from text, in place.
 */
void strip_cmd_tags(text)
char *text;
{
    char *start, *end;
    int tag_close_len;

    tag_close_len = strlen(CMD_TAG_CLOSE);

    while ((start = strstr(text, CMD_TAG_OPEN)) != NULL) {
        end = strstr(start, CMD_TAG_CLOSE);
        if (!end) break;
        end += tag_close_len;
        /* Shift everything after the tag back */
        memmove(start, end, strlen(end) + 1);
    }
}

/*
 * Execute a command and capture its output.
 * Returns 0 on success, -1 on failure.
 */
int execute_cmd(cmd, output, output_size)
char *cmd;
char *output;
int output_size;
{
    FILE *pp;
    int total = 0;
    int n;

    pp = popen(cmd, "r");
    if (!pp) {
        strcpy(output, "(failed to execute command)");
        return -1;
    }

    while (total < output_size - 1) {
        n = fread(output + total, 1, output_size - 1 - total, pp);
        if (n <= 0) break;
        total += n;
    }
    output[total] = '\0';
    pclose(pp);

    return 0;
}

/*
 * Ask user for permission to run a command.
 * Returns 1 if approved, 0 if denied.
 */
int ask_permission(cmd)
char *cmd;
{
    char answer[16];

    printf("  Execute: %s\n", cmd);
    printf("  Allow? [y/n] ");
    fflush(stdout);

    if (fgets(answer, sizeof(answer), stdin) == NULL)
        return 0;

    return (answer[0] == 'y' || answer[0] == 'Y');
}

/* --- Platform detection --- */

/*
 * Run a command and capture first line of output into buf.
 * Returns 0 on success, -1 on failure.
 */
int run_capture(cmd, buf, buf_size)
char *cmd;
char *buf;
int buf_size;
{
    FILE *pp;
    int len;

    pp = popen(cmd, "r");
    if (!pp) {
        buf[0] = '\0';
        return -1;
    }

    if (fgets(buf, buf_size, pp) == NULL) {
        buf[0] = '\0';
        pclose(pp);
        return -1;
    }
    pclose(pp);

    /* Strip trailing newline */
    len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
        buf[--len] = '\0';

    return 0;
}

/*
 * Build the platform system prompt by detecting the environment.
 */
void build_platform_prompt()
{
    char host_info[512];
    char host_name[128];
    char arch_name[64];

    host_info[0] = '\0';
    host_name[0] = '\0';
    arch_name[0] = '\0';

    run_capture("hostinfo 2>/dev/null", host_info, sizeof(host_info));
    run_capture("hostname 2>/dev/null", host_name, sizeof(host_name));
    run_capture("arch 2>/dev/null", arch_name, sizeof(arch_name));

    sprintf(platform_prompt,
        "You are running natively on a NeXTSTEP machine.\\n"
        "System: %s\\n"
        "Hostname: %s\\n"
        "Architecture: %s\\n"
        "Working directory: %s\\n"
        "This is a vintage NeXTSTEP 3.3 system with BSD 4.3 tools. "
        "Use only commands compatible with this platform. "
        "No GNU extensions, no -p flag on mkdir, etc.\\n"
        "When you need to inspect the system to answer a question, "
        "include <cmd>command</cmd> in your response. "
        "The command will be executed and you will receive the output. "
        "Only use commands that read or inspect - never modify, delete, or move files. "
        "Commands are restricted to the working directory.",
        host_info[0] ? host_info : "NeXTSTEP 3.3",
        host_name[0] ? host_name : "unknown",
        arch_name[0] ? arch_name : "m68k",
        cwd);

    log_msg("Platform prompt built");
}

/*
 * Rebuild the combined system prompt from platform + user parts.
 */
void rebuild_system_prompt()
{
    if (user_prompt[0]) {
        sprintf(system_prompt, "%s\\n\\n%s", platform_prompt, user_prompt);
    } else {
        strcpy(system_prompt, platform_prompt);
    }
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
        printf("  (conversation history cleared -- memory full)\n\n");
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
    body = (char *)malloc(HISTORY_BUF + 4096);
    if (!body) { strcpy(response, "Out of memory"); return -1; }

    if (system_prompt[0]) {
        sprintf(body,
            "{\"model\":\"%s\","
            "\"max_tokens\":%d,"
            "\"temperature\":%.1f,"
            "\"system\":\"%s\","
            "\"messages\":[%s]}",
            model, MAX_TOKENS, (double)temperature, system_prompt, history);
    } else {
        sprintf(body,
            "{\"model\":\"%s\","
            "\"max_tokens\":%d,"
            "\"temperature\":%.1f,"
            "\"messages\":[%s]}",
            model, MAX_TOKENS, (double)temperature, history);
    }
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
        /* Extract token usage */
        last_input_tokens = json_find_int(body_start, "input_tokens");
        last_output_tokens = json_find_int(body_start, "output_tokens");
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

/*
 * Load available models from .claude_models file (one per line).
 * Falls back to DEFAULT_MODEL if file not found.
 */
void load_models()
{
    FILE *fp;
    char path[512];
    char *home;
    char line[128];
    int len;

    model_count = 0;

    /* Try current directory first */
    fp = fopen(MODELS_FILE, "r");
    if (!fp) {
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, MODELS_FILE);
            fp = fopen(path, "r");
        }
    }

    if (fp) {
        while (model_count < MAX_MODELS && fgets(line, sizeof(line), fp)) {
            len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
            if (len > 0) {
                strncpy(models[model_count], line, 127);
                models[model_count][127] = '\0';
                model_count++;
            }
        }
        fclose(fp);
    }

    /* Ensure at least the default model is available */
    if (model_count == 0) {
        strncpy(models[0], DEFAULT_MODEL, 127);
        model_count = 1;
    }
}

/*
 * Load last-used model from .claude_model file, or use first from models list.
 */
void load_model()
{
    FILE *fp;
    int len;
    char path[512];
    char *home;

    /* Default to first model in list */
    strncpy(model, models[0], sizeof(model) - 1);

    /* Try current directory first */
    fp = fopen(MODEL_FILE, "r");
    if (!fp) {
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

/*
 * Save current model to .claude_model file for next session.
 */
void save_model()
{
    FILE *fp;
    char path[512];
    char *home;

    fp = fopen(MODEL_FILE, "w");
    if (!fp) {
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, MODEL_FILE);
            fp = fopen(path, "w");
        }
    }
    if (fp) {
        fprintf(fp, "%s\n", model);
        fclose(fp);
    }
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
    int i;

    signal(SIGINT, handle_sigint);

    /* Parse arguments */
    auto_execute = 0;
    api_key[0] = '\0';

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dangerously-skip-permissions") == 0 ||
            strcmp(argv[i], "-y") == 0) {
            auto_execute = 1;
        } else if (strncmp(argv[i], "sk-", 3) == 0) {
            strncpy(api_key, argv[i], sizeof(api_key) - 1);
        }
    }

    /* Load API key if not passed as argument */
    if (api_key[0] == '\0' && load_api_key() != 0) {
        printf("\n  Claude for NeXTSTEP\n\n");
        printf("  API key not found. Create a file called '%s'\n", KEY_FILE);
        printf("  containing your Anthropic API key, or pass it as an argument:\n\n");
        printf("    ./claude sk-ant-...\n\n");
        return 1;
    }

    /* Get working directory */
    if (getwd(cwd) == NULL) {
        strcpy(cwd, ".");
    }

    /* Open log */
    open_log();
    log_fmt2("CWD: %s, Auto-execute: %s",
        cwd, auto_execute ? "yes" : "no");

    /* Load available models, then load last-used model */
    load_models();
    load_model();

    /* Load command safety rules */
    load_cmd_rules();

    /* Initialize */
    history[0] = '\0';
    history_len = 0;
    user_prompt[0] = '\0';

    /* Build platform-aware system prompt */
    build_platform_prompt();
    rebuild_system_prompt();

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
        if (strcmp(input, "/exit") == 0 || strcmp(input, "/quit") == 0)
            break;

        if (strcmp(input, "/clear") == 0) {
            history[0] = '\0';
            history_len = 0;
            msg_count = 0;
            printf("  (conversation cleared)\n\n");
            continue;
        }

        if (strcmp(input, "/new") == 0) {
            history[0] = '\0';
            history_len = 0;
            msg_count = 0;
            printf("  (new conversation started)\n\n");
            continue;
        }

        if (strcmp(input, "/model") == 0) {
            char pick[16];
            int choice;

            printf("\n  Available models:\n");
            for (i = 0; i < model_count; i++) {
                printf("    %d. %s", i + 1, models[i]);
                if (strcmp(models[i], model) == 0)
                    printf("  (active)");
                printf("\n");
            }
            printf("\n  Select [1-%d] or Enter to cancel: ", model_count);
            fflush(stdout);

            if (fgets(pick, sizeof(pick), stdin) != NULL) {
                choice = atoi(pick);
                if (choice >= 1 && choice <= model_count) {
                    strncpy(model, models[choice - 1], sizeof(model) - 1);
                    model[sizeof(model) - 1] = '\0';
                    save_model();
                    printf("  Model changed to: %s\n\n", model);
                } else {
                    printf("  (no change)\n\n");
                }
            }
            continue;
        }

        if (strncmp(input, "/model ", 7) == 0) {
            strncpy(model, input + 7, sizeof(model) - 1);
            model[sizeof(model) - 1] = '\0';
            save_model();
            printf("  Model changed to: %s\n\n", model);
            continue;
        }

        if (strncmp(input, "/system ", 8) == 0) {
            strncpy(user_prompt, input + 8, sizeof(user_prompt) - 1);
            user_prompt[sizeof(user_prompt) - 1] = '\0';
            rebuild_system_prompt();
            printf("  System prompt set.\n\n");
            continue;
        }

        if (strcmp(input, "/system") == 0) {
            if (user_prompt[0]) {
                printf("  System prompt: %s\n\n", user_prompt);
            } else {
                printf("  No custom system prompt. Platform context is active.\n\n");
            }
            continue;
        }

        if (strncmp(input, "/temp ", 6) == 0) {
            double t;
            t = atof(input + 6);
            if (t >= 0.0 && t <= 1.0) {
                temperature = (float)t;
                printf("  Temperature set to %.1f\n\n", t);
            } else {
                printf("  Temperature must be 0.0 to 1.0\n\n");
            }
            continue;
        }

        if (strcmp(input, "/temp") == 0) {
            printf("  Temperature: %.1f\n\n", (double)temperature);
            continue;
        }

        if (strcmp(input, "/tokens") == 0) {
            if (last_input_tokens > 0 || last_output_tokens > 0) {
                printf("  Last request:\n");
                printf("    Input tokens:  %d\n", last_input_tokens);
                printf("    Output tokens: %d\n\n", last_output_tokens);
            } else {
                printf("  No token data yet. Send a message first.\n\n");
            }
            continue;
        }

        if (strncmp(input, "/save ", 6) == 0) {
            FILE *sf;
            sf = fopen(input + 6, "w");
            if (sf) {
                fprintf(sf, "Claude for NeXTSTEP - Conversation Log\n");
                fprintf(sf, "Model: %s\n", model);
                fprintf(sf, "Messages: %d\n", msg_count);
                fprintf(sf, "--------------------------------------\n\n");
                fprintf(sf, "%s\n", history);
                fclose(sf);
                printf("  Conversation saved to: %s\n\n", input + 6);
            } else {
                printf("  Error: could not open %s for writing\n\n", input + 6);
            }
            continue;
        }

        if (strcmp(input, "/info") == 0) {
            printf("  Model:       %s\n", model);
            printf("  Temperature: %.1f\n", (double)temperature);
            printf("  System:      %s\n", user_prompt[0] ? user_prompt : "(platform only)");
            printf("  Auto-exec:   %s\n", auto_execute ? "yes" : "no");
            printf("  CWD:         %s\n", cwd);
            printf("  Messages:    %d\n", msg_count);
            printf("  History:     %d / %d bytes\n\n", history_len, HISTORY_BUF);
            continue;
        }

        if (strcmp(input, "/version") == 0) {
            printf("  Claude for NeXTSTEP v%s\n", VERSION);
            printf("  (c) 2026 ARNLTony & Claude\n\n");
            continue;
        }

        if (strcmp(input, "/key") == 0) {
            if (load_api_key() == 0) {
                printf("  API key reloaded.\n\n");
            } else {
                printf("  Error: could not reload API key.\n\n");
            }
            continue;
        }

        if (strcmp(input, "/help") == 0) {
            printf("  Commands:\n");
            printf("    /model          - list & select model\n");
            printf("    /model <name>   - switch to model\n");
            printf("    /system <text>  - set custom system prompt\n");
            printf("    /temp <0-1>     - set temperature\n");
            printf("    /tokens         - show last token usage\n");
            printf("    /save <file>    - save conversation\n");
            printf("    /new            - new conversation\n");
            printf("    /clear          - clear conversation\n");
            printf("    /info           - show session info\n");
            printf("    /key            - reload API key\n");
            printf("    /version        - show version\n");
            printf("    /exit           - exit\n");
            printf("\n  Startup flags:\n");
            printf("    -y, --dangerously-skip-permissions\n");
            printf("                    - auto-execute commands\n\n");
            continue;
        }

        /* Send to Claude */
        printf("\n");
        response[0] = '\0';
        result = claude_send(input, response, sizeof(response));

        if (result == 0 && response[0]) {
            /* Command execution loop */
            int cmd_loops = 0;
            char *cmd;

            while (cmd_loops < MAX_CMD_LOOPS &&
                   (cmd = find_cmd_tag(response)) != NULL) {
                int safety;
                char cmd_output[CMD_OUTPUT_BUF];
                char feedback[CMD_OUTPUT_BUF + 256];

                cmd_loops++;
                safety = check_cmd_safety(cmd);

                if (safety == 0) {
                    /* Denied */
                    printf("  [DENIED] %s\n", cmd);
                    log_fmt2("CMD DENIED: %s", cmd, "");
                    sprintf(feedback,
                        "Command denied (blocked by safety rules): %s. "
                        "Please answer without running that command, or try "
                        "a different command.", cmd);
                    strip_cmd_tags(response);
                    history_append("assistant", response);
                    response[0] = '\0';
                    result = claude_send(feedback, response, sizeof(response));
                    if (result != 0) break;
                    continue;
                }

                if (safety == 2) {
                    /* Ask user */
                    if (!ask_permission(cmd)) {
                        printf("  [SKIPPED]\n");
                        log_fmt2("CMD SKIPPED: %s", cmd, "");
                        sprintf(feedback,
                            "The user denied the command: %s. "
                            "Please answer without it.", cmd);
                        strip_cmd_tags(response);
                        history_append("assistant", response);
                        response[0] = '\0';
                        result = claude_send(feedback, response, sizeof(response));
                        if (result != 0) break;
                        continue;
                    }
                }

                /* Execute */
                printf("  [RUN] %s\n", cmd);
                log_fmt2("CMD EXEC: %s", cmd, "");
                cmd_output[0] = '\0';
                execute_cmd(cmd, cmd_output, sizeof(cmd_output));
                log_fmt2("CMD OUTPUT: %s", cmd_output, "");

                /* Send output back to Claude */
                strip_cmd_tags(response);
                history_append("assistant", response);
                sprintf(feedback, "Command output for '%s':\n%s", cmd, cmd_output);
                response[0] = '\0';
                result = claude_send(feedback, response, sizeof(response));
                if (result != 0) break;
            }

            /* Display final response (with any remaining tags stripped) */
            strip_cmd_tags(response);
            history_append("assistant", response);
            msg_count++;
            printf("\n");
            print_wrapped("claude> ", response, WRAP_WIDTH);
        } else {
            printf("  Error: %s\n", response);
            log_fmt2("API ERROR: %s", response, "");
        }
        printf("\n");
    }

    printf("\n  Goodbye!\n\n");
    log_msg("Session ended");
    if (logfp) fclose(logfp);
    return 0;
}
