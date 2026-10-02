#define _GNU_SOURCE
#include <curl/curl.h>
#include <json-c/json.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define DEFAULT_BASE_UID 1000000000ULL
#define DEFAULT_REGISTRY "/var/lib/apiusers"
#define MAX_RESPONSE_SIZE (1024U * 1024U)
#define MAX_CHALLENGE_SIZE 512

struct response_buffer {
    char *data;
    size_t length;
    bool overflow;
};

struct module_options {
    const char *base_url;
    const char *registry;
    uid_t base_uid;
    long timeout_seconds;
};

static size_t receive_response(char *data, size_t size, size_t count, void *context)
{
    struct response_buffer *buffer = context;
    size_t incoming = size * count;

    if (incoming > MAX_RESPONSE_SIZE - buffer->length) {
        buffer->overflow = true;
        return 0;
    }

    char *next = realloc(buffer->data, buffer->length + incoming + 1);
    if (!next)
        return 0;

    buffer->data = next;
    memcpy(buffer->data + buffer->length, data, incoming);
    buffer->length += incoming;
    buffer->data[buffer->length] = '\0';
    return incoming;
}

static bool parse_options(int argc, const char **argv, struct module_options *options)
{
    options->base_url = NULL;
    options->registry = DEFAULT_REGISTRY;
    options->base_uid = (uid_t) DEFAULT_BASE_UID;
    options->timeout_seconds = 5;

    for (int index = 0; index < argc; index++) {
        if (strncmp(argv[index], "base_url=", 9) == 0) {
            options->base_url = argv[index] + 9;
        } else if (strncmp(argv[index], "registry=", 9) == 0) {
            options->registry = argv[index] + 9;
        } else if (strncmp(argv[index], "base_uid=", 9) == 0) {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(argv[index] + 9, &end, 10);
            if (errno || end == argv[index] + 9 || *end != '\0'
                    || parsed > (unsigned long long) (uid_t) -1)
                return false;
            options->base_uid = (uid_t) parsed;
        } else if (strncmp(argv[index], "timeout=", 8) == 0) {
            char *end = NULL;
            errno = 0;
            long parsed = strtol(argv[index] + 8, &end, 10);
            if (errno || end == argv[index] + 8 || *end != '\0'
                    || parsed < 1 || parsed > 30)
                return false;
            options->timeout_seconds = parsed;
        } else {
            return false;
        }
    }

    bool is_https = options->base_url
        && strncmp(options->base_url, "https://", 8) == 0
        && options->base_url[8] != '\0';
    bool is_http = options->base_url
        && strncmp(options->base_url, "http://", 7) == 0
        && options->base_url[7] != '\0';
    if ((!is_https && !is_http) || options->registry[0] != '/')
        return false;

    for (const char *cursor = options->base_url; *cursor; cursor++) {
        if (*cursor <= ' ' || *cursor == '\\')
            return false;
    }

    return true;
}

static char *make_url(const char *base_url, const char *path)
{
    size_t length = strlen(base_url);
    while (length > 8 && base_url[length - 1] == '/')
        length--;

    size_t path_length = strlen(path);
    char *url = malloc(length + path_length + 1);
    if (!url)
        return NULL;

    memcpy(url, base_url, length);
    memcpy(url + length, path, path_length + 1);
    return url;
}

static bool write_json_string(FILE *stream, const char *value)
{
    if (fputc('"', stream) == EOF)
        return false;

    for (const unsigned char *cursor = (const unsigned char *) value;
         *cursor; cursor++) {
        switch (*cursor) {
        case '"':
        case '\\':
            if (fputc('\\', stream) == EOF || fputc(*cursor, stream) == EOF)
                return false;
            break;
        case '\b': if (fputs("\\b", stream) == EOF) return false; break;
        case '\f': if (fputs("\\f", stream) == EOF) return false; break;
        case '\n': if (fputs("\\n", stream) == EOF) return false; break;
        case '\r': if (fputs("\\r", stream) == EOF) return false; break;
        case '\t': if (fputs("\\t", stream) == EOF) return false; break;
        default:
            if (*cursor < 0x20) {
                if (fprintf(stream, "\\u%04x", (unsigned int) *cursor) < 0)
                    return false;
            } else if (fputc(*cursor, stream) == EOF) {
                return false;
            }
        }
    }

    return fputc('"', stream) != EOF;
}

static char *make_json_payload(const char *username, const char *field,
                               const char *value, const char *challenge,
                               size_t *payload_length)
{
    char *payload = NULL;
    size_t length = 0;
    FILE *stream = open_memstream(&payload, &length);
    if (!stream)
        return NULL;

    bool success = fputs("{\"username\":", stream) != EOF
        && write_json_string(stream, username)
        && fprintf(stream, ",\"%s\":", field) >= 0
        && write_json_string(stream, value);
    if (success && challenge)
        success = fputs(",\"challenge\":", stream) != EOF
            && write_json_string(stream, challenge);
    if (success)
        success = fputc('}', stream) != EOF;

    if (fclose(stream) != 0)
        success = false;
    if (!success) {
        if (payload) {
            explicit_bzero(payload, length);
            free(payload);
        }
        return NULL;
    }

    *payload_length = length;
    return payload;
}

static bool post_json(const char *url, const char *body, size_t body_length,
                      long timeout_seconds, struct response_buffer *response)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return false;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    bool is_https = strncmp(url, "https://", 8) == 0;
    bool is_http = strncmp(url, "http://", 7) == 0;
    if (!is_https && !is_http) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, is_https ? "https" : "http");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                     is_https ? CURLPROTO_HTTPS : CURLPROTO_HTTP);
#endif
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) body_length);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");

    CURLcode result = curl_easy_perform(curl);
    long status = 0;
    if (result == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result == CURLE_OK && status >= 200 && status < 300
        && !response->overflow && response->data != NULL;
}

static bool response_string(struct json_object *object, const char *key,
                            const char **value)
{
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(object, key, &field)
            || json_object_get_type(field) != json_type_string)
        return false;

    *value = json_object_get_string(field);
    return *value != NULL;
}

static struct json_object *parse_response(const struct response_buffer *response)
{
    if (!response->data || response->overflow)
        return NULL;

    struct json_tokener *tokener = json_tokener_new();
    if (!tokener)
        return NULL;

    struct json_object *object = json_tokener_parse_ex(
        tokener, response->data, (int) response->length
    );
    enum json_tokener_error error = json_tokener_get_error(tokener);
    json_tokener_free(tokener);

    if (error != json_tokener_success || !object
            || json_object_get_type(object) != json_type_object) {
        if (object)
            json_object_put(object);
        return NULL;
    }
    return object;
}

static bool verify_login_response(struct json_object *object, const char *username,
                                  char challenge[MAX_CHALLENGE_SIZE])
{
    const char *result = NULL;
    const char *returned_username = NULL;
        const char *stage = NULL;
    const char *returned_challenge = NULL;

    if (!response_string(object, "result", &result)
            || strcmp(result, "Success") != 0
            || !response_string(object, "stage", &stage)
            || strcmp(stage, "2fa_required") != 0
            || !response_string(object, "username", &returned_username)
            || strcmp(returned_username, username) != 0
            || !response_string(object, "challenge", &returned_challenge)
            || returned_challenge[0] == '\0'
            || strlen(returned_challenge) >= MAX_CHALLENGE_SIZE)
        return false;

    memcpy(challenge, returned_challenge, strlen(returned_challenge) + 1);
    return true;
}

static bool verify_totp_response(struct json_object *object, const char *username)
{
    const char *result = NULL;
    const char *returned_username = NULL;
    const char *access_token = NULL;

    return response_string(object, "result", &result)
        && strcmp(result, "Success") == 0
        && response_string(object, "username", &returned_username)
        && strcmp(returned_username, username) == 0
        && response_string(object, "access_token", &access_token)
        && access_token[0] != '\0';
}

static int resolve_user(const char *username, struct passwd *record,
                        char **storage)
{
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = suggested > 0 ? (size_t) suggested : 16384;
    *storage = malloc(size);
    if (!*storage)
        return ENOMEM;

    struct passwd *found = NULL;
    int result = getpwnam_r(username, record, *storage, size, &found);
    if (result || !found) {
        free(*storage);
        *storage = NULL;
        return result ? result : ENOENT;
    }
    return 0;
}

static bool read_registry_name(int directory_fd, const char *uid_text,
                               const char *username)
{
    int fd = openat(directory_fd, uid_text, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;

    struct stat status;
    char existing[256];
    ssize_t length = -1;
    if (fstat(fd, &status) == 0 && S_ISREG(status.st_mode)
            && status.st_uid == 0 && !(status.st_mode & 0022))
        length = read(fd, existing, sizeof(existing));
    close(fd);

    size_t expected_length = strlen(username);
    return length >= 0 && (size_t) length == expected_length
        && memcmp(existing, username, expected_length) == 0;
}

static bool register_user(const char *registry, uid_t uid, const char *username)
{
    char uid_text[32];
    int count = snprintf(uid_text, sizeof(uid_text), "%lu", (unsigned long) uid);
    if (count <= 0 || (size_t) count >= sizeof(uid_text)
            || strlen(username) >= 256)
        return false;

    int directory_fd = open(registry, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0)
        return false;

    struct stat directory_status;
    if (fstat(directory_fd, &directory_status) != 0
            || !S_ISDIR(directory_status.st_mode)
            || directory_status.st_uid != 0
            || (directory_status.st_mode & 0022)) {
        close(directory_fd);
        return false;
    }

    int fd = openat(directory_fd, uid_text,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (fd < 0 && errno == EEXIST) {
        bool matches = read_registry_name(directory_fd, uid_text, username);
        close(directory_fd);
        return matches;
    }
    if (fd < 0) {
        close(directory_fd);
        return false;
    }

    size_t remaining = strlen(username);
    const char *cursor = username;
    bool success = true;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            success = false;
            break;
        }
        cursor += written;
        remaining -= (size_t) written;
    }
    if (success && fsync(fd) != 0)
        success = false;
    if (close(fd) != 0)
        success = false;
    if (!success)
        (void) unlinkat(directory_fd, uid_text, 0);
    close(directory_fd);
    return success;
}

static void log_result(pam_handle_t *pamh, int priority, const char *message,
                       const char *username)
{
    const void *service = NULL;
    (void) pam_get_item(pamh, PAM_SERVICE, &service);
    pam_syslog(pamh, priority, "pam_api_2fa %s user=%s service=%s", message,
               username ? username : "?",
               service ? (const char *) service : "?");
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                  const char **argv)
{
    (void) flags;
    struct module_options options;
    if (!parse_options(argc, argv, &options)) {
        pam_syslog(pamh, LOG_ERR, "invalid module configuration");
        return PAM_SERVICE_ERR;
    }

    const char *username = NULL;
    int status = pam_get_user(pamh, &username, NULL);
    if (status != PAM_SUCCESS || !username || username[0] == '\0')
        return status == PAM_SUCCESS ? PAM_USER_UNKNOWN : status;

    struct passwd record;
    char *passwd_storage = NULL;
    if (resolve_user(username, &record, &passwd_storage) != 0) {
        log_result(pamh, LOG_NOTICE, "user lookup failed", username);
        return PAM_USER_UNKNOWN;
    }

    uid_t uid = record.pw_uid;
    free(passwd_storage);
    if (uid < options.base_uid)
        return PAM_IGNORE;

    const char *password = NULL;
    status = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "API password: ");
    if (status != PAM_SUCCESS || !password || password[0] == '\0') {
        log_result(pamh, LOG_NOTICE, "password prompt failed", username);
        return status == PAM_SUCCESS ? PAM_AUTH_ERR : status;
    }

    char *login_url = make_url(options.base_url, "/api/login");
    char *totp_url = make_url(options.base_url, "/api/2fa");
    if (!login_url || !totp_url) {
        free(login_url);
        free(totp_url);
        return PAM_BUF_ERR;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        free(login_url);
        free(totp_url);
        return PAM_SERVICE_ERR;
    }

    size_t login_payload_length = 0;
    char *login_payload = make_json_payload(
        username, "password", password, NULL, &login_payload_length
    );
    if (!login_payload) {
        curl_global_cleanup();
        free(login_url);
        free(totp_url);
        return PAM_BUF_ERR;
    }

    struct response_buffer login_response = {0};
    bool login_ok = post_json(login_url, login_payload, login_payload_length,
                              options.timeout_seconds, &login_response);
    explicit_bzero(login_payload, login_payload_length);
    free(login_payload);

    char challenge[MAX_CHALLENGE_SIZE] = {0};
    struct json_object *login_object = login_ok ? parse_response(&login_response) : NULL;
    login_ok = login_object && verify_login_response(login_object, username, challenge);
    if (login_object)
        json_object_put(login_object);
    if (login_response.data) {
        explicit_bzero(login_response.data, login_response.length);
        free(login_response.data);
    }

    if (!login_ok) {
        explicit_bzero(challenge, sizeof(challenge));
        log_result(pamh, LOG_NOTICE, "password verification failed", username);
        curl_global_cleanup();
        free(login_url);
        free(totp_url);
        return PAM_AUTH_ERR;
    }

    char *otp = NULL;
    status = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp,
                        "Authenticator code: ");
    if (status != PAM_SUCCESS || !otp || otp[0] == '\0') {
        if (otp) {
            explicit_bzero(otp, strlen(otp));
            free(otp);
        }
        explicit_bzero(challenge, sizeof(challenge));
        curl_global_cleanup();
        free(login_url);
        free(totp_url);
        log_result(pamh, LOG_NOTICE, "OTP prompt failed", username);
        return status == PAM_SUCCESS ? PAM_AUTH_ERR : status;
    }

    size_t totp_payload_length = 0;
    char *totp_payload = make_json_payload(
        username, "code", otp, challenge, &totp_payload_length
    );
    if (!totp_payload) {
        explicit_bzero(otp, strlen(otp));
        free(otp);
        explicit_bzero(challenge, sizeof(challenge));
        curl_global_cleanup();
        free(login_url);
        free(totp_url);
        return PAM_BUF_ERR;
    }
    explicit_bzero(otp, strlen(otp));
    free(otp);
    explicit_bzero(challenge, sizeof(challenge));

    struct response_buffer totp_response = {0};
    bool totp_ok = post_json(totp_url, totp_payload, totp_payload_length,
                             options.timeout_seconds, &totp_response);
    explicit_bzero(totp_payload, totp_payload_length);
    free(totp_payload);

    struct json_object *totp_object = totp_ok ? parse_response(&totp_response) : NULL;
    totp_ok = totp_object && verify_totp_response(totp_object, username);
    if (totp_object)
        json_object_put(totp_object);
    if (totp_response.data) {
        explicit_bzero(totp_response.data, totp_response.length);
        free(totp_response.data);
    }

    if (totp_ok)
        totp_ok = register_user(options.registry, uid, username);

    curl_global_cleanup();
    free(login_url);
    free(totp_url);

    if (!totp_ok) {
        log_result(pamh, LOG_NOTICE, "OTP verification or registration failed", username);
        return PAM_AUTH_ERR;
    }

    log_result(pamh, LOG_INFO, "two-factor authentication succeeded", username);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                             const char **argv)
{
    (void) pamh;
    (void) flags;
    (void) argc;
    (void) argv;
    return PAM_SUCCESS;
}