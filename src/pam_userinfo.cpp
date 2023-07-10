#include "include/config.hpp"
#include "include/nlohmann/json.hpp"

#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/param.h>

#ifdef BSD
#include <security/pam_appl.h>
#else
#include <security/pam_ext.h>
#endif

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <syslog.h>
#include <thread>
#include <vector>

using json = nlohmann::json;

// TODO: set method docs
// TODO: see that exceptions are always handled

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

void appendFile(std::string newLine, std::string fileName)
{
    std::ofstream ofstrAppend;
    ofstrAppend.open(fileName.c_str(), std::ios::app);
    if (!ofstrAppend)
    {
        syslog(LOG_WARNING, "Not able to open file %s for appending. May result as PAM stack failure at later point", fileName.c_str());
        return;
    }
    syslog(LOG_INFO, "Appending %s to file %s", newLine.c_str(), fileName.c_str());
    ofstrAppend << newLine.c_str() << std::endl;
    ofstrAppend.close();
}

void addUserToGroup(std::string strUser, std::string strGroup)
{
    std::fstream fstrGroup;
    fstrGroup.open("/etc/group", std::ios::in);
    if (!fstrGroup)
    {
        syslog(LOG_WARNING, "Not able to open file /etc/group for reading. User is not added to users group");
        return;
    }
    std::string contents((std::istreambuf_iterator<char>(fstrGroup)), std::istreambuf_iterator<char>());
    fstrGroup.close();
    size_t last = 0;
    size_t next = 0;
    std::vector<std::string> vecFields;
    while ((next = contents.find_first_of("\n", last)) != std::string::npos)
    {
        std::string strLine = contents.substr(last, next - last);
        vecFields.push_back((strLine.find(strGroup + ":x") != std::string::npos) ? (strLine.back() == ':' ? strLine + strUser : strLine + "," + strUser) : strLine);
        last = next + 1;
    }
    std::ofstream fstrNewGroup("/etc/group");
    if (!fstrNewGroup)
    {
        syslog(LOG_WARNING, "Not able to open file /etc/group for writing. User is not added to users group");
        return;
    }
    for (const auto &e : vecFields)
        fstrNewGroup << e << "\n";
    fstrNewGroup.close();
}

void addUser(const char *pUsername)
{
    std::string strUser(pUsername);
    std::fstream fstrPasswd;
    fstrPasswd.open("/etc/passwd", std::ios::in);
    if (!fstrPasswd)
    {
        syslog(LOG_WARNING, "Not able to open file /etc/passwd for reading. May result as PAM stack failure at later point");
        return;
    }
    std::string contents((std::istreambuf_iterator<char>(fstrPasswd)), std::istreambuf_iterator<char>());
    fstrPasswd.close();
    size_t last = 0;
    size_t next = 0;
    std::vector<std::string> vecFields;
    while ((next = contents.find_first_of(":\n", last)) != std::string::npos)
    {
        vecFields.push_back(contents.substr(last, next - last));
        last = next + 1;
    }
    if (find(vecFields.begin(), vecFields.end(), strUser) != vecFields.end())
    {
        // User is already in /etc/passwd, nothing to do
        return;
    }
    // Generate uid between 1000-1999
    int i = 1000 + rand() % 1000;
    while (find(vecFields.begin(), vecFields.end(), std::to_string(i)) != vecFields.end())
    {
        // Userid may be taken already, generate a new one.
        i = 1000 + rand() % 1000;
    }
    // We make bold assumption that if groupid is not in /etc/passwd it is not reserved yet
    std::string strPasswdEntry = strUser + ":x:" + std::to_string(i) + ":" + std::to_string(i) + "::/home/" + strUser + ":/bin/bash";
    appendFile(strPasswdEntry, "/etc/passwd");
    std::string strGroupsEntry = strUser + ":x:" + std::to_string(i) + ":";
    appendFile(strGroupsEntry, "/etc/group");
    // We add user always to users group
    addUserToGroup(strUser, "users");

    // podman specific subuid and subgid
    std::string strSubEntry = strUser + ":10000:65536";
    appendFile(strSubEntry, "/etc/subuid");
    appendFile(strSubEntry, "/etc/subgid");
}

bool validate_userinfo_response(std::string response, const char *username, Config config)
{
    json parsedResponse;
    try
    {
        parsedResponse = json::parse(response);
    }
    catch (json::exception &e)
    {
        syslog(LOG_ERR, "Json parsing failed, error=%s", e.what());
        return false;
    }
    // Check if we have received Error Response
    if (parsedResponse.contains("error"))
    {
        std::string error = parsedResponse.at("error");
        std::string error_description = parsedResponse.contains("error_description") ? parsedResponse.at("error_description") : "";
        syslog(LOG_ERR, "UserInfo response indicates error, error=%s, error_description=%s", error.c_str(), error_description.c_str());
        return false;
    }
    // Successful UserInfo response must contain sub claim
    if (!parsedResponse.contains("sub"))
    {
        syslog(LOG_ERR, "UserInfo response does not contain sub claim");
        return false;
    }
    // Verify there is a claim matching PAM login. PAM login must match sub unless there is alternative claim defined.
    std::set<std::string>::iterator it = config.username_matches.begin();
    bool match = false;
    while (it != config.username_matches.end())
    {
        if (parsedResponse.contains((*it).c_str()))
        {
            std::string value = parsedResponse.at((*it).c_str());
            if (value.compare(username) == 0)
            {
                match = true;
                break;
            }
        }
        it++;
    }
    // If specific claim set we verify PAM login equals sub claim value
    if (config.username_matches.size() == 0)
    {
        std::string sub = parsedResponse.at("sub");
        if (sub.compare(username) == 0)
        {
            match = true;
        }
    }
    if (!match)
    {
        syslog(LOG_ERR, "Access token does not match the user %s", username);
        return false;
    }
    // Now verify that there is a claim indicating access token is meant for login
    if (!parsedResponse.contains("login_aud"))
    {
        syslog(LOG_ERR, "UserInfo response does not contain login_aud claim");
        return false;
    }
    // One of the space separated strings must match our audience
    std::string login_aud = parsedResponse.at("login_aud");
    std::istringstream streamAudiences(login_aud);
    std::vector<std::string> audiences(std::istream_iterator<std::string>{streamAudiences},
                                       std::istream_iterator<std::string>());
    if (!(std::find(audiences.begin(), audiences.end(), config.login_aud) != audiences.end()))
    {
        syslog(LOG_ERR, "UserInfo response claim login_aud does not contain %s", config.login_aud.c_str());
        return false;
    }
    return true;
}

std::string get_userinfo_response(const char *userinfo_endpoint,
                                  const char *token)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl)
    {
        syslog(LOG_ERR, "Failed to initialize curl");
        throw std::runtime_error("Failed to initialize curl");
    }
    curl_easy_setopt(curl, CURLOPT_URL, userinfo_endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    std::string auth_header = "Authorization: Bearer ";
    auth_header += token;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        syslog(LOG_ERR, "Http request failed, error=%d", res);
        throw std::runtime_error("Http request failed");
    }
    syslog(LOG_DEBUG, "UserInfo response: %s", readBuffer.c_str());
    return readBuffer;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    Config config;

    openlog("PAM SDS", LOG_PID | LOG_NDELAY, LOG_AUTH);
    try
    {
        (argc > 0) ? config.load(argv[0]) : config.load("/etc/pam_userinfo/config.json");
    }
    catch (json::exception &e)
    {
        syslog(LOG_ERR, "Fatal! Failed loading configuration");
        closelog();
        return PAM_AUTH_ERR;
    }
    const char *pUsername;
    int retval;
    retval = pam_get_user(pamh, &pUsername, "Username: ");
    if (retval != PAM_SUCCESS)
    {
        syslog(LOG_ERR, "Fetching username failed %d", retval);
        closelog();
        return PAM_AUTH_ERR;
    }

    syslog(LOG_DEBUG, "Username %s", pUsername);
    const char *pToken;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pToken, "Token: ");
    if (retval != PAM_SUCCESS)
    {
        syslog(LOG_ERR, "Fetching token failed %d", retval);
        closelog();
        return PAM_AUTH_ERR;
    }
    syslog(LOG_DEBUG, "user presented access");
    std::string response;
    try
    {
        response = get_userinfo_response(config.userinfo_endpoint.c_str(), pToken);
    }
    catch (std::exception const &e)
    {
        syslog(LOG_ERR, "UserInfo request failed %s", e.what());
        closelog();
        return PAM_SYSTEM_ERR;
    }
    if (!validate_userinfo_response(response, pUsername, config))
    {
        syslog(LOG_ERR, "UserInfo response validation failed");
        closelog();
        return PAM_SYSTEM_ERR;
    }
    char *envvar;
    asprintf(&envvar, "%s=%s", "SDS_ACCESS_TOKEN", pToken);
    retval = pam_putenv(pamh, envvar);
    if (retval != PAM_SUCCESS)
    {
        syslog(LOG_ERR, "Failed(%d) to set environment variable %s", retval, envvar);
        closelog();
        return PAM_AUTH_ERR;
    }
    free(envvar);
    syslog(LOG_INFO, "Authentication succeeded");
    addUser(pUsername);
    closelog();
    return PAM_SUCCESS;
}
