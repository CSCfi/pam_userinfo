#ifndef PAM_USERINFO_CONFIG_HPP
#define PAM_USERINFO_CONFIG_HPP

#include <set>
#include <string>

class Config
{
public:
    void load(const char *path);

    // UserInfo endpoint to retrieve claims from    
    std::string userinfo_endpoint,
        //login_aud claim value acceptable for PAM authentication
        login_aud;

    // List of claim names that one of which needs to contain username used in PAM authentication
    std::set<std::string> username_matches;

    // Optional list of claim names in preferrance order of which value is be used as login username instead of one passed by user
    std::set<std::string> usernames;
};

#endif // PAM_USERINFO_CONFIG_HPP
