#include <fstream>
#include <set>

#include "config.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

void Config::load(const char *path)
{
    std::ifstream config_fstream(path);
    json j;
    config_fstream >> j;
    // TODO: Fail gracefully if mandatory parameter is missing
    userinfo_endpoint = j.at("userinfo_endpoint").get<std::string>();
    if (j.find("login_aud") != j.end())
    {
        login_aud = j.at("login_aud").get<std::string>();
    }
    if (j.find("usernames") != j.end())
    {
        for (auto &names : j["usernames"])
        {
            usernames.insert((std::string)names);
        }
    }
    if (j.find("username_matches") != j.end())
    {
        for (auto &matches : j["username_matches"])
        {
            username_matches.insert((std::string)matches);
        }
    }
}
