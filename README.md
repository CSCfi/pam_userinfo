# pam_userinfo
PAM module treating the authentication token as OIDC Access Token to access https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

# Configuration
## Example /etc/pam_userinfo/config.json

    {
      "username_matches": [
        "YOUR_CLAIM"
      ],
      "login_aud": "YOUR_AUD_VALUE",
      "userinfo_endpoint": "https://example.com/userinfo"
    }
    
## PAM configuration example

    auth        required	  pam_env.so
    auth        required	  pam_faildelay.so delay=2000000
    auth        sufficient    pam_userinfo.so
    auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
    auth        required	  pam_deny.so

    account     required	  pam_userinfo.so
    account     sufficient    pam_localuser.so
    account     sufficient    pam_succeed_if.so uid < 1000 quiet
    account     required	  pam_permit.so

    session    required	  pam_mkhomedir.so skel=/etc/skel/ umask=0022
    session     optional	  pam_keyinit.so revoke
    session     required	  pam_limits.so
    -session     optional	   pam_systemd.so
    session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
    session     required	  pam_unix.so