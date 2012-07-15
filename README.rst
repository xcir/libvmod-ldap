===================
vmod_ldap
===================

-------------------------------
LDAP module for Varnish
-------------------------------

:Author: Syohei Tanaka(@xcir)
:Date: 2012-07-15
:Version: (:3[__])
:Manual section: 3

SYNOPSIS
===========

import ldap;

In development.

        ::

                import ldap;
                
                sub vcl_error {
                  if (obj.status == 401) {
                    set obj.http.WWW-Authenticate = {"Basic realm="Authorization Required""};
                    synthetic {"Error 401 Unauthorized"};
                    return(deliver);
                  }
                }
                
                sub vcl_recv{
                
                if(req.url ~ "^/member/"){
                        if(!(req.http.Authorization && ldap.auth(
                                true,
                                "cn=Manager,dc=ldap,dc=example,dc=com",
                                "password",
                                "ldap://192.168.1.1/ou=people,dc=ldap,dc=example,dc=com?uid?sub?(objectClass=*)",
                                regsub(digest.base64_decode(regsub(req.http.Authorization, "^Basic (.*)$","\1")), "^([^:]+):.*$", "\1"),
                                regsub(digest.base64_decode(regsub(req.http.Authorization, "^Basic (.*)$","\1")), "^.*:([^:]+)$", "\1")
                        ))){
                                error 401;
                        }
                }
                