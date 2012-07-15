#include <stdlib.h>
#include "vcl.h"
#include "vrt.h"
#include "bin/varnishd/cache.h"

#include <syslog.h>
#include <stdio.h>

#include "vcc_if.h"

#include <ldap.h>

#define VMODLDAP_HDR "\020X-VMOD-LDAP-PTR:"

struct vmod_ldap {
	unsigned			magic;
#define VMOD_LDAP_MAGIC 0x8d4f21ef
	LDAP        *ld;
	LDAPMessage *searchResult;
};

struct vmod_ldap *vmodldap_get_raw(struct sess *sp){
	const char *tmp;
	struct vmod_ldap *c;

	tmp = VRT_GetHdr(sp, HDR_REQ, VMODLDAP_HDR);
	
	if(tmp){
		c = (struct vmod_ldap *)atol(tmp);
		return c;
	}
	return NULL;
}

void vmodldap_free(struct vmod_ldap *c){
	if(!c) return;
	if(c->ld) ldap_unbind_s(c->ld);
	if(c->searchResult) ldap_msgfree(c->searchResult);
	FREE_OBJ(c);
}


/*
set("url"				,"ldap://192.168.1.1/ou=people,dc=ldap,dc=example,dc=com?uid?sub?(objectClass=*)");
set("bind_dn cn"		,"cn=Manager,dc=ldap,dc=example,dc=com");
set("bind_dn passwd"	,"password");

*/
void vmod_set(){
	
}
struct vmod_ldap *vmodldap_init(struct sess *sp){
	struct vmod_ldap *c;
	char buf[64];
	buf[0] = 0;
	ALLOC_OBJ(c, VMOD_LDAP_MAGIC);
	AN(c);
	snprintf(buf,64,"%lu",c);
	VRT_SetHdr(sp, HDR_REQ, VMODLDAP_HDR, buf, vrt_magic_string_end);
	return c;
}

unsigned vmod_ldap_pre(struct sess *sp, unsigned V3, const char* basedn, const char*basepw, const char*searchdn, const char*user){

	AN(basedn);
	AN(basepw);
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	if(c) vmodldap_free(c);//前の接続の切断
	c = vmodldap_init(sp);
	
	int ret;
	struct timeval timeOut = { 10, 0 };
	unsigned res = (0==1);
	LDAPURLDesc *ludpp;
	int filterlen = 0;
	char *filter;
	char *dn;
	int version;
	char *host;
	//URLパース
	ret = ldap_url_parse(searchdn, &ludpp);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_url_parse: %d, (%s)", ret, ldap_err2string(ret));
		ldap_free_urldesc(ludpp);
		return;
	}
	
	host = calloc(1,strlen(searchdn)+4);
	sprintf(host,"%s://%s:%d/", ludpp->lud_scheme,ludpp->lud_host,ludpp->lud_port);
	//接続
	ret = ldap_initialize(&c->ld, host);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_initialize: %d, (%s)", ret, ldap_err2string(ret));
		vmodldap_free(c);
		ldap_free_urldesc(ludpp);
		free(host);
		return res;
	}
	free(host);
	//V3認証
	if(V3){
		version = LDAP_VERSION3;
		ldap_set_option(c->ld, LDAP_OPT_PROTOCOL_VERSION, &version );
		if(ret != LDAP_SUCCESS){
			syslog(6,"ldap_set_option: %d, (%s)", ret, ldap_err2string(ret));
			vmodldap_free(c);
			ldap_free_urldesc(ludpp);
			return res;
		}
	}
	//base認証
	ret = ldap_simple_bind_s(c->ld,basedn,basepw);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_simple_bind_s: %d, (%s)", ret, ldap_err2string(ret));
		vmodldap_free(c);
		ldap_free_urldesc(ludpp);
		return res;
	}

	//文字列長調整
	if(ludpp->lud_filter){
		filterlen += strlen(ludpp->lud_filter);
	}else{
		filterlen += 15;//"(objectClass=*)"
	}
	filterlen += strlen(ludpp->lud_attrs[0]);
	filterlen += strlen(user);
	filter = calloc(1,filterlen +1);
	sprintf(filter,"(&%s(%s=%s))", ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)", ludpp->lud_attrs[0], user);

	//リスト取得
	ret = ldap_search_ext_s(c->ld, ludpp->lud_dn, ludpp->lud_scope, filter, NULL, 0, NULL, NULL, &timeOut, 0,&c->searchResult);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_search_ext_s: %d, (%s)", ret, ldap_err2string(ret));
		vmodldap_free(c);
		return res;
	}else{
		res = (1==1);
	}
	free(filter);
	ldap_free_urldesc(ludpp);
	return res;

}


unsigned vmod_auth(struct sess *sp,unsigned V3,const char* basedn,const char*basepw,const char*searchdn,const char*user,const char*pass){
	struct berval bvalue;
	int ret;
	unsigned res = (0==1);
	char *dn;
	
	ret = vmod_ldap_pre(sp, V3, basedn, basepw, searchdn, user);
	if(!ret) return res;
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	if (ldap_count_entries(c->ld, c->searchResult) > 0){
		dn = ldap_get_dn(c->ld, c->searchResult);
		ret = ldap_simple_bind_s(c->ld, dn, pass);
		if(ret == LDAP_SUCCESS) res =(1==1);
	}
	
	
	vmodldap_free(c);
	syslog(6,"result = %d",res);
	return res;
}

/*
unsigned vmod_ldap_generic(struct sess *sp,const char *host,unsigned V3,const char* basedn,const char*basepw,const char*searchdn,const char*user,const char*pass){
	LDAP	*ld;
	struct berval bvalue;
	int ret;
	LDAPMessage *searchResult;
	unsigned res = (0==1);
	char *dn;
	
	ret = vmod_ldap_pre(sp, host, V3, basedn, basepw, searchdn, user, &ld, &searchResult);
	if(!ret) return res;
	
	
	if (ldap_count_entries(ld, searchResult) > 0){
		dn = ldap_get_dn(ld, searchResult);
		syslog(6,"%s>>>",dn);
		if (dn != NULL) {
			
			bvalue.bv_val=user;
			bvalue.bv_len=strlen(user);
			//ユーザ検索
			ret = ldap_compare_ext_s(ld, dn, "uid",&bvalue, NULL, NULL);
			if(ret == LDAP_COMPARE_TRUE){
				//認証
				ret = ldap_simple_bind_s(ld, dn, pass);
				if(ret == LDAP_SUCCESS) res =(1==1);
			}
		}
	
	}
	
	
	vmod_ldap_free(ld,searchResult);
	syslog(6,"result = %d",res);
	return res;
}
*/
int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{

	return (0);
}
