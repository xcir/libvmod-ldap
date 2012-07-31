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
	char        *user;
	int         userlen;
	const char  *dn;
	int         dnlen;
	int         result;
	const char  *pass;
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

void vmodldap_free(struct sess *sp){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	if(!c) return;
	if(c->ld) ldap_unbind_s(c->ld);
	if(c->searchResult) ldap_msgfree(c->searchResult);
	if(c->user) free(c->user);
	if(c->pass) free(c->pass);
	FREE_OBJ(c);
	VRT_SetHdr(sp, HDR_REQ, VMODLDAP_HDR, 0);
}



struct vmod_ldap *vmodldap_init(struct sess *sp, const char*user, const char*pass){
	struct vmod_ldap *c;
	int passlen;
	char buf[64];
	buf[0] = 0;
	ALLOC_OBJ(c, VMOD_LDAP_MAGIC);
	AN(c);
	snprintf(buf,64,"%lu",c);
	
	passlen = strlen(pass);
	c->userlen = strlen(user);
	c->user = calloc(1, c->userlen +1);
	AN(c->user);
	memcpy(c->user, user ,c->userlen);
	
	c->pass = calloc(1, passlen +1);
	AN(c->pass);
	memcpy(c->pass, pass ,passlen);

	VRT_SetHdr(sp, HDR_REQ, VMODLDAP_HDR, buf, vrt_magic_string_end);
	return c;
}


unsigned vmod_open(struct sess *sp, unsigned V3, const char* basedn, const char*basepw, const char*searchdn, const char*user, const char *pass){

	AN(basedn);
	AN(basepw);
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	if(c) vmodldap_free(sp);//前の接続の切断
	c = vmodldap_init(sp,user,pass);
	
	int ret;
	struct timeval timeOut = { 10, 0 };
	unsigned res = (0==1);
	LDAPURLDesc *ludpp;
	int filterlen = 0;
	char *filter;
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
		vmodldap_free(sp);
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
			vmodldap_free(sp);
			ldap_free_urldesc(ludpp);
			return res;
		}
	}
	//base認証
	ret = ldap_simple_bind_s(c->ld,basedn,basepw);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_simple_bind_s: %d, (%s)", ret, ldap_err2string(ret));
		vmodldap_free(sp);
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
		vmodldap_free(sp);
	}else if(ldap_count_entries(c->ld, c->searchResult) > 0) {
		c->dn = ldap_get_dn(c->ld, c->searchResult);
		c->dnlen = strlen(c->dn);
		res = (1==1);
	}
	free(filter);
	ldap_free_urldesc(ludpp);
	c->result = (int)res;
	return res;

}

unsigned vmod_require_user(struct sess *sp,const char *val){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	unsigned res = (0==1);
	int ret;
	if(!c) return res;
	if(!c->result) return res;
	if(strncmp(val,c->dn,strlen(val)) == 0) res = (1==1);
	return res;
}

unsigned vmod_compare_user(struct sess *sp,const char *val,const char *attr){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	unsigned res = (0==1);
	int ret;
	if(!c) return res;
	if(!c->result) return res;
	
	struct berval bvalue;
	bvalue.bv_val = c->user;
	bvalue.bv_len = c->userlen;
	ret = ldap_compare_ext_s(c->ld, val, attr,&bvalue, NULL, NULL);
	if(ret == LDAP_COMPARE_TRUE) res = (1==1);
	return res;
}
unsigned vmod_compare_dn(struct sess *sp,const char *val,const char *attr){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	unsigned res = (0==1);
	int ret;
	if(!c) return res;
	if(!c->result) return res;
	
	struct berval bvalue;
	bvalue.bv_val = c->dn;
	bvalue.bv_len = c->dnlen;
	ret = ldap_compare_ext_s(c->ld, val, attr,&bvalue, NULL, NULL);
	if(ret == LDAP_COMPARE_TRUE) res = (1==1);
	return res;
}
unsigned vmod_compare_attribute(struct sess *sp,const char *val,const char *attr){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	unsigned res = (0==1);
	int ret;
	if(!c) return res;
	if(!c->result) return res;
	
	struct berval bvalue;
	bvalue.bv_val = val;
	bvalue.bv_len = strlen(val);
	ret = ldap_compare_ext_s(c->ld, c->dn, attr,&bvalue, NULL, NULL);
	if(ret == LDAP_COMPARE_TRUE) res = (1==1);
	return res;
}


unsigned vmod_bind(struct sess *sp){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	unsigned res = (0==1);
	int ret;
	if(!c) return res;
	if(!c->result) return res;

	ret = ldap_simple_bind_s(c->ld, c->dn, c->pass);
	if(ret == LDAP_SUCCESS) res =(1==1);
	
	return res;
}

void vmod_close(struct sess *sp){
	struct vmod_ldap *c;
	c = vmodldap_get_raw(sp);
	if(!c) return;
	vmodldap_free(sp);
}

unsigned vmod_simple_auth(struct sess *sp,unsigned V3,const char* basedn,const char*basepw,const char*searchdn,const char*user,const char*pass){
	unsigned res;
	vmod_open(sp, V3, basedn, basepw, searchdn, user, pass);
	res = vmod_bind(sp);
	vmod_close(sp);
	return res;
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{

	return (0);
}
