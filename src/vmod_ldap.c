#include <stdlib.h>
#include "vcl.h"
#include "vrt.h"
#include "bin/varnishd/cache.h"

#include <syslog.h>
#include <stdio.h>

#include "vcc_if.h"

#include <ldap.h>

#define VMODLDAP_LD "\023X-VMOD-LDAP-PTR-LD:"
#define VMODLDAP_SR "\021X-VMOD-LDAP-PTR-SR:"

void vmod_ldap_free(LDAP*ld, LDAPMessage *searchResult){
	if(ld) ldap_unbind_s(ld);
	if(searchResult) ldap_msgfree(searchResult);
}



unsigned vmod_ldap_pre(struct sess *sp, const char *host, unsigned V3, const char* basedn, const char*basepw, const char*searchdn, const char*user, LDAP **rld, LDAPMessage **rsearchResult){
	AN(host);
	AN(basedn);
	AN(basepw);
	LDAP	*ld = NULL;
	int ret;
	LDAPMessage *searchResult = NULL;
	struct timeval timeOut = { 10, 0 };
	unsigned res = (0==1);
	LDAPURLDesc *ludpp;
	int filterlen = 0;
	char *filter;
	char *dn;
	int version;
	

	
	//接続
	ret = ldap_initialize(&ld, host);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_initialize: %d, (%s)", ret, ldap_err2string(ret));
		vmod_ldap_free(ld,searchResult);
		return res;
	}
	//V3認証
	if(V3){
		version = LDAP_VERSION3;
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
		if(ret != LDAP_SUCCESS){
			syslog(6,"ldap_set_option: %d, (%s)", ret, ldap_err2string(ret));
			vmod_ldap_free(ld,searchResult);
			return res;
		}
	}
	//base認証
	ret = ldap_simple_bind_s(ld,basedn,basepw);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_simple_bind_s: %d, (%s)", ret, ldap_err2string(ret));
		vmod_ldap_free(ld,searchResult);
		return res;
	}
	//URLパース
	ret = ldap_url_parse(searchdn, &ludpp);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_url_parse: %d, (%s)", ret, ldap_err2string(ret));
		vmod_ldap_free(ld,searchResult);
		return;
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
	ret = ldap_search_ext_s(ld, ludpp->lud_dn, ludpp->lud_scope, filter, NULL, 0, NULL, NULL, &timeOut, 0,&searchResult);
	if(ret != LDAP_SUCCESS){
		syslog(6,"ldap_search_ext_s: %d, (%s)", ret, ldap_err2string(ret));
		vmod_ldap_free(ld,searchResult);
		return res;
	}else{
		res = (1==1);
	}
	free(filter);
	ldap_free_urldesc(ludpp);
	*rld = ld;
	*rsearchResult = searchResult;
	return res;

}


unsigned vmod_auth(struct sess *sp,const char *host,unsigned V3,const char* basedn,const char*basepw,const char*searchdn,const char*user,const char*pass){
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
		ret = ldap_simple_bind_s(ld, dn, pass);
		if(ret == LDAP_SUCCESS) res =(1==1);
	}
	
	
	vmod_ldap_free(ld,searchResult);
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
