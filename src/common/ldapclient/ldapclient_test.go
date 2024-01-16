package ldapclient

import (
	"configcenter/src/web_server/app/options"
	"context"
	"strings"
	"testing"
)

func init() {

	//clamin, _ := cc.StringSlice("uid:username,sn:last_name,givenName:first_name,mail:email")
	clamin := strings.Split("uid:username,sn:last_name,givenName:first_name,mail:email", ",")
	claimAttr := map[string]string{}
	for _, v := range clamin {
		kv := strings.Split(v, ":")
		if len(kv) == 2 {
			claimAttr[kv[0]] = kv[1]
		}
	}

	//clamin, _ := cc.StringSlice("uid:name,sn:family_name,givenName:given_name,mail:email")

	defaultCfg := &options.Ldap{
		Endpoints:  []string{"10.11.148.2:389"},
		BindDN:     "cn=pmt,ou=service_account,dc=carizon,dc=work",
		BaseDN:     "dc=carizon,dc=work",
		BindPass:   "sDDF,\\sda15sdf!sfjlkj",
		TimeOut:    5,
		AttrClaims: claimAttr,
	}

	InitLdapClient(defaultCfg)
}

func TestAuthenticate(t *testing.T) {
	ldapClient.Authenticate(context.TODO(), "zz7lte6", "sDDF,\\sda15sdf!sfjlkj")
}
