/*
 * Tencent is pleased to support the open source community by making 蓝鲸 available.
 * Copyright (C) 2017-2018 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package blueking defines user login method in blueking system
package ldap

import (
	"configcenter/src/common"
	cc "configcenter/src/common/backbone/configcenter"
	"configcenter/src/common/blog"
	"configcenter/src/common/errors"
	"configcenter/src/common/http/httpclient"
	cli "configcenter/src/common/ldapclient"
	"configcenter/src/common/metadata"
	"configcenter/src/common/util"
	webCommon "configcenter/src/web_server/common"
	"configcenter/src/web_server/middleware/user/plugins/manager"
	"fmt"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func init() {
	plugin := &metadata.LoginPluginInfo{
		Name:       "carizon ldap system",
		Version:    common.LdapLoginPluginVersion,
		HandleFunc: &user{},
	}
	manager.RegisterPlugin(plugin) // ("blueking login system", "self", "")
}

type user struct{}

// LoginUser user login
func (m *user) LoginUser(c *metadata.LoginContext, config map[string]string, isMultiOwner bool) (user *metadata.LoginUserInfo,
	loginSucc bool) {
	rid := util.GetHTTPCCRequestID(c.Context.Request.Header)
	session := sessions.Default(c.Context)

	cookieOwnerID, err := c.Context.Cookie(common.BKHTTPOwnerID)
	if "" == cookieOwnerID || nil != err {
		c.Context.SetCookie(common.BKHTTPOwnerID, common.BKDefaultOwnerID, 0, "/", "", false, false)
		session.Set(common.WEBSessionOwnerUinKey, cookieOwnerID)
	} else if cookieOwnerID != session.Get(common.WEBSessionOwnerUinKey) {
		session.Set(common.WEBSessionOwnerUinKey, cookieOwnerID)
	}
	if err := session.Save(); err != nil {
		blog.Warnf("save session failed, err: %s, rid: %s", err.Error(), rid)
	}

	cookieUser, err := c.Context.Cookie(common.BKUser)
	if "" == cookieUser || nil != err {
		blog.Errorf("login user not found, rid: %s", rid)
		return nil, false
	}

	if c.UserName == "" || c.Password == "" {
		blog.Errorf("login user or password not set, rid: %s", rid)
		return nil, false
	}

	//var resultData loginResult
	httpCli := httpclient.NewHttpClient()
	httpCli.SetTimeOut(30 * time.Second)

	ldapClient := cli.LdapClient()
	_, _, err = ldapClient.Authenticate(c.Context, c.UserName, c.Password)
	if err != nil {
		blog.Errorf("ldap to authenticate failed, error: %v, rid: %s", err, rid)
		return nil, false
	}

	return &metadata.LoginUserInfo{
		UserName: cookieUser,
		ChName:   cookieUser,
		Phone:    "",
		Email:    "carizon",
		Role:     "",
		BkToken:  "",
		OnwerUin: "0",
		IsOwner:  false,
		Language: webCommon.GetLanguageByHTTPRequest(c.Context),
	}, true
}

// GetLoginUrl get login url
func (m *user) GetLoginUrl(c *gin.Context, config map[string]string, input *metadata.LogoutRequestParams) string {
	var loginURL string
	var siteURL string
	var appCode string
	var err error

	if common.LogoutHTTPSchemeHTTPS == input.HTTPScheme {
		loginURL, err = cc.String("webServer.site.bkHttpsLoginUrl")
	} else {
		loginURL, err = cc.String("webServer.site.bkLoginUrl")
	}
	if err != nil {
		loginURL = ""
	}

	if common.LogoutHTTPSchemeHTTPS == input.HTTPScheme {
		siteURL, err = cc.String("webServer.site.httpsDomainUrl")
	} else {
		siteURL, err = cc.String("webServer.site.domainUrl")
	}
	if err != nil {
		siteURL = ""
	}

	appCode, err = cc.String("webServer.site.appCode")
	if err != nil {
		appCode = ""
	}

	loginURL = fmt.Sprintf(loginURL, appCode, fmt.Sprintf("%s%s", siteURL, c.Request.URL.String()))
	return loginURL
}

// GetUserList get user list
func (m *user) GetUserList(c *gin.Context, params map[string]string) ([]*metadata.LoginSystemUserInfo,
	*errors.RawErrorInfo) {
	rid := util.GetHTTPCCRequestID(c.Request.Header)
	username, ok := c.GetQuery("fuzzy_lookups")
	if !ok {
		return make([]*metadata.LoginSystemUserInfo, 0), nil
	}

	// try to use ldap list user
	ldapClient := cli.LdapClient()
	result, err := ldapClient.SearchUserList("", username, "dn", "cn", "uid")
	if err != nil {
		blog.Errorf("get users by ldap client failed, error: %+v, rid: %s", err, rid)
		return nil, &errors.RawErrorInfo{
			ErrCode: common.CCErrCommLdapClientUnknownUserName,
		}
	}
	users := make([]*metadata.LoginSystemUserInfo, 0)
	for _, userInfo := range result {
		user := &metadata.LoginSystemUserInfo{
			CnName: fmt.Sprint(userInfo["cn"]),
			EnName: fmt.Sprint(userInfo["cn"]),
		}
		users = append(users, user)
	}

	return users, nil
}
