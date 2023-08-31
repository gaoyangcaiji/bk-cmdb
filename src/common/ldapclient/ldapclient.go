package ldapclient

import (
	"configcenter/src/common"
	"configcenter/src/common/blog"
	"configcenter/src/common/errors"
	"configcenter/src/web_server/app/options"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	ldapClient  LdapClientInterface
	lastInitErr errors.CCErrorCoder
	// ErrInvalidCredentials is an error that means user's password is invalid.
	ErrInvalidCredentials = errors.NewCCError(common.CCErrCommLdapClientBindFailed, "invalid credentials,ldap client bind failed")
	// ErrConnectionTimeout is an errorr that means no one ldap endpoint responds.
	ErrConnectionTimeout = errors.New(common.CCErrCommLdapClientConnectionTimeout, "ldap connection timeout")
	// ErrUnknownUsername means username does not exsit.
	ErrUnknownUsername = errors.New(common.CCErrCommLdapClientUnknownUserName, "ldap username unknown")
)

type LdapClientInterface interface {
	Authenticate(ctx context.Context, username, password string) (bool, map[string]interface{}, error)
	UserSearch(ctx context.Context, username string, attrs []string) (map[string]interface{}, error)
	PassReset(ctx context.Context, username, newPass string) (bool, error)
	PassModify(ctx context.Context, username, oldPass, newPass string) (bool, error)
	SearchUserList(organizationName, username string, attrs ...string) ([]map[string]interface{}, error)
	getLastUIDNumber(cn conn, numberType string) (int, error)
	connect(ctx context.Context, masterNode bool) <-chan conn
	FindBasicUserDetails(cn conn, userName string, attrs []string) (map[string]interface{}, error)
}

// low level client
type conn interface {
	Bind(bindDN, password string) error
	SearchEntries(baseDN, organizationName, userName string, scope int, attrs ...string) ([]map[string]interface{}, error)
	searchEntriesLow(baseDN, query string, attrs []string) ([]map[string]interface{}, error)
	ResetPassword(userIden, newPass string) (bool, error)
	AddEntry(dn string, userattrs map[string][]string) error
	DelEntry(dn string) error
	ModEntityAttr(dn string, attrs map[string][]string) error
	Close() (err error)
}

type Connector interface {
	Connect(ctx context.Context, addr string, timeout int) (conn, error)
}

// Client is a LDAP client (compatible with Active Directory).
type ldapsrv struct {
	Config    *options.Ldap
	connector Connector
}

func LdapClient() LdapClientInterface {
	return ldapClient
}

// InitLdapClient TODO
func InitLdapClient(defaultCfg *options.Ldap) errors.CCErrorCoder {
	ldapSvc, err := newLdap(defaultCfg)
	if err != nil {
		blog.Errorf(" ldap service initialization error. err:%s", err.Error())
		lastInitErr = errors.NewCCError(common.CCErrCommLdapClientInitFailed, "'ldap' initialization failed")
		return lastInitErr
	}
	ldapClient = ldapSvc
	return nil
}

// New creates a new LDAP client.
func newLdap(cnf *options.Ldap) (LdapClientInterface, error) {
	return &ldapsrv{
		Config:    cnf,
		connector: &ldapConnector{BaseDN: cnf.BaseDN, RoleBaseDN: cnf.RoleBaseDN, IsTLS: cnf.IsTLS},
	}, nil
}

// Authenticate authenticates a user with a username and password.
// If no username or password in LDAP it returns false and no error.
func (cli *ldapsrv) Authenticate(ctx context.Context, username, password string) (bool, map[string]interface{}, error) {
	// emailRexPattern is email regular expression.
	//var cancel context.CancelFunc
	ctx, _ = context.WithCancel(ctx)

	cn, ok := <-cli.connect(ctx, false)
	//cancel()
	if !ok {
		return false, nil, ErrConnectionTimeout
	}
	defer cn.Close()

	// Find a user DN by his or her username.
	details, err := cli.FindBasicUserDetails(cn, username, []string{"dn"})
	if err != nil {
		return false, nil, err
	}

	if err := cn.Bind(details["dn"].(string), password); err != nil {
		return false, nil, err
	}

	return true, details, nil
}

// UserSearch return user info.
func (cli *ldapsrv) UserSearch(ctx context.Context, username string, attrs []string) (map[string]interface{}, error) {
	//var cancel context.CancelFunc
	//ctx, cancel = context.WithCancel(ctx)

	cn, ok := <-cli.connect(ctx, false)
	//cancel()
	if !ok {
		return nil, ErrConnectionTimeout
	}
	defer cn.Close()

	// Find a user info username.
	details, err := cli.FindBasicUserDetails(cn, username, attrs)
	if err != nil {
		return nil, err
	}
	return details, nil
}

// PassReset reset user password.
func (cli *ldapsrv) PassReset(ctx context.Context, username, newPass string) (bool, error) {
	// emailRexPattern is email regular expression.
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	cn, ok := <-cli.connect(ctx, true)
	cancel()
	if !ok {
		return false, ErrConnectionTimeout
	}
	defer cn.Close()

	// Find a user DN by his or her username.
	details, err := cli.FindBasicUserDetails(cn, username, []string{"dn"})
	if err != nil {
		return false, err
	}
	userIden := details["dn"].(string)
	return cn.ResetPassword(userIden, newPass)
}

// PassModify modify user password.
func (cli *ldapsrv) PassModify(ctx context.Context, username, oldPass, newPass string) (bool, error) {
	return true, nil
}

// SearchUserList return all users's info from ldap.
func (cli *ldapsrv) SearchUserList(organizationName, username string, attrs ...string) ([]map[string]interface{}, error) {
	// connect to ldap server.
	ctx, cancel := context.WithCancel(context.Background())
	cn, ok := <-cli.connect(ctx, false)
	cancel()
	if !ok {
		return nil, ErrConnectionTimeout
	}
	defer cn.Close()
	if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
		return nil, ErrInvalidCredentials
	}
	entries, err := cn.SearchEntries(cli.Config.BaseDN, organizationName, username, ldap.ScopeWholeSubtree, attrs...)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (cli *ldapsrv) getLastUIDNumber(cn conn, numberType string) (int, error) {
	// get last uid of the latest created user, if no user found, return 50000 instead
	if numberType == "" {
		numberType = "uidNumber"
	}
	args := numberType
	defaultUIDNumber := 50000
	entries, err := cn.searchEntriesLow(cli.Config.BaseDN, "(objectClass=*)", []string{})
	if err != nil { // no such organization found
		blog.Info("error searchEntriesLow", cli.Config.BaseDN, err)
		return 0, nil
	}
	if len(entries) == 0 { // organization found, but no history users
		return defaultUIDNumber, errors.New(common.CCErrCommLdapClientEntryNotFound, "no entry found")
	}
	for _, entry := range entries {
		if v, ok := entry[args]; ok {
			lastUIDNumber, err1 := strconv.Atoi(v.(string))
			if err1 == nil && lastUIDNumber > defaultUIDNumber {
				defaultUIDNumber = lastUIDNumber
			}
		}
	}
	return defaultUIDNumber, nil
}

// connect connect to ldap server and return the first server connect.
// ldap server is master-slave mode, and master server address is at the
// end of Endpoints. If masterNode is true, just connect to master node.
func (cli *ldapsrv) connect(ctx context.Context, masterNode bool) <-chan conn {
	var (
		wg sync.WaitGroup
		ch = make(chan conn)
	)
	//log := rlog.FromContext(ctx).Sugar()
	endpoints := cli.Config.Endpoints
	if masterNode && len(endpoints) >= 1 {
		endpoints = endpoints[len(endpoints)-1:]
	}

	wg.Add(len(endpoints))
	for _, addr := range endpoints {
		go func(addr string) {
			defer wg.Done()
			startTime := time.Now()
			cn, err := cli.connector.Connect(ctx, addr, cli.Config.TimeOut)
			endTime := time.Now()
			timeDiff := endTime.Sub(startTime)
			blog.Info("connect to ldap", "address", addr, "cost ", timeDiff.Milliseconds())
			if err != nil {
				blog.Info("Failed to create a LDAP connection ", err.Error())
				return
			}
			select {
			case <-ctx.Done():
				fmt.Println("ctx.Done()")
				cn.Close()
				blog.Info("a LDAP connection is cancelled", "address", addr)
				return
			case ch <- cn:
			}
		}(addr)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

func (cli *ldapsrv) AddOrganization(cn conn, organizationName string) error {
	// add organization if not exist
	// a example of addou ldif configure
	// dn: ou=testLx,dc=hosso,dc=cc
	// ou: testLx
	// objectClass: top
	// objectClass: organizationalunit
	if cn == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cnnew, ok := <-cli.connect(ctx, false)
		cancel()
		if !ok {
			return ErrConnectionTimeout
		}
		cn = cnnew
		defer cn.Close()
	}
	if cli.Config.BindDN != "" {
		if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
			return ErrInvalidCredentials
		}
	}

	dn := fmt.Sprintf("ou=%s,%s", organizationName, cli.Config.BaseDN)
	userattrs1 := map[string][]string{
		"objectClass": {"top", "organizationalunit"},
		"ou":          {organizationName},
	}

	err1 := cn.AddEntry(dn, userattrs1)
	if err1 != nil {
		return errors.New(common.CCErrCommLdapClientOperate, fmt.Sprintf("ldap operate error,%s", err1.Error()))
	}

	return nil
}

func (cli *ldapsrv) DelOrganization(cn conn, organizationName string) error {
	if cn == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cnnew, ok := <-cli.connect(ctx, false)
		cancel()
		if !ok {
			return ErrConnectionTimeout
		}
		cn = cnnew
		defer cn.Close()
	}
	if cli.Config.BindDN != "" {
		if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
			return ErrInvalidCredentials
		}
	}

	dn := fmt.Sprintf("ou=%s,%s", organizationName, cli.Config.BaseDN)
	err1 := cn.DelEntry(dn)
	if err1 != nil {
		return errors.New(common.CCErrCommLdapClientOperate, fmt.Sprintf("ldap operate error,%s", err1.Error()))
	}

	return nil
}

func (cli *ldapsrv) FindOrganization(cn conn, organizationName string) error {
	if cn == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cnnew, ok := <-cli.connect(ctx, false)
		cancel()
		if !ok {
			return ErrConnectionTimeout
		}
		cn = cnnew
		defer cn.Close()
	}
	if cli.Config.BindDN != "" {
		if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
			return ErrInvalidCredentials
		}
	}
	query := fmt.Sprintf("(&(objectClass=top)(ou=%s))", organizationName)
	// fmt.Println(query, dn, "====")
	entries, err := cn.searchEntriesLow(cli.Config.BaseDN, query, []string{})
	blog.InfoJSON("entries:%s", entries)
	if err != nil {
		return errors.New(common.CCErrCommLdapClientOperate, fmt.Sprintf("ldap operate error,%s", err.Error()))
	}
	return nil
}

// AddUser is a main function to add user to ldap
func (cli *ldapsrv) AddUser(userName, password, organizationName, title, email string) error {
	// add user information to the determined organizationunit
	// in this situation: organizationunit is defined  to be organization
	// a test configure of adduser ldif configure
	// dn: cn=testname1.zhang,ou=testLx,dc=hosso,dc=cc
	// changetype: add
	// objectclass: person
	// objectClass: inetOrgPerson
	// objectClass: posixAccount
	// cn: testname1.zhang
	// ou: regular-engineer
	// uid: testname1.zhang
	// uidNumber: 1113334
	// gidNumber: 1113334
	// title: labelengineer (title discarded)
	// mail: testname1.zhang@horizon.ai
	// homeDirectory: /home/users/testname1.zhang
	// userPassword:: xxxxxxxxx

	// as gpfs need to use ldap on linux, we must add more info
	// dn: cn=xxx,ou=Group,dc=hosso,dc=cc
	// objectClass: top
	// objectClass: posixGroup
	// gidNumber: 1113334
	// cn: xxx

	ctx, cancel := context.WithCancel(context.Background())
	cn, ok := <-cli.connect(ctx, false)
	cancel()
	if !ok {
		return ErrConnectionTimeout
	}
	defer cn.Close()

	if cli.Config.BindDN != "" {
		if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
			return ErrInvalidCredentials
		}
	}

	// get last entry uidnumber of the whole users, uidnumber and gidnumber should be unique in users
	lastUIDNumber, err := cli.getLastUIDNumber(cn, "")
	if err != nil {
		return err
	}
	// now uidnumber
	nowUIDNumber := lastUIDNumber + 1
	nowGIDNumber := nowUIDNumber

	// add account
	dn1 := fmt.Sprintf("cn=%s,ou=%s,%s", userName, organizationName, cli.Config.BaseDN)
	userattrs1 := map[string][]string{
		"objectClass":   {"person", "inetOrgPerson", "posixAccount"},
		"cn":            {userName},
		"sn":            {userName},
		"ou":            {organizationName},
		"uid":           {userName},
		"uidNumber":     {fmt.Sprintf("%d", nowUIDNumber)},
		"gidNumber":     {fmt.Sprintf("%d", nowGIDNumber)},
		"loginShell":    {"/bin/bash"},
		"mail":          {email},
		"homeDirectory": {fmt.Sprintf("/home/users/%s", userName)},
		"userPassword":  {password},
	}

	err1 := cn.AddEntry(dn1, userattrs1)
	if err1 != nil {
		return errors.New(common.CCErrCommLdapClientOperate, fmt.Sprintf("ldap operate error,%s", err1.Error()))
	}

	// add Group info
	dn2 := fmt.Sprintf("cn=%s,ou=Group,dc=hosso,dc=cc", userName)
	userattrs2 := map[string][]string{
		"objectClass": {"top", "posixGroup"},
		"cn":          {userName},
		"gidNumber":   {fmt.Sprintf("%d", nowGIDNumber)},
	}

	err2 := cn.AddEntry(dn2, userattrs2)
	if err2 != nil {
		return errors.New(common.CCErrCommLdapClientOperate, fmt.Sprintf("ldap operate error,%s", err1.Error()))
	}

	return nil
}

// findBasicUserDetails finds user's LDAP attributes that were specified. It returns nil if no such user.
func (cli *ldapsrv) FindBasicUserDetails(cn conn, userName string, attrs []string) (map[string]interface{}, error) {
	if cli.Config.BindDN != "" {
		// We need to login to a LDAP server with a service account for retrieving user data.
		if err := cn.Bind(cli.Config.BindDN, cli.Config.BindPass); err != nil {
			return nil, ErrInvalidCredentials
		}
	}

	entries, err := cn.SearchEntries(cli.Config.BaseDN, "", userName, ldap.ScopeWholeSubtree, attrs...)
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		// We didn't find the user.
		return nil, ErrUnknownUsername
	}

	var (
		entry   = entries[0]
		details = make(map[string]interface{})
	)
	for _, attr := range attrs {
		if v, ok := entry[attr]; ok {
			details[attr] = v
		}
	}
	return details, nil
}

type ldapConnector struct {
	BaseDN     string
	RoleBaseDN string
	IsTLS      bool
}

func (c *ldapConnector) Connect(ctx context.Context, addr string, timeout int) (conn, error) {
	d := net.Dialer{Timeout: time.Second * time.Duration(timeout)}
	tcpcn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if c.IsTLS {
		tlscn, err := tls.DialWithDialer(&d, "tcp", addr, nil)
		if err != nil {
			return nil, err
		}
		tcpcn = tlscn
	}

	ldapcn := ldap.NewConn(tcpcn, c.IsTLS)

	ldapcn.Start()
	return &ldapConn{Conn: ldapcn, BaseDN: c.BaseDN, RoleBaseDN: c.RoleBaseDN}, nil
}

type ldapConn struct {
	*ldap.Conn
	BaseDN     string
	RoleBaseDN string
}

func (c *ldapConn) Bind(bindDN, password string) error {
	err := c.Conn.Bind(bindDN, password)
	if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return ErrInvalidCredentials
	}
	return err
}

func (c *ldapConn) SearchEntries(baseDN, organizationName, userName string, scope int, attrs ...string) ([]map[string]interface{}, error) {
	// user and ou can be * means all the person dataset, can be "" means not only person dataset
	//  scope can be ldap.ScopeBaseObject 0, and 	ldap.ScopeSingleLevel 1 and 	ldap.ScopeWholeSubtree 2
	var query string

	if userName == "" {
		query = "(objectClass=*)"
	} else { // user can be *
		query = fmt.Sprintf(
			"(&(objectClass=inetOrgPerson)(uid=%[1]s))", userName)
	}

	if organizationName != "" {
		baseDN = fmt.Sprintf("ou=%s,%s", organizationName, baseDN)
	}
	req := ldap.NewSearchRequest(baseDN, scope, ldap.NeverDerefAliases, 0, 0, false, query, attrs, nil)
	res, err := c.Search(req)

	if err != nil {
		return nil, err
	}

	var entries []map[string]interface{}
	for _, v := range res.Entries {
		entry := map[string]interface{}{"dn": v.DN}
		for _, attr := range v.Attributes {
			// We need the first value only for the named attribute.
			entry[attr.Name] = attr.Values[0]
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// searchEntries executes a LDAP query, and returns a result as entries where each entry is mapping of LDAP attributes.
func (c *ldapConn) searchEntriesLow(baseDN, query string, attrs []string) ([]map[string]interface{}, error) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, query, attrs, nil)
	res, err := c.Search(req)
	if err != nil {
		return nil, err
	}
	var entries []map[string]interface{}
	for _, v := range res.Entries {
		entry := map[string]interface{}{"dn": v.DN}
		for _, attr := range v.Attributes {
			// We need the first value only for the named attribute.
			entry[attr.Name] = attr.Values[0]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (c *ldapConn) AddEntry(dn string, attrs map[string][]string) error {
	addReq := ldap.NewAddRequest(dn, nil)

	for k, v := range attrs {
		addReq.Attribute(k, []string(v))
	}
	if err := c.Add(addReq); err != nil {
		return err
	}
	return nil
}

func (c *ldapConn) DelEntry(dn string) error {
	delReq := ldap.NewDelRequest(dn, nil)

	if err := c.Del(delReq); err != nil {
		return err
	}
	return nil
}

func (c *ldapConn) ModEntityAttr(dn string, attrs map[string][]string) error {
	modReq := ldap.NewModifyRequest(dn, nil)
	for k, v := range attrs {
		modReq.Replace(k, v)
	}
	if err := c.Modify(modReq); err != nil {
		return err
	}
	return nil
}

func (c *ldapConn) ResetPassword(userIden, newPass string) (bool, error) {
	return c.updatePassword(userIden, "", newPass)
}

func (c *ldapConn) updatePassword(userIden, oldPass, newPass string) (bool, error) {
	req := ldap.NewPasswordModifyRequest(userIden, oldPass, newPass)
	if _, err := c.PasswordModify(req); err != nil {
		return false, err
	}
	return true, nil
}
