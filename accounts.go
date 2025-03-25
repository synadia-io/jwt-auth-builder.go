package authb

import (
	"errors"
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func NewAccountFromJWT(token string) (Account, error) {
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return nil, err
	}

	return &AccountData{
		Claim: ac,
		BaseData: BaseData{
			Loaded:     ac.IssuedAt,
			EntityName: ac.Name,
			Token:      token,
			readOnly:   true,
		},
	}, nil
}

func (a *AccountData) Name() string {
	return a.EntityName
}

func (a *AccountData) issue(key *Key) error {
	var err error
	// self-sign
	if key == nil {
		key = a.Key
	}
	token, err := a.Operator.SigningService.Sign(a.Claim, key)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return err
	}
	a.Claim = claim
	a.Token = token
	a.Modified = true
	return nil
}

func (a *AccountData) ScopedSigningKeys() ScopedKeys {
	return &accountSigningKeys{data: a}
}

func (a *AccountData) Subject() string {
	return a.Claim.Subject
}

func (a *AccountData) Issuer() string {
	return a.Claim.Issuer
}

func (a *AccountData) SetIssuer(issuer string) error {
	if issuer != "" {
		_, err := KeyFrom(issuer, nkeys.PrefixByteOperator)
		if err != nil {
			return err
		}
	}

	found := issuer == "" || a.Operator.Key.Public == issuer
	if !found {
		for i := 0; i < len(a.Operator.OperatorSigningKeys); i++ {
			if a.Operator.OperatorSigningKeys[i].Public == issuer {
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("issuer is not a registered operator key")
	}
	a.Claim.Issuer = issuer
	return a.update()
}

func (a *AccountData) update() error {
	if a.BaseData.readOnly {
		return fmt.Errorf("account is read-only")
	}

	var vr jwt.ValidationResults
	a.Claim.Validate(&vr)
	if vr.IsBlocking(true) {
		return vr.Errors()[0]
	}
	if a.Claim.Issuer == "" {
		a.Claim.Issuer = a.Operator.Key.Public
	}

	if a.Claim.Issuer == a.Operator.Key.Public {
		return a.issue(a.Operator.Key)
	}
	for i := 0; i < len(a.Operator.OperatorSigningKeys); i++ {
		if a.Claim.Issuer == a.Operator.OperatorSigningKeys[i].Public {
			return a.issue(a.Operator.OperatorSigningKeys[i])
		}
	}
	return fmt.Errorf("operator signing key %q is was not found", a.Claim.Issuer)
}

func (a *AccountData) getRevocations() jwt.RevocationList {
	if a.Claim.Revocations == nil {
		a.Claim.Revocations = jwt.RevocationList{}
	}
	return a.Claim.Revocations
}

func (a *AccountData) getRevocationPrefix() nkeys.PrefixByte {
	return nkeys.PrefixByteUser
}

func (a *AccountData) Revocations() Revocations {
	return &revocations{data: a}
}

func (a *AccountData) GetTracingContext() *TracingContext {
	if a.Claim.Trace == nil {
		return nil
	}
	return &TracingContext{
		Destination: string(a.Claim.Trace.Destination),
		Sampling:    a.Claim.Trace.Sampling,
	}
}

func (a *AccountData) SetTracingContext(opts *TracingContext) error {
	if opts == nil || *opts == (TracingContext{}) {
		a.Claim.Trace = nil
	} else {
		a.Claim.Trace = opts.toTrace()
	}
	return a.update()
}

func (a *AccountData) SetExpiry(exp int64) error {
	a.Claim.Expires = exp
	return a.update()
}

func (a *AccountData) Expiry() int64 {
	return a.Claim.Expires
}

func (a *AccountData) Users() Users {
	return &UsersImpl{accountData: a}
}

func (a *AccountData) getKey(key string) (*Key, bool, error) {
	if key == a.Key.Public {
		return a.Key, false, nil
	}
	for _, k := range a.AccountSigningKeys {
		if k.Public == key {
			return k, true, nil
		}
	}
	return nil, false, errors.New("key not found")
}

func (a *AccountData) Limits() AccountLimits {
	return &accountLimits{data: a}
}

func (a *AccountData) SetExternalAuthorizationUser(users []interface{}, accounts []interface{}, encryption string) error {
	if users == nil {
		// disable
		a.Claim.Authorization.AuthUsers = nil
		a.Claim.Authorization.AllowedAccounts = nil
		a.Claim.Authorization.XKey = ""
	} else {
		var ukeys []string
		for _, u := range users {
			switch v := u.(type) {
			case string:
				k, err := KeyFrom(v, nkeys.PrefixByteUser)
				if err != nil {
					return err
				}
				ukeys = append(ukeys, k.Public)
			case User:
				ukeys = append(ukeys, v.Subject())
			default:
				return errors.New("not a string or user")
			}
		}
		a.Claim.Authorization.AuthUsers = ukeys

		var akeys []string
		for _, a := range accounts {
			switch v := a.(type) {
			case string:
				if v != "*" {
					var err error
					k, err := KeyFrom(v, nkeys.PrefixByteAccount)
					if err != nil {
						return err
					}
					v = k.Public
				}
				akeys = append(akeys, v)
			case Account:
				akeys = append(akeys, v.Subject())
			default:
				return errors.New("not a string or account")
			}
		}
		a.Claim.Authorization.AllowedAccounts = akeys

		if encryption != "" {
			key, err := KeyFrom(encryption, nkeys.PrefixByteCurve)
			if err != nil {
				return err
			}
			a.Claim.Authorization.XKey = key.Public
		} else {
			a.Claim.Authorization.XKey = ""
		}
	}
	return a.update()
}

func (a *AccountData) ExternalAuthorization() ([]string, []string, string) {
	config := a.Claim.Authorization
	return config.AuthUsers, config.AllowedAccounts, config.XKey
}

func (a *AccountData) IssueAuthorizationResponse(claim *jwt.AuthorizationResponseClaims, key string) (string, error) {
	return a.IssueClaim(claim, key)
}

func (a *AccountData) IssueClaim(claim jwt.Claims, key string) (string, error) {
	if key == "" {
		key = a.Key.Public
	}
	k, _, err := a.getKey(key)
	if err != nil {
		return "", err
	}
	_, scoped := a.ScopedSigningKeys().Contains(key)

	switch c := claim.(type) {
	case *jwt.OperatorClaims:
		return "", errors.New("accounts cannot issue operator claims")
	case *jwt.AccountClaims:
		if c.Subject != k.Public {
			return "", errors.New("accounts can only self-sign")
		}
	case *jwt.UserClaims:
		if scoped {
			// cannot have any sort of permission
			c.UserPermissionLimits = jwt.UserPermissionLimits{}
		}
		c.IssuerAccount = a.Key.Public
	case *jwt.AuthorizationResponseClaims:
		if scoped {
			return "", fmt.Errorf("scoped keys can only issue user claims")
		}
		if key != a.Key.Public {
			c.IssuerAccount = a.Key.Public
		}
	case *jwt.AuthorizationRequestClaims:
		return "", errors.New("accounts cannot issue authorization request claims")
	case *jwt.GenericClaims:
		if scoped {
			return "", fmt.Errorf("scoped keys can only issue user claims")
		}
	}
	return a.Operator.SigningService.Sign(claim, k)
}

type exports struct {
	*AccountData
}

func (a *AccountData) Exports() Exports {
	return &exports{a}
}

func (e *exports) Services() ServiceExports {
	return &serviceExports{e.AccountData}
}

func (e *exports) Streams() StreamExports {
	return &streamExports{e.AccountData}
}

type imports struct {
	*AccountData
}

func (a *AccountData) Imports() Imports {
	return &imports{a}
}

func (i *imports) Services() ServiceImports {
	return &serviceImports{i.AccountData}
}

func (i *imports) Streams() StreamImports {
	return &streamImports{i.AccountData}
}

func (a *AccountData) getServiceExports() []ServiceExport {
	var buf []ServiceExport
	for _, e := range a.Claim.Exports {
		if e.IsService() {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) deleteExport(subject string, service bool) (bool, error) {
	if subject == "" {
		return false, errors.New("invalid subject")
	}
	if service {
		for idx, e := range a.Claim.Exports {
			if e.IsService() && e.Subject == jwt.Subject(subject) {
				a.Claim.Exports = append(a.Claim.Exports[:idx], a.Claim.Exports[idx+1:]...)
				return true, a.update()
			}
		}
	} else {
		for idx, e := range a.Claim.Exports {
			if e.IsStream() && e.Subject == jwt.Subject(subject) {
				a.Claim.Exports = append(a.Claim.Exports[:idx], a.Claim.Exports[idx+1:]...)
				return true, a.update()
			}
		}
	}

	return false, nil
}

func (a *AccountData) getServiceExport(subject string) *ServiceExportImpl {
	for _, e := range a.Claim.Exports {
		if e.IsService() && string(e.Subject) == subject {
			se := &ServiceExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) getStreamExports() []StreamExport {
	var buf []StreamExport
	for _, e := range a.Claim.Exports {
		if e.IsStream() {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) getStreamExport(subject string) *StreamExportImpl {
	for _, e := range a.Claim.Exports {
		if e.IsStream() && string(e.Subject) == subject {
			se := &StreamExportImpl{}
			se.data = a
			se.export = e
			return se
		}
	}
	return nil
}

func (a *AccountData) addExport(export *jwt.Export) error {
	if export == nil {
		return errors.New("invalid export")
	}
	if export.Name == "" {
		return errors.New("export name is not specified")
	}
	if export.Type == jwt.Unknown {
		return errors.New("export type is not specified")
	}
	if export.Subject == "" {
		return errors.New("export subject is not specified")
	}
	a.Claim.Exports = append(a.Claim.Exports, export)
	return nil
}

func (a *AccountData) addImport(in *jwt.Import) error {
	if in == nil {
		return errors.New("invalid export")
	}
	if in.Name == "" {
		return errors.New("import name is not specified")
	}
	if in.Type == jwt.Unknown {
		return errors.New("import type is not specified")
	}
	if in.Subject == "" {
		return errors.New("export subject is not specified")
	}
	ak, err := KeyFrom(in.Account, nkeys.PrefixByteAccount)
	if err != nil {
		return err
	}
	in.Account = ak.Public
	a.Claim.Imports = append(a.Claim.Imports, in)
	return nil
}

func (a *AccountData) newExport(name string, subject string, kind jwt.ExportType) error {
	export := &jwt.Export{
		Name:    name,
		Subject: jwt.Subject(subject),
		Type:    kind,
	}
	return a.addExport(export)
}

func (a *AccountData) newImport(name string, account string, subject string, kind jwt.ExportType) error {
	k, err := KeyFrom(account, nkeys.PrefixByteAccount)
	if err != nil {
		return err
	}
	ii := &jwt.Import{
		Name:    name,
		Subject: jwt.Subject(subject),
		Account: k.Public,
		Type:    kind,
	}
	return a.addImport(ii)
}

func (a *AccountData) getServiceImports() []ServiceImport {
	var buf []ServiceImport
	for _, e := range a.Claim.Imports {
		if e.IsService() {
			se := &ServiceImportImpl{}
			se.data = a
			se.in = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) getStreamImports() []StreamImport {
	var buf []StreamImport
	for _, e := range a.Claim.Imports {
		if e.IsStream() {
			se := &StreamImportImpl{}
			se.data = a
			se.in = e
			buf = append(buf, se)
		}
	}
	return buf
}

func (a *AccountData) getServiceImport(subject string) *ServiceImportImpl {
	for _, e := range a.Claim.Imports {
		if e.IsService() && string(e.Subject) == subject {
			se := &ServiceImportImpl{}
			se.data = a
			se.in = e
			return se
		}
	}
	return nil
}

func (a *AccountData) getStreamImport(subject string) *StreamImportImpl {
	for _, e := range a.Claim.Imports {
		if e.IsStream() && string(e.Subject) == subject {
			se := &StreamImportImpl{}
			se.data = a
			se.in = e
			return se
		}
	}
	return nil
}

func (a *AccountData) deleteImport(subject string, service bool) (bool, error) {
	if subject == "" {
		return false, errors.New("invalid subject")
	}
	if service {
		for idx, e := range a.Claim.Imports {
			if e.IsService() && e.Subject == jwt.Subject(subject) {
				a.Claim.Imports = append(a.Claim.Imports[:idx], a.Claim.Imports[idx+1:]...)
				return true, a.update()
			}
		}
	} else {
		for idx, e := range a.Claim.Imports {
			if e.IsStream() && e.Subject == jwt.Subject(subject) {
				a.Claim.Imports = append(a.Claim.Imports[:idx], a.Claim.Imports[idx+1:]...)
				return true, a.update()
			}
		}
	}

	return false, nil
}

func (a *AccountData) Tags() Tags {
	return &AccountTags{
		a: a,
	}
}

type AccountTags struct {
	a *AccountData
}

func (at *AccountTags) Add(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	at.a.Claim.Tags.Add(tag...)
	return at.a.update()
}

func (at *AccountTags) Remove(tag string) (bool, error) {
	ok := at.a.Claim.Tags.Contains(tag)
	if ok {
		at.a.Claim.Tags.Remove(tag)
		err := at.a.update()
		return ok, err
	}
	return false, nil
}

func (at *AccountTags) Contains(tag string) bool {
	return at.a.Claim.Tags.Contains(tag)
}

func (at *AccountTags) Set(tag ...string) error {
	if err := NotEmpty(tag...); err != nil {
		return err
	}
	at.a.Claim.Tags = tag
	return at.a.update()
}

func (at *AccountTags) All() ([]string, error) {
	return at.a.Claim.Tags, nil
}

func (a *AccountData) SetClusterTraffic(traffic string) error {
	ct := jwt.ClusterTraffic(traffic)
	if err := ct.Valid(); err != nil {
		return err
	}
	a.Claim.ClusterTraffic = ct
	return a.update()
}

func (a *AccountData) ClusterTraffic() string {
	return string(a.Claim.ClusterTraffic)
}

func (a *AccountData) SubjectMappings() SubjectMappings {
	return &SubjectMappingsImpl{a}
}

type SubjectMappingsImpl struct {
	data *AccountData
}

func (m *SubjectMappingsImpl) Get(subject string) Mappings {
	if m.data.Claim.Mappings == nil {
		return nil
	}
	wm := m.data.Claim.Mappings[jwt.Subject(subject)]
	if wm == nil {
		return nil
	}
	var mm Mappings
	for _, e := range wm {
		var me Mapping
		me.Subject = string(e.Subject)
		me.Weight = e.Weight
		me.Cluster = e.Cluster
		mm = append(mm, me)
	}
	return mm
}

func (m *SubjectMappingsImpl) Set(subject string, me ...Mapping) error {
	var wm []jwt.WeightedMapping
	for _, e := range me {
		var w jwt.WeightedMapping
		w.Subject = jwt.Subject(e.Subject)
		w.Weight = e.Weight
		w.Cluster = e.Cluster
		wm = append(wm, w)
	}

	// FIXME: validation issues here need to be addressed by possibly
	//  reverting the changes and reloading from the JWT...
	mappings := jwt.Mapping(make(map[jwt.Subject][]jwt.WeightedMapping))
	mappings[jwt.Subject(subject)] = wm
	var vr jwt.ValidationResults
	mappings.Validate(&vr)
	if vr.IsBlocking(true) {
		return vr.Errors()[0]
	}

	if m.data.Claim.Mappings == nil {
		m.data.Claim.Mappings = make(map[jwt.Subject][]jwt.WeightedMapping)
	}
	m.data.Claim.AddMapping(jwt.Subject(subject), wm...)
	return m.data.update()
}

func (m *SubjectMappingsImpl) Delete(subject string) error {
	if m.data.Claim.Mappings != nil {
		delete(m.data.Claim.Mappings, jwt.Subject(subject))
		return m.data.update()
	}
	return nil
}

func (m *SubjectMappingsImpl) List() []string {
	var buf []string
	for k := range m.data.Claim.Mappings {
		buf = append(buf, string(k))
	}
	return buf
}
