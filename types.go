package authb

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/jwt/v2"
)

var ErrNotFound = errors.New("not found")

// Auth is the interface for managing the auth store. Auth is created
// using the NewAuth function
type Auth interface {
	// Commit persists the changes made to operators, accounts, users, etc.
	Commit() error
	// Reload reloads the store from its persisted state
	Reload() error
	// Operators returns an interface for managing operators
	Operators() Operators
}

// AuthProvider is the interface that wraps the basic Load and
// Store methods to read/store data into a store. The provider
// and Auth APIs communicate using the OperatorData, AccountData,
// and UserData structures.
type AuthProvider interface {
	Load() ([]*OperatorData, error)
	Store(operators []*OperatorData) error
}

// BaseData is shared across all entities
type BaseData struct {
	// Loaded matches the issue time of a loaded JWT (UTC in seconds). When
	// the entity is new, it should be 0. The AuthProvider
	// stores claims that have been modified and have
	// an issue time greater than this value or have been Modified. On Store(),
	// it should be set to the tokens issue time.
	Loaded int64 `json:"-"`
	// Modified is true if the entity has been modified since it was loaded
	Modified bool `json:"-"`
	// EntityName is the name for the entity - in some cases NSC
	// will display simple name which differs from the actual name
	// of the entity stored in the JWT.
	EntityName string `json:"name"`
	// Key is the main identity key for the entity.
	Key *Key `json:"key"`
	// Token is the JWT for the entity, always kept up-to-date
	// by the APIs
	Token string `json:"token"`

	readOnly bool
}

type OperatorData struct {
	BaseData
	// OperatorSigningKeys is the list of all current signing keys for
	// the operator. All keys should be reachable by the APIs.
	OperatorSigningKeys []*Key `json:"signingKeys,omitempty"`
	// Claim is the currently decoded version of the JWT. Always up-to-date by
	// the APIs.
	Claim *jwt.OperatorClaims
	// AccountDatas The list of all Accounts for the operator
	AccountDatas []*AccountData `json:"accounts"`
	// DeletedAccounts is a list of all accounts that were deleted using
	// the API. On calling Commit() the AuthProvider will remove them
	// and set this to nil.
	DeletedAccounts []*AccountData `json:"-"`
	// AddedKeys is a list of added keys related to the operator entity tree
	AddedKeys []*Key `json:"-"`
	// List of deleted keys related to the operator entity tree
	DeletedKeys []string `json:"-"`

	SigningService IssuingService `json:"-"`
}

func (o *OperatorData) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BaseData
		OperatorSigningKeys []*Key         `json:"signingKeys"`
		Accounts            []*AccountData `json:"accounts"`
	}{
		BaseData:            o.BaseData,
		OperatorSigningKeys: o.OperatorSigningKeys,
		Accounts:            o.AccountDatas,
	})
}

func (o *OperatorData) UnmarshalJSON(data []byte) error {
	var v struct {
		BaseData
		OperatorSigningKeys []*Key         `json:"signingKeys"`
		Accounts            []*AccountData `json:"accounts"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.BaseData = v.BaseData
	o.OperatorSigningKeys = v.OperatorSigningKeys
	o.AccountDatas = v.Accounts
	if len(o.OperatorSigningKeys) > 0 {
		o.AddedKeys = append(o.AddedKeys, o.OperatorSigningKeys...)
	}
	for _, ad := range o.AccountDatas {
		ad.Operator = o
		o.AddedKeys = append(o.AddedKeys, ad.Key)
		if len(ad.AccountSigningKeys) > 0 {
			o.AddedKeys = append(o.AddedKeys, ad.AccountSigningKeys...)
		}
		for _, ud := range ad.UserDatas {
			o.AddedKeys = append(o.AddedKeys, ud.Key)
		}
	}
	oc, err := jwt.DecodeOperatorClaims(o.Token)
	if err != nil {
		return err
	}
	o.Claim = oc
	o.Modified = true
	return nil
}

type AccountData struct {
	BaseData
	// Operator the operator that manages the account
	Operator *OperatorData
	// AccountSigningKeys is the list of all current signing keys for
	// the account. All keys should be reachable by the API
	AccountSigningKeys []*Key `json:"signingKeys,omitempty"`
	// Claim is the currently decoded version of the JWT. Always up-to-date by
	// the APIs
	Claim *jwt.AccountClaims
	// UserData is the list of account users
	UserDatas []*UserData `json:"users"`
	// DeletedUsers is a list of users that will be deleted on the next commit
	DeletedUsers []*UserData
}

func (a *AccountData) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BaseData
		AccountsSigningKeys []*Key      `json:"signingKeys"`
		Users               []*UserData `json:"users"`
	}{
		BaseData:            a.BaseData,
		AccountsSigningKeys: a.AccountSigningKeys,
		Users:               a.UserDatas,
	})
}

func (a *AccountData) UnmarshalJSON(data []byte) error {
	var v struct {
		BaseData
		AccountsSigningKeys []*Key      `json:"signingKeys"`
		Users               []*UserData `json:"users"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	a.BaseData = v.BaseData
	a.Modified = true
	a.AccountSigningKeys = v.AccountsSigningKeys
	a.UserDatas = v.Users
	for _, ud := range a.UserDatas {
		ud.AccountData = a
	}
	ac, err := jwt.DecodeAccountClaims(a.Token)
	if err != nil {
		return err
	}
	a.Claim = ac
	return nil
}

type UserData struct {
	BaseData
	AccountData *AccountData
	RejectEdits bool
	Claim       *jwt.UserClaims
	Ephemeral   bool
}

func (u *UserData) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BaseData
	}{
		BaseData: u.BaseData,
	})
}

func (u *UserData) UnmarshalJSON(data []byte) error {
	var v struct {
		BaseData
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	u.BaseData = v.BaseData
	uc, err := jwt.DecodeUserClaims(u.Token)
	if err != nil {
		return err
	}
	u.Claim = uc
	u.Modified = true
	return nil
}

// Operators is an interface for managing operators
type Operators interface {
	// List returns a list of Operator
	List() []Operator
	// Add creates a new Operator with the specified name
	Add(name string) (Operator, error)
	// Get returns an Operator by name or matching the specified ID
	Get(name string) (Operator, error)
	// Delete an Operator by name or matching the specified ID
	Delete(name string) error
	// Import an Operator from JWT bytes and keys
	Import(jwt []byte, keys []string) (Operator, error)
}

type Tags interface {
	Add(tag ...string) error
	Remove(tag string) (bool, error)
	Contains(tag string) bool
	Set(tag ...string) error
	All() ([]string, error)
}

// Operator is an interface for editing the operator
type Operator interface {
	// Name returns the name of the operator
	Name() string
	// Subject returns the identity of the operator
	Subject() string
	// Accounts returns an interface for managing accounts
	Accounts() Accounts
	// SigningKeys returns an interface for managing signing keys
	SigningKeys() Keys
	// SetAccountServerURL sets the account server URL
	SetAccountServerURL(url string) error
	// AccountServerURL returns the account server URL
	AccountServerURL() string
	// SetOperatorServiceURL sets the operator service URLs
	SetOperatorServiceURL(url ...string) error
	// OperatorServiceURLs returns the operator service URLs
	OperatorServiceURLs() []string
	// SystemAccount returns the system account. If the system account is
	// not found or not set, the bool argument is set to false
	SystemAccount() (Account, error)
	// SetSystemAccount sets the system account
	SetSystemAccount(account Account) error
	// MemResolver generates a mem resolver server configuration
	MemResolver() ([]byte, error)
	// SetExpiry sets the expiry for the operator in Unix Time Seconds.
	// 0 never expires.
	SetExpiry(exp int64) error
	// Expiry returns the expiry for the operator in Unix Time Seconds.
	// 0 never expires
	Expiry() int64
	// JWT returns the encoded token
	JWT() string
	// Tags returns an object that you can use to manage tags for the operator
	Tags() Tags
	// IssueClaim issues the specified jwt.Claim using the specified operator key
	IssueClaim(claim jwt.Claims, key string) (string, error)
}

// Accounts is an interface for managing accounts
type Accounts interface {
	// Add creates a new Account with the specified name
	Add(name string) (Account, error)
	// Delete an Account by matching its name or subject
	Delete(name string) error
	// Get returns an Account by matching its name or subject
	Get(name string) (Account, error)
	// List returns a list of Account
	List() []Account
}

type TracingContext struct {
	Destination string
	Sampling    int
}

func (t *TracingContext) toTrace() *jwt.MsgTrace {
	return &jwt.MsgTrace{
		Destination: jwt.Subject(t.Destination),
		Sampling:    t.Sampling,
	}
}

// Account is an interface for editing an account
type Account interface {
	// Name returns the name of the account
	Name() string
	// Subject returns the identity of the account
	Subject() string
	// Issuer returns the identity of the account issuer
	Issuer() string
	// Users returns an interface for managing users in the account
	Users() Users
	// ScopedSigningKeys returns an interface for managing signing keys
	ScopedSigningKeys() ScopedKeys
	// Imports returns an interface for managing imports
	Imports() Imports
	// Exports returns an interface for managing exports
	Exports() Exports
	// Limits returns an interface for managing account limits
	Limits() AccountLimits
	// SetExpiry sets the expiry for the account in Unix Time Seconds.
	// 0 never expires.
	SetExpiry(exp int64) error
	// Expiry returns the expiry for the account in Unix Time Seconds.
	// 0 never expires
	Expiry() int64
	// JWT returns the encoded token
	JWT() string
	// Revocations manage user revocations
	Revocations() Revocations
	// GetTracingContext returns the TracingContext or nil if not set
	GetTracingContext() *TracingContext
	// SetTracingContext sets the TracingContext - if null the tracing context is removed
	SetTracingContext(opts *TracingContext) error
	// Tags returns an object that you can use to manage tags for the account
	Tags() Tags

	// SetExternalAuthorizationUser updates external authorization by associating users public keys, account public keys, and an encryption key.
	// ExternalAuthorization requires at the very list one user
	SetExternalAuthorizationUser(users []User, accounts []Account, encryption string) error

	// ExternalAuthorization retrieves a list of authorized users, associated accounts, and encryption key.
	// if the users value is nil, ExternalAuthorization is not enabled
	ExternalAuthorization() ([]string, []string, string)

	// IssueAuthorizationResponse generates a signed JWT token for an AuthorizationResponseClaims using the specified key.
	IssueAuthorizationResponse(claim *jwt.AuthorizationResponseClaims, key string) (string, error)
	// IssueClaim issues the specified jwt.Claim using the specified account key
	IssueClaim(claim jwt.Claims, key string) (string, error)
}

// Users is an interface for managing users
type Users interface {
	// Add creates a new User with the specified name and signed using
	// the specified signer key. Note that you simply specify the public key
	// you want to use for signing, and the key must be one of the account's
	// signing keys. If the key is associated with a scope, the user will
	// be a scoped user.
	Add(name string, signer string) (User, error)
	// AddWithIdentity creates user with the specified name and signed using
	// the specified signer key.
	// If the provided ID is only a public key the user will be ephemeral and will not stored,
	// other operations, as cred generation will fail
	AddWithIdentity(name string, signer string, id string) (User, error)
	// ImportEphemeral imports an ephemeral user from a claim
	ImportEphemeral(c *jwt.UserClaims, key string) (User, error)
	// Delete the user by matching its name or subject
	Delete(name string) error
	// Get returns the user by matching its name or subject
	Get(name string) (User, error)
	// List returns a list of User from the account
	List() []User
}

// User is an interface for editing a User
type User interface {
	// Name returns the name for the user
	Name() string
	// IsScoped returns true if the user is a scoped user - that is signed
	// with a signing key that has associated user permissions or ScopeLimits.
	// If a user is scoped, you cannot edit its limits or permissions, as
	// a scoped user must have no permissions associated with it. At runtime
	// the server will assign the exact permissions defined by the ScopeLimits
	IsScoped() bool
	// Subject returns the identity of the user
	Subject() string
	// Creds generates a credentials for the specified user. A credentials file is
	// an armored JWT and nkey secret that a client can use to connect to NATS.
	Creds(expiry time.Duration) ([]byte, error)
	// Issuer returns the issuer of the user. Typically, this will be the account's
	// ID or a signing key. If it is a signing key, IssuerAccount will return the
	// ID of the account owning the user
	Issuer() string
	// IssuerAccount returns the ID of the account owning the user. Note that if not set,
	// it returns Issuer
	IssuerAccount() string
	// JWT returns the encoded token
	JWT() string
	// Tags returns an object that you can use to manage tags for the account
	Tags() Tags

	UserLimits
}

// AccountLimits is an interface for managing account limits. Normally AccountLimits
// are managed by the Operator. When managed, any value you set here may be discarded
// by the Operator.
type AccountLimits interface {
	NatsLimits
	EditableNatsLimits
	// MaxConnections is the maximum number of connections that can be created
	// by the account
	MaxConnections() int64
	// SetMaxConnections sets the maximum number of connections that can be created
	// by the account
	SetMaxConnections(max int64) error
	// MaxLeafNodeConnections is the maximum number of leaf node connections that can be created
	// by the account
	MaxLeafNodeConnections() int64
	// SetMaxLeafNodeConnections sets the maximum number of leaf node connections that can be created
	// by the account
	SetMaxLeafNodeConnections(max int64) error
	// MaxImports is the maximum number of imports that can be used by the account.
	// Note that if some environments may not count environment specific imports to this limit.
	MaxImports() int64
	// SetMaxImports sets the maximum number of imports that can be used by the account.
	SetMaxImports(max int64) error
	// MaxExports is the maximum number of exports that can be created by the account.
	MaxExports() int64
	// SetMaxExports sets the maximum number of exports that can be created by the account.
	SetMaxExports(max int64) error
	// AllowWildcardExports returns true if the account can create wildcard exports
	AllowWildcardExports() bool
	// SetAllowWildcardExports sets whether the account can create wildcard exports
	SetAllowWildcardExports(tf bool) error
	// DisallowBearerTokens returns true if the server should reject bearer tokens for the account.
	DisallowBearerTokens() bool
	// SetDisallowBearerTokens sets whether the server should reject bearer tokens for the account.
	SetDisallowBearerTokens(tf bool) error
	// JetStream returns an interface for managing JetStream limits for the account
	JetStream() JetStreamTieredLimits
}

// JetStreamTieredLimits is an interface for managing JetStreamLimits
// tiers are expressed as a replication factor. With factor 0 being
// the default tier, which is applied to non-specified tiers. Use
// of the global tier is discouraged.
type JetStreamTieredLimits interface {
	// Get returns the JetStreamLimits for the specified tier or nil
	// if the tier doesn't exist. Tier 0 is the default tier, and always
	// exists, but may be unlimited.
	Get(tier int8) (JetStreamLimits, error)
	// Add creates a default JetStreamLimits for the specified tier, and
	// returns the JetStreamLimits interface for editing the limits.
	// Note that you cannot Add tier 0, as it is the default tier and it
	// always exists.
	Add(tier int8) (JetStreamLimits, error)
	// Delete removes the specified tier. If tier is 0, it will disable JetStream.
	Delete(tier int8) (bool, error)
	// IsJetStreamEnabled returns true if JetStream is enabled for the account
	IsJetStreamEnabled() bool
}

// JetStreamLimits is an interface for managing JetStream limits
type JetStreamLimits interface {
	// MaxMemoryStorage returns the maximum amount of memory that
	// memory streamExports can allocate across all streamExports in the account.
	MaxMemoryStorage() (int64, error)
	// SetMaxMemoryStorage sets the maximum amount of memory that
	// can be allocated for all streamExports in the account
	SetMaxMemoryStorage(max int64) error
	// MaxDiskStorage returns the maximum amount of disk storage
	// that disk streamExports can allocate across all streamExports in the account.
	MaxDiskStorage() (int64, error)
	// SetMaxDiskStorage sets the maximum amount of disk storage
	// that can be allocated for all streamExports in the account
	SetMaxDiskStorage(max int64) error
	// MaxMemoryStreamSize returns the maximum size of a memory stream
	MaxMemoryStreamSize() (int64, error)
	// SetMaxMemoryStreamSize sets the maximum size of a memory stream
	SetMaxMemoryStreamSize(max int64) error
	// MaxDiskStreamSize returns the maximum size of a disk stream
	MaxDiskStreamSize() (int64, error)
	// SetMaxDiskStreamSize sets the maximum size of a disk stream
	SetMaxDiskStreamSize(max int64) error
	// MaxStreamSizeRequired when true requires all stream allocations
	// to specify their maximum size.
	MaxStreamSizeRequired() (bool, error)
	// SetMaxStreamSizeRequired sets whether all stream allocations
	// require setting a maximum size
	SetMaxStreamSizeRequired(tf bool) error
	// MaxStreams is the maximum number of streamExports that can be created
	// by the account
	MaxStreams() (int64, error)
	// SetMaxStreams sets the maximum number of streamExports that can be created
	// by the account
	SetMaxStreams(max int64) error
	// MaxConsumers is the maximum number of consumers that can be created
	// by the account
	MaxConsumers() (int64, error)
	// SetMaxConsumers sets the maximum number of consumers that can be created
	// by the account
	SetMaxConsumers(max int64) error
	// MaxAckPending is the maximum number of messages that can be pending
	// for a consumer by default
	MaxAckPending() (int64, error)
	// SetMaxAckPending sets the maximum number of messages that can be pending
	// for a consumer by default
	SetMaxAckPending(max int64) error
	// IsUnlimited returns true if the limits are unlimited
	IsUnlimited() (bool, error)
	// SetUnlimited Sets all options to be Unlimited (-1)
	SetUnlimited() error
	// Delete removes the JetStreamLimit. If the tier is 0, it will disable JetStream.
	// Note that after using this function, any update to the limit will fail as the
	// limit reference is invalid.
	Delete() error
}

type Exports interface {
	Services() ServiceExports
	Streams() StreamExports
}

type Imports interface {
	Services() ServiceImports
	Streams() StreamImports
}

type ServiceImports interface {
	// Add creates and adds a new import of a public service importing the
	// specified subject from the specified account
	Add(name string, account string, subject string) (ServiceImport, error)
	// AddWithConfig adds a copy of the specified import configuration to the account
	AddWithConfig(i ServiceImport) error
	// Get returns imports that are exported by accounts under the specified subject
	Get(subject string) (ServiceImport, error)
	// GetByName returns an import stored under the specified name. Note that
	// the first import is returned.
	GetByName(name string) (ServiceImport, error)
	Delete(subject string) (bool, error)
	List() []ServiceImport
	Set(imports ...ServiceImport) error
}

type ServiceExports interface {
	// Add creates and adds a new public service with the specified name and subject
	Add(name string, subject string) (ServiceExport, error)
	// AddWithConfig adds a copy of the specified configuration to the account
	AddWithConfig(e ServiceExport) error
	// Get returns the ServiceExport matching the subject
	Get(subject string) (ServiceExport, error)
	// Delete deletes the ServiceExport matching the subject
	Delete(subject string) (bool, error)
	// GetByName returns the ServiceExport matching the specified name,
	// note that the first service is returned
	GetByName(name string) (ServiceExport, error)
	// List returns a list of ServiceExport in the account
	List() []ServiceExport
	// Set replaces all serviceExports with the specified ones
	Set(exports ...ServiceExport) error
}

type StreamImports interface {
	Add(name string, account string, subject string) (StreamImport, error)
	Get(subject string) (StreamImport, error)
	GetByName(name string) (StreamImport, error)
	Delete(subject string) (bool, error)
	List() []StreamImport
	Set(imports ...StreamImport) error
	AddWithConfig(i StreamImport) error
}

type StreamExports interface {
	// Add creates and add a new public stream with the specified name and subject
	Add(name string, subject string) (StreamExport, error)
	// AddWithConfig adds a copy of the specified configuration to the account
	AddWithConfig(e StreamExport) error
	// Get returns the StreamExport matching the subject or nil if not found
	Get(subject string) (StreamExport, error)
	// Delete deletes the StreamExport matching the subject
	Delete(subject string) (bool, error)
	// GetByName returns the StreamExport matching the specified name,
	// note that the first stream is returned
	GetByName(name string) (StreamExport, error)
	// List returns a list of StreamExport in the account
	List() []StreamExport
	// Set replaces all streamExports with the specified ones
	Set(exports ...StreamExport) error
}

type RevocationEntry interface {
	PublicKey() string
	At() time.Time
}

type Revocations interface {
	// Add revoke the specified nkey for credentials issued on the specified date or earlier
	//  The special `*` key targets all entities
	Add(key string, at time.Time) error
	// Delete deletes the specified nkey from the revocation list
	Delete(key string) (bool, error)
	// Compact removes revocations that are handled by a more recent wildcard revocation
	Compact() ([]RevocationEntry, error)
	// List returns a copy of current Revocations
	List() []RevocationEntry
	// Set replaces the current revocation list with the provided one
	Set(revocations []RevocationEntry) error
	// Contains returns true if the public key or "*" is in the revocation list
	Contains(key string) (bool, error)
}

type Revocable interface {
	Revocations() Revocations
}

type NameSubject interface {
	Name() string
	SetName(n string) error
	Subject() string
	SetSubject(s string) error
}

type Export interface {
	NameSubject
	Revocable
	TokenRequired() bool
	SetTokenRequired(tf bool) error
	Description() string
	SetDescription(s string) error
	InfoURL() string
	SetInfoURL(u string) error
	AccountTokenPosition() uint
	SetAccountTokenPosition(n uint) error
	// IsAdvertised returns true if the export is advertised - note that
	// the notion of Advertised may not be implemented by the operator
	IsAdvertised() bool
	// SetAdvertised sets whether the export is advertised - note that
	// the notion of Advertised may not be implemented by the operator
	SetAdvertised(tf bool) error
	// GenerateActivation an activation token for the specified account signed with the specified issuer
	GenerateActivation(account string, issuer string) (string, error)
}

type SamplingRate int

type LatencyOpts struct {
	SamplingRate SamplingRate
	Subject      string
}

type ServiceExport interface {
	Export
	// GetLatencyOptions returns the LatencyOpts if enabled otherwise nil
	GetLatencyOptions() *LatencyOpts
	// SetLatencyOptions enables latency tracing for a service, if nil, the latency tracing is disabled
	SetLatencyOptions(config *LatencyOpts) error
	// GenerateImport generates an import that can be added to an Account
	GenerateImport() (ServiceImport, error)
	// AllowTracing returns true if the service export allows tracing
	AllowTracing() bool
	// SetAllowTracing enables tracing messages to follow the service implementation
	SetAllowTracing(tf bool) error
}

type StreamExport interface {
	Export
	GenerateImport() (StreamImport, error)
}

type Import interface {
	NameSubject
	Account() string
	SetAccount(s string) error
	Token() string
	SetToken(t string) error
	LocalSubject() string
	SetLocalSubject(subject string) error
	IsShareConnectionInfo() bool
	SetShareConnectionInfo(tf bool) error
}

type StreamImport interface {
	Import
	// AllowTracing returns true if the service export allows tracing
	AllowTracing() bool
	// SetAllowTracing enables tracing messages to follow the service implementation
	SetAllowTracing(tf bool) error
}

type ServiceImport interface {
	Import
}

// SigningKeys is an interface for managing signing keys
type SigningKeys interface {
	SigningKeys() Keys
}

// Keys is an interface for managing signing keys.
type Keys interface {
	// Add creates a new signing key returning the public key that was generated. When
	// adding an entity specify the public key and the library will locate the private
	// key and sign it. Mutations to the entity will re-sign using the same key
	Add() (string, error)
	// Delete the signing key by matching its public key
	Delete(string) (bool, error)
	// Rotate the specified signing key with a new one. The new key will be used to
	// reissue entities that were issued by the old key. Note that if the account is
	// deployed, users issued by the old key will not be able to connect until handed
	// new credentials. Rotate is a mechanism for invalidating a signing key and reissuing.
	Rotate(string) (string, error)
	// List returns a list of signing keys
	List() []string
}

// ScopedSigningKeys is an interface for managing scoped signing keys
// that have an associated ScopeLimits with them. When a signing key has
// an associated ScopeLimits, the ScopeLimits are applied to the user
// at runtime by the NATS server.
type ScopedSigningKeys interface {
	// SigningKeys returns an interface for managing scoped signing keys
	SigningKeys() ScopedKeys
}

// ScopeLimits is an interface for managing the limits and permissions
// for a connection by simply issuing the user with a signing key.
type ScopeLimits interface {
	UserLimits
	// Key returns the public key associated with the scope
	Key() string
	// Role returns the role associated with the scope. The role is simply a name
	// that you can use to identify the scope. It is not used by the server.
	Role() string
	// SetRole sets the role associated with the scope. The role is simply a name
	// that you can use to identify the scope. It is not used by the server.
	SetRole(name string) error
	// Description returns an user-assigned description associated with the scope.
	Description() string
	// SetDescription sets an user-assigned description associated with the scope.
	SetDescription(description string) error
}

// ConnectionTypes is an interface for managing connection types that the connection
// can use. You can specify "STANDARD", "WEBSOCKET", "LEAFNODE", "LEAFNODE_WS", "MQTT"
type ConnectionTypes interface {
	// Set the possible connection types
	Set(connType ...string) error
	// Types returns a list of connection types that are currently set
	Types() []string
}

// Permissions is an interface for managing NATS subject permissions
type Permissions interface {
	// Allow returns a list of allowed NATS subjects
	Allow() []string
	// SetAllow sets the allowed NATS subjects
	SetAllow(subjects ...string) error
	// Deny returns a list of NATS subjects that the client is not able to use
	Deny() []string
	// SetDeny sets the NATS subjects that the client is not able to use
	SetDeny(subjects ...string) error
}

// ResponsePermissions is an interface for managing whether the client can
// respond to requests from other clients on the subject of the request.
// By default, clients are only able to public on publish permissions that is
// on subjects that the client can publish. ResponsePermissions allow you
// to allow a requester to set any reply subject it can subscribe to, while
// constraining the responding client from publishing on unexpected subjects.
type ResponsePermissions interface {
	// SetMaxMessages sets the maximum number of messages that the client can
	// send when responding to a request.
	SetMaxMessages(maxMessages int) error
	// SetExpires sets the maximum amount of time that the client will be allowed
	// to send a response on a reply subject
	SetExpires(expires time.Duration) error
	// MaxMessages returns the maximum number of messages that the client can
	// send when responding to a request.
	MaxMessages() int
	// Expires returns the amount of time that the client will be allowed
	// to send a response on a reply subject
	Expires() time.Duration
	// Unset removes the response permission
	Unset() error
}

// ConnectionSources is an interface for managing the allowed connection sources.
// ConnectionSources is a CIDR list of IP addresses that the client is allowed to
// connect from. If the client is connecting from an IP address that is not in the
// list, the connection will be rejected.
type ConnectionSources interface {
	// Sources returns a list of allowed connection sources
	Sources() []string
	// Contains returns true if the source is in the list of allowed connection sources
	Contains(p string) bool
	// Add the specified connection source to the list of allowed sources
	Add(p ...string) error
	// Remove the specified connection source from the list of allowed sources
	Remove(p ...string) error
	// Set the list of allowed connection sources
	Set(values string) error
}

type EditableNatsLimits interface {
	// SetMaxSubscriptions sets the maximum number of subscriptions that the client can have.
	// Set to -1 for unlimited.
	SetMaxSubscriptions(max int64) error
	// SetMaxPayload sets the maximum payload size that the client can publish in bytes
	// Set to -1 for unlimited.
	SetMaxPayload(max int64) error
	// SetMaxData sets the maximum data size that the client can send bytes
	// Set to -1 for unlimited.
	SetMaxData(max int64) error
}

type NatsLimits interface {
	// MaxSubscriptions returns the maximum number of subscriptions that the client can have
	MaxSubscriptions() int64
	// MaxPayload returns the maximum payload size that the client can publish in bytes
	MaxPayload() int64
	// MaxData returns the maximum amount of data that the client can send in bytes
	MaxData() int64
}

// EditableUserLimits is an interface for editing the user limits
type EditableUserLimits interface {
	EditableNatsLimits
	// SetBearerToken sets whether the client can use bearer tokens. A bearer token
	// is a JWT that doesn't require the client to sign the nonce when connecting. Thus,
	// the private key for the client is not required.
	SetBearerToken(tf bool) error
	// SetLocale sets the locale for the client.
	SetLocale(locale string) error
}

// UserLimits is an interface for managing the user limits
type UserLimits interface {
	EditableUserLimits
	NatsLimits
	// BearerToken returns true if the client can use bearer tokens
	BearerToken() bool
	// Locale returns the locale for the client.
	Locale() string
	// ConnectionTypes returns an interface for managing connection types
	ConnectionTypes() ConnectionTypes
	// ConnectionSources returns an interface for managing connection sources
	ConnectionSources() ConnectionSources
	// ConnectionTimes returns an interface for maintaining connection times
	ConnectionTimes() ConnectionTimes
	// PubPermissions returns an interface for managing NATS subjects that the client can publish.
	PubPermissions() Permissions
	// SubPermissions returns an interface for managing NATS subjects that a client can create subscriptions on.
	SubPermissions() Permissions
	// ResponsePermissions returns an interface for managing whether the client can respond
	// to requests that have a reply subject different from its publish permissions.
	ResponsePermissions() ResponsePermissions
}

// TimeRange is a time range
type TimeRange struct {
	// Start is the start time in the format HH:MM:SS
	Start string
	// End is the end time in the format HH:MM:SS
	End string
}

// ConnectionTimes is an interface for managing connection times
type ConnectionTimes interface {
	// Set sets the allowed connection times
	Set(r ...TimeRange) error
	// List returns the allowed connection times
	List() []TimeRange
}

// ScopedKeys is an interface for managing scoped signing keys
type ScopedKeys interface {
	// Add creates a new signing key returning the public key that was generated. Note
	// this is not a scoped key, but a general signing key
	Add() (string, error)
	// Delete the specified signing key and any underlying scope
	Delete(string) (bool, error)
	// Rotate the specified key with a new one. The old key is deleted and the new key
	// is used to reissue any entities that were issued by the old key.
	Rotate(string) (string, error)
	// AddScope creates a new scope with the specified role, and associates it with
	// a new signing key.
	AddScope(role string) (ScopeLimits, error)
	// GetScope returns the scope associated with the specified key.
	// Note that if the signing key is not scoped, it returns a not found error
	GetScope(string) (ScopeLimits, error)
	// GetScopeByRole returns the first scope that matches the specified role.
	// Note that the search must be an exact match of the scope role, and
	GetScopeByRole(string) ([]ScopeLimits, error)
	// List returns a list of signing keys
	List() []string
	// ListRoles returns the names of roles associated with the account
	// Note that role names can be duplicated, and this name of roles
	// will not contain duplicates so long as roles have the same capitalization, etc.
	ListRoles() []string
	// Contains returns found as true if the signing key was found, and isScoped as true
	// if the signing key is scoped.
	Contains(sk string) (found bool, isScoped bool)
}
