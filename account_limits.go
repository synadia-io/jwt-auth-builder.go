package authb

import (
	"github.com/nats-io/jwt/v2"
)

type accountLimits struct {
	data *AccountData
}

func (a *accountLimits) OperatorLimits() jwt.OperatorLimits {
	return a.data.Claim.Limits
}

func (a *accountLimits) SetOperatorLimits(limits jwt.OperatorLimits) error {
	a.data.Claim.Limits = limits
	return a.data.update()
}

func (a *accountLimits) MaxSubscriptions() int64 {
	return a.data.Claim.Limits.Subs
}

func (a *accountLimits) SetMaxSubscriptions(max int64) error {
	a.data.Claim.Limits.Subs = max
	return a.data.update()
}

func (a *accountLimits) MaxPayload() int64 {
	return a.data.Claim.Limits.Payload
}

func (a *accountLimits) SetMaxPayload(max int64) error {
	a.data.Claim.Limits.Payload = max
	return a.data.update()
}

func (a *accountLimits) MaxData() int64 {
	return a.data.Claim.Limits.Data
}

func (a *accountLimits) SetMaxData(max int64) error {
	a.data.Claim.Limits.Data = max
	return a.data.update()
}

func (a *accountLimits) MaxConnections() int64 {
	return a.data.Claim.Limits.Conn
}

func (a *accountLimits) SetMaxConnections(max int64) error {
	a.data.Claim.Limits.Conn = max
	return a.data.update()
}

func (a *accountLimits) MaxLeafNodeConnections() int64 {
	return a.data.Claim.Limits.LeafNodeConn
}

func (a *accountLimits) SetMaxLeafNodeConnections(max int64) error {
	a.data.Claim.Limits.LeafNodeConn = max
	return a.data.update()
}

func (a *accountLimits) MaxImports() int64 {
	return a.data.Claim.Limits.Imports
}

func (a *accountLimits) SetMaxImports(max int64) error {
	a.data.Claim.Limits.Imports = max
	return a.data.update()
}

func (a *accountLimits) MaxExports() int64 {
	return a.data.Claim.Limits.Exports
}

func (a *accountLimits) SetMaxExports(max int64) error {
	a.data.Claim.Limits.Exports = max
	return a.data.update()
}

func (a *accountLimits) AllowWildcardExports() bool {
	return a.data.Claim.Limits.WildcardExports
}

func (a *accountLimits) SetAllowWildcardExports(tf bool) error {
	a.data.Claim.Limits.WildcardExports = tf
	return a.data.update()
}

func (a *accountLimits) DisallowBearerTokens() bool {
	return a.data.Claim.Limits.DisallowBearer
}

func (a *accountLimits) SetDisallowBearerTokens(tf bool) error {
	a.data.Claim.Limits.DisallowBearer = tf
	return a.data.update()
}

func (a *accountLimits) JetStream() JetStreamTieredLimits {
	return &accountJsTieredLimits{data: a.data}
}
