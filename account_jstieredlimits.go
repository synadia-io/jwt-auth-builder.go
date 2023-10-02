package nats_auth

import (
	"fmt"
	"github.com/nats-io/jwt/v2"
)

type accountJsTieredLimits struct {
	data *AccountData
}

func (a *accountJsTieredLimits) Get(tier int8) (JetStreamLimits, error) {
	return a.getLimit(tier)
}
func (a *accountJsTieredLimits) Add(tier int8) (JetStreamLimits, error) {
	exists, err := a.getLimit(tier)
	if err != nil {
		return nil, err
	}
	if exists != nil {
		return nil, fmt.Errorf("tier %d already exists", tier)
	}
	if len(a.data.Claim.Limits.JetStreamTieredLimits) == 0 {
		a.data.Claim.Limits.JetStreamTieredLimits = make(map[string]jwt.JetStreamLimits)
	}
	a.data.Claim.Limits.JetStreamTieredLimits[fmt.Sprintf("R%d", tier)] = jwt.JetStreamLimits{}
	if err != a.data.update() {
		return nil, err
	}
	return a.getLimit(tier)
}

func (a *accountJsTieredLimits) Delete(tier int8) (bool, error) {
	ok := false
	if tier == 0 {
		a.data.Claim.Limits.JetStreamLimits = jwt.JetStreamLimits{}
		ok = true
	} else {
		k := fmt.Sprintf("R%d", tier)
		if _, ok = a.data.Claim.Limits.JetStreamTieredLimits[k]; ok {
			delete(a.data.Claim.Limits.JetStreamTieredLimits, k)
			if len(a.data.Claim.Limits.JetStreamTieredLimits) == 0 {
				a.data.Claim.Limits.JetStreamTieredLimits = nil
			}
		}
	}
	if err := a.data.update(); err != nil {
		return ok, err
	}
	return ok, nil
}

func (a *accountJsTieredLimits) IsJetStreamEnabled() bool {
	return a.data.Claim.Limits.JetStreamLimits.IsUnlimited()
}

func (a *accountJsTieredLimits) getLimit(tier int8) (JetStreamLimits, error) {
	if tier < 0 {
		return nil, fmt.Errorf("invalid tier %d", tier)
	}
	var err error
	lim := &jsLimits{limits: a, tier: tier}
	if lim.lim, err = lim.limit(); err != nil {
		return nil, nil
	}
	return lim, nil
}

type jsLimits struct {
	limits *accountJsTieredLimits
	tier   int8
	lim    *jwt.JetStreamLimits
}

func (l *jsLimits) limit() (*jwt.JetStreamLimits, error) {
	if l.tier == 0 {
		return &l.limits.data.Claim.Limits.JetStreamLimits, nil
	}
	lim, ok := l.limits.data.Claim.Limits.JetStreamTieredLimits[fmt.Sprintf("R%d", l.tier)]
	if !ok {
		return nil, fmt.Errorf("limit not found for tier %d", l.tier)
	}
	l.lim = &lim
	return l.lim, nil
}

func (l *jsLimits) update() error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	if l.tier == 0 {
		l.limits.data.Claim.Limits.JetStreamLimits = *l.lim
	} else {
		l.limits.data.Claim.Limits.JetStreamTieredLimits[fmt.Sprintf("R%d", l.tier)] = *l.lim
	}
	return l.limits.data.update()
}

func (l *jsLimits) MaxMemoryStorage() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.MemoryStorage, nil
}
func (l *jsLimits) SetMaxMemoryStorage(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.MemoryStorage = max
	return l.update()
}
func (l *jsLimits) MaxDiskStorage() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.DiskStorage, nil
}
func (l *jsLimits) SetMaxDiskStorage(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.DiskStorage = max
	return l.update()
}
func (l *jsLimits) MaxMemoryStreamSize() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.MemoryMaxStreamBytes, nil
}
func (l *jsLimits) SetMaxMemoryStreamSize(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.MemoryMaxStreamBytes = max
	return l.update()
}
func (l *jsLimits) MaxDiskStreamSize() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.DiskMaxStreamBytes, nil
}
func (l *jsLimits) SetMaxDiskStreamSize(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.DiskMaxStreamBytes = max
	return l.update()
}
func (l *jsLimits) MaxStreamSizeRequired() (bool, error) {
	if err := l.checkDeleted(); err != nil {
		return false, err
	}
	return l.lim.MaxBytesRequired, nil
}
func (l *jsLimits) SetMaxStreamSizeRequired(tf bool) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.MaxBytesRequired = tf
	return l.update()
}
func (l *jsLimits) MaxStreams() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.Streams, nil
}
func (l *jsLimits) SetMaxStreams(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.Streams = max
	return l.update()
}
func (l *jsLimits) MaxConsumers() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.Consumer, nil
}
func (l *jsLimits) SetMaxConsumers(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.Consumer = max
	return l.update()
}
func (l *jsLimits) MaxAckPending() (int64, error) {
	if err := l.checkDeleted(); err != nil {
		return 0, err
	}
	return l.lim.MaxAckPending, nil
}
func (l *jsLimits) SetMaxAckPending(max int64) error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim.MaxAckPending = max
	return l.update()
}
func (l *jsLimits) IsUnlimited() (bool, error) {
	if err := l.checkDeleted(); err != nil {
		return false, err
	}
	return l.lim.IsUnlimited(), nil
}

func (l *jsLimits) SetUnlimited() error {
	if err := l.checkDeleted(); err != nil {
		return err
	}
	l.lim = &jwt.JetStreamLimits{
		MemoryStorage: jwt.NoLimit,
		DiskStorage:   jwt.NoLimit,
		Streams:       jwt.NoLimit,
		Consumer:      jwt.NoLimit}
	return l.update()
}

func (l *jsLimits) checkDeleted() error {
	if l.tier == -1 {
		return fmt.Errorf("limit deleted")
	}
	return nil
}

func (l *jsLimits) Delete() error {
	_, err := l.limits.Delete(l.tier)
	if err != nil {
		return err
	}
	l.lim = nil
	l.tier = -1
	return nil
}
