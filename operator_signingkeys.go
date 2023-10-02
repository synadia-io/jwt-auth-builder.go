package nats_auth

import "github.com/nats-io/nkeys"

type operatorSigningKeys struct {
	data *OperatorData
}

func (os *operatorSigningKeys) Add() (string, error) {
	k, err := os.add()
	if err != nil {
		return "", err
	}
	return k.Public, nil
}

func (os *operatorSigningKeys) add() (*Key, error) {
	key, err := KeyFor(nkeys.PrefixByteOperator)
	if err != nil {
		return nil, err
	}
	err = os.data.update()
	if err != nil {
		return nil, err
	}
	os.data.AddedKeys = append(os.data.AddedKeys, key)
	os.data.OperatorSigningKeys = append(os.data.OperatorSigningKeys, key)
	os.data.Claim.SigningKeys = append(os.data.Claim.SigningKeys, key.Public)
	return key, nil
}

func (os *operatorSigningKeys) Delete(key string) (bool, error) {
	for idx, k := range os.data.Claim.SigningKeys {
		if k == key {
			os.data.DeletedKeys = append(os.data.DeletedKeys, key)
			os.data.Claim.SigningKeys = append(os.data.Claim.SigningKeys[:idx], os.data.Claim.SigningKeys[idx+1:]...)
			return true, os.data.update()
		}
	}
	return false, nil
}

func (os *operatorSigningKeys) Rotate(key string) (string, error) {
	k, err := os.add()
	if err != nil {
		return "", err
	}
	ok, err := os.Delete(key)
	if !ok || err != nil {
		return "", err
	}

	// reissue all the accounts that were issued with the rotated signing key
	for _, a := range os.data.AccountDatas {
		if a.Claim.Issuer == key {
			err := a.issue(k)
			if err != nil {
				return "", err
			}
		}
	}
	return k.Public, err
}

func (os *operatorSigningKeys) List() []string {
	v := make([]string, len(os.data.Claim.SigningKeys))
	copy(v, os.data.Claim.SigningKeys)
	return v
}
