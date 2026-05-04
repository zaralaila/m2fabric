//go:build !pkcs11
// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.
Modifications Copyright Zara Laila Cheong — PQC factory registration.
SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

const pkcs11Enabled = false

type FactoryOpts struct {
	Default string   `json:"default" yaml:"Default"`
	SW      *SwOpts  `json:"SW,omitempty" yaml:"SW,omitempty"`
	PQC     *PQCOpts `json:"PQC,omitempty" yaml:"PQC,omitempty"`
}

func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		factoriesInitError = initFactories(config)
	})
	return factoriesInitError
}

func initFactories(config *FactoryOpts) error {
	if config == nil {
		config = GetDefaultOpts()
	}
	if config.Default == "" {
		config.Default = "SW"
	}
	if config.SW == nil {
		config.SW = GetDefaultOpts().SW
	}

	if config.Default == "SW" && config.SW != nil {
		f := &SWFactory{}
		var err error
		defaultBCCSP, err = initBCCSP(f, config)
		if err != nil {
			return errors.Wrapf(err, "Failed initializing BCCSP")
		}
	}

	if config.Default == "PQC" {
		if config.PQC == nil {
			config.PQC = &PQCOpts{Algorithm: "MLDSA44"}
		}
		f := &PQCFactory{}
		var err error
		defaultBCCSP, err = initBCCSP(f, config)
		if err != nil {
			return errors.Wrapf(err, "Failed initializing PQC BCCSP")
		}
	}

	if defaultBCCSP == nil {
		return errors.Errorf("Could not find default `%s` BCCSP", config.Default)
	}
	return nil
}

func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.Default {
	case "SW":
		f = &SWFactory{}
	case "PQC":
		f = &PQCFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.Default)
	}
	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

func StringToKeyIds() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		return data, nil
	}
}
