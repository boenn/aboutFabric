/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"fmt"
	"sync"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
)

var (
	// BCCSP的默认值
	defaultBCCSP bccsp.BCCSP
	// 当InitFactories未被调用，则暂时使用此BCCSP
	bootBCCSP bccsp.BCCSP
	// BCCSP的工厂
	bccspMap map[string]bccsp.BCCSP
	// 工厂的初始化同步
	factoriesInitOnce sync.Once
	bootBCCSPInitOnce sync.Once
	// 工厂的初始化错误
	factoriesInitError error

	logger = flogging.MustGetLogger("bccsp")
)

// BCCSPFactory用于获取BCCSP接口的实例。
type BCCSPFactory interface {
	// Name返回使用的工厂名
	Name() string
	// Get使用opts返回BCCSP的一个实例。
	Get(opts *FactoryOpts) (bccsp.BCCSP, error)
}

// GetDefault返回非临时（长期）BCCSP
func GetDefault() bccsp.BCCSP {
	if defaultBCCSP == nil {
		logger.Warning("Before using BCCSP, please call InitFactories(). Falling back to bootBCCSP.")
		bootBCCSPInitOnce.Do(func() {
			var err error
			f := &SWFactory{}
			bootBCCSP, err = f.Get(GetDefaultOpts())
			if err != nil {
				panic("BCCSP Internal error, failed initialization with GetDefaultOpts!")
			}
		})
		return bootBCCSP
	}
	return defaultBCCSP
}


// GetBCCSP返回根据输入中传递的选项创建的BCCSP。
func GetBCCSP(name string) (bccsp.BCCSP, error) {
	csp, ok := bccspMap[name]
	if !ok {
		return nil, fmt.Errorf("Could not find BCCSP, no '%s' provider", name)
	}
	return csp, nil
}


// 对BCCSP初始化
func initBCCSP(f BCCSPFactory, config *FactoryOpts) error {
	csp, err := f.Get(config)
	if err != nil {
		return fmt.Errorf("Could not initialize BCCSP %s [%s]", f.Name(), err)
	}

	logger.Debugf("Initialize BCCSP [%s]", f.Name())
	bccspMap[f.Name()] = csp
	return nil
}
