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


// GetDefaultOpts为Opts提供默认实现，每次都会返回一个新实例
func GetDefaultOpts() *FactoryOpts {
	//read config file
	//if(){
	//return 
	//}
	//
	return &FactoryOpts{
		ProviderName: "SW",
		SwOpts: &SwOpts{
			HashFamily: "SM3",
			SecLevel:   256,

			Ephemeral: true,
		},
	}
}


// FactoryName返回提供者的名称
func (o *FactoryOpts) FactoryName() string {
	return o.ProviderName
}


// 修改
func GetDefaultOpts() *FactoryOpts {
	b, err := ioutil.ReadFile("test.log")
	if err != nil {
		fmt.Print(err)
	}
	str := string(b)
	fmt.Println(str)
	if str == "1"{
		return &FactoryOpts{
			ProviderName: "SW",
			SwOpts: &SwOpts{
				HashFamily: "SM3",
				SecLevel:   256,

				Ephemeral: true,
			},
		}
	}  else if str=="2" {
	   return &FactoryOpts{
			ProviderName: "SW",
			SwOpts: &SwOpts{
				HashFamily: "SHA2",
				SecLevel:   256,

				Ephemeral: true,
			},
		}
	}return &FactoryOpts{
			ProviderName: "HW",
			HwOpts: &HwOpts{
				HashFamily: "SM3",
				SecLevel:   256,

				Ephemeral: true,
			},
		}
		


}

