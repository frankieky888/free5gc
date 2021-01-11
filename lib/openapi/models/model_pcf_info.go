/*
 * NRF NFManagement Service
 *
 * NRF NFManagement Service
 *
 * API version: 1.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package models

type PcfInfo struct {
	DnnList     []string    `json:"dnnList,omitempty" yaml:"dnnList" bson:"dnnList" mapstructure:"DnnList"`
	SupiRanges  []SupiRange `json:"supiRanges,omitempty" yaml:"supiRanges" bson:"supiRanges" mapstructure:"SupiRanges"`
	RxDiamHost  string      `json:"rxDiamHost,omitempty" yaml:"rxDiamHost" bson:"rxDiamHost" mapstructure:"RxDiamHost"`
	RxDiamRealm string      `json:"rxDiamRealm,omitempty" yaml:"rxDiamRealm" bson:"rxDiamRealm" mapstructure:"RxDiamRealm"`
}