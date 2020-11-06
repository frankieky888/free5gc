/*
 * AUSF API
 *
 * OpenAPI specification for AUSF
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package models

type AuthResult string

// List of AuthResult
const (
	AuthResult_SUCCESS AuthResult = "AUTHENTICATION_SUCCESS"
	AuthResult_FAILURE AuthResult = "AUTHENTICATION_FAILURE"
	AuthResult_ONGOING AuthResult = "AUTHENTICATION_ONGOING"
)
