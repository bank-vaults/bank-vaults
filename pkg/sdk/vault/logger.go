// Copyright © 2020 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

// Logger is a unified interface for various logging use cases and practices, including:
// 		- leveled logging
// 		- structured logging
//
// See the original repository for more information: https://github.com/logur/logur
type Logger interface {
	// Trace logs a Trace event.
	//
	// Even more fine-grained information than Debug events.
	// Loggers not supporting this level should fall back to Debug.
	Trace(msg string, fields ...map[string]interface{})

	// Debug logs a Debug event.
	//
	// A verbose series of information events.
	// They are useful when debugging the system.
	Debug(msg string, fields ...map[string]interface{})

	// Info logs an Info event.
	//
	// General information about what's happening inside the system.
	Info(msg string, fields ...map[string]interface{})

	// Warn logs a Warn(ing) event.
	//
	// Non-critical events that should be looked at.
	Warn(msg string, fields ...map[string]interface{})

	// Error logs an Error event.
	//
	// Critical events that require immediate attention.
	// Loggers commonly provide Fatal and Panic levels above Error level,
	// but exiting and panicing is out of scope for a logging library.
	Error(msg string, fields ...map[string]interface{})
}

// noopLogger is a no-op logger that discards all received log events.
//
// It implements the Logger interface.
type noopLogger struct{}

func (noopLogger) Trace(_ string, _ ...map[string]interface{}) {}
func (noopLogger) Debug(_ string, _ ...map[string]interface{}) {}
func (noopLogger) Info(_ string, _ ...map[string]interface{})  {}
func (noopLogger) Warn(_ string, _ ...map[string]interface{})  {}
func (noopLogger) Error(_ string, _ ...map[string]interface{}) {}
