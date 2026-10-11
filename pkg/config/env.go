package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "GOPHERSTORAGE_"

// loadEnvironment loads only variables whose names exactly match a YAML leaf
// path after uppercasing and joining path components with underscores.
func loadEnvironment(k *koanf.Koanf) (map[string]struct{}, error) {
	schema := configSchema(reflect.TypeOf(Config{}), "")
	known := make(map[string]envField, len(schema))
	for path, field := range schema {
		known[strings.ToUpper(strings.ReplaceAll(path, ".", "_"))] = field
	}

	var unknown []string
	var invalid []string
	overridden := make(map[string]struct{})
	provider := env.Provider(".", env.Opt{
		Prefix: envPrefix,
		TransformFunc: func(key, value string) (string, any) {
			name := strings.TrimPrefix(key, envPrefix)
			if name == key || name == "CONFIG" {
				return "", nil
			}
			field, ok := known[name]
			if !ok {
				unknown = append(unknown, key)
				return "", nil
			}
			parsed, err := parseEnvironmentValue(field.typ, value)
			if err != nil {
				invalid = append(invalid, key)
				return "", nil
			}
			overridden[field.path] = struct{}{}
			return field.path, parsed
		},
	})
	if err := k.Load(provider, nil); err != nil {
		return nil, fmt.Errorf("load config environment: %w", err)
	}
	if len(unknown) != 0 {
		return nil, fmt.Errorf("unknown configuration environment variables: %s", strings.Join(unknown, ", "))
	}
	if len(invalid) != 0 {
		return nil, fmt.Errorf("invalid value for configuration environment variables: %s", strings.Join(invalid, ", "))
	}
	return overridden, nil
}

type envField struct {
	path string
	typ  reflect.Type
}

func configSchema(t reflect.Type, prefix string) map[string]envField {
	fields := make(map[string]envField)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Duration(0)) {
			for key, value := range configSchema(f.Type, path) {
				fields[key] = value
			}
			continue
		}
		fields[path] = envField{path: path, typ: f.Type}
	}
	return fields
}

func parseEnvironmentValue(t reflect.Type, value string) (any, error) {
	if t == reflect.TypeOf(time.Duration(0)) {
		return time.ParseDuration(value)
	}
	switch t.Kind() {
	case reflect.String:
		return value, nil
	case reflect.Bool:
		return strconv.ParseBool(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.ParseInt(value, 10, t.Bits())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.ParseUint(value, 10, t.Bits())
	case reflect.Slice:
		if t.Elem().Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported list type")
		}
		var values []string
		if !strings.HasPrefix(strings.TrimSpace(value), "[") || json.Unmarshal([]byte(value), &values) != nil || values == nil {
			return nil, fmt.Errorf("expected a JSON string array")
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unsupported environment type")
	}
}
