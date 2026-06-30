// internal/config/loader.go
package config

import (
    "bytes"
    "io"
    "sync"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/rs/zerolog"
    "github.com/spf13/viper"
    "gopkg.in/yaml.v3"
)

var (
    policyMu   sync.RWMutex
    loadedPolicy *LoadedPolicy
    logger = zerolog.New(io.Discard).With().Timestamp().Logger() // will be replaced by actual logger in init
)

// InitLoader sets up Viper and file watcher for the policy file.
func InitLoader(policyPath string) error {
    v := viper.New()
    v.SetConfigFile(policyPath)
    v.SetConfigType("yaml")
    v.AutomaticEnv()

    if err := v.ReadInConfig(); err != nil {
        return err
    }
    if err := unmarshalPolicy(v); err != nil {
        return err
    }

    // Watcher
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    go watchConfig(watcher, policyPath)
    if err := watcher.Add(policyPath); err != nil {
        return err
    }
    return nil
}

func unmarshalPolicy(v *viper.Viper) error {
    var p Policy
    // viper unmarshals into map; we use yaml for richer support
    raw := v.AllSettings()
    buf, err := yaml.Marshal(raw)
    if err != nil {
        return err
    }
    if err := yaml.NewDecoder(bytes.NewReader(buf)).Decode(&p); err != nil {
        return err
    }
    policyMu.Lock()
    loadedPolicy = &LoadedPolicy{Policy: p, LoadedAt: time.Now()}
    policyMu.Unlock()
    logger.Info().Msg("policy loaded successfully")
    return nil
}

func watchConfig(w *fsnotify.Watcher, path string) {
    defer w.Close()
    for {
        select {
        case event, ok := <-w.Events:
            if !ok {
                return
            }
            if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
                logger.Info().Str("file", path).Msg("policy file changed, reloading")
                v := viper.New()
                v.SetConfigFile(path)
                v.SetConfigType("yaml")
                if err := v.ReadInConfig(); err != nil {
                    logger.Error().Err(err).Msg("failed to read updated policy, keeping previous")
                    continue
                }
                if err := unmarshalPolicy(v); err != nil {
                    logger.Error().Err(err).Msg("failed to unmarshal updated policy, keeping previous")
                }
            }
        case err, ok := <-w.Errors:
            if !ok {
                return
            }
            logger.Error().Err(err).Msg("watcher error")
        }
    }
}

// GetPolicy safely returns the current policy snapshot.
func GetPolicy() Policy {
    policyMu.RLock()
    defer policyMu.RUnlock()
    if loadedPolicy == nil {
        return Policy{}
    }
    return loadedPolicy.Policy
}

// ReloadPolicy manually triggers a policy reload
func ReloadPolicy() error {
	policyPath := "configs/policy.yaml"
	v := viper.New()
	v.SetConfigFile(policyPath)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return err
	}
	if err := unmarshalPolicy(v); err != nil {
		return err
	}
	logger.Info().Msg("policy manually reloaded successfully")
	return nil
}
