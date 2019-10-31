package registry

import "testing"

func TestNewImageCache(t *testing.T) {
	tests := []string{
		"none",
		"inmemory",
		"redis",
		"memcache",
	}
	for _, test := range tests {
		cache := NewImageCache(test, nil)
		if cache == nil {
			t.Errorf("NewImageCache(%s, nil) == nil", test)
		}
		opts := &ImageCacheOptions{}
		cache = NewImageCache(test, opts)
		if cache == nil {
			t.Errorf("NewImageCache(%s, %v) == nil", test, opts)
		}
	}
}
