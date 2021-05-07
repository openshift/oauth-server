package locales

import (
	"reflect"
	"testing"
)

func TestLocales(t *testing.T) {
	tests := []struct {
		name   string
		header string
		locale Localization
	}{
		{
			name:   "Test empty 'Accept-Language' request header which defaults to English language",
			header: "",
			locale: locale_en,
		},
		{
			name:   "Test 'Accept-Language' request header which favours English language",
			header: "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
			locale: locale_en,
		},
		{
			name:   "Test 'Accept-Language' request header which favours Japan language",
			header: "ja;q=0.8, en;q=0.7",
			locale: locale_ja,
		},
		{
			name:   "Test 'Accept-Language' request header which favours Korean language",
			header: "ja;q=0.8, ko;q=0.9",
			locale: locale_ko,
		},
		{
			name:   "Test 'Accept-Language' request header which favours Chinese language",
			header: "en;q=0.3, zh;q=0.7",
			locale: locale_zh,
		},
		{
			name:   "Test empty 'Accept-Language' request header which doesn't match any supported languages, so defaults to English language",
			header: "fr;q=0.5, de;q=0.8",
			locale: locale_en,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(GetLocale(tt.header), tt.locale) {
				t.Error(tt.name)
			}
		})
	}
}
