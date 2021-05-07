package locales

import (
	"golang.org/x/text/language"
	"k8s.io/klog/v2"
)

type Localization map[string]string

var supportedLocalizations = map[string]Localization{
	language.English.String():  locale_en,
	language.Chinese.String():  locale_zh,
	language.Japanese.String(): locale_ja,
	language.Korean.String():   locale_ko,
}

func GetLocale(acceptLangHeader string) Localization {
	locale, ok := supportedLocalizations[getPreferredLang(acceptLangHeader)]
	if !ok {
		return locale_en
	}
	return locale
}

func getPreferredLang(acceptLangHeader string) string {
	matcher := language.NewMatcher(supportedLangs)
	userPrefs, _, err := language.ParseAcceptLanguage(acceptLangHeader)
	if err != nil {
		klog.V(5).Infof("Error parsing 'Accept-Language' header, falling back to English language: %v", err)
		return language.English.String()
	}
	tag, _, _ := matcher.Match(userPrefs...)
	base, _ := tag.Base()
	return base.String()
}

var supportedLangs = []language.Tag{
	language.English,  // en - first language is fallback
	language.Chinese,  // zh
	language.Japanese, // ja
	language.Korean,   // ko
}

var locale_en = Localization{
	"LogInToYourAccount": "Log in to your account",
	"Username":           "Username",
	"Password":           "Password",
	"LogIn":              "Log in",
	"WelcomeTo":          "Welcome to",
	"LogInWith":          "Log in with",
	"Error":              "Error",
}

var locale_zh = Localization{
	"LogInToYourAccount": "登录到您的帐户",
	"Username":           "用户名",
	"Password":           "密码",
	"LogIn":              "登录",
	"WelcomeTo":          "欢迎使用",
	"LogInWith":          "登录使用",
	"Error":              "错误",
}

var locale_ja = Localization{
	"LogInToYourAccount": "アカウントにログイン",
	"Username":           "ユーザー名",
	"Password":           "パスワード",
	"LogIn":              "ログイン",
	"WelcomeTo":          "ようこそ:",
	"LogInWith":          "ログイン:",
	"Error":              "エラー",
}

var locale_ko = Localization{
	"LogInToYourAccount": "귀하의 계정에 로그인하십시오",
	"Username":           "사용자 이름",
	"Password":           "암호",
	"LogIn":              "로그인",
	"WelcomeTo":          "환영합니다",
	"LogInWith":          "로그인",
	"Error":              "오류",
}
