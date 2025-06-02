package locales

import (
	"golang.org/x/text/language"
	"k8s.io/klog/v2"
)

type Localization map[string]string

var supportedLocalizations = map[string]Localization{
	language.English.String():  locale_en,
	language.Spanish.String():  locale_es,
	language.French.String():   locale_fr,
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
	language.Spanish,  // es
	language.French,   // fr
	language.Chinese,  // zh
	language.Japanese, // ja
	language.Korean,   // ko
}

var locale_en = Localization{
	"LogInToYourAccount":                   "Log in to your account",
	"Username":                             "Username",
	"Password":                             "Password",
	"LogIn":                                "Log in",
	"WelcomeTo":                            "Welcome to",
	"LogInWith":                            "Log in with",
	"Error":                                "Error",
	"LoginIsRequiredPleaseTryAgain":        "Login is required. Please try again.",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "Could not check CSRF token. Please try again.",
	"InvalidLoginOrPasswordPleaseTryAgain": "Invalid login or password. Please try again.",
	"CouldNotCreateUser":                   "Could not create user.",
	"CouldNotFindUser":                     "Could not find user.",
	"AnAuthenticationErrorOccurred":        "An authentication error occurred.",
	"GrantErrorOccurred":                   "A grant error occurred.",
}

var locale_es = Localization{
	"LogInToYourAccount":                   "Inicia sesión en tu cuenta",
	"Username":                             "Nombre de usuario",
	"Password":                             "Contraseña",
	"LogIn":                                "Iniciar sesión",
	"WelcomeTo":                            "Bienvenido a",
	"LogInWith":                            "Inicia sesión con",
	"Error":                                "Error",
	"LoginIsRequiredPleaseTryAgain":        "Se requiere iniciar sesión. Por favor, inténtalo de nuevo.",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "No se pudo verificar el token CSRF. Por favor, inténtalo de nuevo.",
	"InvalidLoginOrPasswordPleaseTryAgain": "Usuario o contraseña inválidos. Por favor, inténtalo de nuevo.",
	"CouldNotCreateUser":                   "No se pudo crear el usuario.",
	"CouldNotFindUser":                     "No se pudo encontrar el usuario.",
	"AnAuthenticationErrorOccurred":        "Se produjo un error de autenticación.",
	"GrantErrorOccurred":                   "Se produjo un error de concesión.",
}

var locale_fr = Localization{
	"LogInToYourAccount":                   "Connectez-vous à votre compte",
	"Username":                             "Nom d'utilisateur",
	"Password":                             "Mot de passe",
	"LogIn":                                "Se connecter",
	"WelcomeTo":                            "Bienvenue à",
	"LogInWith":                            "Connectez-vous avec",
	"Error":                                "Erreur",
	"LoginIsRequiredPleaseTryAgain":        "La connexion est requise. Veuillez réessayer.",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "Impossible de vérifier le jeton CSRF. Veuillez réessayer.",
	"InvalidLoginOrPasswordPleaseTryAgain": "Identifiant ou mot de passe invalide. Veuillez réessayer.",
	"CouldNotCreateUser":                   "Impossible de créer l'utilisateur.",
	"CouldNotFindUser":                     "Impossible de trouver l'utilisateur.",
	"AnAuthenticationErrorOccurred":        "Une erreur d'authentification s'est produite.",
	"GrantErrorOccurred":                   "Une erreur de concession s'est produite.",
}

var locale_zh = Localization{
	"LogInToYourAccount":                   "登录到您的帐户",
	"Username":                             "用户名",
	"Password":                             "密码",
	"LogIn":                                "登录",
	"WelcomeTo":                            "欢迎使用",
	"LogInWith":                            "登录使用",
	"Error":                                "错误",
	"LoginIsRequiredPleaseTryAgain":        "需要登录。请再次尝试。",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "无法检查 CSRF 令牌。请重试。",
	"InvalidLoginOrPasswordPleaseTryAgain": "无效的登录或密码。请再次尝试。",
	"CouldNotCreateUser":                   "无法创建用户。",
	"CouldNotFindUser":                     "无法找到用户。",
	"AnAuthenticationErrorOccurred":        "发生身份验证错误。",
	"GrantErrorOccurred":                   "发生授权错误。",
}

var locale_ja = Localization{
	"LogInToYourAccount":                   "アカウントにログイン",
	"Username":                             "ユーザー名",
	"Password":                             "パスワード",
	"LogIn":                                "ログイン",
	"WelcomeTo":                            "ようこそ:",
	"LogInWith":                            "ログイン:",
	"Error":                                "エラー",
	"LoginIsRequiredPleaseTryAgain":        "ログインが必要です。もう一度やり直してください。",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "CSRF トークンを確認できませんでした。もう一度やり直してください。",
	"InvalidLoginOrPasswordPleaseTryAgain": "無効なログインまたはパスワードです。もう一度やり直してください。",
	"CouldNotCreateUser":                   "ユーザーを作成できませんでした。",
	"CouldNotFindUser":                     "ユーザーが見つかりませんでした。",
	"AnAuthenticationErrorOccurred":        "認証エラーが発生しました。",
	"GrantErrorOccurred":                   "許可エラーが発生しました。",
}

var locale_ko = Localization{
	"LogInToYourAccount":                   "귀하의 계정에 로그인하십시오",
	"Username":                             "사용자 이름",
	"Password":                             "암호",
	"LogIn":                                "로그인",
	"WelcomeTo":                            "환영합니다",
	"LogInWith":                            "로그인",
	"Error":                                "오류",
	"LoginIsRequiredPleaseTryAgain":        "로그인이 필요합니다. 다시 시도하십시오.",
	"CouldNotCheckCSRFTokenPleaseTryAgain": "CSRF 토큰을 확인할 수 없습니다. 다시 시도하십시오.",
	"InvalidLoginOrPasswordPleaseTryAgain": "로그인 또는 비밀번호가 잘못되었습니다. 다시 시도하십시오",
	"CouldNotCreateUser":                   "사용자를 만들 수 없습니다.",
	"CouldNotFindUser":                     "사용자를 찾을 수 없습니다.",
	"AnAuthenticationErrorOccurred":        "인증 오류가 발생했습니다.",
	"GrantErrorOccurred":                   "권한 부여 오류가 발생했습니다.",
}
