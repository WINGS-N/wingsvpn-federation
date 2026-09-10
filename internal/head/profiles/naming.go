package profiles

import (
	"fmt"
	"strings"
)

// DisplayName собирает имя, которое человек видит в списке серверов:
// флаг, страна, номер внутри страны и транспорт
func DisplayName(country string, index int, transport string) string {
	name := CountryName(country)
	if flag := CountryFlag(country); flag != "" {
		// VKTP выходит через релеи ВК, поэтому к флагу страны добавляется
		// белый: точка выхода принадлежит не ноде
		if strings.EqualFold(transport, "vktp") {
			flag += "\U0001F3F3"
		}
		name = flag + " " + name
	}
	if index > 0 {
		name = fmt.Sprintf("%s #%d", name, index)
	}
	if transport == "" {
		return name
	}
	return name + " / " + strings.ToUpper(transport)
}

// CountryFlag превращает код страны в эмодзи: две буквы кода заменяются
// региональными индикаторами, из которых шрифт и собирает флаг
func CountryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	const base = 0x1F1E6
	runes := make([]rune, 0, 2)
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return ""
		}
		runes = append(runes, rune(base+int(c-'A')))
	}
	return string(runes)
}

// countryNames - страны, где ноды бывают чаще всего. Остальные показываются
// кодом: выдуманное название хуже честных двух букв
var countryNames = map[string]string{
	"RU": "Russia", "DE": "Germany", "NL": "Netherlands", "FI": "Finland",
	"FR": "France", "GB": "United Kingdom", "US": "United States", "SE": "Sweden",
	"PL": "Poland", "LV": "Latvia", "LT": "Lithuania", "EE": "Estonia",
	"KZ": "Kazakhstan", "AM": "Armenia", "GE": "Georgia", "TR": "Turkey",
	"CH": "Switzerland", "AT": "Austria", "CZ": "Czechia", "MD": "Moldova",
	"UA": "Ukraine", "BY": "Belarus", "RS": "Serbia", "BG": "Bulgaria",
	"RO": "Romania", "IT": "Italy", "ES": "Spain", "CA": "Canada",
	"JP": "Japan", "SG": "Singapore", "HK": "Hong Kong", "AE": "UAE",
}

// CountryName - человеческое название страны или её код
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return "Node"
	}
	if name, ok := countryNames[code]; ok {
		return name
	}
	return code
}
