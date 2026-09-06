package report

import (
	"strings"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

// RenderLocalized renders canonical JSON unchanged and localizes the stable
// structure of human-readable text/Markdown reports.
func RenderLocalized(
	diagnosis model.Diagnosis,
	format Format,
	language string,
	modes ...privacy.Mode,
) ([]byte, error) {
	content, err := Render(diagnosis, format, modes...)
	if err != nil || format == FormatJSON || strings.ToLower(strings.TrimSpace(language)) != "ru" {
		return content, err
	}
	return localizeRussianReport(content), nil
}

func localizeRussianReport(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	for index, line := range lines {
		lines[index] = localizeRussianReportLine(line)
	}
	return []byte(strings.Join(lines, "\n"))
}

func localizeRussianReportLine(line string) string {
	exact := map[string]string{
		"Orynelo diagnostic report":                  "Диагностический отчёт Orynelo",
		"# Orynelo diagnostic report":                "# Диагностический отчёт Orynelo",
		"Network paths:":                             "Сетевые пути:",
		"## Network paths":                           "## Сетевые пути",
		"Checks:":                                    "Проверки:",
		"## Checks":                                  "## Проверки",
		"Evidence:":                                  "Данные проверки:",
		"Recommended actions:":                       "Рекомендуемые действия:",
		"Recommended next actions:":                  "Рекомендуемые следующие действия:",
		"## Recommended next actions":                "## Рекомендуемые следующие действия",
		"- No correlated network path was recorded.": "- Связанный сетевой путь не записан.",
		"No correlated network path was recorded.":   "Связанный сетевой путь не записан.",
	}
	if translated, ok := exact[line]; ok {
		return translated
	}
	prefixes := [][2]string{
		{"Target: ", "Цель: "}, {"Status: ", "Статус: "},
		{"Started: ", "Начало: "}, {"Finished: ", "Завершение: "},
		{"Duration: ", "Длительность: "}, {"Summary: ", "Итог: "},
		{"Scenario: ", "Сценарий: "}, {"Redirect policy: ", "Политика перенаправлений: "},
		{"Redirect limits: ", "Лимиты перенаправлений: "},
		{"Probe mode: ", "Режим проверки: "},
		{"   Error code: ", "   Код ошибки: "}, {"   Role: ", "   Роль: "},
		{"   Check ID: ", "   ID проверки: "}, {"   Started: ", "   Начало: "},
		{"   Finished: ", "   Завершение: "}, {"   Evidence: ", "   Данные проверки: "},
		{"     Evidence ID: ", "     ID данных: "}, {"     Evidence code: ", "     Код данных: "},
		{"   Next: ", "   Далее: "},
		{"- **Target:** ", "- **Цель:** "}, {"- **Status:** ", "- **Статус:** "},
		{"- **Started:** ", "- **Начало:** "}, {"- **Finished:** ", "- **Завершение:** "},
		{"- **Duration:** ", "- **Длительность:** "}, {"- **Probe mode:** ", "- **Режим проверки:** "},
		{"- **Address limit:** ", "- **Лимит адресов:** "}, {"- **Matrix budget:** ", "- **Бюджет матрицы:** "},
		{"- **Scenario:** ", "- **Сценарий:** "}, {"- **Redirect policy:** ", "- **Политика перенаправлений:** "},
		{"- **Redirect limits:** ", "- **Лимиты перенаправлений:** "},
		{"- **Actual HTTP reserve:** ", "- **Фактический резерв HTTP:** "},
		{"- **Error code:** ", "- **Код ошибки:** "}, {"- **Role:** ", "- **Роль:** "},
		{"- **Check ID:** ", "- **ID проверки:** "},
	}
	for _, replacement := range prefixes {
		if strings.HasPrefix(line, replacement[0]) {
			line = replacement[1] + strings.TrimPrefix(line, replacement[0])
			switch replacement[0] {
			case "Redirect limits: ":
				line = strings.Replace(line, "; actual HTTP reserve: ", "; фактический резерв HTTP: ", 1)
			case "Probe mode: ":
				line = strings.Replace(line, "; address limit: ", "; лимит адресов: ", 1)
				line = strings.Replace(line, "; matrix budget: ", "; бюджет матрицы: ", 1)
			}
			return line
		}
	}
	if strings.HasPrefix(line, "- ") && strings.Contains(line, ": role=") {
		line = strings.Replace(line, ": role=", ": роль=", 1)
		line = strings.Replace(line, " kind=", " тип=", 1)
		return line
	}
	if strings.HasPrefix(line, "    - ") && strings.Contains(line, ": kind=") {
		replacements := [][2]string{{": kind=", ": тип="}, {" state=", " состояние="}, {" remote=", " удалённый="}, {" local=", " локальный="}, {" selected=", " выбрана="}, {" reused=", " переиспользовано="}}
		for _, replacement := range replacements {
			line = strings.Replace(line, replacement[0], replacement[1], 1)
		}
		return line
	}
	if strings.HasPrefix(line, "    - timing ") {
		return "    - время " + strings.TrimPrefix(line, "    - timing ")
	}
	if strings.HasPrefix(line, "  - ") &&
		(strings.Contains(line, "; selected=") || strings.Contains(line, "; remote=")) {
		replacements := [][2]string{{"; selected=", "; выбрана="}, {"; remote=", "; удалённый="}, {"; local=", "; локальный="}, {"; reused=", "; переиспользовано="}}
		for _, replacement := range replacements {
			line = strings.Replace(line, replacement[0], replacement[1], 1)
		}
		return line
	}
	if strings.HasPrefix(line, "- `") && strings.Contains(line, ": role `") {
		line = strings.Replace(line, ": role `", ": роль `", 1)
		line = strings.Replace(line, ", kind `", ", тип `", 1)
		return line
	}
	if strings.HasPrefix(line, "    - `") && strings.Contains(line, ", state `") {
		replacements := [][2]string{{", state `", ", состояние `"}, {", remote `", ", удалённый `"}, {", local `", ", локальный `"}, {", selected `", ", выбрана `"}, {", reused `", ", переиспользовано `"}}
		for _, replacement := range replacements {
			line = strings.Replace(line, replacement[0], replacement[1], 1)
		}
		return line
	}
	if strings.HasPrefix(line, "    - timing `") {
		return "    - время `" + strings.TrimPrefix(line, "    - timing `")
	}
	if strings.HasPrefix(line, "  - `") && strings.Contains(line, " at `") {
		line = strings.Replace(line, " at `", " по адресу `", 1)
		replacements := [][2]string{{"; selected `", "; выбрана `"}, {"; remote `", "; удалённый `"}, {"; local `", "; локальный `"}, {"; reused `", "; переиспользовано `"}}
		for _, replacement := range replacements {
			line = strings.Replace(line, replacement[0], replacement[1], 1)
		}
		return line
	}
	return line
}
