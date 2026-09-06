package presenter

import (
	"fmt"
	"strings"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/gui/localization"
)

// localizedCheckName translates current check IDs and keeps the supplied name
// as a compatibility fallback for snapshots produced by older versions.
func localizedCheckName(texts localization.Catalog, id, fallback string) string {
	keys := map[string]localization.Key{
		"target": localization.CheckTarget, "environment": localization.CheckEnvironment,
		"dns": localization.CheckDNS, "route": localization.CheckRoute,
		"tcp": localization.CheckTCP, "tls": localization.CheckTLS,
		"http": localization.CheckHTTP,
	}
	if key, ok := keys[strings.ToLower(strings.TrimSpace(id))]; ok {
		return texts.Text(key)
	}
	return fallback
}

func localizedPathRole(texts localization.Catalog, role model.NetworkPathRole) string {
	switch role {
	case model.NetworkPathRoleClientEffective:
		return texts.Text(localization.PathRoleClient)
	case model.NetworkPathRoleAddressMatrix:
		return texts.Text(localization.PathRoleMatrix)
	case model.NetworkPathRoleAuxiliaryDirect:
		return texts.Text(localization.PathRoleAuxiliary)
	default:
		return string(role)
	}
}

func localizedPathKind(texts localization.Catalog, kind model.NetworkPathKind) string {
	switch kind {
	case model.NetworkPathDirect:
		return texts.Text(localization.PathKindDirect)
	case model.NetworkPathHTTPProxy:
		return texts.Text(localization.PathKindHTTPProxy)
	case model.NetworkPathHTTPSConnect:
		return texts.Text(localization.PathKindConnect)
	default:
		return string(kind)
	}
}

func localizedHopKind(texts localization.Catalog, kind model.NetworkHopKind) string {
	switch kind {
	case model.NetworkHopOrigin:
		return texts.Text(localization.HopKindOrigin)
	case model.NetworkHopProxyPeer:
		return texts.Text(localization.HopKindProxy)
	case model.NetworkHopRedirect:
		return texts.Text(localization.HopKindRedirect)
	default:
		return string(kind)
	}
}

func localizedAttemptKind(texts localization.Catalog, kind model.NetworkAttemptKind) string {
	return localizedTimingPhase(texts, string(kind))
}

func localizedTimingPhase(texts localization.Catalog, phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "dns":
		return texts.Text(localization.TimingDNS)
	case "tcp", "connect":
		return texts.Text(localization.TimingTCP)
	case "tls", "handshake":
		return texts.Text(localization.TimingTLS)
	case "ttfb", "first_byte":
		return texts.Text(localization.TimingTTFB)
	default:
		return strings.ToUpper(strings.TrimSpace(phase))
	}
}

func referencedEvidenceForCheck(
	value model.Diagnosis,
	checkID string,
	references []string,
) []string {
	allowed := make(map[string]struct{}, len(references))
	for _, reference := range references {
		allowed[reference] = struct{}{}
	}
	result := make([]string, 0)
	for _, check := range value.Checks {
		if check.ID != checkID {
			continue
		}
		for _, evidence := range check.Evidence {
			if _, ok := allowed[evidence.ID]; ok {
				result = append(result, evidence.ID)
			}
		}
		break
	}
	return result
}

func fallbackBreakPoint(value model.Diagnosis) string {
	for _, check := range value.Checks {
		if check.Status == model.StatusFailed || check.Status == model.StatusCancelled {
			name := strings.TrimSpace(check.Name)
			if name == "" {
				name = check.ID
			}
			return name
		}
	}
	return ""
}

// localizedDomainText translates stable current domain copy. The fallback is
// intentional: old snapshots stored English prose before message references
// existed, and must remain readable rather than exposing an internal key.
func localizedDomainText(texts localization.Catalog, messageID, fallback string) string {
	if localization.LanguageOf(texts) != localization.LanguageRussian {
		return fallback
	}
	if translated, ok := russianDomainMessageIDs[strings.TrimSpace(messageID)]; ok {
		return translated
	}
	if translated, ok := russianDomainMessages[fallback]; ok {
		return translated
	}
	if translated, ok := localizedRussianDomainPattern(fallback); ok {
		return translated
	}
	if strings.HasPrefix(fallback, "The ") && strings.Contains(fallback, " stage exceeded its configured per-check budget") {
		stage := strings.TrimPrefix(strings.Split(fallback, " stage exceeded")[0], "The ")
		return fmt.Sprintf("Этап %s превысил настроенный тайм-аут проверки.", stage)
	}
	return fallback
}

func localizedRussianDomainPattern(fallback string) (string, bool) {
	var first, second, third, fourth int
	switch {
	case strings.HasPrefix(fallback, "Parsed ") && strings.HasSuffix(fallback, "."):
		parts := strings.SplitN(strings.TrimSuffix(strings.TrimPrefix(fallback, "Parsed "), "."), " target ", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("Цель %s разобрана и нормализована: %s.", parts[0], parts[1]), true
		}
	case strings.HasPrefix(fallback, "HTTP request succeeded with ") && strings.HasSuffix(fallback, "."):
		status := strings.TrimSuffix(strings.TrimPrefix(fallback, "HTTP request succeeded with "), ".")
		return fmt.Sprintf("HTTP-запрос успешно завершён со статусом %s.", status), true
	case strings.HasPrefix(fallback, "HTTP transport succeeded; the application returned ") && strings.HasSuffix(fallback, "."):
		status := strings.TrimSuffix(strings.TrimPrefix(fallback, "HTTP transport succeeded; the application returned "), ".")
		return fmt.Sprintf("Транспорт HTTP сработал; приложение вернуло статус %s.", status), true
	}
	if _, err := fmt.Sscanf(fallback, "TCP connections succeeded for all %d address(es).", &first); err == nil {
		return fmt.Sprintf("TCP-соединения успешно установлены для всех адресов: %d.", first), true
	}
	if _, err := fmt.Sscanf(fallback, "TCP connected to %d of %d address(es).", &first, &second); err == nil {
		return fmt.Sprintf("TCP-соединение установлено для %d из %d адресов.", first, second), true
	}
	if _, err := fmt.Sscanf(fallback, "TLS failed for all %d selected backend address(es).", &first); err == nil {
		return fmt.Sprintf("TLS не сработал ни для одного из выбранных адресов серверов: %d.", first), true
	}
	if _, err := fmt.Sscanf(fallback, "TLS succeeded for %d of %d selected backend address(es).", &first, &second); err == nil {
		return fmt.Sprintf("TLS сработал для %d из %d выбранных адресов серверов.", first, second), true
	}
	if _, err := fmt.Sscanf(fallback, "TLS verification succeeded, but %d selected certificate(s) approach expiration.", &first); err == nil {
		return fmt.Sprintf("Проверка TLS успешна, но срок действия выбранных сертификатов скоро истечёт: %d.", first), true
	}
	if _, err := fmt.Sscanf(fallback, "TLS negotiation, hostname validation, and trust validation succeeded for %d selected backend address(es).", &first); err == nil {
		return fmt.Sprintf("Согласование TLS, проверка имени и цепочки доверия успешны для выбранных адресов серверов: %d.", first), true
	}
	if _, err := fmt.Sscanf(fallback, "Discovered a source address for %d of %d selected remote address(es).", &first, &second); err == nil {
		return fmt.Sprintf("Локальный исходный адрес найден для %d из %d выбранных удалённых адресов.", first, second), true
	}
	if _, err := fmt.Sscanf(fallback, "%s lookup returned %d unique address(es).", new(string), &first); err == nil {
		recordType := strings.Fields(fallback)[0]
		return fmt.Sprintf("Поиск %s вернул уникальных адресов: %d.", recordType, first), true
	}
	if _, err := fmt.Sscanf(fallback, "TCP connection attempts were cancelled after %d of %d started attempt(s) completed; %d of %d address(es) were never started.", &first, &second, &third, &fourth); err == nil {
		return fmt.Sprintf("Попытки TCP отменены после завершения %d из %d начатых; %d из %d адресов не проверялись.", first, second, third, fourth), true
	}
	if _, err := fmt.Sscanf(fallback, "Route discovery was cancelled after %d of %d started attempt(s) completed; %d of %d selected address(es) were never started.", &first, &second, &third, &fourth); err == nil {
		return fmt.Sprintf("Определение маршрута отменено после завершения %d из %d начатых попыток; %d из %d выбранных адресов не проверялись.", first, second, third, fourth), true
	}
	return "", false
}

// russianDomainMessageIDs translates stable recommendation identifiers first.
// Text matching below remains only for summary prose and legacy snapshots that
// predate stable message identifiers.
var russianDomainMessageIDs = map[string]string{
	"environment.correct_proxy":           "Исправьте или явно отключите конфигурацию прокси и повторите попытку.",
	"environment.verify_proxy":            "Проверьте доступность выбранного прокси и убедитесь, что он предназначен для этой цели.",
	"dns.investigate_partial":             "Перед выводом о всём узле проверьте затронутое семейство адресов и данные резолвера.",
	"tcp.investigate_partial":             "Сравните маршрутизацию семейств адресов и слушающие сервисы для недоступных адресов.",
	"tcp.verify_service":                  "Проверьте маршрутизацию, фильтрацию пакетов и прослушивание сервисом целевого порта.",
	"tls.inspect_failures":                "Проверьте записанные ошибки TLS и конфигурацию сертификатов на недоступных адресах.",
	"tls.investigate_partial":             "Сравните конфигурацию сертификатов и TLS на недоступных адресах серверов.",
	"tls.enable_verification":             "Включите проверку TLS, прежде чем полагаться на это соединение.",
	"tls.renew_soon":                      "Обновите и разверните затронутый сертификат до истечения срока его действия.",
	"http.choose_connect_ip_route":        "Отключите прокси для этого запуска или удалите фиксированный IP подключения.",
	"http.configure_proxy_authentication": "Проверьте учётные данные прокси и политику его аутентификации.",
	"http.verify_status_expectation":      "Проверьте состояние сервиса и настроенный диапазон ожидаемых статусов.",
	"http.investigate_latency":            "Перед повтором проверьте время каждого перехода и задержку сервиса.",
	"http.investigate_server":             "Проверьте состояние сервиса, вышестоящие зависимости и журналы сервера.",
	"http.verify_request":                 "Проверьте URL, метод запроса, политику доступа и требуемую аутентификацию.",
	"dns.select_literal_family":           "Выберите семейство IP, соответствующее указанному адресу.",
}

//nolint:gosec // Translation source text names credentials but contains no credential values.
var russianDomainMessages = map[string]string{
	"Diagnosis completed":                           "Диагностика завершена",
	"Diagnosis completed with warnings":             "Диагностика завершена с предупреждениями",
	"Diagnosis detected a failure":                  "Диагностика выявила ошибку",
	"Diagnosis timed out":                           "Время диагностики истекло",
	"Diagnostic check timed out":                    "Время проверки истекло",
	"Diagnosis cancelled":                           "Диагностика отменена",
	"Invalid target":                                "Некорректная цель",
	"Proxy configuration is invalid":                "Некорректная конфигурация прокси",
	"DNS resolution failed":                         "Не удалось разрешить DNS-имя",
	"TCP connection failed":                         "Не удалось установить TCP-соединение",
	"TCP connections refused":                       "TCP-соединения отклонены",
	"TCP connections timed out":                     "Время TCP-соединений истекло",
	"Mixed TCP results":                             "Неодинаковые результаты TCP",
	"IPv4 reachable; IPv6 connection failed":        "IPv4 доступен, соединение IPv6 не удалось",
	"IPv6 reachable; IPv4 connection failed":        "IPv6 доступен, соединение IPv4 не удалось",
	"TLS certificate expired":                       "Срок действия сертификата TLS истёк",
	"TLS hostname mismatch":                         "Имя узла не соответствует сертификату TLS",
	"TLS chain is not trusted":                      "Цепочка TLS не является доверенной",
	"TLS certificate not yet valid":                 "Сертификат TLS ещё не действует",
	"TLS negotiation failed":                        "Согласование TLS не удалось",
	"HTTP redirect chain failed":                    "Цепочка HTTP-перенаправлений завершилась ошибкой",
	"Target reachable with HTTP client error":       "Цель доступна, но вернула клиентскую ошибку HTTP",
	"Target reachable with application-level error": "Цель доступна, но вернула ошибку приложения",
	"HTTP transport failed":                         "Транспорт HTTP завершился ошибкой",
	"HTTP request completed with warnings":          "HTTP-запрос завершён с предупреждениями",
	"Target reachable through selected proxy":       "Цель доступна через выбранный прокси",
	"Proxy selected":                                "Выбран прокси",
	"No applicable diagnostic checks":               "Нет применимых диагностических проверок",
	"Applicable diagnostic checks were skipped":     "Применимые диагностические проверки пропущены",
	"No adverse diagnostic facts were recorded.":    "Неблагоприятные диагностические факты не обнаружены.",
	"All applicable diagnostic checks completed without a failed critical check.":                               "Все применимые проверки завершились без критической ошибки.",
	"The global diagnosis timeout elapsed before every stage completed.":                                        "Общий тайм-аут истёк до завершения всех этапов.",
	"The target could not be validated, so no network conclusion can be made.":                                  "Цель не прошла проверку, поэтому сделать вывод о сети невозможно.",
	"The configured proxy was rejected, so Orynelo did not silently fall back to a direct request.":             "Настроенный прокси отклонён; Orynelo не стал незаметно переходить к прямому запросу.",
	"DNS produced no usable address for the requested IP mode. TCP reachability was therefore not tested.":      "DNS не вернул подходящего адреса для выбранного режима IP, поэтому доступность TCP не проверялась.",
	"The operation was cancelled before all diagnostic stages completed. Completed evidence remains available.": "Операция отменена до завершения всех этапов; уже собранные данные сохранены.",
	"Increase the global timeout or investigate the stage that consumed the available time.":                    "Увеличьте общий тайм-аут или проверьте этап, израсходовавший доступное время.",
	"Correct the target syntax and include a valid host and port.":                                              "Исправьте синтаксис цели и укажите корректные узел и порт.",
	"Correct or remove the invalid proxy setting, then run the diagnosis again.":                                "Исправьте или удалите некорректную настройку прокси и повторите диагностику.",
	"Verify the hostname, resolver configuration, and expected A or AAAA records.":                              "Проверьте имя узла, настройки резолвера и ожидаемые записи A или AAAA.",
	"Run the diagnosis again when the full result is needed.":                                                   "Повторите диагностику, если требуется полный результат.",
	"Renew and deploy the certificate, then verify the served chain.":                                           "Обновите и разверните сертификат, затем проверьте выдаваемую цепочку.",
	"Use the intended hostname or deploy a certificate whose SAN covers it.":                                    "Используйте нужное имя узла или сертификат, SAN которого включает это имя.",
	"Verify the intended trust root and that the server sends required intermediate certificates.":              "Проверьте корневой центр доверия и передачу сервером необходимых промежуточных сертификатов.",
	"Inspect the recorded TLS error, protocol support, and certificate configuration.":                          "Изучите ошибку TLS, поддержку протоколов и конфигурацию сертификата.",
	"Inspect each Location response and correct the redirect rules.":                                            "Проверьте каждый ответ Location и исправьте правила перенаправления.",
	"Inspect service health, dependencies, and server logs.":                                                    "Проверьте состояние сервиса, зависимости и журналы сервера.",
	"Review the HTTP evidence and the actual request path.":                                                     "Проверьте данные HTTP и фактический путь запроса.",
	"The TLS handshake timed out.":                                                                              "Время рукопожатия TLS истекло.",
	"The peer did not negotiate a compatible TLS protocol.":                                                     "Удалённая сторона не согласовала совместимый протокол TLS.",
	"The peer closed the connection during the TLS handshake.":                                                  "Удалённая сторона закрыла соединение во время рукопожатия TLS.",
	"The TLS handshake was cancelled.":                                                                          "Рукопожатие TLS отменено.",
	"The TLS handshake failed.":                                                                                 "Рукопожатие TLS завершилось ошибкой.",
	"The TLS certificate has expired.":                                                                          "Срок действия сертификата TLS истёк.",
	"The TLS certificate is not yet valid.":                                                                     "Сертификат TLS ещё не действует.",
	"The TLS certificate chain is not trusted by the system.":                                                   "Система не доверяет цепочке сертификата TLS.",
	"The TLS certificate is not valid for the target hostname.":                                                 "Сертификат TLS недействителен для целевого имени узла.",
	"TLS certificate verification failed.":                                                                      "Проверка сертификата TLS завершилась ошибкой.",
	"The hostname has addresses, but not for the requested IP family.":                                          "У имени узла есть адреса, но не для выбранного семейства IP.",
	"The DNS resolver reported that the hostname does not exist.":                                               "DNS-резолвер сообщил, что имя узла не существует.",
	"DNS answered successfully but returned no requested address records.":                                      "DNS ответил успешно, но не вернул запрошенных адресных записей.",
	"The DNS server could not complete the lookup.":                                                             "DNS-сервер не смог завершить поиск.",
	"DNS resolution timed out.":                                                                                 "Время разрешения DNS истекло.",
	"DNS resolution was cancelled.":                                                                             "Разрешение DNS отменено.",
	"DNS resolution failed for the requested IP mode.":                                                          "Разрешение DNS не удалось для выбранного режима IP.",
	"The HTTP request was cancelled.":                                                                           "HTTP-запрос отменён.",
	"The HTTP request timed out.":                                                                               "Время HTTP-запроса истекло.",
	"The configured proxy is invalid; direct fallback was blocked.":                                             "Настроенный прокси некорректен; прямой обход заблокирован.",
	"The selected proxy requires authentication.":                                                               "Выбранный прокси требует аутентификацию.",
	"An HTTPS to HTTP redirect was blocked by policy.":                                                          "Перенаправление с HTTPS на HTTP заблокировано политикой.",
	"A public to private-network redirect was blocked by policy.":                                               "Перенаправление из публичной в частную сеть заблокировано политикой.",
	"The target could not be parsed.":                                                                           "Не удалось разобрать цель.",
	"Target validation rejected the supplied value.":                                                            "Проверка цели отклонила переданное значение.",
	"The check stopped because of an internal error.":                                                           "Проверка остановлена из-за внутренней ошибки.",
	"The diagnostic check encountered an internal error.":                                                       "Во время диагностической проверки произошла внутренняя ошибка.",
	"The diagnostic check exceeded its configured timeout.":                                                     "Диагностическая проверка превысила настроенный тайм-аут.",
	"The check was cancelled before it started.":                                                                "Проверка отменена до запуска.",
	"The reserved actual-route budget was preserved.":                                                           "Резерв времени для фактического маршрута сохранён.",
	"The direct-origin comparison was not selected in client-effective proxy mode.":                             "Сравнение с прямым подключением к цели не выбрано в режиме фактического маршрута клиента.",
	"Only the actual proxy route was exercised; enable address-matrix mode for a direct-origin comparison.":     "Проверен только фактический маршрут через прокси; для прямого сравнения включите матрицу адресов.",
	"The direct-origin check was skipped because proxy selection did not complete.":                             "Прямая проверка цели пропущена, поскольку выбор прокси не завершился.",
	"No direct-origin network operation was started while proxy policy was unresolved.":                         "Пока политика прокси не определена, прямые сетевые операции с целью не запускались.",
	"The direct-origin check was skipped because proxy configuration is invalid.":                               "Прямая проверка цели пропущена из-за некорректной конфигурации прокси.",
	"No direct-origin network operation was started while the configured proxy was invalid.":                    "При некорректном настроенном прокси прямые сетевые операции с целью не запускались.",
	"Proxy environment does not apply to direct TCP diagnostics.":                                               "Переменные окружения прокси не применяются к прямой диагностике TCP.",
	"Proxy variables are configured, but this host:port target uses direct TCP checks.":                         "Переменные прокси настроены, но цель host:port проверяется напрямую по TCP.",
	"Direct HTTP was explicitly selected; proxy policy did not select an applicable proxy for this target.":     "Явно выбран прямой HTTP; политика прокси не выбрала подходящий прокси для этой цели.",
	"Proxy use is explicitly disabled for this diagnosis.":                                                      "Использование прокси явно отключено для этой диагностики.",
	"The configured proxy is invalid; direct fallback is blocked.":                                              "Настроенный прокси некорректен; прямой обход заблокирован.",
	"Proxy selection failed closed before any HTTP request was sent.":                                           "Выбор прокси завершился безопасным отказом до отправки HTTP-запроса.",
	"Proxy rules explicitly bypass this target.":                                                                "Правила прокси явно исключают эту цель.",
	"A direct HTTP route was selected by an explicit bypass rule.":                                              "Явное правило обхода выбрало прямой маршрут HTTP.",
	"Configured proxy variables do not apply to this target scheme.":                                            "Настроенные переменные прокси не применяются к схеме этой цели.",
	"The configured scheme-specific proxy does not apply to this target URL.":                                   "Прокси для конкретной схемы не применяется к URL этой цели.",
	"A proxy is selected for the actual HTTP request.":                                                          "Для фактического HTTP-запроса выбран прокси.",
	"Proxy environment rules selected a validated proxy for the target.":                                        "Правила окружения прокси выбрали проверенный прокси для цели.",
	"No proxy is configured for this target.":                                                                   "Для этой цели прокси не настроен.",
	"The actual HTTP request will use a direct route because no proxy is configured.":                           "Фактический HTTP-запрос пойдёт напрямую, поскольку прокси не настроен.",
	"The target is missing a host or port.":                                                                     "В цели отсутствует имя узла или порт.",
	"The target was parsed and normalized.":                                                                     "Цель разобрана и нормализована.",
	"The target is an IP literal; DNS lookup is not required.":                                                  "Цель задана IP-адресом; поиск DNS не требуется.",
	"The target contains a canonical IP address.":                                                               "Цель содержит канонический IP-адрес.",
	"The target IP family does not match the requested IP mode.":                                                "Семейство IP цели не соответствует выбранному режиму IP.",
	"The literal address family does not match the requested IP mode.":                                          "Семейство указанного адреса не соответствует выбранному режиму IP.",
	"Resolver provenance available to this platform was collected.":                                             "Собраны доступные на этой платформе сведения о происхождении ответа резолвера.",
	"Optional detailed DNS evidence could not be collected.":                                                    "Не удалось собрать дополнительные подробные данные DNS.",
	"Resolved backend addresses were omitted by the configured probe bound.":                                    "Часть разрешённых адресов серверов пропущена из-за настроенного ограничения проверок.",
	"The system resolver reported no result without exposing whether it was NXDOMAIN or NODATA.":                "Системный резолвер не вернул результат и не сообщил, был ли это NXDOMAIN или NODATA.",
	"A records are absent; the other address family remains usable in auto mode.":                               "Записи A отсутствуют; другое семейство адресов остаётся доступным в автоматическом режиме.",
	"AAAA records are absent; the other address family remains usable in auto mode.":                            "Записи AAAA отсутствуют; другое семейство адресов остаётся доступным в автоматическом режиме.",
	"Route discovery was skipped because no selected remote addresses are available.":                           "Определение маршрута пропущено: выбранные удалённые адреса отсутствуют.",
	"A local source address was selected, but interface metadata is incomplete.":                                "Локальный исходный адрес выбран, но сведения об интерфейсе неполны.",
	"Route source discovery was cancelled after it started.":                                                    "Определение исходного адреса маршрута отменено после запуска.",
	"Some local interface metadata could not be enumerated.":                                                    "Не удалось получить часть сведений о локальных интерфейсах.",
	"Route probes omitted resolved backends beyond the configured address bound.":                               "Проверки маршрута пропустили адреса серверов сверх настроенного ограничения.",
	"No local source address could be discovered for the selected addresses.":                                   "Не удалось определить локальный исходный адрес для выбранных адресов.",
	"TCP checks were skipped because no remote addresses are available.":                                        "Проверки TCP пропущены: удалённые адреса отсутствуют.",
	"Additional resolved addresses were not probed because the configured address limit was reached.":           "Дополнительные разрешённые адреса не проверялись из-за настроенного лимита.",
	"The client-effective probe stopped after selecting a usable connection path.":                              "Проверка фактического маршрута клиента завершилась после выбора рабочего пути соединения.",
	"TCP connection failed.":                                                                                    "Не удалось установить TCP-соединение.",
	"TCP connection attempt was cancelled.":                                                                     "Попытка TCP-соединения отменена.",
	"The client-effective TCP probe selected a reachable backend address.":                                      "Проверка фактического TCP-маршрута выбрала доступный адрес сервера.",
	"TCP connections failed for all resolved addresses.":                                                        "TCP-соединения не установлены ни с одним разрешённым адресом.",
	"Every remote address refused the TCP connection.":                                                          "Каждый удалённый адрес отклонил TCP-соединение.",
	"Every TCP connection attempt timed out.":                                                                   "Время каждой попытки TCP-соединения истекло.",
	"The network was unreachable for every TCP connection attempt.":                                             "Сеть была недоступна для каждой попытки TCP-соединения.",
	"The remote host was unreachable for every TCP connection attempt.":                                         "Удалённый узел был недоступен для каждой попытки TCP-соединения.",
	"TLS is not enabled for this target.":                                                                       "TLS не включён для этой цели.",
	"TLS was skipped because no TCP connection succeeded.":                                                      "TLS пропущен, поскольку ни одно TCP-соединение не было установлено.",
	"The configured custom CA bundle could not be used.":                                                        "Не удалось использовать настроенный пользовательский набор CA.",
	"Custom trust roots were rejected before a TLS connection was started.":                                     "Пользовательские корни доверия отклонены до запуска TLS-соединения.",
	"All TLS attempts were cancelled.":                                                                          "Все попытки TLS отменены.",
	"TLS negotiation succeeded, but certificate verification is disabled.":                                      "Согласование TLS успешно, но проверка сертификата отключена.",
	"TLS peer and certificate metadata were collected.":                                                         "Собраны сведения об узле TLS и сертификате.",
	"The address-specific TLS attempt recorded a failure.":                                                      "Попытка TLS для конкретного адреса завершилась ошибкой.",
	"Check system time and deploy a certificate with a valid time window.":                                      "Проверьте системное время и разверните сертификат с корректным периодом действия.",
	"Deploy a chain anchored in an intended trust root, including required intermediate certificates.":          "Разверните цепочку до нужного корня доверия, включая необходимые промежуточные сертификаты.",
	"Use the intended hostname or deploy a certificate whose SAN covers this target.":                           "Используйте нужное имя узла или сертификат, SAN которого включает эту цель.",
	"Inspect the peer certificate chain and TLS endpoint configuration.":                                        "Проверьте цепочку сертификатов узла и конфигурацию конечной точки TLS.",
	"HTTP is not enabled for this TCP target.":                                                                  "HTTP не включён для этой TCP-цели.",
	"HTTP was not sent because proxy selection did not complete.":                                               "HTTP-запрос не отправлен, поскольку выбор прокси не завершился.",
	"The HTTP check failed closed before transport because proxy policy was unresolved.":                        "Проверка HTTP завершилась безопасным отказом до транспорта из-за неопределённой политики прокси.",
	"HTTP was not sent because the configured proxy is invalid.":                                                "HTTP-запрос не отправлен из-за некорректного настроенного прокси.",
	"The HTTP check failed closed instead of using a direct fallback.":                                          "Проверка HTTP завершилась безопасным отказом вместо прямого обхода.",
	"The HTTP request could not be constructed.":                                                                "Не удалось сформировать HTTP-запрос.",
	"The HTTP request was not sent because a fixed connect IP is incompatible with the selected proxy route.":   "HTTP-запрос не отправлен: фиксированный IP подключения несовместим с выбранным маршрутом прокси.",
	"Proxy selection did not complete, so the HTTP request was blocked.":                                        "Выбор прокси не завершился, поэтому HTTP-запрос заблокирован.",
	"The selected proxy could not establish the HTTP connection.":                                               "Выбранный прокси не смог установить HTTP-соединение.",
	"The custom certificate-authority bundle is invalid.":                                                       "Пользовательский набор центров сертификации некорректен.",
	"The configured connect IP is invalid.":                                                                     "Настроенный IP подключения некорректен.",
	"A redirect was blocked because its network scope could not be resolved safely.":                            "Перенаправление заблокировано: не удалось безопасно определить его сетевую область.",
	"A redirect Location exceeded the configured byte limit.":                                                   "Значение Location перенаправления превысило настроенный лимит размера.",
	"The HTTP redirect chain contains a loop.":                                                                  "Цепочка HTTP-перенаправлений содержит цикл.",
	"The HTTP response exceeded the configured redirect limit.":                                                 "HTTP-ответ превысил настроенный лимит перенаправлений.",
	"The HTTP transport request failed.":                                                                        "Транспортный HTTP-запрос завершился ошибкой.",
	"The HTTP response status did not match the configured expectation.":                                        "Статус HTTP-ответа не соответствует настроенному ожиданию.",
	"The HTTP response exceeded the configured latency threshold.":                                              "HTTP-ответ превысил настроенный порог задержки.",
	"The HTTP response arrived, but its bounded body could not be read completely.":                             "HTTP-ответ получен, но ограниченное тело не удалось прочитать полностью.",
	"Bounded HTTP transport and response metadata were collected.":                                              "Собраны ограниченные сведения о транспорте HTTP и ответе.",
	"HTTP redirect policy allowed this hop.":                                                                    "Политика HTTP-перенаправлений разрешила этот переход.",
	"HTTP redirect policy blocked this hop.":                                                                    "Политика HTTP-перенаправлений заблокировала этот переход.",
	"Cross-origin redirect followed after sensitive headers were removed.":                                      "Междоменное перенаправление выполнено после удаления чувствительных заголовков.",
	"Cross-origin redirect followed with sensitive-header forwarding blocked by policy.":                        "Междоменное перенаправление выполнено без передачи чувствительных заголовков согласно политике.",
}
