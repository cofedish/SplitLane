# Проверка доменных политик на рабочей Windows

Дата: 2026-10-02. Ветка: `feature/domain-policies`.
Это промежуточный протокол проверки, а не заявление о завершении всей задачи.

## Репозиторий

- Remote: `https://github.com/cofedish/SplitLane.git`.
- Исходная ветка: `windows`, upstream: `origin/windows`.
- Локальный и полученный через `git fetch --prune origin` upstream HEAD перед работой:
  `f7056147b7027c54cd7f9124561974a85dc1121e`.
- Локальное и удалённое деревья совпадали; ahead/behind: `0/0`.
- До начала задачи незакоммиченных и untracked изменений не было.
- Pull, merge и rebase не потребовались. Новая ветка создана от проверенного HEAD.

## Фактически выполнено

- `dotnet test SplitLane.Windows.slnx -c Release`: Core 527, Engine 202;
  всего 729 успешных тестов, 0 ошибок, 0 пропусков.
- `dotnet build SplitLane.Windows.slnx -c Release --no-restore`: все проекты,
  включая WPF App, собраны; 0 ошибок и 0 предупреждений.
- Пять новых socket-интеграционных сценариев `ProxyOnlyIntegrationTests`:
  недоступный proxy, timeout handshake, неверный пароль, отказ CONNECT,
  закрытие настоящего соединения proxy во время greeting. В каждом случае
  контрольный доступный TCP origin не получил прямого подключения.
  Проверка — отсутствие pending accept у слушающего socket, а не timeout приложения.
- `DomainPacketPolicyTests`: 13 проверок результата настоящего classifier на
  буферах TCP/UDP IPv4/IPv6. Драйвер и физическая сеть в этих тестах не участвуют.
- `NatTableTests.StrictPolicyDoesNotExpireIntoDirectWhileSocketIsOpen`:
  продвижение тестового времени на час не снимает `PROXY_ONLY` и `BLOCK`;
  закрытие сокета очищает записи.
- `dotnet format ... whitespace --verify-no-changes --no-restore --include ...`:
  успешно для изменённых в ходе этой проверки packet/NAT модулей, новых Engine
  тестов, `DomainPattern` и `DomainPolicySnapshot`; не полная проверка formatting всей solution.
- `dotnet list SplitLane.Windows.slnx package --vulnerable --include-transitive`:
  известных уязвимых пакетов по текущим источникам NuGet не найдено.
- `git diff --check`: ошибок whitespace нет; Git сообщает только о преобразовании LF/CRLF.
- Первоначальный Release engine `--check`: `WinDivert.dll: found`, `Elevated: no`.
  После запуска elevated сессии проверен настоящий WinDivert 2.2.
- Служба `SplitLane` остановлена, `StartMode: Manual`, использует установленный
  `C:\Program Files\SplitLane\Engine\SplitLane.Engine.exe`, а не новую сборку из репозитория.

## Исправления, выявленные проверкой

1. Позднее решение `PROXY_ONLY` больше не пропускает ACK/data напрямую, если SYN
   не был перенаправлен. Теперь результат — `Drop`, приложение должно переподключиться.
2. Истечение обычного пятиминутного срока NAT больше не отменяет `PROXY_ONLY`,
   `BLOCK` или pending verification. Записи ограничены пространством source ports;
   потерянное CLOSE может удержать запись до её замены или остановки routing.
3. При отсутствии UDP BIND распознанное защищённое назначение удерживается,
   но посторонний UDP, включая DNS, не блокируется только из-за наличия доменных правил.
4. Live-захват выявил исходящие FIN/ACK после CLOSE. Добавлены ограниченные
   tombstone и отказ для потерянной атрибуции распознанного строгого назначения.
   Новый CONNECT заменяет tombstone. UDP CLOSE больше не удаляет TCP NAT на том же порту.
5. `DivertHandle.Shutdown` вызывал SEND-only вместо BOTH. Исправлено значение
   с `2` на `3`; завершение Receive и остановка стенда подтверждены реальным запуском.
   Значения сверены с [исходным заголовком WinDivert](https://github.com/basil00/WinDivert/blob/master/include/windivert.h).

## Live-проверка после получения прав администратора

Проверка выполнена `tools/domain-policy-probe`: production `DivertPipeline`,
`RedirectListener`, `DnsObserver` и SOCKS5 testbed, конфигурация только в памяти.
Тестовые приложения — отдельные дочерние процессы, не self-traffic engine.
Нормальный DNS-ответ получен через `8.8.8.8`, имя `www.example.com` распознано
живым packet loop, а не вручную добавлено в DNS observer.

Последний успешный прогон: `windows/artifacts/domain-live-20261002-08`.
В нём выбран `8.6.112.0`; для каждого запуска IP берётся из настоящего DNS-ответа.
Измерялся physical component `69`, `Realtek PCIe 2.5GbE Family Controller`,
Lower/Outbound, с фильтром по тестовому IP. Независимый WinDivert sniff priority
`-100` фиксировал исходящие TCP/UDP к origin после policy routing в обычный PCAP.

| Сценарий | Физические исходящие пакеты к origin | Post-routing пакеты к origin |
|---|---:|---:|
| Прямой положительный контроль | 7 | 7 (3 UDP и 4 TCP) |
| Proxy недоступен | 0 | 0 |
| Proxy timeout | 0 | 0 |
| Неверный пароль proxy | 0 | 0 |
| Исправный proxy | 0 | 0; proxy получил `CONNECT www.example.com:80` |

При неверном пароле TCP activity содержит `AuthenticationFailed`, UDP association
отказана. Стенд требует ненулевой прямой контроль с TCP и UDP, проверяет physical
счётчики и содержимое PCAP и завершается ошибкой при утечке. Это не вывод по timeout.

Экспорт `pktmon` ETL в PCAPNG на этой Windows дал пустые файлы даже при ненулевом
прямом контроле. Они НЕ используются как доказательство. Доказательства —
`*.counters.json` физического адаптера и независимые `*.post-routing.pcap`.
Первые прогоны сохранены, включая воспроизведение FIN/ACK до исправления;
PASS относится к последнему прогону, не к этим ранним артефактам.

Remy (`PID 8924`) и `remy-service` (`PID 5244`) сохранили PID и время запуска.
Служба SplitLane осталась остановленной, как до проверки. Пользовательская
конфигурация и installation не изменялись. После проверки нет тестовых процессов,
`pktmon` остановлен, тестовый фильтр удалён.

## Что не проверено и не гарантируется

Socket-тесты подтверждают отсутствие fallback в relay, но не доказывают отсутствие
утечки во всех возможных путях WinDivert. Live-проверка относится к выбранному
IPv4 origin, нормальному DNS, TCP/UDP и указанным сценариям.
IPv6 проверен unit-тестами, но не live-захватом. Нет подтверждения для crash,
restart и reboot; перезагрузка не выполнялась, чтобы не останавливать Remy.
Постоянного WFP/firewall барьера нет: остановленный перехват не защищает сеть.
DNS cache до запуска, DoH/DoT, неоднозначные shared IP и неполные TCP DNS frames
не дают надёжного имени. IPv6 extension headers требуют отдельной проверки.

## Как повторить на Windows

1. Открыть elevated терминал. Убедиться, что другой engine и `pktmon` не запущены
   и существующих фильтров `pktmon` нет. Стенд отказывается заменять их.
2. Из `windows/` собрать стенд:
   `dotnet build tools/domain-policy-probe/SplitLane.DomainPolicyProbe.csproj -c Release`.
3. Через `pktmon list --all` выбрать physical component. На проверенной машине — `69`.
4. Запустить, указав НОВЫЙ каталог артефактов:

   ```powershell
   .\tools\domain-policy-probe\bin\Release\net10.0-windows\win-x64\SplitLane.DomainPolicyProbe.exe E:\Projects\SplitLane\windows\artifacts\domain-manual-NEW 69 8.8.8.8 www.example.com
   ```

5. Ожидать `PASS` и код `0`. Сопоставить `direct-control.counters.json`
   (Outbound > 0) с защищёнными фазами (Outbound = 0).
   Открыть `*.post-routing.pcap` в Wireshark: контроль содержит SYN и UDP;
   защищённые фазы не содержат исходящих пакетов к origin.

Скрипты `verify-divert.ps1`, `stress-divert.ps1` и `measure-direct-cost.ps1`
не запускались: они могут удалить пользовательские данные. Стенд не изменяет
службы, credentials, DNS-настройки или конфигурацию SplitLane. Он временно
перехватывает трафик машины и не является production-установкой новой версии.
