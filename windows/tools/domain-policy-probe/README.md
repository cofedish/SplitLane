# Безопасный live-стенд доменных политик

Временная elevated проверка существующих production packet/relay компонентов
с конфигурацией в памяти. Не устанавливает продукт, не останавливает службы
и не заменяет `%ProgramData%\SplitLane`. Remy и её службы не затрагиваются.

Стенд требует остановленного `pktmon` без фильтров и отсутствия другого
`SplitLane.Engine`. Не используйте одновременно с другим capture. Состояние
предварительно проверяется для русского/английского вывода `pktmon`.

Из `windows/`:

```powershell
dotnet build tools/domain-policy-probe/SplitLane.DomainPolicyProbe.csproj -c Release
pktmon list --all
.\tools\domain-policy-probe\bin\Release\net10.0-windows\win-x64\SplitLane.DomainPolicyProbe.exe <НОВЫЙ-КАТАЛОГ> <PHYSICAL-COMPONENT-ID> <DNS-IP> www.example.com
```

Выберите ID нижнего физического адаптера, не виртуального коммутатора.
DNS-IP должен отвечать на обычный UDP DNS. Порт 53 на машине стенд не занимает,
DNS-настройки не изменяет. Адрес origin берётся из DNS-ответа при каждом запуске.

Фазы: прямой TCP/UDP контроль, недоступный SOCKS5 proxy, timeout, неверный пароль,
исправный proxy. Для защищённых фаз запрещены все исходящие пакеты к origin:
проверяются physical Lower counters и WinDivert sniff после routing. Для
исправного proxy также требуется domain CONNECT. Тестовый proxy не поддерживает
успешную UDP association: её отказ должен блокировать датаграммы.

Артефакты: physical `*.counters.json`, raw-IP `*.post-routing.pcap`, исходный
`*.etl` и экспорт `*.pcapng`. Последний может оказаться пустым на некоторых
Windows: его пустота не считается доказательством. PCAP после routing — отдельная
точка наблюдения; physical counters подтверждают поведение адаптера.

Стенд сохраняет артефакты, завершает свои ресурсы в `finally`, не убивает процессы
по имени и не перезагружает машину. При аварийном принудительном завершении
самого стенда проверьте `pktmon status` и фильтры вручную; WinDivert handles
закрываются при выходе процесса. Остановленный перехват не даёт fail-closed защиты.

Подробный протокол и ограничения: [DOMAIN_POLICY_VALIDATION.md](../../docs/DOMAIN_POLICY_VALIDATION.md).
