
# Secure Signing Platform (Schulprojekt)
~~~text
  
  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗   ███████╗██╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝   ██╔════╝██║██╔════╝ ████╗  ██║██║████╗  ██║██╔════╝
  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗     ███████╗██║██║  ███╗██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝     ╚════██║██║██║   ██║██║╚██╗██║██║██║╚██╗██║██║   ██║
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗   ███████║██║╚██████╔╝██║ ╚████║██║██║ ╚████║╚██████╔╝
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝

                    ██████╗ ██╗      █████╗ ████████╗███████╗ ██████╗ ██████╗ ███╗   ███╗
                    ██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗████╗ ████║
                    ██████╔╝██║     ███████║   ██║   █████╗  ██║   ██║██████╔╝██╔████╔██║
                    ██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║
                    ██║     ███████╗██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║
                    ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝

~~~

![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)
---



Dieses Projekt ist ein Schulprojekt und demonstriert, wie ein sicheres
Signatur-System mit Client‑Server Architektur aufgebaut werden kann.

Ziel des Projekts ist es zu zeigen:

-   wie digitale Signaturen funktionieren
-   wie ein zentraler Signing‑Server arbeitet
-   wie Clients Signaturen erstellen und prüfen
-   wie Audit Logs und Monitoring integriert werden
-   wie ein Security System nachvollziehbar überwacht werden kann

Das System basiert auf **Python**, **Ed25519 Signaturen**, **Audit
Logging** und **Monitoring über Grafana**.

Wichtig: Dieses Projekt ist ein **Lern- und Demonstrationssystem** und
nicht für den produktiven Einsatz gedacht.

------------------------------------------------------------------------

# Systemübersicht

Das System besteht aus drei Hauptkomponenten.

1.  Signing Server\
2.  Client Agent\
3.  Monitoring System (Grafana + Metrics)

Architektur:

``` text
           +---------------------+
           |     Grafana         |
           |  Monitoring UI      |
           +----------+----------+
                      |
                      |
               +------+------ +
               |  Signing    |
               |   Server    |
               |  API + Logs |
               +------+------ +
                      |
        +-------------+-------------+
        |                           |
   +----+----+                 +----+----+
   | Client  |                 | Client  |
   | Agent   |                 | Agent   |
   +---------+                 +---------+
```

------------------------------------------------------------------------

# Projektstruktur

``` text
secure-signing-platform
│
├── client
│   ├── bin
│   │   ├── sign.py
│   │   ├── verify.py
│   │   └── log_client_daemon.py
│   │
│   ├── config
│   │   └── client.yaml
│   │
│   ├── keys
│   ├── logs
│   └── systemd
│
├── server
│   ├── api
│   │   └── app.py
│   │
│   ├── audit
│   │   └── audit.log
│   │
│   ├── config
│   │   └── service.yaml
│   │
│   ├── keys
│   ├── tls
│   ├── monitoring
│   │   └── dashboard.py
│   └── systemd
│
├── monitoring
│   ├── grafana
│   └── prometheus
│
├── requirements.txt
├── README.md
└── LICENSE
```

------------------------------------------------------------------------

# Voraussetzungen

Das Projekt benötigt folgende Software:

Python 3.9 oder neuer\
pip\
systemd (Linux)\
Grafana\
Prometheus (optional für Metrics)

Installation der Grundpakete:

``` bash
sudo apt update
sudo apt install python3 python3-pip grafana prometheus
```

------------------------------------------------------------------------

# Schritt 1 -- Repository klonen

``` bash
git clone https://github.com/username/secure-signing-platform.git
cd secure-signing-platform
```

------------------------------------------------------------------------

# Schritt 2 -- Python Abhängigkeiten installieren

``` bash
pip install -r requirements.txt
```

Typische Libraries:

-   fastapi
-   uvicorn
-   cryptography
-   pynacl
-   requests
-   pyyaml

------------------------------------------------------------------------

# Schritt 3 -- Server konfigurieren

Server Konfigurationsdatei:

    server/config/service.yaml

Beispiel:

``` yaml
server:
  host: 0.0.0.0
  port: 8080

security:
  algorithm: ed25519

logging:
  audit_log: server/audit/audit.log
```

------------------------------------------------------------------------

# Schritt 4 -- Schlüssel generieren

Digitale Signaturen benötigen ein Key Pair.

Hinweis: Beim ersten Start erzeugt der Service automatisch:
         server/keys/private.pem server/keys/public.pem

``` bash
mkdir server/keys
python3 generate_keys.py
```

Erzeugt:

``` text
server/keys/private.pem
server/keys/public.pem
```

Der **Private Key darf niemals veröffentlicht werden**.

------------------------------------------------------------------------

# Schritt 5 -- Signing Server starten

``` bash
cd server/api

uvicorn app:app --host 0.0.0.0 --port 8080
```

API Test:

``` bash
curl http://localhost:8080/health
```

Antwort:

``` json
{"status":"ok"}
```

------------------------------------------------------------------------

# Schritt 6 -- Client konfigurieren

Datei:

    client/config/client.yaml

Beispiel:

``` yaml
server:
  url: http://server:8080

keys:
  public_key: keys/public.pem

logging:
  audit_log: logs/audit.log
```

------------------------------------------------------------------------

# Schritt 7 -- Datei signieren

Beispiel:

``` bash
python3 sign.py testfiles/script.sh
```

Erzeugt:

    script.sh.sig

------------------------------------------------------------------------

# Schritt 8 -- Signatur prüfen

``` bash
python3 verify.py testfiles/script.sh
```

Ausgabe:

    SIGNATURE VALID

------------------------------------------------------------------------

# Audit Logging

Jede Operation wird protokolliert.

Client Log:

    client/logs/audit.log

Server Log:

    server/audit/audit.log

Ein Log Eintrag kann z.B. enthalten:

-   Timestamp
-   Client ID
-   signierte Datei
-   Ergebnis der Prüfung

------------------------------------------------------------------------

# Monitoring mit Grafana

Monitoring ermöglicht die Visualisierung der Signaturaktivität.

Grafana zeigt z.B.

-   Signaturen pro Stunde
-   aktive Clients
-   API Requests
-   Fehlgeschlagene Verifikationen

------------------------------------------------------------------------

# Schritt 1 -- Prometheus konfigurieren

Prometheus sammelt die Metrics.

Datei:

    prometheus.yml

Beispiel:

``` yaml
scrape_configs:
  - job_name: signing-server
    static_configs:
      - targets: ['localhost:9100']
```

Prometheus starten:

``` bash
sudo systemctl start prometheus
```

------------------------------------------------------------------------

# Schritt 2 -- Grafana starten

``` bash
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

Grafana Webinterface:

    http://localhost:3000

Login:

admin / admin

------------------------------------------------------------------------

# Schritt 3 -- Prometheus als Data Source hinzufügen

Grafana → Settings → Data Sources

Neue Data Source:

Prometheus

URL:

    http://localhost:9090

------------------------------------------------------------------------

# Schritt 4 -- Dashboard erstellen

Neues Dashboard erstellen.

Beispiele für Panels:

Signaturen pro Stunde

    rate(sign_operations_total[1h])

API Requests

    rate(api_requests_total[5m])

Verifikationsfehler

    verification_failures_total

------------------------------------------------------------------------

# Sicherheitshinweise

Folgende Dateien dürfen niemals im Repository liegen:

    *.private.pem
    *.key
    logs/
    *.db

Empfohlen:

    .gitignore

``` text
__pycache__/
logs/
*.db
*.key
*.pem
```

------------------------------------------------------------------------

# Lernziele des Projekts

Dieses Projekt demonstriert:

Digitale Signaturen\
Client Server Security Architektur\
Audit Logging\
Monitoring und Observability\
Secure Deployment Konzepte

Das Projekt eignet sich für:

-   IT Security Unterricht
-   DevOps Grundlagen
-   Software Architektur Kurse
-   Cybersecurity Schulprojekte

------------------------------------------------------------------------

# Hinweis

Dieses Repository ist ein **Schulprojekt**.

Der Code dient zur Demonstration von Konzepten und nicht für produktive
Systeme.
