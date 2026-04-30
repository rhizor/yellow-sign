# 🔍 Yellow Sign - Secrets Scanner

> *"That is not dead which can eternal lie, and with strange aeons even death may die."
> — H.P. Lovecraft*

## 📋 Descripción

**Yellow Sign** es un potente escáner de secrets que detecta:
- API keys (AWS, GitHub, Google, Slack, Stripe, etc.)
- Tokens y credenciales
- Claves privadas (SSH, PGP, RSA)
- Passwords en URLs y configuraciones
- Cualquier string de alta entropía (posible secret)

## 🚀 Features

- Core engine con análisis de entropía
- 25+ reglas de detección (AWS, GitHub, Slack, Stripe, etc.)
- CLI con Click
- Tests unitarios
- Git hooks para pre-commit
- Integración CI/CD (SARIF output)
- Instalable vía pip

## 📦 Instalación

### Desde GitHub:
```bash
# Instalar desde GitHub
pip install git+https://github.com/rhizor/yellow-sign.git

# O clonar e instalar en modo desarrollo
git clone https://github.com/rhizor/yellow-sign.git
cd yellow-sign
pip install -e .
```

### Uso:
```bash
# Escanear directorio
yellow-sign scan .

# Escanear con salida JSON
yellow-sign scan . --output json

# Instalar git hook
yellow-sign install-hook

# Listar reglas
yellow-sign list-rules

# Verificar entropía de un string
yellow-sign check-entropy "AKIAIOSFODNN7EXAMPLE"
```

## 📁 Estructura del Proyecto

```
secrets-scanner-yellow-sign/
├── src/
│   └── yellow_sign/
│       ├── __init__.py           # Package init
│       ├── __main__.py           # Entry point
│       ├── scanner.py            # Core engine
│       ├── rules.py              # 25+ detection rules
│       ├── entropy.py            # Entropy analyzer
│       ├── findings.py           # Data models
│       └── cli.py                # CLI con Click
├── tests/
│   └── test_yellow_sign.py       # Tests unitarios
├── config/
│   └── yellow-sign.yaml.example  # Configuración
├── requirements.txt              # Dependencias
├── requirements-dev.txt          # Dev dependencies
├── setup.py                      # Setup tradicional
├── pyproject.toml               # Modern packaging
└── README.md                     # Este archivo
```

## 🎯 Reglas Implementadas (25+)

### Cloud Providers:
- AWS Access Key ID
- AWS Secret Access Key
- Azure Service Principal
- Google API Key
- Heroku API Key

### Development:
- GitHub Personal Access Token
- GitHub OAuth Token
- NPM Access Token
- PyPI API Token
- Docker Hub Token

### Communication:
- Slack Webhook URL
- Slack API Token
- Discord Webhook URL
- Telegram Bot Token
- SendGrid API Key

### Financial:
- Stripe API Key (live/test)
- Twilio API Key

### Crypto/Security:
- Private Keys (RSA, DSA, EC, OpenSSH)
- PGP Private Key Block
- SSH Private Key
- JWT Tokens

### Generic:
- Database Connection Strings
- Password in URL
- Generic API Key patterns
- Hardcoded passwords

## 🔬 Características Técnicas

### Análisis de Entropía (Shannon)
- **Thresholds:**
  - >4.5 = High (muy probable secret)
  - >4.0 = Medium (revisar)
  - <3.5 = Low (probablemente no)
- **False positives filtrados:** UUIDs, IPs, version strings

### Paralelización
- Multi-threading con ThreadPoolExecutor
- Workers configurables (default: 4)
- Manejo de archivos grandes (>10MB skip)

### Formatos de Salida
- **Text:** Coloreado, human-readable
- **JSON:** Para integración
- **SARIF:** Para GitHub/CodeQL

## 🧪 Tests

```bash
# Ejecutar tests
pytest tests/ -v

# Con coverage
pytest tests/ --cov=yellow_sign --cov-report=html

# Linting
black src/
flake8 src/
mypy src/
```

## 🔗 Integración Git Hooks

```bash
# Instalar hook
yellow-sign install-hook

# El hook automáticamente:
# 1. Escanea archivos staged antes de commit
# 2. Bloquea el commit si encuentra secrets
# 3. Muestra dónde están los secrets

# Desinstalar
yellow-sign uninstall-hook
```

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────┐
│              YELLOW SIGN                    │
├─────────────────────────────────────────────┤
│  Entrada: Archivo / Directorio               │
│                      ↓                       │
│  ┌────────────────────────────────┐        │
│  │  Scanner Engine                │        │
│  │  ┌───────────┐ ┌────────────┐│        │
│  │  │  Rules    │ │  Entropy   ││        │
│  │  │  Engine   │ │  Analyzer  ││        │
│  │  └─────┬─────┘ └─────┬──────┘│        │
│  │        └─────────────┘        │        │
│  │              ↓                │        │
│  │     ┌──────────────┐         │        │
│  │     │  Aggregator  │         │        │
│  │     │  (Deduplicate)│         │        │
│  │     └──────┬───────┘         │        │
│  └─────────────┼────────────────┘        │
│                ↓                            │
│  ┌────────────────────────────────┐      │
│  │  Results                       │      │
│  │  - Console (color)            │      │
│  │  - JSON / SARIF                │      │
│  │  - Exit code (CI/CD)           │      │
│  └────────────────────────────────┘      │
└─────────────────────────────────────────────┘
```

## 📊 Performance

- **~1000 archivos/segundo** (depende de tamaño)
- **Entropía calculada en O(n)**
- **Paralelización automática**
- **Skip de archivos binarios**

## 🛡️ Seguridad

- **No almacena secrets detectados** (solo hashes)
- **Memoria eficiente** (streaming de archivos grandes)
- **No envía datos a servidores externos**
- **Todo el procesamiento local**

## 🚀 Deployment

### Instalación desde GitHub
```bash
pip install git+https://github.com/rhizor/yellow-sign.git
```

### GitHub Action
```yaml
name: Secrets Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: rhizor/yellow-sign-action@v1
```

### Pre-commit hook
```bash
# Cada developer ejecuta:
yellow-sign install-hook
```

## 📈 Roadmap

- [ ] Integración con HashiCorp Vault
- [ ] Machine Learning para reducir falsos positivos
- [ ] Dashboard web (Necronomicon SIEM)
- [ ] Scaneo de historial Git completo
- [ ] Integración con 1Password/Bitwarden
- [ ] Scan de Docker images
- [ ] API REST

## 🏆 Logros

- Proyecto completo con 25+ reglas de detección
- Paralelización implementada
- CLI production-ready
- Tests coverage
- Arquitectura extensible

## 📚 Recursos

- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [SARIF Format](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Token Scanning](https://docs.github.com/en/code-security/secret-scanning)

---

**Versión:** 1.0.0  
**Autor:** rhizor  
**Licencia:** MIT

