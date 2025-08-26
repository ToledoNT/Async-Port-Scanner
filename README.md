Async TCP Port Scanner 🚀

Scanner de portas TCP assíncrono com detecção de serviços, modo stealth e sistema de logging completo.

⚠️ AVISO: Use apenas para fins educativos e em redes que você possui permissão explícita para testar.
✨ Características

    ⚡ Escaneamento assíncrono de alta performance

    🔍 Detecção automática de serviços e banners

    🕵️ Modo stealth para evasão de firewalls

    📊 Sistema de logging completo e configurável

    🌐 Suporte a redes CIDR e hosts individuais

    🎨 Saída colorida e formatada

    ⚖️ Rate limiting e randomização de portas

    🛡️ Detecção de firewalls e verificação de robots.txt

    💾 Exportação de resultados em múltiplos formatos

📋 Requisitos

    Python 3.8+

    Bibliotecas padrão Python:

        asyncio

        ipaddress

        socket

        logging

        argparse

📦 Dependências Opcionais
bash

# Para barra de progresso (recomendado)
pip install tqdm

🚀 Instalação
bash

# Clone o repositório
git clone https://github.com/ToledoNT/Async-Port-Scanner.git
cd Async-Port-Scanner

# Torne executável (opcional)
chmod +x portScan.py

💻 Como Usar
Escaneamento Básico
bash

# Escanear um host específico
python3 portScan.py 192.168.0.1

# Escanear uma rede completa
python3 portScan.py 192.168.0.0/24

# Escanear um domínio
python3 portScan.py example.com

Escaneamento Avançado
bash

# Escanear portas específicas
python3 portScan.py 192.168.0.1 -s 20 -e 1000

# Ativar modo stealth (recomendado)
python3 portScan.py 192.168.0.1 --stealth

# Com barra de progresso
python3 portScan.py 192.168.0.1 --progress

# Salvar resultados
python3 portScan.py 192.168.0.1 -o resultados.json

Exemplos Completos
bash

# Scan completo com modo stealth e progresso
python3 portScan.py 192.168.1.0/24 --stealth --progress -o rede_scan.json

# Scan específico com alta concorrência
python3 portScan.py 10.0.0.1 -s 1 -e 10000 -c 1000 --progress

# Scan com verificação de robots.txt
python3 portScan.py example.com --check-robots --stealth

🔧 Configuração

As configurações padrão podem ser modificadas diretamente no script:
python

DEFAULT_CONFIG = {
    "TARGET": "192.168.0.1",
    "PORTS_RANGE": (1, 65535),
    "CONCURRENCY": 500,
    "TIMEOUT": 1.5,
    "MAX_RETRIES": 2,
    "MAX_RATE": 100,
    "LOG_FILE": "logs/port_scanner.log",
    "LOG_LEVEL": "INFO"
}

🛡️ Modo Stealth

O modo stealth inclui automaticamente:

    ✅ Randomização de ordem de portas

    ✅ Limitação de taxa de conexões (50/segundo)

    ✅ Timeout aumentado (2.0 segundos)

    ✅ Tentativas aumentadas (3 por porta)

    ✅ Verificação de robots.txt

    ✅ Atrasos aleatórios entre conexões

📝 Logging

Os logs são salvos em logs/port_scanner.log por padrão:
text

2024-01-15 10:30:01 - PortScanner - INFO - Iniciando scanner de portas
2024-01-15 10:30:02 - PortScanner - INFO - Porta aberta encontrada: 192.168.0.1:22 - SSH
2024-01-15 10:35:23 - PortScanner - INFO - Scan finalizado. 3 portas abertas encontradas

🚨 Limitações e Considerações

    Performance: Escaneamentos muito largos podem consumir recursos significativos

    Detecção: Firewalls avançados podem ainda detectar a atividade

    Legalidade: Sempre obtenha permissão antes de escanear qualquer rede

    Ética: Use apenas para testes de segurança autorizados

⚠️ Aviso Legal

Este software é fornecido apenas para fins educacionais e de teste de segurança autorizado. O uso não autorizado deste software contra redes que você não possui ou não tem permissão para testar é estritamente proibido e pode violar leis locais, estaduais e federais. Os desenvolvedores não se responsabilizam por qualquer uso indevido ou dano causado por este software.

Sempre obtenha permissão explícita por escrito antes de realizar qualquer teste de segurança.

Happy (and ethical) scanning! 🎯