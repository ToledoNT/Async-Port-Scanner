#!/usr/bin/env python3
"""
Async TCP Port Scanner com detecção de serviços, modo stealth e sistema de logs

Características:
- Escaneamento assíncrono de alta performance
- Detecção automática de serviços e banners
- Modo stealth para evasão de firewalls
- Sistema de logging completo
- Suporte a redes CIDR e hosts individuais
- Saída colorida e formatada
- Rate limiting e randomização
- Detecção de firewalls e verificação de robots.txt

Uso:
  - Escanear um host:      python3 portScan.py 192.168.0.1
  - Escanear uma rede:     python3 portScan.py 192.168.0.0/24
  - Portas específicas:    python3 portScan.py 192.168.0.1 -s 20 -e 1000
  - Modo stealth:          python3 portScan.py 192.168.0.1 --stealth

Autor: Port Scanner Pro
Versão: 2.0
"""

import asyncio
import json
import ipaddress
import socket
import random
import logging
import os
import sys
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

# ===================== CONFIGURAÇÕES GLOBAIS ===================== #
DEFAULT_CONFIG = {
    "TARGET": "192.168.0.1",
    "PORTS_RANGE": (1, 65535),
    "CONCURRENCY": 500,
    "TIMEOUT": 1.5,
    "BANNER_READ": 1024,
    "RANDOMIZE_PORTS": True,
    "DELAY_BETWEEN_SCANS": 0.1,
    "JITTER": 0.05,
    "MAX_RETRIES": 2,
    "MAX_RATE": 100,
    "USER_AGENTS": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.25.1"
    ],
    "LOG_FILE": "logs/port_scanner.log",
    "LOG_LEVEL": "INFO"
}

# ===================== INICIALIZAÇÃO DO LOGGING ===================== #
def setup_logging(log_file: str = DEFAULT_CONFIG["LOG_FILE"], 
                 log_level: str = DEFAULT_CONFIG["LOG_LEVEL"]) -> logging.Logger:
    """
    Configura o sistema de logging com arquivo e console
    
    Args:
        log_file: Caminho do arquivo de log
        log_level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Logger configurado
    """
    # Criar diretório de logs se não existir
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Converter string de nível para nível de logging
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configurar formato do log
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configurar handlers
    handlers = []
    
    # Handler para arquivo
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    handlers.append(file_handler)
    
    # Handler para console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    handlers.append(console_handler)
    
    # Configurar logger principal
    logger = logging.getLogger("PortScanner")
    logger.setLevel(level)
    
    # Remover handlers existentes e adicionar novos
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    for handler in handlers:
        logger.addHandler(handler)
    
    # Silenciar loggers de bibliotecas externas
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    return logger

# ===================== CONSTANTES DE CORES ===================== #
class Colors:
    """Códigos ANSI para cores no terminal"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

# ===================== BANNER INICIAL ===================== #
def display_banner():
    """Exibe banner inicial do scanner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                🚀 ASYNC TCP PORT SCANNER                    ║
║                   Versão 2.0 - Python 3                     ║
║                                                              ║
║    Use apenas em redes que você tem permissão para testar    ║
╚══════════════════════════════════════════════════════════════╗
{Colors.RESET}
"""
    print(banner)

# ===================== CLASSES AUXILIARES ===================== #
class RateLimiter:
    """Limita a taxa de conexões por segundo para evitar detecção"""
    
    def __init__(self, max_rate: float):
        self.max_rate = max_rate
        self.tokens = max_rate
        self.updated_at = asyncio.get_running_loop().time()

    async def acquire(self):
        """Adquire permissão para fazer uma conexão"""
        now = asyncio.get_running_loop().time()
        elapsed = now - self.updated_at
        self.tokens = min(self.max_rate, self.tokens + elapsed * self.max_rate)
        self.updated_at = now
        if self.tokens < 1:
            await asyncio.sleep((1 - self.tokens) / self.max_rate)
            self.tokens = 0
        else:
            self.tokens -= 1

# ===================== FUNÇÕES PRINCIPAIS ===================== #
def detect_service(port: int, banner: str) -> str:
    """
    Detecta serviço baseado em porta e banner
    
    Args:
        port: Número da porta
        banner: Banner recebido da conexão
    
    Returns:
        Nome do serviço detectado
    """
    common_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
        995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        27017: "MongoDB", 6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch",
        3000: "Node.js/Express", 4200: "Angular", 8000: "Python/Django",
        8080: "Web Server/Proxy", 9000: "PHP", 5000: "Flask/Express"
    }
    
    service = common_services.get(port, "Unknown")
    banner_upper = banner.upper()
    
    if service == "Unknown" and banner_upper:
        mapping = {
            "SSH": "SSH", "HTTP": "HTTP Server", "FTP": "FTP", "SMTP": "SMTP",
            "POP3": "POP3", "IMAP": "IMAP", "MYSQL": "MySQL",
            "POSTGRES": "PostgreSQL", "REDIS": "Redis", "MONGODB": "MongoDB"
        }
        for keyword in mapping:
            if keyword in banner_upper:
                return mapping[keyword]
    
    return service

def adaptive_timeout(host: str, base_timeout: float) -> float:
    """
    Ajusta timeout baseado na latência do host
    
    Args:
        host: Endereço do host
        base_timeout: Timeout base
    
    Returns:
        Timeout ajustado
    """
    try:
        start = datetime.now().timestamp()
        socket.gethostbyname(host)
        end = datetime.now().timestamp()
        latency = end - start
        return max(base_timeout, latency * 3)
    except Exception as e:
        logger.warning(f"Não foi possível ajustar timeout para {host}: {e}")
        return base_timeout

async def check_robots_txt(host: str) -> bool:
    """
    Verifica robots.txt antes do scan
    
    Args:
        host: Endereço do host
    
    Returns:
        True se pode prosseguir, False se deve respeitar robots.txt
    """
    try:
        reader, writer = await asyncio.open_connection(host, 80)
        writer.write(f"GET /robots.txt HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        response = await reader.read(2048)
        writer.close()
        await writer.wait_closed()
        
        if b"Disallow: /" in response or b"User-agent: *" in response:
            logger.warning(f"robots.txt encontrado em {host} - respeitar diretrizes")
            return False
    except Exception as e:
        logger.debug(f"Erro ao verificar robots.txt em {host}: {e}")
    
    return True

async def detect_firewall(host: str) -> Dict[str, Any]:
    """
    Detecta possíveis firewalls sem alterar o scan principal
    
    Args:
        host: Endereço do host
    
    Returns:
        Informações sobre possível firewall
    """
    test_ports = [22, 21, 25, 80, 443, random.randint(40000, 50000)]
    results = {}
    
    for port in test_ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=1.5
            )
            writer.close()
            await writer.wait_closed()
            results[port] = "open"
        except asyncio.TimeoutError:
            results[port] = "filtered"
        except ConnectionRefusedError:
            results[port] = "closed"
        except Exception as e:
            results[port] = f"error: {str(e)}"
    
    filtered_count = sum(1 for r in results.values() if r == "filtered")
    likely_firewall = filtered_count >= len(test_ports) - 1
    
    if likely_firewall:
        logger.info(f"Possível firewall detectado em {host}")
    
    return {"likely_firewall": likely_firewall, "port_results": results}

async def check_port(sem: asyncio.Semaphore, host: str, port: int, timeout: float,
                    retries: int = DEFAULT_CONFIG["MAX_RETRIES"], 
                    limiter: Optional[RateLimiter] = None) -> Dict[str, Any]:
    """
    Verifica porta com retries, banner grabbing e evasão
    
    Args:
        sem: Semáforo para controle de concorrência
        host: Endereço do host
        port: Porta a ser verificada
        timeout: Timeout da conexão
        retries: Número de tentativas
        limiter: Limitador de taxa
    
    Returns:
        Resultado da verificação da porta
    """
    for attempt in range(retries):
        try:
            if limiter:
                await limiter.acquire()
            
            if attempt > 0:
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            async with sem:
                current_timeout = timeout * (attempt + 1)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    current_timeout
                )
                
                banner = ""
                try:
                    headers = [
                        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(DEFAULT_CONFIG['USER_AGENTS'])}\r\n\r\n",
                        f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n",
                        "\r\n\r\n"
                    ]
                    writer.write(random.choice(headers).encode())
                    await writer.drain()
                    
                    banner_bytes = b""
                    for _ in range(3):
                        chunk = await asyncio.wait_for(reader.read(512), timeout=0.5)
                        if not chunk:
                            break
                        banner_bytes += chunk
                    
                    banner = banner_bytes.decode(errors='ignore').strip()
                except Exception as e:
                    logger.debug(f"Erro ao ler banner em {host}:{port}: {e}")
                finally:
                    writer.close()
                    await writer.wait_closed()

                result = {
                    "port": port,
                    "state": "open",
                    "service": detect_service(port, banner),
                    "banner": banner,
                    "protocol": "tcp",
                    "attempts": attempt + 1
                }
                
                logger.info(f"Porta aberta encontrada: {host}:{port} - {result['service']}")
                return result
                
        except asyncio.TimeoutError:
            if attempt == retries - 1:
                logger.debug(f"Porta filtrada: {host}:{port}")
                return {
                    "port": port, 
                    "state": "filtered", 
                    "service": "", 
                    "banner": "", 
                    "protocol": "tcp"
                }
                
        except ConnectionRefusedError:
            logger.debug(f"Porta fechada: {host}:{port}")
            return {
                "port": port, 
                "state": "closed", 
                "service": "", 
                "banner": "", 
                "protocol": "tcp"
            }
            
        except OSError as e:
            if e.errno == 113:
                logger.debug(f"Porta filtrada (OSError): {host}:{port}")
                return {
                    "port": port, 
                    "state": "filtered", 
                    "service": "", 
                    "banner": "", 
                    "protocol": "tcp"
                }
            if attempt == retries - 1:
                logger.warning(f"Erro OSError em {host}:{port}: {e}")
                return {
                    "port": port, 
                    "state": f"error: {str(e)}", 
                    "service": "", 
                    "banner": "", 
                    "protocol": "tcp"
                }
                
        except Exception as e:
            if attempt == retries - 1:
                logger.error(f"Erro inesperado em {host}:{port}: {e}")
                return {
                    "port": port, 
                    "state": f"error: {str(e)}", 
                    "service": "", 
                    "banner": "", 
                    "protocol": "tcp"
                }
    
    return {
        "port": port, 
        "state": "error: max retries", 
        "service": "", 
        "banner": "", 
        "protocol": "tcp"
    }

async def scan_host(host: str, ports: List[int], 
                   concurrency: int = DEFAULT_CONFIG["CONCURRENCY"],
                   timeout: float = DEFAULT_CONFIG["TIMEOUT"], 
                   show_progress: bool = False,
                   randomize: bool = DEFAULT_CONFIG["RANDOMIZE_PORTS"], 
                   max_rate: float = DEFAULT_CONFIG["MAX_RATE"],
                   retries: int = DEFAULT_CONFIG["MAX_RETRIES"]) -> List[Dict[str, Any]]:
    """
    Executa scan completo em um host
    
    Args:
        host: Endereço do host
        ports: Lista de portas para escanear
        concurrency: Número de conexões simultâneas
        timeout: Timeout por conexão
        show_progress: Mostrar barra de progresso
        randomize: Randomizar ordem das portas
        max_rate: Máximo de conexões por segundo
        retries: Número de tentativas por porta
    
    Returns:
        Lista de portas abertas encontradas
    """
    if randomize:
        random.shuffle(ports)
    
    sem = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(max_rate)
    results = []
    tasks = []

    logger.info(f"Iniciando scan do host: {host}")
    
    # Detectar possível firewall
    firewall_info = await detect_firewall(host)
    if firewall_info["likely_firewall"]:
        print(f"{Colors.YELLOW}⚠️  Possível firewall detectado em {host}{Colors.RESET}")

    # Criar tasks para cada porta
    for port in ports:
        if randomize and random.random() < 0.3:
            await asyncio.sleep(random.uniform(0, DEFAULT_CONFIG["DELAY_BETWEEN_SCANS"]))
        tasks.append(asyncio.create_task(
            check_port(sem, host, port, timeout, retries, limiter)
        ))

    # Processar resultados com ou sem barra de progresso
    if show_progress:
        try:
            from tqdm import tqdm
            pbar = tqdm(total=len(tasks), desc=f"{Colors.CYAN}🔍 Scanning {host}{Colors.RESET}", unit="port")
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                pbar.update(1)
            pbar.close()
        except ImportError:
            logger.warning("Biblioteca tqdm não instalada. Progresso não será mostrado.")
            results = await asyncio.gather(*tasks)
    else:
        results = await asyncio.gather(*tasks)

    # Filtrar apenas portas abertas
    open_ports = [r for r in results if r["state"] == "open"]
    logger.info(f"Scan de {host} concluído. {len(open_ports)} portas abertas encontradas.")
    
    return sorted(open_ports, key=lambda x: x["port"])

def print_open_ports(host: str, results: List[Dict[str, Any]]):
    """
    Exibe resultados de portas abertas formatados
    
    Args:
        host: Endereço do host
        results: Lista de resultados
    """
    if results:
        print(f"\n{Colors.GREEN}✅ PORTAS ABERTAS EM {host}:{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.YELLOW}{'PORTA':<8} {'SERVIÇO':<20} {'BANNER'}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
        
        for r in results:
            port_color = Colors.MAGENTA + Colors.BOLD if r['port'] in [22, 21, 25, 53, 80, 443, 3306, 5432, 27017] else Colors.GREEN
            banner_preview = (r.get('banner','')[:45] + "...") if len(r.get('banner','')) > 45 else r.get('banner','')
            attempts_info = f" ({r.get('attempts', 1)} tentativas)" if r.get('attempts', 1) > 1 else ""
            
            print(f"{port_color}{r['port']:<8}{Colors.RESET} {Colors.CYAN}{r['service']:<20}{Colors.RESET} {Colors.WHITE}{banner_preview}{attempts_info}{Colors.RESET}")
    else:
        print(f"{Colors.RED}❌ Nenhuma porta aberta encontrada em {host}{Colors.RESET}")
        logger.info(f"Nenhuma porta aberta encontrada em {host}")

def save_results(filename: str, data: Dict[str, Any]) -> str:
    """
    Salva resultados em JSON, CSV ou TXT
    
    Args:
        filename: Nome do arquivo de saída
        data: Dados a serem salvos
    
    Returns:
        Nome do arquivo salvo
    
    Raises:
        Exception: Erro ao salvar arquivo
    """
    try:
        if filename.endswith('.json'):
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        elif filename.endswith('.csv'):
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Host,Port,State,Service,Banner,Attempts\n")
                for host, results in data["results"].items():
                    for r in results:
                        banner_clean = r.get('banner','').replace('"',"'").replace(",",";")
                        f.write(f'{host},{r["port"]},{r["state"]},"{r["service"]}","{banner_clean}",{r.get("attempts", 1)}\n')
                        
        elif filename.endswith('.txt'):
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"Scan realizado em: {data['scan_start']}\nDuração: {data['scan_duration']}\nAlvo: {data['target']}\n")
                f.write("="*60+"\n")
                total_open = sum(len(results) for results in data["results"].values())
                f.write(f"PORTAS ABERTAS ENCONTRADAS: {total_open}\n")
                f.write("="*60+"\n\n")
                
                for host, results in data["results"].items():
                    if any(r["state"]=="open" for r in results):
                        f.write(f"HOST: {host}\n{'-'*40}\n")
                        for r in results:
                            if r["state"]=="open":
                                banner_info = f" - {r.get('banner','')}" if r.get('banner') else ""
                                attempts_info = f" ({r.get('attempts', 1)} tentativas)" if r.get('attempts', 1) > 1 else ""
                                f.write(f"Porta {r['port']}/tcp → {r['service']}{banner_info}{attempts_info}\n")
                        f.write("\n")
        else:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Resultados salvos em: {filename}")
        return filename
        
    except Exception as e:
        logger.error(f"Erro ao salvar resultados em {filename}: {e}")
        raise

# ===================== CONFIGURAÇÃO DE ARGUMENTOS ===================== #
def setup_argument_parser() -> argparse.ArgumentParser:
    """Configura e retorna o parser de argumentos"""
    
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}🚀 Async TCP Port Scanner{Colors.RESET}\n{Colors.YELLOW}Use apenas em hosts que você possui permissão para testar.{Colors.RESET}",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"{Colors.GRAY}Exemplos:\n"
              f"  python3 portScan.py 192.168.0.1\n"
              f"  python3 portScan.py 192.168.0.0/24 -s 1 -e 1000\n"
              f"  python3 portScan.py example.com --stealth --progress{Colors.RESET}"
    )
    
    # Argumentos principais
    parser.add_argument("target", nargs="?", default=DEFAULT_CONFIG["TARGET"], 
                       help="IP, hostname ou rede (ex: 192.168.0.1 ou 192.168.0.0/24)")
    
    # Opções de porta
    parser.add_argument("-s", "--start", type=int, default=DEFAULT_CONFIG["PORTS_RANGE"][0], 
                       help="Porta inicial (padrão: 1)")
    parser.add_argument("-e", "--end", type=int, default=DEFAULT_CONFIG["PORTS_RANGE"][1], 
                       help="Porta final (padrão: 65535)")
    
    # Opções de performance
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONFIG["CONCURRENCY"], 
                       help="Conexões simultâneas (padrão: 500)")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_CONFIG["TIMEOUT"], 
                       help="Timeout por conexão em segundos (padrão: 1.5)")
    
    # Opções de saída
    parser.add_argument("-o", "--output", type=str, 
                       help="Arquivo de saída (suporta .json, .csv, .txt)")
    parser.add_argument("--progress", action="store_true", 
                       help="Mostrar barra de progresso")
    parser.add_argument("--format", choices=["json", "csv", "txt"], default="json", 
                       help="Formato de saída (padrão: json)")
    
    # Opções stealth
    parser.add_argument("--stealth", action="store_true", 
                       help="Modo stealth (mais lento, menos detectável)")
    parser.add_argument("--randomize", action="store_true", 
                       help="Escanear portas em ordem aleatória")
    parser.add_argument("--max-rate", type=float, default=DEFAULT_CONFIG["MAX_RATE"], 
                       help="Máximo de conexões por segundo (padrão: 100)")
    parser.add_argument("--retries", type=int, default=DEFAULT_CONFIG["MAX_RETRIES"], 
                       help="Número de tentativas por porta (padrão: 2)")
    parser.add_argument("--check-robots", action="store_true", 
                       help="Verificar robots.txt antes de escanear")
    
    # Opções de logging
    parser.add_argument("--log-file", type=str, default=DEFAULT_CONFIG["LOG_FILE"], 
                       help=f"Arquivo de log (padrão: {DEFAULT_CONFIG['LOG_FILE']})")
    parser.add_argument("--log-level", type=str, default=DEFAULT_CONFIG["LOG_LEVEL"], 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                       help="Nível de detalhamento do log (padrão: INFO)")
    
    return parser

# ===================== FUNÇÃO PRINCIPAL ===================== #
def main():
    """Função principal do scanner"""
    
    # Exibir banner inicial
    display_banner()
    
    # Configurar parser de argumentos
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Configurar logging
    global logger
    logger = setup_logging(args.log_file, args.log_level)
    
    logger.info(f"Iniciando scanner de portas com argumentos: {vars(args)}")
    
    # Aplicar configurações stealth
    if args.stealth:
        args.randomize = True
        args.max_rate = 50
        args.retries = 3
        args.timeout = 2.0
        args.check_robots = True
        print(f"{Colors.YELLOW}🔒 Modo stealth ativado{Colors.RESET}")
        logger.info("Modo stealth ativado")
    
    # Validar range de portas
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        error_msg = f"Portas inválidas: {args.start}-{args.end}"
        print(f"{Colors.RED}❌ {error_msg}{Colors.RESET}")
        logger.error(error_msg)
        return
    
    # Resolver alvo(s)
    hosts = []
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        msg = f"Escaneando rede: {args.target} ({len(hosts)} hosts)"
        print(f"{Colors.BLUE}🌐 {msg}{Colors.RESET}")
        logger.info(msg)
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(args.target)
            hosts = [resolved_ip]
            if resolved_ip != args.target:
                msg = f"{args.target} resolvido para {resolved_ip}"
                print(f"{Colors.CYAN}🔗 {msg}{Colors.RESET}")
                logger.info(msg)
        except socket.gaierror:
            error_msg = f"Não foi possível resolver {args.target}"
            print(f"{Colors.RED}❌ {error_msg}{Colors.RESET}")
            logger.error(error_msg)
            return
    
    # Verificar robots.txt se solicitado
    if args.check_robots and hosts:
        print(f"{Colors.BLUE}🤖 Verificando robots.txt...{Colors.RESET}")
        logger.info("Verificando robots.txt...")
        for host in hosts[:3]:  # Verificar apenas os primeiros 3 hosts
            asyncio.run(check_robots_txt(host))
    
    # Preparar portas para scan
    ports = list(range(args.start, args.end + 1))
    
    # Exibir configuração do scan
    print(f"{Colors.BLUE}📊 Portas: {args.start}-{args.end} ({len(ports)} portas){Colors.RESET}")
    print(f"{Colors.BLUE}⚡ Concorrência: {args.concurrency}{Colors.RESET}")
    print(f"{Colors.BLUE}⏱️  Timeout: {args.timeout}s{Colors.RESET}")
    print(f"{Colors.BLUE}🔄 Tentativas: {args.retries}{Colors.RESET}")
    print(f"{Colors.BLUE}📏 Taxa máxima: {args.max_rate}/s{Colors.RESET}")
    print(f"{Colors.BLUE}🎲 Ordem aleatória: {'Sim' if args.randomize else 'Não'}{Colors.RESET}")
    
    logger.info(f"Configuração do scan: {len(ports)} portas, concorrência: {args.concurrency}, "
                f"timeout: {args.timeout}s, tentativas: {args.retries}, taxa: {args.max_rate}/s, "
                f"randomização: {args.randomize}")
    
    # Executar scan
    start_time = datetime.now(timezone.utc)
    all_results = {}
    
    for host in hosts:
        print(f"{Colors.CYAN}\n🔍 Escaneando {host}...{Colors.RESET}")
        
        open_ports = asyncio.run(scan_host(
            host=host,
            ports=ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            show_progress=args.progress,
            randomize=args.randomize,
            max_rate=args.max_rate,
            retries=args.retries
        ))
        
        print_open_ports(host, open_ports)
        all_results[host] = open_ports
    
    # Finalizar e exibir resultados
    end_time = datetime.now(timezone.utc)
    duration = end_time - start_time
    
    total_open = sum(len(results) for results in all_results.values())
    summary_msg = f"Scan finalizado. {total_open} portas abertas encontradas em {len(hosts)} hosts. Duração: {duration}"
    
    print(f"\n{Colors.GREEN}⏱️  Scan finalizado em {end_time.isoformat()}{Colors.RESET}")
    print(f"{Colors.GREEN}⏳ {summary_msg}{Colors.RESET}")
    logger.info(summary_msg)
    
    # Salvar resultados se solicitado
    if args.output:
        data_to_save = {
            "scan_start": start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "scan_duration": str(duration),
            "target": args.target,
            "results": all_results
        }
        
        try:
            saved_file = save_results(args.output, data_to_save)
            print(f"{Colors.GREEN}💾 Resultados salvos em: {saved_file}{Colors.RESET}")
        except Exception as e:
            error_msg = f"Erro ao salvar resultados: {e}"
            print(f"{Colors.RED}❌ {error_msg}{Colors.RESET}")
            logger.error(error_msg)

# ===================== EXECUÇÃO PRINCIPAL ===================== #
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}⏹️  Scan interrompido pelo usuário{Colors.RESET}")
        logger.warning("Scan interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        error_msg = f"Erro inesperado: {e}"
        print(f"{Colors.RED}❌ {error_msg}{Colors.RESET}")
        logger.exception("Erro inesperado durante a execução")
        sys.exit(1)