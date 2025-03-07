# A tool to make recon, find out new subdomains, subdomains without SSL, WAF and anything
#
#

import socket
import whois
import subprocess
import dns.resolver
import requests
import re
import json


def resolve_host_name(domain):
    ip = socket.gethostbyname(domain)
    print(ip, "\n")
    return


def resolve_whois(domain):
    who = whois.whois(domain)

    print("\nNameservers:")

    # check se existem nameservers na lista
    # domains como Google costumam falhar
    if who.name_server is None:
        comando_ns_servers = f"host -t ns {domain}"
        process = subprocess.Popen([comando_ns_servers], shell=True)
        process.wait()
    else:
        for i in who.name_server:
            print(i)

    # Avaliar domains secundários presentes em e-mails
    print("\nPossíveis domains interessantes para avaliar:")

    if who.email is None:
        return
    
    if who.emails is None:
        return

    if who.email is list:
        for i in who.email:
            print(i)
    else:
        print(who.email)
    return


def get_records(domain):
    resolver = dns.resolver.Resolver()

    # Avaliar registros TXT
    txt_record = resolver.resolve(domain, "TXT")

    print("\nRegistros TXT: ")
    for rdata in txt_record:  # Iteramos pelos registros dentro da resposta
        for txt in rdata.strings:  # Para registros TXT, usamos `.strings`
            print(txt.decode())  # Convertemos de bytes para string

    # Avaliar registros MX
    mx_record = resolver.resolve(domain, "MX")

    print("\nRegistros MX:")
    for rdata in mx_record:
        print(rdata.exchange)

    return


def get_dns_dumpster(domain):
    url = "https://dnsdumpster.com"

    # Obter token para fazer a pesquisa sobre domain
    response = requests.get(url)

    # Verifica se a requisição foi bem-sucedida
    if response.status_code == 200:

        # Formata a resposta simulando o comportamento do `sed`
        formatted_response = response.text.replace("{", "{\n").replace("}", "}\n")

        # Usa regex para encontrar a linha com "Authorization"
        match = re.search(r'"Authorization"\s*:\s*"([^"]+)"', formatted_response)

        if match:
            authorization_token = match.group(1)
            print(authorization_token)
        else:
            print("Token de autorização não encontrado.")
    else:
        print(f"Erro ao acessar {url}: Código {response.status_code}")

    api = "https://api.dnsdumpster.com/htmld/"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
        "Accept": "*/*",
        "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "HX-Request": "true",
        "HX-Target": "results",
        "HX-Current-URL": "https://dnsdumpster.com/",
        "Authorization": f"{authorization_token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://dnsdumpster.com",
        "Connection": "keep-alive",
        "Referer": "https://dnsdumpster.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Priority": "u=0",
    }

    # Dados do corpo da requisição
    data = {"target": f"{domain}"}

    # Faz a requisição POST
    response = requests.post(api, headers=headers, data=data)
    html_content = response.text

    # Verifica se a requisição foi bem-sucedida
    if response.status_code == 200:

        # Expressão regular para capturar os conteúdos dentro de <td>
        padrao_td = r"<td.*?>(.*?)</td>"

        # Encontrar todas as células da tabela
        dados = re.findall(padrao_td, html_content, re.DOTALL)

        # Remover espaços extras e tags HTML internas, se houver
        dados_limpos = [re.sub(r"<.*?>", "", dado).strip() for dado in dados]

        print(dados_limpos)

    else:
        exit(1)

    # Exibe a resposta
    print(response.status_code)  # Código de status HTTP
    print(response.text)  # Corpo da resposta


def main():
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], "<domain>")
        exit(1)

    domain = str(sys.argv[1])
    print("Domínio para scan:", domain)

    # Resolver hostname
    resolve_host_name(domain)

    # whois
    resolve_whois(domain)

    # obter records do domain
    get_records(domain)

    # web scrapper do dnsdumpster


# get_dns_dumpster(domain)

if __name__ == "__main__":
    main()
