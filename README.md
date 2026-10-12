# 🐼 Bounty-Provisioner v2.0

O Bounty-Provisioner é um script de automação robusto, projetado para transformar uma instalação limpa do Linux (Debian/Ubuntu/Kali) em uma estação de trabalho completa para Bug Bounty. Do reconhecimento de subdomínios à descoberta de parâmetros ocultos, este script prepara todo o seu arsenal.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-Beast%20Mode-orange?style=for-the-badge)

---

## 🎯 Propósito
Configurar uma infraestrutura de *Bug Bounty* é uma tarefa repetitiva e propensa a erros. Este projeto automatiza a instalação das melhores ferramentas de *Recon*, *Fuzzing* e *Web Hacking* disponíveis, mantendo uma estrutura de diretórios limpa e organizada.

## 🚀 Principais recursos

| Módulo | Descrição |
|:---|:---|
| **Preflight** | Valida plataforma, `sudo`, `git/curl/wget` e o toolchain Go **antes** de começar. Instala o Go oficial se estiver ausente ou desatualizado (< 1.21). |
| **Sistema** | Atualiza o `apt` e instala dependências críticas (`libpcap`, `build-essential`, `unzip`, `jq`, `chromium`, `nmap`...). |
| **Estrutura** | Cria um espaço de trabalho `~/bounty` padronizado (`tools`, `targets`, `wordlists`) e persiste o `PATH` no `.bashrc`/`.zshrc`/`.profile`. |
| **Ferramentas Go** | Instala **85 ferramentas** em Go (a contagem autoritativa é a de `--list`), agrupadas por etapa do pipeline de recon, em paralelo (`--jobs`). |
| **Python (pipx)** | Instala ferramentas Python em ambientes isolados para evitar o "inferno das dependências" (Arjun, Waymore, ParamSpider, Sqlmap...). |
| **Ferramentas Externas** | Clona e compila o que exige configuração manual (LinkFinder, SecretFinder, MassDNS, Findomain, padrões do `gf`) e atualiza os templates do Nuclei. As dependências de LinkFinder/SecretFinder vão para um venv dedicado (`~/bounty/tools/.venv`), sem poluir o Python do sistema. |
| **Wordlists** | Baixa listas de alta qualidade: SecLists, OneListForAll, fuzzdb, Assetnote e Trickest Resolvers. |
| **Idempotência** | Pula tudo que já está instalado. Use `--force` para reinstalar/atualizar. |
| **Relatório + Log** | Resumo final de instalados/pulados/falhas e log completo em `~/bounty/provisioner.log`. |

---

## 📦 Instalação e uso

```bash
git clone https://github.com/0Willp/Bounty-Provisioner.git
cd Bounty-Provisioner
chmod +x provisioner.py
python3 provisioner.py
```

### Flags

```bash
python3 provisioner.py                 # provisionamento completo (padrão)
python3 provisioner.py -h              # menu de ajuda
python3 provisioner.py --list          # lista o catálogo de ferramentas e sai
python3 provisioner.py --go            # só as ferramentas Go
python3 provisioner.py --go --jobs 16  # Go com 16 instalações em paralelo
python3 provisioner.py --go --force    # reinstala mesmo o que já existe
python3 provisioner.py --system --structure
```

| Flag | Efeito |
|:---|:---|
| `--system` | Atualiza o sistema e instala as dependências de build |
| `--structure` | Cria `~/bounty` e persiste o `PATH` |
| `--go` | Instala as ferramentas Go e linka os binários em `/usr/local/bin` |
| `--python` | Instala as ferramentas Python via `pipx` |
| `--external` | Clona/compila ferramentas externas e atualiza templates do Nuclei |
| `--wordlists` | Baixa as wordlists |
| `--all` | Roda todas as etapas (padrão quando nenhuma flag é passada) |
| `--force` | Reinstala/atualiza mesmo o que já existe |
| `--jobs N` | Instalações Go em paralelo (padrão: `min(8, nproc)`) |
| `--list` | Mostra o catálogo agrupado por categoria e sai |
| `--no-banner` | Suprime o banner |

O código de saída é `1` se qualquer item falhar — útil para CI ou `cloud-init`.

## 📂 Estrutura de diretórios
```bash
~/bounty/
├── targets/           # Relatórios de varredura e dados específicos do domínio
├── tools/             # Ferramentas instaladas via Git/Wget (LinkFinder, MassDNS...)
│   └── .venv/         # venv dedicado para as dependências de LinkFinder/SecretFinder
├── wordlists/         # Listas essenciais (SecLists, Assetnote, Resolvers)
└── provisioner.log    # Log completo da última execução
```

> **LinkFinder / SecretFinder:** execute-os com o interpretador do venv, por exemplo
> `~/bounty/tools/.venv/bin/python ~/bounty/tools/LinkFinder/linkfinder.py -h`
> (o provisioner imprime esse caminho ao final da etapa `--external`).

## 🔄 Mudanças da v1.0 → v2.0

* **Preflight de dependências** — falha cedo e com mensagem clara em vez de emitir 40 erros silenciosos.
* **Instalação do Go automatizada** — baixa o tarball oficial quando o Go está ausente ou desatualizado.
* **`ln -s` em vez de `mv`** — a v1.0 movia `~/go/bin/*` para `/usr/bin`, o que esvaziava o diretório do Go (quebrando a idempotência do `go install`) e podia sobrescrever binários gerenciados pelo `dpkg`. Agora os binários são linkados em `/usr/local/bin`.
* **Instalações Go em paralelo** — de ~40 instalações sequenciais para `--jobs` simultâneas.
* **Idempotência** — cada ferramenta é pulada se já existir; `--force` força a reinstalação.
* **Relatório e log** — nada mais falha em silêncio.
* **Correção do Findomain** — o `else` da v1.0 estava preso ao resultado do `cargo build`, imprimindo "already exists" quando na verdade a compilação havia falhado. Agora usa o binário oficial da release, com `cargo` como fallback.
* **`certstream` removido** — é uma biblioteca sem entrypoint de CLI; o `pipx install` sempre falhava.
* **`trufflehog` migrado para Go** — o pacote homônimo no PyPI é o v2 abandonado.
* **Catálogo orientado a dados** — 40 → 85 ferramentas Go, agrupadas por etapa do pipeline.

## 🐼 Mentalidade
"Ferramentas não encontram bugs; pesquisadores, sim. As ferramentas apenas tornam o palheiro menor."

## ⚖️ Aviso Legal
Este projeto destina-se exclusivamente a fins educacionais e de pesquisa ética em segurança. O autor não se responsabiliza por qualquer uso indevido das ferramentas instaladas por este script. Realize testes apenas em sistemas dentro do escopo autorizado.

Desenvolvido por 0WILLP
🐼 | Escrevendo código e encontrando bugs.
