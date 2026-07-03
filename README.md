# FuzzForge

Fala crias.

**FuzzForge** é uma extensão para Burp Suite que cria wordlists específicas para cada alvo a partir dos paths e parâmetros reais observados durante a navegação.

A ideia surgiu de um problema simples: wordlists genéricas, muitas vezes focadas em inglês, podem não encontrar palavras específicas da aplicação, do idioma ou do contexto do negócio.

Exemplo:

```text
GET /institucional/canais-de-distribuicao?id=12
```

A extensão coleta:

```text
# paths.txt
institucional
canais-de-distribuicao

# full_paths.txt
/institucional/canais-de-distribuicao

# parameters.txt
id
```

Na exportação TXT, `paths` e `full_paths` são unidos em `paths.txt`. Os parâmetros vão para `parameters.txt`.

---

## Requisitos

- Burp Suite
- Java
- Jython standalone

Baixe o Jython:

```bash
curl -L -o jython-standalone-2.7.4.jar https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar
```

No Burp:

```text
Settings
> Extensions
> Core extension settings
> Python environment
```

Selecione o arquivo:

```text
jython-standalone-2.7.4.jar
```

---

## Instalar a extensão

No Burp:

```text
Extensions
> Installed
> Add
```

Escolha:

```text
Extension type: Python
Extension file: fuzzforge.py
```

Depois disso, a aba **FuzzForge** aparecerá no Burp.

---

## Como usar

A extensão coleta automaticamente requests que passam por:

- Proxy
- Target
- Repeater

Ela separa os resultados em:

```text
# paths.txt
intranet
usuarios
perfil

# full_paths.txt
/intranet/usuarios/perfil

# parameters.txt
id
page
search
```

Exemplo:

```text
/intranet/usuarios/perfil?id=10&page=2
```

gera:

```text
intranet
usuarios
perfil
/intranet/usuarios/perfil
id
page
```

Os valores dos parâmetros não são salvos.

---

## Allowlist

Você pode limitar a coleta a hosts específicos.

Exemplo:

```text
example.com
```

Também aceita subdomínios automaticamente:

```text
api.example.com
login.example.com
portal.example.com
```

Isso ajuda a evitar que a extensão colete lixo de sites, trackers e serviços externos.

---

## Opções

### Coletar apenas do escopo do Burp Target

Coleta apenas requests dentro do scope configurado no Burp, além dos hosts da allowlist manual.

### Extrair paths de JavaScript

Procura strings que parecem paths dentro de respostas JavaScript.

Pode revelar rotas que não apareceram diretamente durante a navegação, mas também pode gerar mais ruído. Por isso, use quando fizer sentido.

---

## Filtros

A extensão filtra por padrão coisas que normalmente poluem a wordlist:

- assets como `.js`, `.css`, `.png`, `.ico`
- hosts de analytics e tracking
- segmentos de frameworks
- hashes e build IDs
- parâmetros como `utm_*`, `gclid` e `fbclid`

Os filtros podem ser alterados nas abas:

```text
Hosts
Segmentos
Arquivos
Extensões
Parâmetros
```

O botão `Restaurar blacklist` volta os filtros para o padrão.

---

## Exportar

### TXT

Gera:

```text
paths.txt
parameters.txt
```

`paths.txt` junta os segmentos e os caminhos completos.

`parameters.txt` salva os nomes dos parâmetros encontrados.

### JSON

Gera:

```text
wordlists.json
```

com os grupos separados:

```json
{
  "paths": ["intranet", "usuarios"],
  "full_paths": ["/intranet/usuarios"],
  "parameters": ["id", "page"]
}
```

---

## Limpar

O botão `Limpar` apaga tudo que foi coletado na sessão atual.

Use quando trocar de alvo ou quiser começar uma coleta nova.

---

## Por que usar?

Uma wordlist genérica pode ter:

```text
users
account
settings
admin
```

Mas uma aplicação real pode usar:

```text
colaborador
solicitacao
atualizacao-cadastral
canais-de-distribuicao
planejamento
```

O objetivo do FuzzForge é aproveitar o vocabulário real do alvo para complementar wordlists genéricas durante fuzzing, recon e testes manuais.

---

## Estado atual

Ela ainda está meio paia e precisa de uso real pra melhorar.

Os filtros estão sendo ajustados conforme aparecem novos casos de ruído, frameworks, trackers e estruturas diferentes de aplicações.

Ainda não é uma extensão pronta para a Burp BApp Store.
