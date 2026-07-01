# Burp Paths/Parametros Extractor

Fala crias.

Essa extensao para Burp Suite coleta paths e parametros das requisicoes que passam pelo Burp e mostra tudo em uma aba propria.

Ela foi feita para ajudar a montar wordlists rapidamente durante recon, fuzzing e testes manuais.

Na tela, ela separa:

```text
# paths.txt
solucoes
verejos

# full_paths.txt
solucoes/verejos

# parameters.txt
ver
id
```

Na hora de exportar, ela gera dois arquivos:

```text
paths.txt
parameters.txt
```

O `paths.txt` exportado junta os valores de `paths` e `full_paths`.

O `parameters.txt` exportado salva os parametros encontrados.

---

## Requisitos

Voce precisa ter:

* Burp Suite
* Java funcionando
* Jython standalone `.jar`

Burp nao usa o Python normal da maquina para rodar extensoes Python. Ele usa Jython.

---

## Baixar o Jython

Baixe o Jython standalone:

```bash
curl -L -o jython-standalone-2.7.4.jar https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar
```

No Windows PowerShell:

```powershell
Invoke-WebRequest -Uri "https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar" -OutFile "jython-standalone-2.7.4.jar"
```

Sugestao de pasta no Windows:

```text
C:\Tools\jython\jython-standalone-2.7.4.jar
```

---

## Configurar Python no Burp

Se voce nunca usou extensao Python no Burp, precisa configurar o Jython.

1. Abra o Burp Suite.
2. Va em `Settings`.
3. Procure por `Extensions`.
4. Entre em `Core extension settings`.
5. Ache `Python environment`.
6. Em `Location of Jython standalone JAR file`, selecione o arquivo:

```text
jython-standalone-2.7.4.jar
```

Depois disso, o Burp vai conseguir carregar extensoes Python.

---

## Instalar a extensao

1. Abra o Burp Suite.
2. Va em `Extensions`.
3. Clique em `Add`.
4. Em `Extension type`, selecione `Python`.
5. Em `Extension file`, selecione o arquivo `.py` deste repositorio.
6. Clique em `Next`.

Se tudo estiver certo, vai aparecer uma nova aba:

```text
Paths/Parametros
```

---

## Como usar

A extensao coleta automaticamente requests novos que passam pelo Burp.

Ela escuta:

* Proxy
* Target
* Repeater

Entao, se voce mandar uma request para o Repeater e executar, ela tambem coleta os paths e parametros dessa request.

---

## Opcoes

### Coletar apenas do escopo do Burp Target

Quando marcado, a extensao so coleta requests que estiverem dentro do escopo configurado no Burp Target.

### Tambem extrair paths reais de JavaScript

Quando marcado, a extensao tenta encontrar paths dentro de respostas JavaScript.

Essa opcao pode trazer mais coisa do que o esperado dependendo do alvo, entao use quando fizer sentido.

### Manual hosts allowlist

Voce tambem pode colocar hosts manualmente na area de allowlist.

Um host por linha:

```text
example.com
api.example.com
```

Isso ajuda quando voce nao quer ou nao pode configurar tudo no Burp Target Scope.

---

## Preview

Na tela, a extensao mostra:

```text
# paths.txt
setor
verejo

# full_paths.txt
setor/verejo

# parameters.txt
ver
```

O preview fica separado para facilitar a visualizacao.

---

## Exportar txt

O botao `Exportar txt` pede uma pasta e salva dois arquivos:

```text
paths.txt
parameters.txt
```

O `paths.txt` exportado junta:

* `paths`
* `full_paths`

Exemplo:

```text
setor
verejo
setor/verejo
```

O `parameters.txt` exportado salva os parametros:

```text
ver
id
tipo
```

---

## Limpar

O botao `Limpar` apaga tudo que foi coletado na aba atual.

Use ele quando trocar de alvo ou quando quiser remover lixo antigo da tela.

---

## Filtros

A extensao ja filtra por padrao varias coisas que normalmente poluem a lista, como:

* arquivos `.css`, `.js`, `.png`, `.ico`
* paths de tracking
* parametros `utm_*`
* parametros de Google Ads/Analytics
* hosts comuns de tracking, como Google Analytics, Google Tag Manager e DoubleClick

Esses filtros rodam por padrao, mas podem ser editados pela interface.

Na parte de configuracao existem abas de blacklist:

* `Hosts`
* `Segmentos`
* `Arquivos`
* `Extensoes`
* `Parametros`

Se voce quiser deixar de filtrar alguma coisa, remova da blacklist correspondente.

Exemplo:

Se quiser que arquivos `.7z` sejam considerados paths validos, remova:

```text
.7z
```

da aba `Extensoes`.

Se quiser deixar `/wp-content` aparecer, remova:

```text
wp-content
```

da aba `Segmentos`.

O botao `Restaurar blacklist` volta os filtros para o padrao da extensao.

Para evitar poluicao, prefira definir o host:

* pelo Burp Target Scope; ou
* pela allowlist manual da extensao.

---

## Observacoes

Ela ainda esta meio paia e precisa de uso real pra melhorar.

A ideia e ir ajustando os filtros conforme aparecerem casos novos.

Se vier lixo demais, tente:

* clicar em `Limpar`;
* deixar a extracao de JavaScript desmarcada;
* configurar o Burp Target Scope;
* usar a allowlist manual com o host do alvo.

---

## Arquivos gerados

Ao exportar:

```text
paths.txt
parameters.txt
```

O arquivo `paths.txt` serve para wordlist de rotas.

O arquivo `parameters.txt` serve para wordlist de parametros.

---

## Status

Extensao local para uso em Burp Suite.

Ainda nao e uma extensao pronta para Burp BApp Store.
