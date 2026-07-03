# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JCheckBox, JTextArea, JScrollPane, JLabel, JButton
from javax.swing import JFileChooser, JTabbedPane
from javax.swing import BoxLayout, BorderFactory
from java.awt import BorderLayout, FlowLayout, Dimension
from java.net import URL, URLDecoder
from java.io import File
import re
import json
import threading


DEFAULT_NOISY_HOSTS = """google-analytics.com
googletagmanager.com
googleadservices.com
doubleclick.net
google.com
google.com.br
gstatic.com
googleapis.com
facebook.com
facebook.net
hotjar.com
segment.com
static.cloudflareinsights.com
cloudflareinsights.com"""

DEFAULT_NOISY_SEGMENTS = """cdn-cgi
rum
_next
_nuxt
_cf
static
chunks
cldr
globalize
highcharts
layout
pace
pivotgridfeatures
orgchart
jquery-notifications
default
collect
ads
ga-audiences
ccm
rmkt
pagead
viewthroughconversion
1p-user-list
wp-content
wp-includes
wp-admin
plugins
plugin
themes
theme
assets
asset
css
js
img
image
images
fonts
font
webfonts
uploads
upload
cookie-notice
npm
node_modules
blocks
block
paragraph
fontawesome
fontawesome-free
@*
*fontawesome*"""

DEFAULT_NOISY_FILES = """favicon.ico
robots.txt
sitemap.xml
warmup.html
site.webmanifest
manifest.json
browserconfig.xml"""

DEFAULT_NOISY_EXTENSIONS = """.css
.js
.map
.png
.jpg
.jpeg
.gif
.svg
.webp
.ico
.woff
.woff2
.ttf
.eot
.mp4
.mp3
.pdf
.zip
.rar
.7z
.webmanifest
.xml
.json"""

DEFAULT_NOISY_PARAMS = """v
_
t
ts
cb
cache
cachebuster
utm_*
ep.*
gap.*
gclid
gbraid
wbraid
fbclid
msclkid
gad_source
gad_campaignid
gad_adgroupid
gad_creativeid
gad_network
od
tid
gtm
_p
_gaz
gcd
npa
dma
ecid
_eu
are
cid
frm
pscdl
rcb
sr
uaa
uab
uafvl
uam
uamb
uap
uapv
uaw
ul
gaf
_s
tag_exp
sid
sct
seg
dl
dr
dt
en
_et
tfd
slf_rd
_r
aip
z
family
display
cx
ae
auid
scrsrc
rnd
gclaw
navt
apve
apvf
apvc
tft
fmt
random
cv
fst
bg
guid
async
u_w
u_h
gclaw_src
tiba
hn
ept
gcp
tids
rfmt
ec_mode
pid
seq
exp
tdp
rtg
slo
hlo
lst
pcid
bt
ct
is_vtc
rmt_tld
ipr
mde
fin
is_td"""


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("FuzzForge")
        callbacks.registerHttpListener(self)

        self.paths = []
        self.full_paths = []
        self.params = []
        self.state_lock = threading.RLock()

        self.panel = JPanel(BorderLayout())

        top = JPanel(BorderLayout())

        options = JPanel()
        options.setLayout(BoxLayout(options, BoxLayout.Y_AXIS))
        options.setBorder(BorderFactory.createTitledBorder("Opcoes"))

        self.only_scope = JCheckBox("Coletar apenas do escopo do Burp Target", False)
        self.extract_js = JCheckBox("Tambem extrair paths reais de JavaScript", False)
        options.add(self.left_row(self.only_scope))
        options.add(self.left_row(self.extract_js))

        buttons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        buttons.add(JButton("Exportar txt", actionPerformed=self.export_txt))
        buttons.add(JButton("Exportar JSON", actionPerformed=self.export_json))
        buttons.add(JButton("Limpar", actionPerformed=self.clear_results))
        buttons.add(JButton("Restaurar blacklist", actionPerformed=self.restore_blacklists))
        options.add(buttons)

        options_wrapper = JPanel(BorderLayout())
        options_wrapper.add(options, BorderLayout.NORTH)
        options_wrapper.setPreferredSize(Dimension(620, 120))

        config_tabs = JTabbedPane()

        allow_panel, self.host_allowlist = self.text_panel(
            "Manual hosts allowlist, opcional",
            "",
            "Opcional. Um host por linha. Ex: senior.com.br tambem aceita www.senior.com.br e site.senior.com.br.",
        )
        noisy_hosts_panel, self.noisy_hosts_area = self.text_panel(
            "Blacklist hosts",
            DEFAULT_NOISY_HOSTS,
            "Um host por linha. Subdominios tambem serao filtrados.",
        )
        noisy_segments_panel, self.noisy_segments_area = self.text_panel(
            "Blacklist segmentos",
            DEFAULT_NOISY_SEGMENTS,
            "Um segmento por linha. Aceita @*, prefixo*, *sufixo e *texto*.",
        )
        noisy_files_panel, self.noisy_files_area = self.text_panel(
            "Blacklist arquivos",
            DEFAULT_NOISY_FILES,
            "Um nome de arquivo por linha.",
        )
        noisy_extensions_panel, self.noisy_extensions_area = self.text_panel(
            "Blacklist extensoes",
            DEFAULT_NOISY_EXTENSIONS,
            "Uma extensao por linha. Ex: .js, .png, .7z",
        )
        noisy_params_panel, self.noisy_params_area = self.text_panel(
            "Blacklist parametros",
            DEFAULT_NOISY_PARAMS,
            "Um parametro por linha. Aceita prefixo com *: utm_*",
        )

        config_tabs.addTab("Allowlist", allow_panel)
        config_tabs.addTab("Hosts", noisy_hosts_panel)
        config_tabs.addTab("Segmentos", noisy_segments_panel)
        config_tabs.addTab("Arquivos", noisy_files_panel)
        config_tabs.addTab("Extensoes", noisy_extensions_panel)
        config_tabs.addTab("Parametros", noisy_params_panel)

        top.add(options_wrapper, BorderLayout.WEST)
        top.add(config_tabs, BorderLayout.CENTER)

        self.preview = JTextArea()
        self.preview.setEditable(False)

        preview_panel = JPanel(BorderLayout())
        preview_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        preview_panel.add(JLabel("Preview"), BorderLayout.NORTH)
        preview_panel.add(JScrollPane(self.preview), BorderLayout.CENTER)

        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(preview_panel, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)
        self.render_preview()

    def left_row(self, component):
        row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        row.add(component)
        return row

    def getTabCaption(self):
        return "FuzzForge"

    def getUiComponent(self):
        return self.panel

    def text_panel(self, title, default_text, footer):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(title))
        area = JTextArea(default_text, 5, 40)
        panel.add(JScrollPane(area), BorderLayout.CENTER)
        panel.add(JLabel(footer), BorderLayout.SOUTH)
        return panel, area

    def restore_blacklists(self, event):
        self.noisy_hosts_area.setText(DEFAULT_NOISY_HOSTS)
        self.noisy_segments_area.setText(DEFAULT_NOISY_SEGMENTS)
        self.noisy_files_area.setText(DEFAULT_NOISY_FILES)
        self.noisy_extensions_area.setText(DEFAULT_NOISY_EXTENSIONS)
        self.noisy_params_area.setText(DEFAULT_NOISY_PARAMS)
        self.preview.append("\n[OK] Blacklists restauradas.\n")

    def text_items(self, area):
        items = []
        for line in area.getText().splitlines():
            item = line.strip().lower()
            if item and not item.startswith("#"):
                items.append(item)
        return items

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag not in [
            self.callbacks.TOOL_PROXY,
            self.callbacks.TOOL_REPEATER,
            self.callbacks.TOOL_TARGET,
        ]:
            return

        request_info = self.helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()

        if not self.url_allowed(url):
            return

        changed = False

        if messageIsRequest:
            with self.state_lock:
                before = len(self.paths) + len(self.full_paths) + len(self.params)

                # O foco da extensão é GET:
                # path real da URL + nomes dos parâmetros depois de "?".
                method = (request_info.getMethod() or "").upper()
                if method == "GET":
                    self.collect_from_url(
                        url,
                        self.paths,
                        self.full_paths,
                        self.params
                    )

                # Em SPAs a barra do navegador pode mudar sem existir um novo
                # GET do documento. Nesse caso, requests seguintes normalmente
                # carregam o endereço atual no Referer. Coletamos esse path também.
                self.collect_from_referer(
                    request_info,
                    self.paths,
                    self.full_paths,
                    self.params
                )

                after = len(self.paths) + len(self.full_paths) + len(self.params)
                changed = after != before

        elif self.extract_js.isSelected():
            response = messageInfo.getResponse()
            if response:
                body = self.get_response_body(response)
                with self.state_lock:
                    before = len(self.paths) + len(self.full_paths)
                    self.collect_from_javascript(
                        body,
                        self.paths,
                        self.full_paths
                    )
                    after = len(self.paths) + len(self.full_paths)
                    changed = after != before

        if changed:
            self.render_preview()

    def render_preview(self):
        # O preview só lê um snapshot.
        # Ele não reatribui self.paths/self.full_paths/self.params,
        # então não consegue apagar um GET coletado por outra callback.
        with self.state_lock:
            paths = self.unique(list(self.paths))
            full_paths = self.unique(list(self.full_paths))
            params = self.unique(list(self.params))

        output = []
        output.append("# paths.txt")
        output.extend(paths)
        output.append("")
        output.append("# full_paths.txt")
        output.extend(full_paths)
        output.append("")
        output.append("# parameters.txt")
        output.extend(params)
        self.preview.setText("\n".join(output))

    def export_txt(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Escolha a pasta para salvar paths.txt e parameters.txt")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return

        folder = chooser.getSelectedFile()
        paths_file = File(folder, "paths.txt")
        params_file = File(folder, "parameters.txt")

        with self.state_lock:
            merged_paths = self.unique(list(self.paths) + list(self.full_paths))
            params = self.unique(list(self.params))

        self.write_text_file(paths_file, "\n".join(merged_paths))
        self.write_text_file(params_file, "\n".join(params))

        self.preview.append("\n\n[OK] Exportado: paths.txt e parameters.txt\n")

    def export_json(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Escolha a pasta para salvar wordlists.json")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return

        folder = chooser.getSelectedFile()
        json_file = File(folder, "wordlists.json")

        with self.state_lock:
            data = {
                "paths": self.unique(list(self.paths)),
                "full_paths": self.unique(list(self.full_paths)),
                "parameters": self.unique(list(self.params)),
            }

        self.write_json_file(json_file, data)
        self.preview.append("\n\n[OK] Exportado: wordlists.json\n")

    def write_json_file(self, file_obj, data):
        writer = None
        try:
            writer = open(file_obj.getAbsolutePath(), "w")
            writer.write(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
            writer.write("\n")
        finally:
            if writer:
                writer.close()

    def clear_results(self, event):
        with self.state_lock:
            self.paths = []
            self.full_paths = []
            self.params = []
        self.render_preview()

    def write_text_file(self, file_obj, text):
        writer = None
        try:
            writer = open(file_obj.getAbsolutePath(), "w")
            writer.write(text)
            if text:
                writer.write("\n")
        finally:
            if writer:
                writer.close()

    def has_allowlist(self):
        return bool(self.host_allowlist.getText().strip())

    def host_in_allowlist(self, url):
        raw = self.host_allowlist.getText().strip()
        if not raw:
            return False

        host = (url.getHost() or "").lower()
        for line in raw.splitlines():
            item = line.strip().lower()
            if not item:
                continue
            if host == item or host.endswith("." + item):
                return True
        return False

    def is_noisy_host(self, url):
        host = (url.getHost() or "").lower()

        for noisy_host in self.text_items(self.noisy_hosts_area):
            if host == noisy_host or host.endswith("." + noisy_host):
                return True
        return False

    def url_allowed(self, url):
        if url is None:
            return False

        if self.is_noisy_host(url):
            return False

        if self.only_scope.isSelected():
            if self.callbacks.isInScope(url):
                return True
            if self.host_in_allowlist(url):
                return True
            return False

        if self.has_allowlist():
            return self.host_in_allowlist(url)

        return True

    def collect_from_referer(self, request_info, paths, full_paths, params):
        try:
            headers = request_info.getHeaders()
            for header in headers:
                lower = header.lower()

                if not (
                    lower.startswith("referer:")
                    or lower.startswith("referrer:")
                ):
                    continue

                raw = header.split(":", 1)[1].strip()
                if not raw:
                    return

                referer_url = URL(raw)

                if not self.url_allowed(referer_url):
                    return

                self.collect_from_url(
                    referer_url,
                    paths,
                    full_paths,
                    params
                )
                return
        except:
            return

    def collect_from_url(self, url, paths, full_paths, params):
        raw_path = url.getPath() or ""
        raw_query = url.getQuery() or ""
        path_segments = self.clean_path_segments(raw_path)

        if self.is_noisy_path_segments(path_segments):
            path_segments = []

        full_path = self.clean_full_path_from_segments(path_segments)
        if full_path:
            full_paths.append(full_path)

        for segment in path_segments:
            cleaned = self.clean_path_segment(segment)
            if cleaned:
                paths.append(cleaned)

        self.collect_query_params(raw_query, params)

    def collect_query_params(self, raw_query, params):
        if not raw_query:
            return

        for pair in raw_query.split("&"):
            if not pair:
                continue
            if "=" in pair:
                key = pair.split("=", 1)[0]
            else:
                key = pair
            key = self.clean_param(key)
            if key:
                params.append(key)

    def collect_from_request_body(self, request, request_info, params):
        # Intencionalmente desativado.
        # Parameters.txt recebe apenas parâmetros reais da query string (?id=1&x=2).
        return

    def collect_from_javascript(self, body, paths, full_paths):
        candidates = re.findall(r"""['"](/[A-Za-z0-9_\-./{}:]+)['"]""", body)
        for candidate in candidates:
            if self.is_noisy_js_candidate(candidate):
                continue

            full_path = self.clean_full_path(candidate)
            if full_path:
                full_paths.append(full_path)

            for segment in candidate.split("/"):
                cleaned = self.clean_path_segment(segment)
                if cleaned:
                    paths.append(cleaned)

    def clean_path_segment(self, value):
        value = self.decode(value)
        value = value.strip()
        value = value.strip("/")
        value = value.split("?", 1)[0]
        value = value.split("#", 1)[0]
        value = value.strip("{}[]()")
        value = value.strip()

        if not value:
            return None

        if self.is_noisy_segment(value):
            return None

        if "/" in value:
            return None

        return value

    def clean_full_path(self, value):
        segments = self.clean_path_segments(value)
        if not segments:
            return None
        if self.is_noisy_path_segments(segments):
            return None
        return self.clean_full_path_from_segments(segments)

    def clean_full_path_from_segments(self, segments):
        cleaned_segments = []
        for segment in segments:
            cleaned = self.clean_path_segment(segment)
            if cleaned:
                cleaned_segments.append(cleaned)

        if not cleaned_segments:
            return None

        return "/" + "/".join(cleaned_segments)

    def clean_path_segments(self, value):
        value = self.decode(value)
        value = value.strip()
        value = value.split("?", 1)[0]
        value = value.split("#", 1)[0]
        value = value.strip("/")

        if not value:
            return []

        raw_segments = [segment for segment in value.split("/") if segment.strip()]
        if not raw_segments:
            return []

        # Se a URL termina em arquivo, remove somente o arquivo e preserva o diretorio.
        if self.is_file_segment(raw_segments[-1]):
            raw_segments = raw_segments[:-1]

        return raw_segments

    def clean_param(self, value):
        value = self.decode(value)
        value = value.strip().lstrip("?&").split("=", 1)[0]
        value = re.sub(r"[^A-Za-z0-9_\-.]", "", value)
        if not value:
            return None
        if self.is_noisy_param(value):
            return None
        return value

    def is_noisy_path_segments(self, parts):
        for part in parts:
            if self.is_noisy_segment(part):
                return True
        return False

    def is_file_segment(self, value):
        lower = value.lower().strip()
        for ext in self.text_items(self.noisy_extensions_area):
            if lower.endswith(ext):
                return True
        return False

    def is_noisy_segment(self, value):
        lower = value.lower().strip()

        if lower.startswith("_"):
            return True

        for pattern in self.text_items(self.noisy_segments_area):
            if self.matches_pattern(lower, pattern):
                return True

        for filename in self.text_items(self.noisy_files_area):
            if lower == filename:
                return True

        for ext in self.text_items(self.noisy_extensions_area):
            if lower.endswith(ext):
                return True

        if self.is_generated_value(lower):
            return True

        return False

    def is_generated_value(self, lower):
        # Só remove formatos com sinal forte de valor gerado.
        # NÃO usa mais comprimento puro, porque isso apagava slugs reais como:
        # higiene-e-perfumaria
        # canais-de-distribuicao

        # Hash hexadecimal.
        if re.match(r"^[a-f0-9]{16,}$", lower):
            return True

        # Cache-buster no formato v + hash hexadecimal.
        if re.match(r"^v[0-9a-f]{16,}$", lower):
            return True

        # UUID.
        if re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            lower,
        ):
            return True

        # IDs puramente numéricos.
        if re.match(r"^[0-9]+$", lower):
            return True

        # Não filtra mais pelo tamanho.
        # Slugs, nomes de parâmetros e segmentos longos são mantidos.

        if "=" in lower:
            return True

        noisy_words = [
            "google", "gstatic", "googletagmanager", "googleapis",
            "google-analytics", "doubleclick", "onegoogle",
            "asyncdataservice", "recaptcha", "facebook", "hotjar",
            "segment", "telemetry", "analytics", "tracking",
        ]
        for word in noisy_words:
            if word in lower:
                return True

        return False

    def matches_pattern(self, value, pattern):
        if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
            return pattern[1:-1] in value
        if pattern.startswith("*") and len(pattern) > 1:
            return value.endswith(pattern[1:])
        if pattern.endswith("*") and len(pattern) > 1:
            return value.startswith(pattern[:-1])
        return value == pattern

    def is_noisy_js_candidate(self, value):
        lower = value.lower().strip()
        if not lower.startswith("/"):
            return True
        if "://" in lower or "\\" in lower:
            return True
        if "=" in lower or "," in lower:
            return True
        parts = [part for part in lower.strip("/").split("/") if part]
        if not parts:
            return True
        for part in parts:
            if self.is_noisy_segment(part):
                return True
        return False

    def is_noisy_param(self, value):
        lower = value.lower().strip()
        for pattern in self.text_items(self.noisy_params_area):
            if self.matches_pattern(lower, pattern):
                return True
        return False

    def decode(self, value):
        try:
            return URLDecoder.decode(value, "UTF-8")
        except:
            return value

    def unique(self, values):
        seen = set()
        result = []
        for value in values:
            key = value.lower()
            if key not in seen:
                seen.add(key)
                result.append(value)
        return sorted(result, key=lambda x: x.lower())

    def get_response_body(self, response):
        response_info = self.helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        return self.helpers.bytesToString(response[body_offset:])
