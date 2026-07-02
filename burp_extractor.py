# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JCheckBox, JTextArea, JScrollPane, JLabel, JButton
from javax.swing import JFileChooser, JOptionPane, JTabbedPane
from javax.swing import BoxLayout, BorderFactory
from java.awt import BorderLayout
from java.net import URL, URLDecoder
from java.io import File
import re
import json


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
cloudflareinsights.com
static.cloudflareinsights.com
cdn.jsdelivr.net
jsdelivr.net
unpkg.com"""

DEFAULT_NOISY_PATH_PREFIXES = """/cdn-cgi/
/__webpack
/sockjs-node"""

DEFAULT_NOISY_FILES = """favicon.ico
robots.txt
sitemap.xml
warmup.html
site.webmanifest
manifest.json
browserconfig.xml
beacon.min.js"""

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
.xml"""

DEFAULT_NOISY_PARAMS = """v
_
t
ts
cb
cache
cachebuster
utm_*
gclid
gbraid
wbraid
fbclid
msclkid
PHPSESSID
JSESSIONID
ASP.NET_SessionId
SESSION
SESSIONID"""


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Extrator de Paths e Parametros")
        callbacks.registerHttpListener(self)

        self.paths = []
        self.params = []
        self.learned_hosts = set()

        self.panel = JPanel(BorderLayout())

        top = JPanel(BorderLayout())

        options = JPanel()
        options.setLayout(BoxLayout(options, BoxLayout.Y_AXIS))
        options.setBorder(BorderFactory.createTitledBorder("Opcoes"))

        self.only_scope = JCheckBox("Coletar apenas do escopo do Burp Target", False)
        self.extract_js = JCheckBox("Tambem extrair paths reais de JavaScript", False)
        self.learn_redirect_hosts = JCheckBox("Aprender hosts por redirects de hosts permitidos", True)

        options.add(self.only_scope)
        options.add(self.extract_js)
        options.add(self.learn_redirect_hosts)

        buttons = JPanel()
        buttons.add(JButton("Exportar txt", actionPerformed=self.export_txt))
        buttons.add(JButton("Exportar JSON", actionPerformed=self.export_json))
        buttons.add(JButton("Limpar", actionPerformed=self.clear_results))
        buttons.add(JButton("Restaurar blacklist", actionPerformed=self.restore_blacklists))
        options.add(buttons)

        config_tabs = JTabbedPane()

        allow_panel, self.host_allowlist = self.text_panel(
            "Manual hosts allowlist, opcional",
            "",
            "Um host por linha. Ex: maristabrasil.org tambem aceita joao.maristabrasil.org.",
        )
        noisy_hosts_panel, self.noisy_hosts_area = self.text_panel(
            "Blacklist hosts",
            DEFAULT_NOISY_HOSTS,
            "Um host por linha. Subdominios tambem serao filtrados.",
        )
        noisy_prefix_panel, self.noisy_prefix_area = self.text_panel(
            "Blacklist prefixos de path",
            DEFAULT_NOISY_PATH_PREFIXES,
            "Um prefixo por linha. Ex: /cdn-cgi/",
        )
        noisy_files_panel, self.noisy_files_area = self.text_panel(
            "Blacklist arquivos",
            DEFAULT_NOISY_FILES,
            "Um nome de arquivo por linha.",
        )
        noisy_extensions_panel, self.noisy_extensions_area = self.text_panel(
            "Blacklist extensoes",
            DEFAULT_NOISY_EXTENSIONS,
            "Uma extensao por linha. Ex: .js, .png, .css",
        )
        noisy_params_panel, self.noisy_params_area = self.text_panel(
            "Blacklist parametros",
            DEFAULT_NOISY_PARAMS,
            "Um parametro por linha. Aceita prefixo com *: utm_*",
        )

        config_tabs.addTab("Allowlist", allow_panel)
        config_tabs.addTab("Hosts", noisy_hosts_panel)
        config_tabs.addTab("Prefixos", noisy_prefix_panel)
        config_tabs.addTab("Arquivos", noisy_files_panel)
        config_tabs.addTab("Extensoes", noisy_extensions_panel)
        config_tabs.addTab("Parametros", noisy_params_panel)

        top.add(options, BorderLayout.WEST)
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

    def getTabCaption(self):
        return "Paths/Parametros"

    def getUiComponent(self):
        return self.panel

    def text_panel(self, title, default_text, footer):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(title))
        area = JTextArea(default_text, 6, 42)
        panel.add(JScrollPane(area), BorderLayout.CENTER)
        panel.add(JLabel(footer), BorderLayout.SOUTH)
        return panel, area

    def restore_blacklists(self, event):
        self.noisy_hosts_area.setText(DEFAULT_NOISY_HOSTS)
        self.noisy_prefix_area.setText(DEFAULT_NOISY_PATH_PREFIXES)
        self.noisy_files_area.setText(DEFAULT_NOISY_FILES)
        self.noisy_extensions_area.setText(DEFAULT_NOISY_EXTENSIONS)
        self.noisy_params_area.setText(DEFAULT_NOISY_PARAMS)

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

        if self.is_noisy_host(url):
            return

        if not self.host_should_be_collected(url):
            return

        if not messageIsRequest and self.learn_redirect_hosts.isSelected():
            self.learn_hosts_from_redirect(messageInfo, url)

        if messageIsRequest:
            self.collect_from_url(url, self.paths, self.params)
            request = messageInfo.getRequest()
            if request:
                self.collect_from_body(request, request_info, self.params)

        if not messageIsRequest and self.extract_js.isSelected():
            response = messageInfo.getResponse()
            if response:
                body = self.get_response_body(response)
                self.collect_from_javascript(body, self.paths)

        self.render_preview()

    def host_should_be_collected(self, url):
        if self.only_scope.isSelected() and self.callbacks.isInScope(url):
            return True

        if self.host_in_allowlist(url):
            return True

        if self.host_in_learned_hosts(url):
            return True

        if self.has_allowlist():
            return False

        return not self.only_scope.isSelected()

    def has_allowlist(self):
        return bool(self.host_allowlist.getText().strip())

    def host_in_allowlist(self, url):
        raw = self.host_allowlist.getText().strip()
        if not raw:
            return False

        host = (url.getHost() or "").lower()
        for line in raw.splitlines():
            item = line.strip().lower()
            if not item or item.startswith("#"):
                continue
            if host == item or host.endswith("." + item):
                return True
        return False

    def host_in_learned_hosts(self, url):
        host = (url.getHost() or "").lower()
        for item in self.learned_hosts:
            if host == item or host.endswith("." + item):
                return True
        return False

    def is_noisy_host(self, url):
        host = (url.getHost() or "").lower()
        for noisy_host in self.text_items(self.noisy_hosts_area):
            if host == noisy_host or host.endswith("." + noisy_host):
                return True
        return False

    def learn_hosts_from_redirect(self, messageInfo, source_url):
        try:
            response = messageInfo.getResponse()
            if not response:
                return

            response_info = self.helpers.analyzeResponse(response)
            status = response_info.getStatusCode()
            if status not in [301, 302, 303, 307, 308]:
                return

            for header in response_info.getHeaders():
                if not header.lower().startswith("location:"):
                    continue

                location = header.split(":", 1)[1].strip()
                target_url = self.resolve_location(source_url, location)
                if not target_url:
                    return

                if self.is_noisy_host(target_url):
                    return

                target_host = (target_url.getHost() or "").lower()
                source_host = (source_url.getHost() or "").lower()

                if target_host and target_host != source_host:
                    self.learned_hosts.add(target_host)
                return
        except:
            return

    def resolve_location(self, source_url, location):
        try:
            if location.startswith("http://") or location.startswith("https://"):
                return URL(location)
            return URL(source_url, location)
        except:
            return None

    def collect_from_url(self, url, paths, params):
        raw_path = url.getPath() or ""
        raw_query = url.getQuery() or ""

        path = self.clean_path(raw_path)
        if path:
            paths.append(path)

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

    def collect_from_body(self, request, request_info, params):
        try:
            body_offset = request_info.getBodyOffset()
            request_string = self.helpers.bytesToString(request)
            body = request_string[body_offset:]

            # form-urlencoded: id=1&file=test
            if "=" in body:
                for match in re.finditer(r'(^|&)([A-Za-z_][A-Za-z0-9_\-.]{0,80})=', body):
                    key = self.clean_param(match.group(2))
                    if key:
                        params.append(key)

            # JSON simples: {"id": 1, "file": "x"}
            if body.strip().startswith("{") or "application/json" in request_string.lower():
                for match in re.finditer(r'"([A-Za-z_][A-Za-z0-9_\-.]{0,80})"\s*:', body):
                    key = self.clean_param(match.group(1))
                    if key:
                        params.append(key)
        except:
            pass

    def collect_from_javascript(self, body, paths):
        if not body:
            return

        # Captura strings completas que parecem paths reais.
        candidates = re.findall(r'''["'](/[^"'<>\\\s]{2,250})["']''', body)
        for candidate in candidates:
            path = self.clean_js_path(candidate)
            if path:
                paths.append(path)

    def clean_js_path(self, path):
        if not path:
            return None

        path = path.split("?", 1)[0]
        path = path.split("#", 1)[0]

        # Evita concatenação quebrada: /ID/'+$('body')...
        if "'+" in path or '"+' in path or "$(" in path or "parseInt" in path:
            return None

        return self.clean_path(path)

    def clean_path(self, path):
        if not path:
            return None

        path = self.decode(path).strip()
        path = path.split("?", 1)[0].split("#", 1)[0]

        if not path.startswith("/"):
            path = "/" + path

        path = re.sub(r"/+", "/", path)

        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        if path == "/":
            return None

        if self.is_noisy_path(path):
            return None

        return path

    def clean_param(self, value):
        value = self.decode(value)
        value = value.strip().lstrip("?&").split("=", 1)[0]
        value = value.strip()

        if not value:
            return None

        value = re.sub(r"[^A-Za-z0-9_\-.]", "", value)

        if not value:
            return None

        if self.is_noisy_param(value):
            return None

        return value

    def is_noisy_path(self, path):
        lower = path.lower()

        for prefix in self.text_items(self.noisy_prefix_area):
            if lower.startswith(prefix):
                return True

        segments = [part for part in lower.strip("/").split("/") if part]
        if not segments:
            return True

        # se qualquer segmento for arquivo estatico/ruido, ignora o path inteiro
        for segment in segments:
            if self.is_file_or_noise_segment(segment):
                return True

        # ids/hash/cache busting gigantes no path
        for segment in segments:
            if self.is_generated_value(segment):
                return True

        return False

    def is_file_or_noise_segment(self, value):
        lower = value.lower().strip()

        for filename in self.text_items(self.noisy_files_area):
            if lower == filename:
                return True

        for ext in self.text_items(self.noisy_extensions_area):
            if lower.endswith(ext):
                return True

        return False

    def is_generated_value(self, lower):
        if re.match(r"^[a-f0-9]{16,}$", lower):
            return True
        if re.match(r"^v[0-9a-f]{16,}$", lower):
            return True
        if re.match(r"^[a-z0-9_-]{40,}$", lower):
            return True
        return False

    def is_noisy_param(self, value):
        lower = value.lower().strip()
        for pattern in self.text_items(self.noisy_params_area):
            if self.matches_pattern(lower, pattern):
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
        return sorted(result)

    def render_preview(self):
        self.paths = self.unique(self.paths)
        self.params = self.unique(self.params)

        output = []
        output.append("# paths.txt")
        output.extend(self.paths)
        output.append("")
        output.append("# parameters.txt")
        output.extend(self.params)
        output.append("")
        output.append("# learned-hosts")
        output.extend(sorted(self.learned_hosts))

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

        self.write_text_file(paths_file, "\n".join(self.unique(self.paths)))
        self.write_text_file(params_file, "\n".join(self.unique(self.params)))

        JOptionPane.showMessageDialog(
            self.panel,
            "Arquivos exportados:\npaths.txt\nparameters.txt",
            "Exportacao concluida",
            JOptionPane.INFORMATION_MESSAGE,
        )

    def export_json(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Escolha a pasta para salvar wordlists.json")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return

        folder = chooser.getSelectedFile()
        json_file = File(folder, "wordlists.json")

        data = {
            "paths": self.unique(self.paths),
            "parameters": self.unique(self.params),
            "learned_hosts": sorted(self.learned_hosts),
        }

        self.write_json_file(json_file, data)

        JOptionPane.showMessageDialog(
            self.panel,
            "Arquivo exportado:\nwordlists.json",
            "Exportacao concluida",
            JOptionPane.INFORMATION_MESSAGE,
        )

    def clear_results(self, event):
        self.paths = []
        self.params = []
        self.learned_hosts = set()
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

    def write_json_file(self, file_obj, data):
        writer = None
        try:
            writer = open(file_obj.getAbsolutePath(), "w")
            writer.write(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
            writer.write("\n")
        finally:
            if writer:
                writer.close()

    def get_response_body(self, response):
        response_info = self.helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        return self.helpers.bytesToString(response[body_offset:])
