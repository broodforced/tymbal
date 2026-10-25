/*
 * tymbal.c — lightweight recon, runs anywhere. One file, C99, libc only.
 * Emits cicada-compatible JSON (the schema shared with cicada).
 *
 * No linked dependencies beyond libc. The one runtime concession is `curl`,
 * used only for HTTPS/TLS (crt.sh, https probing, header/CORS checks) — the
 * same "curl or wget" contract tymbal.sh already documents. Everything else is
 * done natively: DNS brute via getaddrinfo (no nslookup/host/getent), port
 * scan via nonblocking connect (no nc/ncat).
 *
 *   build:  cc -O2 tymbal.c -o tymbal
 *   run:    ./tymbal [-m fast|normal|deep] [-t n] [-T sec] [-o dir] [-v] [-V] <target>
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERSION "0.1.0"
#define MAX_HOSTS 8192
#define MAX_STRING 8192
#define MAX_ASSETS 8192
#define MAX_FINDINGS 256

/* ── wordlist (the DNS brute list) ─────────────────────────────── */
static const char *wordlist[] = {
	"www","mail","ftp","smtp","pop","ns1","ns2","webmail","admin","api",
	"dev","staging","test","beta","app","m","mobile","cdn","static","assets",
	"img","images","media","docs","wiki","blog","shop","store","portal","vpn",
	"remote","git","svn","jenkins","ci","grafana","monitor","status","auth",
	"sso","login","oauth","id","db","mysql","postgres","redis","elastic",
	"kibana","internal","intranet","corp","office","jira","confluence","sandbox",
	"demo","preview","stage","uat","qa","prod","production","edge","gateway",
	"proxy","backup","old","new","v2","v3","next"
};
#define NWORDS (sizeof(wordlist) / sizeof(wordlist[0]))

/* ── config ───────────────────────────────────────────────────── */
static const char *mode = "normal";
static int threads = 5;       /* reserved; parallel probing not yet threaded */
static int timeout = 5;       /* per-request seconds */
static const char *outdir = ".";
static int verbose = 0;

/* ── growing string buffer ────────────────────────────────────── */
typedef struct { char *p; size_t len, cap; } sbuf;
static void sb_init(sbuf *s){ s->cap = 1024; s->p = malloc(s->cap); if (s->p){ s->p[0] = 0; } s->len = 0; }
static void sb_free(sbuf *s){ free(s->p); s->p = NULL; s->len = s->cap = 0; }
static void sb_reserve(sbuf *s, size_t need){
	if (need + 1 <= s->cap) return;
	size_t nc = s->cap;
	while (nc < need + 1) nc *= 2;
	char *np = realloc(s->p, nc);
	if (np){ s->p = np; s->cap = nc; }
}
static void sb_addn(sbuf *s, const char *str, size_t n){
	if (!s->p) sb_init(s);
	sb_reserve(s, s->len + n);
	memcpy(s->p + s->len, str, n);
	s->len += n; s->p[s->len] = 0;
}
static void sb_add(sbuf *s, const char *str){ sb_addn(s, str, strlen(str)); }
static void sb_addc(sbuf *s, char c){ char cc[2] = { c, 0 }; sb_add(s, cc); }
static void sb_addf(sbuf *s, const char *fmt, ...){
	va_list ap; va_start(ap, fmt);
	char tmp[512]; int n = vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
	if (n < 0) return;
	if ((size_t)n < sizeof tmp){ sb_addn(s, tmp, (size_t)n); return; }
	va_start(ap, fmt);
	sb_reserve(s, s->len + (size_t)n);
	vsnprintf(s->p + s->len, (size_t)n + 1, fmt, ap); va_end(ap);
	s->len += (size_t)n;
}

/* ── helpers ──────────────────────────────────────────────────── */
static char *xstrdup(const char *s){ size_t n = strlen(s) + 1; char *p = malloc(n); if (p) memcpy(p, s, n); return p; }

static void lowercase(char *s){ for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32; }

/* case-insensitive substring */
static const char *stristr(const char *hay, const char *needle){
	size_t nl = strlen(needle);
	if (!nl) return hay;
	for (; *hay; hay++){
		size_t i = 0;
		while (i < nl){
			char h = hay[i], n = needle[i];
			if (h >= 'A' && h <= 'Z') h += 32;
			if (n >= 'A' && n <= 'Z') n += 32;
			if (h != n) break;
			i++;
		}
		if (i == nl) return hay;
	}
	return NULL;
}

/* JSON-string escape into buffer; drops raw control chars to keep output valid */
static void json_escape(sbuf *s, const char *str){
	for (; *str; str++){
		unsigned char c = (unsigned char)*str;
		switch (c){
			case '"':  sb_add(s, "\\\""); break;
			case '\\': sb_add(s, "\\\\"); break;
			case '\n': sb_add(s, "\\n"); break;
			case '\r': break;                 /* drop CR */
			case '\t': sb_add(s, "\\t"); break;
			default:
				if (c < 0x20) sb_addf(s, "\\u%04x", c);
				else sb_addc(s, (char)c);
		}
	}
}

/* ISO8601 UTC timestamp (the `ts()` from tymbal.sh) */
static void ts(char *out, size_t n){
	time_t t = time(NULL); struct tm g;
	gmtime_r(&t, &g);
	strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &g);
}

/* strip scheme/path/port, lowercase — the extract_domain() from tymbal.sh */
static void extract_domain(const char *target, char *out, size_t n){
	const char *p = target;
	if (strncasecmp(p, "https://", 8) == 0) p += 8;
	else if (strncasecmp(p, "http://", 7) == 0) p += 7;
	size_t i = 0;
	for (; *p && *p != '/' && *p != ':' && i < n - 1; p++) out[i++] = *p;
	out[i] = 0;
	lowercase(out);
}

/* run a program via fork/exec (no shell), capture its stdout+stderr into out */
static int run_argv(char *const argv[], sbuf *out){
	int fd[2];
	if (pipe(fd) != 0) return -1;
	pid_t pid = fork();
	if (pid < 0){ close(fd[0]); close(fd[1]); return -1; }
	if (pid == 0){
		dup2(fd[1], 1); dup2(fd[1], 2);
		close(fd[0]); close(fd[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(fd[1]);
	char buf[8192]; ssize_t r;
	while ((r = read(fd[0], buf, sizeof buf)) > 0) sb_addn(out, buf, (size_t)r);
	close(fd[0]);
	int st = 0; waitpid(pid, &st, 0);
	return st;
}

/* resolve host → first IPv4 string via getaddrinfo (no nslookup) */
static int resolve_ip(const char *host, char *out, size_t n){
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
	void *a = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	if (!inet_ntop(AF_INET, a, out, (socklen_t)n)) { freeaddrinfo(res); return -1; }
	freeaddrinfo(res);
	return 0;
}

/* ── the collected scan result ───────────────────────────────── */
typedef struct {
	char host[MAX_STRING];
	char ip[MAX_STRING];
	int ports[16];
	int nports;
	char tech[MAX_STRING];      /* comma-separated, ready-to-escape items are raw here */
	int tech_count;
	int status_code;
	int content_length;
	char title[MAX_STRING];
	int cdn;
} asset_t;

typedef struct {
	char title[MAX_STRING];
	char severity[16];
	char category[64];
	char target[MAX_STRING];
	char detail[MAX_STRING];
} finding_t;

static asset_t assets[MAX_ASSETS];
static int nassets;
static finding_t findings[MAX_FINDINGS];
static int nfindings;

static void add_finding(const char *title, const char *sev, const char *cat,
                        const char *target, const char *detail){
	if (nfindings >= MAX_FINDINGS) return;
	finding_t *f = &findings[nfindings];
	snprintf(f->title, sizeof f->title, "%s", title);
	snprintf(f->severity, sizeof f->severity, "%s", sev);
	snprintf(f->category, sizeof f->category, "%s", cat);
	snprintf(f->target, sizeof f->target, "%s", target);
	snprintf(f->detail, sizeof f->detail, "%s", detail);
	nfindings++;
}

/* ── phase 1: subdomain enumeration ──────────────────────────── */
static char *subdomains[MAX_HOSTS];
static int nsubs;

static void add_sub(const char *h){
	if (!*h) return;
	for (int i = 0; i < nsubs; i++) if (strcmp(subdomains[i], h) == 0) return;
	if (nsubs >= MAX_HOSTS) return;
	subdomains[nsubs++] = xstrdup(h);
}

static int subcmp(const void *a, const void *b){
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void crtsh(const char *domain){
	char url[MAX_STRING];
	snprintf(url, sizeof url, "https://crt.sh/?q=%%25.%s&output=json", domain);
	char mt[16]; snprintf(mt, sizeof mt, "%d", timeout);
	char *argv[] = { "curl", "-s", "-k", "--max-time", mt, url, NULL };
	sbuf out; sb_init(&out);
	if (run_argv(argv, &out) != 0 && out.len == 0){ sb_free(&out); return; }

	/* scan for every "name_value":"…" occurrence and harvest hosts */
	const char *needle = "\"name_value\":\"";
	const char *p = out.p;
	while ((p = strstr(p, needle)) != NULL){
		p += strlen(needle);
		char field[MAX_STRING]; size_t i = 0;
		while (*p && *p != '"' && i < sizeof field - 1) field[i++] = *p++;
		field[i] = 0;
		if (*p != '"') break;
		/* name_value may hold many newline- or comma-joined hosts */
		char *tok = field;
		while (*tok){
			char *end = tok;
			int sep2 = 0;
			while (*end){
				if (*end == '\n' || *end == ',' || *end == ' ' || *end == '	') break;
				if (*end == '\\' && end[1] == 'n'){ sep2 = 1; break; }
				end++;
			}
			int at_end = (*end == 0);
			*end = 0;
			char *c = tok;
			if (c[0] == '*' && c[1] == '.') c += 2;
			lowercase(c);
			size_t dl = strlen(domain), cl = strlen(c);
			if (cl == dl && strcmp(c, domain) == 0) add_sub(c);
			else if (cl > dl + 1 && c[cl - dl - 1] == '.' && strcmp(c + cl - dl, domain) == 0) add_sub(c);
			if (at_end) break;
			tok = sep2 ? end + 2 : end + 1;
		}
	}
	sb_free(&out);
}

static void dns_brute(const char *domain){
	for (size_t i = 0; i < NWORDS; i++){
		char host[MAX_STRING];
		snprintf(host, sizeof host, "%s.%s", wordlist[i], domain);
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(host, NULL, &hints, &res) == 0){
			add_sub(host);
			freeaddrinfo(res);
			if (verbose) printf("    → %s\n", host);
		}
	}
}

/* ── phase 2: http probing ───────────────────────────────────── */
static void probe_host(const char *host){
	if (nassets >= MAX_ASSETS) return;
	asset_t *a = &assets[nassets];
	memset(a, 0, sizeof *a);
	snprintf(a->host, sizeof a->host, "%s", host);

	char mt[16]; snprintf(mt, sizeof mt, "%d", timeout);
	char url_https[MAX_STRING], url_http[MAX_STRING];
	snprintf(url_https, sizeof url_https, "https://%s", host);
	snprintf(url_http, sizeof url_http, "http://%s", host);

	sbuf out; sb_init(&out);
	int scheme_https = 1;
	char *argv[] = { "curl", "-s", "-k", "-L", "--max-time", mt, "-D", "-", url_https, NULL };
	if (run_argv(argv, &out) != 0 && out.len == 0){
		scheme_https = 0;
		char *argv2[] = { "curl", "-s", "-k", "-L", "--max-time", mt, "-D", "-", url_http, NULL };
		run_argv(argv2, &out);
	}
	if (out.len == 0){ sb_free(&out); return; }

	/* status: last "HTTP/" line in the buffer */
	const char *hp = out.p, *last = NULL;
	while ((hp = strstr(hp, "HTTP/")) != NULL){ last = hp; hp += 5; }
	if (last){
		const char *q = last + 5;
		while (*q && *q != ' ') q++;   /* skip version */
		while (*q == ' ') q++;
		int code = 0, nd = 0;
		while (*q >= '0' && *q <= '9' && nd < 3){ code = code * 10 + (*q - '0'); q++; nd++; }
		a->status_code = code;
	}

	/* title */
	const char *t = stristr(out.p, "<title");
	if (t){
		while (*t && *t != '>') t++;
		if (*t == '>'){
			t++;
			size_t i = 0;
			while (*t && *t != '<' && i < 60) a->title[i++] = *t++;
			a->title[i] = 0;
		}
	}

	/* server / x-powered-by → technologies */
	int n = 0;
	const char *srv = stristr(out.p, "\nserver:");
	if (!srv) srv = stristr(out.p, "server:");
	if (srv){
		const char *q = strchr(srv, ':');
		if (q){ q++; while (*q == ' ') q++;
			char v[MAX_STRING]; size_t i = 0;
			while (*q && *q != '\r' && *q != '\n' && i < 60) v[i++] = *q++;
			v[i] = 0; if (i){ strncat(a->tech, (n++ ? ", " : ""), sizeof a->tech - strlen(a->tech) - 1); strncat(a->tech, v, sizeof a->tech - strlen(a->tech) - 1); }
		}
	}
	const char *pwr = stristr(out.p, "x-powered-by:");
	if (pwr){
		const char *q = strchr(pwr, ':');
		if (q){ q++; while (*q == ' ') q++;
			char v[MAX_STRING]; size_t i = 0;
			while (*q && *q != '\r' && *q != '\n' && i < 60) v[i++] = *q++;
			v[i] = 0; if (i){ strncat(a->tech, (n ? ", " : ""), sizeof a->tech - strlen(a->tech) - 1); strncat(a->tech, v, sizeof a->tech - strlen(a->tech) - 1); }
		}
	}
	a->tech_count = (strlen(a->tech) > 0);

	/* cdn detection */
	if (stristr(out.p, "cf-ray") || stristr(out.p, "x-cdn") || stristr(out.p, "x-cache") ||
	    stristr(out.p, "x-amz-cf-id") || stristr(out.p, "cloudflare") ||
	    stristr(out.p, "cloudfront") || stristr(out.p, "akamai") || stristr(out.p, "fastly"))
		a->cdn = 1;

	/* ip + port */
	if (resolve_ip(host, a->ip, sizeof a->ip) == 0){
		a->nports = 1;
		a->ports[0] = scheme_https ? 443 : 80;
	}

	nassets++;
	sb_free(&out);
}

/* ── phase 3: port scan (normal/deep) ────────────────────────── */
static const int common_ports[] = { 21,22,80,443,3000,3306,5432,8000,8080,8443,9090,9200,27017 };
#define NPORTS (int)(sizeof(common_ports) / sizeof(common_ports[0]))

static int tcp_open(const char *host, int port, int timeout_ms){
	char ip[MAX_STRING];
	if (resolve_ip(host, ip, sizeof ip) != 0) return 0;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 0;

	struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &sa.sin_addr);

	int on = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
	int ok = 0;
	if (r < 0){
		if (errno == EINPROGRESS){
			struct pollfd pfd = { fd, POLLOUT, 0 };
			int pr = poll(&pfd, 1, timeout_ms);
			if (pr > 0 && (pfd.revents & POLLOUT)){
				int soerr = 0; socklen_t sl = sizeof soerr;
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
				ok = (soerr == 0);
			}
		}
	} else ok = 1;
	close(fd);
	return ok;
}

static void scan_ports(const char *host){
	asset_t *a = NULL;
	for (int i = 0; i < nassets; i++) if (strcmp(assets[i].host, host) == 0){ a = &assets[i]; break; }
	if (!a){ if (nassets >= MAX_ASSETS) return; a = &assets[nassets]; memset(a, 0, sizeof *a); snprintf(a->host, sizeof a->host, "%s", host); nassets++; }
	int n = 0;
	for (int i = 0; i < NPORTS; i++){
		if (tcp_open(host, common_ports[i], timeout * 1000) && n < 16){
			a->ports[n++] = common_ports[i];
		}
	}
	a->nports = n;
}

/* ── phase 4: header + CORS checks (deep) ────────────────────── */
static void check_headers(const char *host){
	char url[MAX_STRING];
	snprintf(url, sizeof url, "https://%s", host);
	char mt[16]; snprintf(mt, sizeof mt, "%d", timeout);

	sbuf h; sb_init(&h);
	{
		char *argv[] = { "curl", "-s", "-k", "-I", "--max-time", mt, url, NULL };
		if (run_argv(argv, &h) != 0 && h.len == 0){ sb_free(&h); return; }
	}
	if (h.len == 0){ sb_free(&h); return; }

	if (!stristr(h.p, "strict-transport-security"))
		add_finding("Missing HSTS Header", "medium", "security-headers", url, "strict-transport-security header not set");
	if (!stristr(h.p, "x-content-type-options"))
		add_finding("Missing X-Content-Type-Options", "low", "security-headers", url, "x-content-type-options header not set");
	if (!stristr(h.p, "content-security-policy"))
		add_finding("Missing Content-Security-Policy", "low", "security-headers", url, "content-security-policy header not set");
	sb_free(&h);
}

static void check_cors(const char *host){
	char url[MAX_STRING];
	snprintf(url, sizeof url, "https://%s", host);
	char mt[16]; snprintf(mt, sizeof mt, "%d", timeout);

	sbuf h; sb_init(&h);
	{
		char *argv[] = { "curl", "-s", "-k", "-I", "--max-time", mt, "-H", "Origin: https://evil.com", url, NULL };
		if (run_argv(argv, &h) != 0 && h.len == 0){ sb_free(&h); return; }
	}
	if (h.len == 0){ sb_free(&h); return; }

	const char *acao = stristr(h.p, "access-control-allow-origin:");
	if (acao){
		const char *q = strchr(acao, ':');
		if (q){ q++; while (*q == ' ') q++;
			char v[MAX_STRING]; size_t i = 0;
			while (*q && *q != '\r' && *q != '\n' && i < sizeof v - 1) v[i++] = *q++;
			v[i] = 0;
			if (strcmp(v, "*") == 0){
				add_finding("CORS Wildcard Origin", "medium", "cors-misconfiguration", url, "Access-Control-Allow-Origin: *");
			} else if (strcmp(v, "https://evil.com") == 0){
				const char *acac = stristr(h.p, "access-control-allow-credentials:");
				const char *sev = "medium";
				if (acac && stristr(acac, "true")) sev = "high";
				char d[MAX_STRING];
				snprintf(d, sizeof d, "Origin evil.com reflected. Credentials: %s", acac ? "true" : "false");
				add_finding("CORS Origin Reflection", sev, "cors-misconfiguration", url, d);
			}
		}
	}
	sb_free(&h);
}

/* ── output ──────────────────────────────────────────────────── */
static void write_json(const char *domain, const char *mode, const char *started, const char *outfile){
	FILE *f = fopen(outfile, "w");
	if (!f){ fprintf(stderr, "  [!] cannot write %s\n", outfile); return; }

	char finished[32]; ts(finished, sizeof finished);

	fprintf(f, "{\n");
	fprintf(f, "\t\"target\": \""); { sbuf s; sb_init(&s); json_escape(&s, domain); fputs(s.p, f); sb_free(&s); } fprintf(f, "\",\n");
	fprintf(f, "\t\"tool\": \"tymbal\",\n");
	fprintf(f, "\t\"version\": \"%s\",\n", VERSION);
	fprintf(f, "\t\"recon\": {\n");
	fprintf(f, "\t\t\"target\": \""); { sbuf s; sb_init(&s); json_escape(&s, domain); fputs(s.p, f); sb_free(&s); } fprintf(f, "\",\n");

	fprintf(f, "		\"subdomains\": [");
	for (int i = 0; i < nsubs; i++){
		if (i) fprintf(f, ",");
		sbuf s; sb_init(&s); json_escape(&s, subdomains[i]);
		fprintf(f, "\""); fputs(s.p, f); fprintf(f, "\"");
		sb_free(&s);
	}
	fprintf(f, "],\n");

	fprintf(f, "\t\t\"assets\": [");
	for (int i = 0; i < nassets; i++){
		asset_t *a = &assets[i];
		if (i) fprintf(f, ",");
		fprintf(f, "\n\t\t\t{");
		fprintf(f, "\"host\": \""); sbuf s; sb_init(&s); json_escape(&s, a->host); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"ip\": \""); sb_init(&s); json_escape(&s, a->ip); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"ports\": [");
		for (int j = 0; j < a->nports; j++){ if (j) fprintf(f, ", "); fprintf(f, "%d", a->ports[j]); }
		fprintf(f, "], ");
		fprintf(f, "\"technologies\": [");
		/* split the comma-joined tech buffer into array items */
		if (a->tech_count){
			char buf[MAX_STRING]; snprintf(buf, sizeof buf, "%s", a->tech);
			char *tk = buf; int first = 1;
			while (*tk){
				char *end = tk; while (*end && *end != ',') end++;
				int had = (*end == ','); if (*end == ',') *end = 0;
				while (*tk == ' ') tk++;
				if (first) first = 0; else fprintf(f, ", ");
				sb_init(&s); json_escape(&s, tk);
				fprintf(f, "\""); fputs(s.p, f); fprintf(f, "\"");
				sb_free(&s);
				if (!had) break;
				tk = end + 1;
			}
		}
		fprintf(f, "], ");
		fprintf(f, "\"status_code\": %d, ", a->status_code);
		fprintf(f, "\"content_length\": %d, ", a->content_length);
		fprintf(f, "\"title\": \""); sb_init(&s); json_escape(&s, a->title); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"cdn\": %s, ", a->cdn ? "true" : "false");
		fprintf(f, "\"source\": \"tymbal\"}");
	}
	fprintf(f, "\n\t\t],\n");

	fprintf(f, "\t\t\"endpoints\": [],\n");
	fprintf(f, "\t\t\"js_files\": [],\n");
	fprintf(f, "\t\t\"parameters\": [],\n");
	fprintf(f, "\t\t\"secrets\": [],\n");
	fprintf(f, "\t\t\"timestamp\": \"%s\"\n", started);
	fprintf(f, "\t},\n");

	fprintf(f, "\t\"findings\": [");
	for (int i = 0; i < nfindings; i++){
		finding_t *g = &findings[i];
		if (i) fprintf(f, ",");
		fprintf(f, "\n\t\t{");
		fprintf(f, "\"title\": \""); sbuf s; sb_init(&s); json_escape(&s, g->title); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"severity\": \"%s\", ", g->severity);
		fprintf(f, "\"category\": \""); sb_init(&s); json_escape(&s, g->category); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"target\": \""); sb_init(&s); json_escape(&s, g->target); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"detail\": \""); sb_init(&s); json_escape(&s, g->detail); fputs(s.p, f); sb_free(&s); fprintf(f, "\", ");
		fprintf(f, "\"evidence\": {\"request\": \"\", \"response\": \"\", \"screenshot\": \"\", \"timestamp\": \"%s\"}, ", finished);
		fprintf(f, "\"tool\": \"tymbal\", ");
		fprintf(f, "\"confidence\": \"medium\", ");
		fprintf(f, "\"reference\": \"\", ");
		fprintf(f, "\"finding_id\": \"tym_%d\"}", i);
	}
	fprintf(f, "\n\t],\n");

	fprintf(f, "\t\"started\": \"%s\",\n", started);
	fprintf(f, "\t\"finished\": \"%s\",\n", finished);
	fprintf(f, "\t\"mode\": \"%s\",\n", mode);
	fprintf(f, "\t\"scope\": []\n");
	fprintf(f, "}\n");

	fclose(f);
}

/* ── usage / main ───────────────────────────────────────────── */
static void usage(void){
	printf("\n  ▀▄▀▄▀▄ tymbal ▄▀▄▀▄▀\n\n");
	printf("  usage: tymbal [options] <target>\n\n");
	printf("  options:\n");
	printf("    -m MODE    fast|normal|deep (default: normal)\n");
	printf("    -t NUM     threads / parallel jobs (default: 5)\n");
	printf("    -T NUM     timeout seconds (default: 5)\n");
	printf("    -o DIR     output directory (default: .)\n");
	printf("    -v         verbose\n");
	printf("    -V         version\n\n");
	printf("  feed to cicada:\n");
	printf("    cicada scan example.com --tymbal tymbal_example_*.json\n\n");
	exit(0);
}

int main(int argc, char **argv){
	int opt;
	while ((opt = getopt(argc, argv, "m:t:T:o:vVh")) != -1){
		switch (opt){
			case 'm': mode = optarg; break;
			case 't': threads = atoi(optarg); break;
			case 'T': timeout = atoi(optarg); break;
			case 'o': outdir = optarg; break;
			case 'v': verbose = 1; break;
			case 'V': printf("tymbal v%s\n", VERSION); return 0;
			case 'h': default: usage();
		}
	}
	if (optind >= argc) usage();
	const char *target = argv[optind];

	char domain[MAX_STRING];
	extract_domain(target, domain, sizeof domain);
	if (!*domain){ fprintf(stderr, "  [!] no domain parsed from %s\n", target); return 1; }

	char started[32]; ts(started, sizeof started);

	printf("\n  ▀▄▀▄▀▄ tymbal v%s ▄▀▄▀▄▀\n\n", VERSION);
	printf("  target: %s\n", domain);
	printf("  mode:   %s\n", mode);

	/* phase 1 */
	printf("\n  [1] SUBDOMAIN ENUMERATION\n");
	crtsh(domain);
	dns_brute(domain);
	add_sub(domain);
	qsort(subdomains, (size_t)nsubs, sizeof subdomains[0], subcmp);
	/* dedupe (already unique via add_sub, but defensive) */
	printf("    → %d subdomains\n", nsubs);

	/* phase 2 */
	printf("\n  [2] HTTP PROBING\n");
	for (int i = 0; i < nsubs; i++) probe_host(subdomains[i]);
	printf("    → %d live hosts\n", nassets);

	/* phase 3 */
	int deep = strcmp(mode, "deep") == 0;
	int normal_or_deep = strcmp(mode, "normal") == 0 || deep;
	if (normal_or_deep){
		printf("\n  [3] PORT SCANNING\n");
		int total = 0;
		for (int i = 0; i < nsubs; i++){
			scan_ports(subdomains[i]);
		}
		for (int i = 0; i < nassets; i++) total += assets[i].nports;
		printf("    → %d open ports\n", total);
	}

	/* phase 4 */
	if (deep){
		printf("\n  [4] SECURITY CHECKS\n");
		for (int i = 0; i < nsubs; i++){ check_headers(subdomains[i]); check_cors(subdomains[i]); }
		printf("    → %d findings\n", nfindings);
	}

	/* write output */
	char filets[32];
	{ time_t t = time(NULL); struct tm l; localtime_r(&t, &l); strftime(filets, sizeof filets, "%Y%m%d_%H%M%S", &l); }
	char outfile[MAX_STRING];
	snprintf(outfile, sizeof outfile, "%s/tymbal_%s_%s.json", outdir, domain, filets);
	write_json(domain, mode, started, outfile);

	printf("\n  ────────────────────────────────────────\n");
	printf("  %d subs | %d live | %d findings\n", nsubs, nassets, nfindings);
	printf("  output → %s\n", outfile);
	printf("  ────────────────────────────────────────\n");
	printf("  feed to cicada:\n");
	printf("    cicada scan %s --tymbal %s\n\n", domain, outfile);

	return 0;
}