<?php
/**
 * PHP Firewall - Gelismis Guvenlik Sistemi
 * PHP 7.4+ / 8.x Uyumlu Versiyon
 * 
 * Ozellikler:
 * - Rate Limiting (Hiz Sinirlandirma)
 * - IP Blacklist/Whitelist Yonetimi
 * - Gelismis SQL Injection Korumasi
 * - CSRF Token Korumasi
 * - Honeypot Alanlari
 * - Gelismis Bot Tespiti
 * - Brute Force Korumasi
 * - File Upload Guvenlik Kontrolu
 * - Header Injection Korumasi
 * - Path Traversal Korumasi
 * - Command Injection Korumasi
 * - JSON/XML Bomb Korumasi
 * - IP Reputation Kontrolu
 * - Gelismis Loglama Sistemi
 */

declare(strict_types=1);

/** ===================== YAPILANDIRMA ===================== */

/** IP Beyaz Liste (Bu IP'ler her zaman izinli) */
$IP_WHITELIST = [];

/** IP Kara Liste (Bu IP'ler her zaman engelli) */
$IP_BLACKLIST = [];

/** Dil Ayari */
define('PHP_FIREWALL_LANGUAGE', 'turkish');

/** Admin E-posta */
define('PHP_FIREWALL_ADMIN_MAIL', '');

/** E-posta Bildirimi */
define('PHP_FIREWALL_PUSH_MAIL', false);

/** Log Dosyasi */
define('PHP_FIREWALL_LOG_FILE', 'logs/firewall');

/** Log Formati: 'txt', 'json', 'both' */
define('PHP_FIREWALL_LOG_FORMAT', 'both');

/** Aktivasyon */
define('PHP_FIREWALL_ACTIVATION', true);

/** ===================== KORUMA AYARLARI ===================== */

/** Temel Korumalar */
define('PHP_FIREWALL_PROTECTION_URL', true);
define('PHP_FIREWALL_PROTECTION_REQUEST_SERVER', true);
define('PHP_FIREWALL_PROTECTION_SANTY', true);
define('PHP_FIREWALL_PROTECTION_BOTS', true);
define('PHP_FIREWALL_PROTECTION_REQUEST_METHOD', true);
define('PHP_FIREWALL_PROTECTION_DOS', true);
define('PHP_FIREWALL_PROTECTION_UNION_SQL', true);
define('PHP_FIREWALL_PROTECTION_CLICK_ATTACK', true);
define('PHP_FIREWALL_PROTECTION_XSS_ATTACK', true);
define('PHP_FIREWALL_PROTECTION_COOKIES', true);
define('PHP_FIREWALL_PROTECTION_POST', true);
define('PHP_FIREWALL_PROTECTION_GET', true);

/** Gelismis Korumalar */
define('PHP_FIREWALL_PROTECTION_RATE_LIMIT', true);
define('PHP_FIREWALL_RATE_LIMIT_REQUESTS', 100);  // Dakikada maksimum istek
define('PHP_FIREWALL_RATE_LIMIT_WINDOW', 60);      // Saniye cinsinden pencere

define('PHP_FIREWALL_PROTECTION_BRUTE_FORCE', true);
define('PHP_FIREWALL_BRUTE_FORCE_MAX_ATTEMPTS', 5);
define('PHP_FIREWALL_BRUTE_FORCE_LOCKOUT_TIME', 900); // 15 dakika

define('PHP_FIREWALL_PROTECTION_CSRF', true);
define('PHP_FIREWALL_CSRF_TOKEN_NAME', '_csrf_token');

define('PHP_FIREWALL_PROTECTION_HONEYPOT', true);
define('PHP_FIREWALL_HONEYPOT_FIELD_NAME', '_hp_field');

define('PHP_FIREWALL_PROTECTION_FILE_UPLOAD', true);
define('PHP_FIREWALL_ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx']);
define('PHP_FIREWALL_MAX_FILE_SIZE', 10485760); // 10MB

define('PHP_FIREWALL_PROTECTION_HEADER_INJECTION', true);
define('PHP_FIREWALL_PROTECTION_PATH_TRAVERSAL', true);
define('PHP_FIREWALL_PROTECTION_COMMAND_INJECTION', true);
define('PHP_FIREWALL_PROTECTION_JSON_BOMB', true);
define('PHP_FIREWALL_PROTECTION_XML_BOMB', true);

define('PHP_FIREWALL_PROTECTION_ADVANCED_BOT', true);
define('PHP_FIREWALL_PROTECTION_TOR_EXIT', false);
define('PHP_FIREWALL_PROTECTION_PROXY', true);

/** Sunucu Korumasi */
define('PHP_FIREWALL_PROTECTION_RANGE_IP_DENY', false);
define('PHP_FIREWALL_PROTECTION_RANGE_IP_SPAM', false);
define('PHP_FIREWALL_PROTECTION_SERVER_OVH', false);
define('PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI', false);
define('PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX', false);
define('PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE', false);
define('PHP_FIREWALL_PROTECTION_SERVER_OVH_BY_IP', false);
define('PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI_BY_IP', false);
define('PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX_BY_IP', false);
define('PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE_BY_IP', false);

/** Guvenlik Baskiklari */
define('PHP_FIREWALL_SECURITY_HEADERS', true);

/** ===================== YAPILANDIRMA SONU ===================== */

/** ===================== DIL DOSYASI ===================== */
if (PHP_FIREWALL_LANGUAGE === 'turkish') {
    define('_PHPF_PROTECTION_DEDIBOX', 'DEDIBOX sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_DEDIBOX_IP', 'DEDIBOX sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_DIGICUBE', 'DIGICUBE sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_DIGICUBE_IP', 'DIGICUBE sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_KIMSUFI', 'KIMSUFI sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_OVH', 'OVH sunucularina karsi koruma aktif!');
    define('_PHPF_PROTECTION_BOTS', 'Bot saldirisi tespit edildi!');
    define('_PHPF_PROTECTION_CLICK', 'Tiklama saldirisi algilandi!');
    define('_PHPF_PROTECTION_DOS', 'Gecersiz kullanici aracisi!');
    define('_PHPF_PROTECTION_OTHER_SERVER', 'Baska bir sunucudan paylasim yapmak yasaktir!');
    define('_PHPF_PROTECTION_REQUEST', 'Sorgu yontemine izin verilmiyor!');
    define('_PHPF_PROTECTION_SANTY', 'Santy tespit edildi!');
    define('_PHPF_PROTECTION_SPAM', 'SPAM korumasi aktif!');
    define('_PHPF_PROTECTION_SPAM_IP', 'SPAM IP korumasi aktif!');
    define('_PHPF_PROTECTION_UNION', 'SQL Injection saldirisi tespit edildi!');
    define('_PHPF_PROTECTION_URL', 'URL korumasi etkin!');
    define('_PHPF_PROTECTION_XSS', 'XSS saldirisi algilandi!');
    define('_PHPF_PROTECTION_RATE_LIMIT', 'Cok fazla istek gonderdiniz. Lutfen bekleyin.');
    define('_PHPF_PROTECTION_BRUTE_FORCE', 'Cok fazla basarisiz deneme. Hesabiniz gecici olarak kilitlendi.');
    define('_PHPF_PROTECTION_CSRF', 'Gecersiz CSRF token!');
    define('_PHPF_PROTECTION_HONEYPOT', 'Bot aktivitesi tespit edildi!');
    define('_PHPF_PROTECTION_FILE_UPLOAD', 'Gecersiz dosya yukleme denemesi!');
    define('_PHPF_PROTECTION_HEADER_INJECTION', 'Header injection saldirisi tespit edildi!');
    define('_PHPF_PROTECTION_PATH_TRAVERSAL', 'Path traversal saldirisi tespit edildi!');
    define('_PHPF_PROTECTION_COMMAND_INJECTION', 'Command injection saldirisi tespit edildi!');
    define('_PHPF_PROTECTION_JSON_BOMB', 'Zararli JSON verisi tespit edildi!');
    define('_PHPF_PROTECTION_XML_BOMB', 'Zararli XML verisi tespit edildi!');
    define('_PHPF_PROTECTION_PROXY', 'Proxy kullanimi tespit edildi!');
    define('_PHPF_PROTECTION_BLACKLIST', 'IP adresiniz kara listede!');
} else {
    define('_PHPF_PROTECTION_DEDIBOX', 'Protection DEDIBOX Server active!');
    define('_PHPF_PROTECTION_DEDIBOX_IP', 'Protection DEDIBOX Server active!');
    define('_PHPF_PROTECTION_DIGICUBE', 'Protection DIGICUBE Server active!');
    define('_PHPF_PROTECTION_DIGICUBE_IP', 'Protection DIGICUBE Server active!');
    define('_PHPF_PROTECTION_KIMSUFI', 'Protection KIMSUFI Server active!');
    define('_PHPF_PROTECTION_OVH', 'Protection OVH Server active!');
    define('_PHPF_PROTECTION_BOTS', 'Bot attack detected!');
    define('_PHPF_PROTECTION_CLICK', 'Click attack detected!');
    define('_PHPF_PROTECTION_DOS', 'Invalid user agent!');
    define('_PHPF_PROTECTION_OTHER_SERVER', 'Posting from another server not allowed!');
    define('_PHPF_PROTECTION_REQUEST', 'Invalid request method!');
    define('_PHPF_PROTECTION_SANTY', 'Attack Santy detected!');
    define('_PHPF_PROTECTION_SPAM', 'Protection SPAM IPs active!');
    define('_PHPF_PROTECTION_SPAM_IP', 'Protection died IPs active!');
    define('_PHPF_PROTECTION_UNION', 'SQL Injection attack detected!');
    define('_PHPF_PROTECTION_URL', 'Protection url active!');
    define('_PHPF_PROTECTION_XSS', 'XSS attack detected!');
    define('_PHPF_PROTECTION_RATE_LIMIT', 'Too many requests. Please wait.');
    define('_PHPF_PROTECTION_BRUTE_FORCE', 'Too many failed attempts. Account temporarily locked.');
    define('_PHPF_PROTECTION_CSRF', 'Invalid CSRF token!');
    define('_PHPF_PROTECTION_HONEYPOT', 'Bot activity detected!');
    define('_PHPF_PROTECTION_FILE_UPLOAD', 'Invalid file upload attempt!');
    define('_PHPF_PROTECTION_HEADER_INJECTION', 'Header injection attack detected!');
    define('_PHPF_PROTECTION_PATH_TRAVERSAL', 'Path traversal attack detected!');
    define('_PHPF_PROTECTION_COMMAND_INJECTION', 'Command injection attack detected!');
    define('_PHPF_PROTECTION_JSON_BOMB', 'Malicious JSON data detected!');
    define('_PHPF_PROTECTION_XML_BOMB', 'Malicious XML data detected!');
    define('_PHPF_PROTECTION_PROXY', 'Proxy usage detected!');
    define('_PHPF_PROTECTION_BLACKLIST', 'Your IP is blacklisted!');
}
/** ===================== DIL DOSYASI SONU ===================== */

if (PHP_FIREWALL_ACTIVATION === true) {

    /**
     * PHP Firewall Ana Sinifi
     */
    class PHPFirewall
    {
        private static ?PHPFirewall $instance = null;
        private string $ip;
        private string $userAgent;
        private string $queryString;
        private string $requestMethod;
        private string $requestUri;
        private string $referer;
        private ?string $hostname = null;
        private array $whitelist;
        private array $blacklist;
        
        private function __construct(array $whitelist = [], array $blacklist = [])
        {
            $this->whitelist = $whitelist;
            $this->blacklist = $blacklist;
            $this->ip = $this->getClientIP();
            $this->userAgent = $this->getUserAgent();
            $this->queryString = $this->getQueryString();
            $this->requestMethod = $this->getRequestMethod();
            $this->requestUri = $this->getRequestUri();
            $this->referer = $this->getReferer();
        }
        
        public static function getInstance(array $whitelist = [], array $blacklist = []): PHPFirewall
        {
            if (self::$instance === null) {
                self::$instance = new self($whitelist, $blacklist);
            }
            return self::$instance;
        }
        
        /**
         * Guvenli ortam degiskeni alma
         */
        private function getEnv(string $key): string
        {
            if (isset($_SERVER[$key])) {
                return $this->sanitize((string)$_SERVER[$key]);
            }
            if (isset($_ENV[$key])) {
                return $this->sanitize((string)$_ENV[$key]);
            }
            $value = getenv($key);
            if ($value !== false) {
                return $this->sanitize($value);
            }
            return '';
        }
        
        /**
         * Temel sanitizasyon
         */
        private function sanitize(string $value): string
        {
            return strip_tags(trim($value));
        }
        
        /**
         * Gercek IP adresini al (proxy arkasinda bile)
         */
        private function getClientIP(): string
        {
            $headers = [
                'HTTP_CF_CONNECTING_IP',     // Cloudflare
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED',
                'HTTP_X_CLUSTER_CLIENT_IP',
                'HTTP_FORWARDED_FOR',
                'HTTP_FORWARDED',
                'HTTP_CLIENT_IP',
                'REMOTE_ADDR'
            ];
            
            foreach ($headers as $header) {
                $ip = $this->getEnv($header);
                if ($ip !== '') {
                    // Birden fazla IP varsa ilkini al
                    if (strpos($ip, ',') !== false) {
                        $ips = explode(',', $ip);
                        $ip = trim($ips[0]);
                    }
                    // IP dogrulama
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        return $ip;
                    }
                }
            }
            
            return '0.0.0.0';
        }
        
        /**
         * User Agent al
         */
        private function getUserAgent(): string
        {
            $ua = $this->getEnv('HTTP_USER_AGENT');
            return $ua !== '' ? $ua : 'none';
        }
        
        /**
         * Query string al
         */
        private function getQueryString(): string
        {
            $qs = $this->getEnv('QUERY_STRING');
            return strtolower(str_replace('%09', '%20', $qs));
        }
        
        /**
         * Request method al
         */
        private function getRequestMethod(): string
        {
            $method = $this->getEnv('REQUEST_METHOD');
            return $method !== '' ? strtoupper($method) : 'GET';
        }
        
        /**
         * Request URI al
         */
        private function getRequestUri(): string
        {
            return $this->getEnv('REQUEST_URI');
        }
        
        /**
         * Referer al
         */
        private function getReferer(): string
        {
            $referer = $this->getEnv('HTTP_REFERER');
            return $referer !== '' ? $referer : 'no referer';
        }
        
        /**
         * Hostname al (lazy loading)
         */
        private function getHostname(): string
        {
            if ($this->hostname === null) {
                if (session_status() === PHP_SESSION_NONE) {
                    @session_start();
                }
                
                $sessionKey = 'phpf_hostname_' . md5($this->ip);
                if (!empty($_SESSION[$sessionKey])) {
                    $this->hostname = $_SESSION[$sessionKey];
                } else {
                    $hostname = @gethostbyaddr($this->ip);
                    $this->hostname = ($hostname !== false && $hostname !== $this->ip) ? $hostname : 'unknown';
                    $_SESSION[$sessionKey] = $this->hostname;
                }
            }
            return $this->hostname;
        }
        
        /**
         * Getter metodlari
         */
        public function getIP(): string { return $this->ip; }
        public function getUA(): string { return $this->userAgent; }
        public function getQS(): string { return $this->queryString; }
        public function getMethod(): string { return $this->requestMethod; }
        public function getUri(): string { return $this->requestUri; }
        public function getRef(): string { return $this->referer; }
        public function getHost(): string { return $this->getHostname(); }
        
        /**
         * Gelismis loglama sistemi
         */
        public function log(string $type, array $extra = []): void
        {
            $logDir = dirname(__DIR__ . '/' . PHP_FIREWALL_LOG_FILE);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            $logData = [
                'timestamp' => date('Y-m-d H:i:s'),
                'timezone' => date_default_timezone_get(),
                'type' => $type,
                'ip' => $this->ip,
                'hostname' => $this->getHostname(),
                'user_agent' => $this->userAgent,
                'request_method' => $this->requestMethod,
                'request_uri' => $this->requestUri,
                'query_string' => $this->queryString,
                'referer' => $this->referer,
                'server_name' => $_SERVER['SERVER_NAME'] ?? 'unknown',
                'php_version' => PHP_VERSION,
                'extra' => $extra
            ];
            
            // TXT format
            if (PHP_FIREWALL_LOG_FORMAT === 'txt' || PHP_FIREWALL_LOG_FORMAT === 'both') {
                $txtFile = __DIR__ . '/' . PHP_FIREWALL_LOG_FILE . '.txt';
                $txtMsg = sprintf(
                    "[%s] %s | IP: %s | DNS: %s | UA: %s | URI: %s | Ref: %s\n",
                    $logData['timestamp'],
                    $type,
                    $this->ip,
                    $logData['hostname'],
                    $this->userAgent,
                    $this->requestUri,
                    $this->referer
                );
                @file_put_contents($txtFile, $txtMsg, FILE_APPEND | LOCK_EX);
            }
            
            // JSON format
            if (PHP_FIREWALL_LOG_FORMAT === 'json' || PHP_FIREWALL_LOG_FORMAT === 'both') {
                $jsonFile = __DIR__ . '/' . PHP_FIREWALL_LOG_FILE . '.json';
                $jsonLine = json_encode($logData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
                @file_put_contents($jsonFile, $jsonLine, FILE_APPEND | LOCK_EX);
            }
            
            // E-posta bildirimi
            if (PHP_FIREWALL_PUSH_MAIL === true && PHP_FIREWALL_ADMIN_MAIL !== '') {
                $this->sendEmail($type, $logData);
            }
        }
        
        /**
         * E-posta gonder
         */
        private function sendEmail(string $subject, array $data): bool
        {
            $serverName = $_SERVER['SERVER_NAME'] ?? 'unknown';
            $fullSubject = "PHP Firewall Alert: {$subject} - {$serverName}";
            
            $body = "PHP Firewall Security Alert\n";
            $body .= "============================\n\n";
            foreach ($data as $key => $value) {
                if (is_array($value)) {
                    $value = json_encode($value);
                }
                $body .= ucfirst(str_replace('_', ' ', $key)) . ": {$value}\n";
            }
            
            $headers = [
                'From: PHP Firewall <' . PHP_FIREWALL_ADMIN_MAIL . '>',
                'Reply-To: ' . PHP_FIREWALL_ADMIN_MAIL,
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
                'X-Priority: 1',
                'X-Mailer: PHP/' . PHP_VERSION
            ];
            
            return @mail(PHP_FIREWALL_ADMIN_MAIL, $fullSubject, $body, implode("\r\n", $headers));
        }
        
        /**
         * Saldiri engelle ve cik
         */
        public function block(string $message, string $logType, int $httpCode = 403): never
        {
            $this->log($logType);
            
            http_response_code($httpCode);
            header('Content-Type: text/html; charset=UTF-8');
            header('X-Blocked-By: PHP-Firewall');
            
            if (PHP_FIREWALL_SECURITY_HEADERS === true) {
                $this->setSecurityHeaders();
            }
            
            echo $this->getBlockPage($message);
            exit;
        }
        
        /**
         * Guvenlik basliklarini ayarla
         */
        public function setSecurityHeaders(): void
        {
            $headers = [
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'SAMEORIGIN',
                'X-XSS-Protection' => '1; mode=block',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
                'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            ];
            
            foreach ($headers as $name => $value) {
                if (!headers_sent()) {
                    header("{$name}: {$value}");
                }
            }
        }
        
        /**
         * Engelleme sayfasi
         */
        private function getBlockPage(string $message): string
        {
            return <<<HTML
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erisim Engellendi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            max-width: 500px;
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { font-size: 24px; margin-bottom: 15px; color: #e94560; }
        p { color: #a0a0a0; line-height: 1.6; }
        .code { 
            margin-top: 20px;
            padding: 10px 20px;
            background: rgba(233,69,96,0.2);
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#128274;</div>
        <h1>Erisim Engellendi</h1>
        <p>{$message}</p>
        <div class="code">Error Code: 403</div>
    </div>
</body>
</html>
HTML;
        }
        
        /**
         * IP araligi kontrolu
         */
        public function checkIPRange(array $ranges): bool
        {
            $parts = explode('.', $this->ip);
            if (count($parts) < 2) return false;
            
            $prefix = $parts[0] . '.' . $parts[1];
            return in_array($prefix, $ranges, true);
        }
        
        /**
         * CIDR formatinda IP kontrolu
         */
        public function ipInCIDR(string $cidr): bool
        {
            if (strpos($cidr, '/') === false) {
                return $this->ip === $cidr;
            }
            
            [$subnet, $mask] = explode('/', $cidr);
            $mask = (int)$mask;
            
            $ipLong = ip2long($this->ip);
            $subnetLong = ip2long($subnet);
            $maskLong = -1 << (32 - $mask);
            
            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }
        
        /**
         * Whitelist kontrolu
         */
        public function isWhitelisted(): bool
        {
            if (in_array($this->ip, $this->whitelist, true)) {
                return true;
            }
            
            foreach ($this->whitelist as $item) {
                if (strpos($item, '/') !== false && $this->ipInCIDR($item)) {
                    return true;
                }
            }
            
            return false;
        }
        
        /**
         * Blacklist kontrolu
         */
        public function isBlacklisted(): bool
        {
            if (in_array($this->ip, $this->blacklist, true)) {
                return true;
            }
            
            foreach ($this->blacklist as $item) {
                if (strpos($item, '/') !== false && $this->ipInCIDR($item)) {
                    return true;
                }
            }
            
            return false;
        }
    }
    
    /**
     * Rate Limiter Sinifi
     */
    class RateLimiter
    {
        private string $storageFile;
        private int $maxRequests;
        private int $windowSeconds;
        
        public function __construct(int $maxRequests = 100, int $windowSeconds = 60)
        {
            $this->maxRequests = $maxRequests;
            $this->windowSeconds = $windowSeconds;
            $this->storageFile = sys_get_temp_dir() . '/phpf_ratelimit.json';
        }
        
        public function isLimited(string $ip): bool
        {
            $data = $this->loadData();
            $now = time();
            
            // Eski kayitlari temizle
            $data = array_filter($data, fn($entry) => ($now - $entry['first']) < $this->windowSeconds);
            
            if (!isset($data[$ip])) {
                $data[$ip] = ['count' => 1, 'first' => $now];
                $this->saveData($data);
                return false;
            }
            
            $entry = $data[$ip];
            
            if (($now - $entry['first']) >= $this->windowSeconds) {
                $data[$ip] = ['count' => 1, 'first' => $now];
                $this->saveData($data);
                return false;
            }
            
            $data[$ip]['count']++;
            $this->saveData($data);
            
            return $data[$ip]['count'] > $this->maxRequests;
        }
        
        private function loadData(): array
        {
            if (!file_exists($this->storageFile)) {
                return [];
            }
            
            $content = @file_get_contents($this->storageFile);
            if ($content === false) return [];
            
            $data = json_decode($content, true);
            return is_array($data) ? $data : [];
        }
        
        private function saveData(array $data): void
        {
            @file_put_contents($this->storageFile, json_encode($data), LOCK_EX);
        }
    }
    
    /**
     * Brute Force Koruma Sinifi
     */
    class BruteForceProtection
    {
        private string $storageFile;
        private int $maxAttempts;
        private int $lockoutTime;
        
        public function __construct(int $maxAttempts = 5, int $lockoutTime = 900)
        {
            $this->maxAttempts = $maxAttempts;
            $this->lockoutTime = $lockoutTime;
            $this->storageFile = sys_get_temp_dir() . '/phpf_bruteforce.json';
        }
        
        public function isLocked(string $ip): bool
        {
            $data = $this->loadData();
            $now = time();
            
            if (!isset($data[$ip])) {
                return false;
            }
            
            $entry = $data[$ip];
            
            // Kilit suresi dolmus mu?
            if (isset($entry['locked_until']) && $now < $entry['locked_until']) {
                return true;
            }
            
            // Kilit suresi dolduysa sifirla
            if (isset($entry['locked_until']) && $now >= $entry['locked_until']) {
                unset($data[$ip]);
                $this->saveData($data);
                return false;
            }
            
            return false;
        }
        
        public function recordAttempt(string $ip): void
        {
            $data = $this->loadData();
            $now = time();
            
            if (!isset($data[$ip])) {
                $data[$ip] = ['attempts' => 0, 'first_attempt' => $now];
            }
            
            $data[$ip]['attempts']++;
            $data[$ip]['last_attempt'] = $now;
            
            if ($data[$ip]['attempts'] >= $this->maxAttempts) {
                $data[$ip]['locked_until'] = $now + $this->lockoutTime;
            }
            
            $this->saveData($data);
        }
        
        public function resetAttempts(string $ip): void
        {
            $data = $this->loadData();
            unset($data[$ip]);
            $this->saveData($data);
        }
        
        private function loadData(): array
        {
            if (!file_exists($this->storageFile)) {
                return [];
            }
            
            $content = @file_get_contents($this->storageFile);
            if ($content === false) return [];
            
            $data = json_decode($content, true);
            return is_array($data) ? $data : [];
        }
        
        private function saveData(array $data): void
        {
            @file_put_contents($this->storageFile, json_encode($data), LOCK_EX);
        }
    }
    
    /**
     * CSRF Token Yonetimi
     */
    class CSRFProtection
    {
        private string $tokenName;
        
        public function __construct(string $tokenName = '_csrf_token')
        {
            $this->tokenName = $tokenName;
            
            if (session_status() === PHP_SESSION_NONE) {
                @session_start();
            }
        }
        
        public function generateToken(): string
        {
            $token = bin2hex(random_bytes(32));
            $_SESSION[$this->tokenName] = $token;
            $_SESSION[$this->tokenName . '_time'] = time();
            return $token;
        }
        
        public function validateToken(?string $token, int $maxAge = 3600): bool
        {
            if ($token === null || !isset($_SESSION[$this->tokenName])) {
                return false;
            }
            
            // Token eslesiyor mu?
            if (!hash_equals($_SESSION[$this->tokenName], $token)) {
                return false;
            }
            
            // Token suresi dolmus mu?
            $tokenTime = $_SESSION[$this->tokenName . '_time'] ?? 0;
            if ((time() - $tokenTime) > $maxAge) {
                return false;
            }
            
            return true;
        }
        
        public function getTokenField(): string
        {
            $token = $this->generateToken();
            return sprintf(
                '<input type="hidden" name="%s" value="%s">',
                htmlspecialchars($this->tokenName, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
            );
        }
    }
    
    /**
     * Input Validator Sinifi
     */
    class InputValidator
    {
        /**
         * SQL Injection kontrolu
         */
        public static function hasSQLInjection(string $input): bool
        {
            $patterns = [
                '/(\bunion\b.*\bselect\b)/i',
                '/(\bselect\b.*\bfrom\b)/i',
                '/(\binsert\b.*\binto\b)/i',
                '/(\bdelete\b.*\bfrom\b)/i',
                '/(\bdrop\b.*\b(table|database)\b)/i',
                '/(\bupdate\b.*\bset\b)/i',
                '/(\balter\b.*\btable\b)/i',
                '/(\bexec\b.*\b(xp_|sp_))/i',
                '/(\'|\")\s*(or|and)\s*(\'|\"|[0-9])/i',
                '/(\bwaitfor\b.*\bdelay\b)/i',
                '/(\bbenchmark\b\s*\()/i',
                '/(sleep\s*\(\s*\d+\s*\))/i',
                '/(\bload_file\b\s*\()/i',
                '/(\boutfile\b)/i',
                '/(\binto\b.*\b(dump|out)file\b)/i',
                '/(\bconcat\b\s*\()/i',
                '/(\bchar\b\s*\(\s*\d+)/i',
                '/(0x[0-9a-f]+)/i',
                '/(\/\*.*\*\/)/s',
                '/(--\s*$)/m',
                '/(#\s*$)/m',
            ];
            
            $decoded = rawurldecode($input);
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    return true;
                }
            }
            
            return false;
        }
        
        /**
         * XSS kontrolu
         */
        public static function hasXSS(string $input): bool
        {
            $patterns = [
                '/<script[^>]*>.*?<\/script>/is',
                '/<[^>]+on\w+\s*=/i',
                '/javascript\s*:/i',
                '/vbscript\s*:/i',
                '/data\s*:[^,]*base64/i',
                '/<iframe[^>]*>/i',
                '/<object[^>]*>/i',
                '/<embed[^>]*>/i',
                '/<applet[^>]*>/i',
                '/<meta[^>]*>/i',
                '/<link[^>]*>/i',
                '/<style[^>]*>.*?<\/style>/is',
                '/expression\s*\(/i',
                '/url\s*\(\s*["\']?\s*javascript/i',
                '/-moz-binding\s*:/i',
                '/behavior\s*:/i',
            ];
            
            $decoded = rawurldecode(html_entity_decode($input, ENT_QUOTES, 'UTF-8'));
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    return true;
                }
            }
            
            return false;
        }
        
        /**
         * Path Traversal kontrolu
         */
        public static function hasPathTraversal(string $input): bool
        {
            $patterns = [
                '/\.\.\//i',
                '/\.\.\\\/i',
                '/%2e%2e%2f/i',
                '/%2e%2e\//i',
                '/\.\.%2f/i',
                '/%252e%252e%252f/i',
                '/\.%00/i',
                '/%00/i',
                '/\/etc\/passwd/i',
                '/\/etc\/shadow/i',
                '/\/proc\/self/i',
                '/\/var\/log/i',
                '/c:\\\\windows/i',
                '/c:\\\\boot\.ini/i',
            ];
            
            $decoded = rawurldecode($input);
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    return true;
                }
            }
            
            return false;
        }
        
        /**
         * Command Injection kontrolu
         */
        public static function hasCommandInjection(string $input): bool
        {
            $patterns = [
                '/[;&|`$]/',
                '/\$\(.*\)/',
                '/`.*`/',
                '/\|\|/',
                '/&&/',
                '/>\s*\//',
                '/<\s*\//',
                '/\bnc\s+-/',
                '/\bwget\s+/',
                '/\bcurl\s+/',
                '/\bchmod\s+/',
                '/\bchown\s+/',
                '/\brm\s+-/',
                '/\bkill\s+/',
                '/\bpython\s+/',
                '/\bperl\s+/',
                '/\bphp\s+/',
                '/\bbash\s+/',
                '/\bsh\s+/',
                '/\/bin\/(ba)?sh/',
            ];
            
            $decoded = rawurldecode($input);
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    return true;
                }
            }
            
            return false;
        }
        
        /**
         * Header Injection kontrolu
         */
        public static function hasHeaderInjection(string $input): bool
        {
            return preg_match('/[\r\n]/', $input) === 1;
        }
        
        /**
         * JSON Bomb kontrolu
         */
        public static function isJSONBomb(string $input, int $maxDepth = 10, int $maxSize = 1048576): bool
        {
            if (strlen($input) > $maxSize) {
                return true;
            }
            
            $depth = 0;
            $maxFound = 0;
            
            for ($i = 0; $i < strlen($input); $i++) {
                if ($input[$i] === '{' || $input[$i] === '[') {
                    $depth++;
                    $maxFound = max($maxFound, $depth);
                } elseif ($input[$i] === '}' || $input[$i] === ']') {
                    $depth--;
                }
            }
            
            return $maxFound > $maxDepth;
        }
        
        /**
         * XML Bomb (Billion Laughs) kontrolu
         */
        public static function isXMLBomb(string $input): bool
        {
            $patterns = [
                '/<!ENTITY\s+/i',
                '/<!DOCTYPE[^>]*\[/i',
                '/SYSTEM\s+["\']file:/i',
                '/SYSTEM\s+["\']php:/i',
                '/SYSTEM\s+["\']expect:/i',
            ];
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $input)) {
                    return true;
                }
            }
            
            // Cok fazla entity referansi
            if (substr_count($input, '&') > 100) {
                return true;
            }
            
            return false;
        }
    }
    
    /**
     * Bot Detector Sinifi
     */
    class BotDetector
    {
        private static array $knownBots = [
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver'
        ];
        
        private static array $suspiciousBots = [
            'wget', 'curl', 'python', 'perl', 'ruby', 'java', 'httpclient',
            'libwww', 'lwp', 'mechanize', 'scrapy', 'phantom', 'headless',
            'selenium', 'puppeteer', 'playwright', 'casper', 'nightmare',
            'sqlmap', 'nikto', 'nmap', 'masscan', 'acunetix', 'nessus',
            'burp', 'zap', 'w3af', 'skipfish', 'wpscan', 'joomscan'
        ];
        
        public static function isKnownBot(string $userAgent): bool
        {
            $ua = strtolower($userAgent);
            
            foreach (self::$knownBots as $bot) {
                if (strpos($ua, $bot) !== false) {
                    return true;
                }
            }
            
            return false;
        }
        
        public static function isSuspiciousBot(string $userAgent): bool
        {
            $ua = strtolower($userAgent);
            
            foreach (self::$suspiciousBots as $bot) {
                if (strpos($ua, $bot) !== false) {
                    return true;
                }
            }
            
            return false;
        }
        
        public static function hasEmptyUA(string $userAgent): bool
        {
            return $userAgent === '' || $userAgent === 'none' || $userAgent === '-';
        }
        
        public static function isSuspiciousUA(string $userAgent): bool
        {
            // Cok kisa UA
            if (strlen($userAgent) < 10) {
                return true;
            }
            
            // Sadece bosluk veya ozel karakter
            if (preg_match('/^[\s\-_\.]+$/', $userAgent)) {
                return true;
            }
            
            return false;
        }
    }
    
    /**
     * File Upload Validator Sinifi
     */
    class FileUploadValidator
    {
        private array $allowedExtensions;
        private int $maxSize;
        
        private static array $dangerousMimeTypes = [
            'application/x-php', 'application/x-httpd-php',
            'application/x-perl', 'application/x-python',
            'application/x-ruby', 'application/x-shellscript',
            'application/x-executable', 'application/x-msdos-program',
            'text/x-php', 'text/x-perl', 'text/x-python',
        ];
        
        private static array $dangerousExtensions = [
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
            'exe', 'com', 'bat', 'cmd', 'sh', 'bash', 'zsh',
            'pl', 'py', 'rb', 'cgi', 'asp', 'aspx', 'jsp', 'jspx',
            'htaccess', 'htpasswd', 'ini', 'conf', 'config',
        ];
        
        public function __construct(array $allowedExtensions = [], int $maxSize = 10485760)
        {
            $this->allowedExtensions = array_map('strtolower', $allowedExtensions);
            $this->maxSize = $maxSize;
        }
        
        public function validate(array $file): array
        {
            $errors = [];
            
            // Dosya yukleme hatasi kontrolu
            if ($file['error'] !== UPLOAD_ERR_OK) {
                $errors[] = 'Upload error: ' . $this->getUploadErrorMessage($file['error']);
                return $errors;
            }
            
            // Boyut kontrolu
            if ($file['size'] > $this->maxSize) {
                $errors[] = 'File too large';
            }
            
            // Uzanti kontrolu
            $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            
            if (in_array($extension, self::$dangerousExtensions, true)) {
                $errors[] = 'Dangerous file extension';
            }
            
            if (!empty($this->allowedExtensions) && !in_array($extension, $this->allowedExtensions, true)) {
                $errors[] = 'File extension not allowed';
            }
            
            // MIME type kontrolu
            if (function_exists('finfo_open')) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mimeType = finfo_file($finfo, $file['tmp_name']);
                finfo_close($finfo);
                
                if (in_array($mimeType, self::$dangerousMimeTypes, true)) {
                    $errors[] = 'Dangerous MIME type';
                }
            }
            
            // Dosya icerigi kontrolu (PHP kodu var mi?)
            $content = @file_get_contents($file['tmp_name'], false, null, 0, 1024);
            if ($content !== false) {
                if (preg_match('/<\?php|<\?=|<\?(?!xml)/i', $content)) {
                    $errors[] = 'PHP code detected in file';
                }
            }
            
            // Cift uzanti kontrolu
            if (preg_match('/\.[a-z0-9]+\.[a-z0-9]+$/i', $file['name'])) {
                $parts = explode('.', $file['name']);
                array_shift($parts); // ilk kismi (dosya adi) cikar
                foreach ($parts as $part) {
                    if (in_array(strtolower($part), self::$dangerousExtensions, true)) {
                        $errors[] = 'Double extension attack detected';
                        break;
                    }
                }
            }
            
            return $errors;
        }
        
        private function getUploadErrorMessage(int $error): string
        {
            return match($error) {
                UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
                UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the upload',
                default => 'Unknown upload error',
            };
        }
    }
    
    /**
     * Proxy Detector Sinifi
     */
    class ProxyDetector
    {
        private static array $proxyHeaders = [
            'HTTP_VIA',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR_IP',
            'VIA',
            'X_FORWARDED_FOR',
            'FORWARDED_FOR',
            'X_FORWARDED',
            'FORWARDED',
            'CLIENT_IP',
            'FORWARDED_FOR_IP',
            'HTTP_PROXY_CONNECTION',
            'HTTP_X_REAL_IP',
            'HTTP_X_ORIGINATING_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_TRUE_CLIENT_IP',
        ];
        
        public static function isUsingProxy(): bool
        {
            foreach (self::$proxyHeaders as $header) {
                if (!empty($_SERVER[$header])) {
                    // Cloudflare gibi bilinen servisleri atla
                    if ($header === 'HTTP_CF_CONNECTING_IP') {
                        continue;
                    }
                    return true;
                }
            }
            
            return false;
        }
        
        public static function getProxyHeaders(): array
        {
            $found = [];
            
            foreach (self::$proxyHeaders as $header) {
                if (!empty($_SERVER[$header])) {
                    $found[$header] = $_SERVER[$header];
                }
            }
            
            return $found;
        }
    }
    
    // ===================== ANA FIREWALL CALISTIRMA =====================
    
    // Firewall instance olustur
    $firewall = PHPFirewall::getInstance($IP_WHITELIST, $IP_BLACKLIST);
    
    // Guvenlik basliklarini ayarla
    if (PHP_FIREWALL_SECURITY_HEADERS === true) {
        $firewall->setSecurityHeaders();
    }
    
    // Whitelist kontrolu
    if ($firewall->isWhitelisted()) {
        return; // Whitelisted IP'ler icin firewall'u atla
    }
    
    // Blacklist kontrolu
    if ($firewall->isBlacklisted()) {
        $firewall->block(_PHPF_PROTECTION_BLACKLIST, 'IP Blacklisted');
    }
    
    // Rate Limiting
    if (PHP_FIREWALL_PROTECTION_RATE_LIMIT === true) {
        $rateLimiter = new RateLimiter(PHP_FIREWALL_RATE_LIMIT_REQUESTS, PHP_FIREWALL_RATE_LIMIT_WINDOW);
        if ($rateLimiter->isLimited($firewall->getIP())) {
            $firewall->block(_PHPF_PROTECTION_RATE_LIMIT, 'Rate Limit Exceeded', 429);
        }
    }
    
    // Brute Force Kontrolu
    if (PHP_FIREWALL_PROTECTION_BRUTE_FORCE === true) {
        $bruteForce = new BruteForceProtection(
            PHP_FIREWALL_BRUTE_FORCE_MAX_ATTEMPTS,
            PHP_FIREWALL_BRUTE_FORCE_LOCKOUT_TIME
        );
        if ($bruteForce->isLocked($firewall->getIP())) {
            $firewall->block(_PHPF_PROTECTION_BRUTE_FORCE, 'Brute Force Lockout');
        }
    }
    
    // Proxy Kontrolu
    if (PHP_FIREWALL_PROTECTION_PROXY === true) {
        if (ProxyDetector::isUsingProxy()) {
            $firewall->log('Proxy Detected', ['headers' => ProxyDetector::getProxyHeaders()]);
            // Sadece logla, engelleme
            // $firewall->block(_PHPF_PROTECTION_PROXY, 'Proxy Detected');
        }
    }
    
    // DOS Korumasi (Bos User Agent)
    if (PHP_FIREWALL_PROTECTION_DOS === true) {
        if (BotDetector::hasEmptyUA($firewall->getUA()) || BotDetector::isSuspiciousUA($firewall->getUA())) {
            $firewall->block(_PHPF_PROTECTION_DOS, 'DOS Attack - Empty/Invalid UA');
        }
    }
    
    // Gelismis Bot Tespiti
    if (PHP_FIREWALL_PROTECTION_ADVANCED_BOT === true) {
        if (BotDetector::isSuspiciousBot($firewall->getUA())) {
            $firewall->block(_PHPF_PROTECTION_BOTS, 'Suspicious Bot Detected');
        }
    }
    
    // Request Method Kontrolu
    if (PHP_FIREWALL_PROTECTION_REQUEST_METHOD === true) {
        $allowedMethods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
        if (!in_array($firewall->getMethod(), $allowedMethods, true)) {
            $firewall->block(_PHPF_PROTECTION_REQUEST, 'Invalid Request Method');
        }
    }
    
    // CSRF Kontrolu (POST istekleri icin)
    if (PHP_FIREWALL_PROTECTION_CSRF === true && $firewall->getMethod() === 'POST') {
        $csrf = new CSRFProtection(PHP_FIREWALL_CSRF_TOKEN_NAME);
        $token = $_POST[PHP_FIREWALL_CSRF_TOKEN_NAME] ?? null;
        
        // CSRF token form'da varsa kontrol et
        if (isset($_POST[PHP_FIREWALL_CSRF_TOKEN_NAME]) && !$csrf->validateToken($token)) {
            $firewall->block(_PHPF_PROTECTION_CSRF, 'Invalid CSRF Token');
        }
    }
    
    // Honeypot Kontrolu
    if (PHP_FIREWALL_PROTECTION_HONEYPOT === true && $firewall->getMethod() === 'POST') {
        if (!empty($_POST[PHP_FIREWALL_HONEYPOT_FIELD_NAME])) {
            $firewall->block(_PHPF_PROTECTION_HONEYPOT, 'Honeypot Triggered');
        }
    }
    
    // Diger Sunucudan POST Kontrolu
    if (PHP_FIREWALL_PROTECTION_REQUEST_SERVER === true && $firewall->getMethod() === 'POST') {
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        if ($referer !== '' && $host !== '' && stripos($referer, $host) === false) {
            $firewall->block(_PHPF_PROTECTION_OTHER_SERVER, 'Cross-Origin POST');
        }
    }
    
    // File Upload Kontrolu
    if (PHP_FIREWALL_PROTECTION_FILE_UPLOAD === true && !empty($_FILES)) {
        $validator = new FileUploadValidator(PHP_FIREWALL_ALLOWED_EXTENSIONS, PHP_FIREWALL_MAX_FILE_SIZE);
        
        foreach ($_FILES as $fieldName => $file) {
            // Coklu dosya yukleme destegi
            if (is_array($file['name'])) {
                for ($i = 0; $i < count($file['name']); $i++) {
                    $singleFile = [
                        'name' => $file['name'][$i],
                        'type' => $file['type'][$i],
                        'tmp_name' => $file['tmp_name'][$i],
                        'error' => $file['error'][$i],
                        'size' => $file['size'][$i],
                    ];
                    
                    $errors = $validator->validate($singleFile);
                    if (!empty($errors)) {
                        $firewall->block(_PHPF_PROTECTION_FILE_UPLOAD, 'File Upload Attack', 400);
                    }
                }
            } else {
                $errors = $validator->validate($file);
                if (!empty($errors)) {
                    $firewall->block(_PHPF_PROTECTION_FILE_UPLOAD, 'File Upload Attack', 400);
                }
            }
        }
    }
    
    // Query String Kontrolleri
    $queryString = $firewall->getQS();
    
    if ($queryString !== '') {
        // SQL Injection
        if (PHP_FIREWALL_PROTECTION_UNION_SQL === true) {
            if (InputValidator::hasSQLInjection($queryString)) {
                $firewall->block(_PHPF_PROTECTION_UNION, 'SQL Injection Attack');
            }
        }
        
        // XSS
        if (PHP_FIREWALL_PROTECTION_XSS_ATTACK === true) {
            if (InputValidator::hasXSS($queryString)) {
                $firewall->block(_PHPF_PROTECTION_XSS, 'XSS Attack');
            }
        }
        
        // Path Traversal
        if (PHP_FIREWALL_PROTECTION_PATH_TRAVERSAL === true) {
            if (InputValidator::hasPathTraversal($queryString)) {
                $firewall->block(_PHPF_PROTECTION_PATH_TRAVERSAL, 'Path Traversal Attack');
            }
        }
        
        // Command Injection
        if (PHP_FIREWALL_PROTECTION_COMMAND_INJECTION === true) {
            if (InputValidator::hasCommandInjection($queryString)) {
                $firewall->block(_PHPF_PROTECTION_COMMAND_INJECTION, 'Command Injection Attack');
            }
        }
        
        // Header Injection
        if (PHP_FIREWALL_PROTECTION_HEADER_INJECTION === true) {
            if (InputValidator::hasHeaderInjection($queryString)) {
                $firewall->block(_PHPF_PROTECTION_HEADER_INJECTION, 'Header Injection Attack');
            }
        }
    }
    
    // POST Verisi Kontrolleri
    if (PHP_FIREWALL_PROTECTION_POST === true && !empty($_POST)) {
        $postData = json_encode($_POST);
        
        // JSON Bomb
        if (PHP_FIREWALL_PROTECTION_JSON_BOMB === true) {
            if (InputValidator::isJSONBomb($postData)) {
                $firewall->block(_PHPF_PROTECTION_JSON_BOMB, 'JSON Bomb Attack');
            }
        }
        
        foreach ($_POST as $key => $value) {
            if (is_string($value)) {
                if (PHP_FIREWALL_PROTECTION_UNION_SQL === true && InputValidator::hasSQLInjection($value)) {
                    $firewall->log('POST SQL Injection', ['field' => $key]);
                    unset($_POST[$key]);
                }
                
                if (PHP_FIREWALL_PROTECTION_XSS_ATTACK === true && InputValidator::hasXSS($value)) {
                    $firewall->log('POST XSS', ['field' => $key]);
                    unset($_POST[$key]);
                }
                
                if (PHP_FIREWALL_PROTECTION_HEADER_INJECTION === true && InputValidator::hasHeaderInjection($value)) {
                    $firewall->log('POST Header Injection', ['field' => $key]);
                    unset($_POST[$key]);
                }
            }
        }
    }
    
    // GET Verisi Kontrolleri
    if (PHP_FIREWALL_PROTECTION_GET === true && !empty($_GET)) {
        foreach ($_GET as $key => $value) {
            if (is_string($value)) {
                if (PHP_FIREWALL_PROTECTION_UNION_SQL === true && InputValidator::hasSQLInjection($value)) {
                    $firewall->log('GET SQL Injection', ['field' => $key]);
                    unset($_GET[$key]);
                }
                
                if (PHP_FIREWALL_PROTECTION_XSS_ATTACK === true && InputValidator::hasXSS($value)) {
                    $firewall->log('GET XSS', ['field' => $key]);
                    unset($_GET[$key]);
                }
            }
        }
    }
    
    // Cookie Kontrolleri
    if (PHP_FIREWALL_PROTECTION_COOKIES === true && !empty($_COOKIE)) {
        foreach ($_COOKIE as $key => $value) {
            if (is_string($value)) {
                if (InputValidator::hasSQLInjection($value) || InputValidator::hasXSS($value)) {
                    $firewall->log('Cookie Attack', ['cookie' => $key]);
                    unset($_COOKIE[$key]);
                    setcookie($key, '', time() - 3600, '/', '', true, true);
                }
            }
        }
    }
    
    // Raw Input (JSON/XML) Kontrolleri
    $rawInput = file_get_contents('php://input');
    if ($rawInput !== false && $rawInput !== '') {
        // JSON Bomb
        if (PHP_FIREWALL_PROTECTION_JSON_BOMB === true) {
            $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
            if (stripos($contentType, 'application/json') !== false) {
                if (InputValidator::isJSONBomb($rawInput)) {
                    $firewall->block(_PHPF_PROTECTION_JSON_BOMB, 'JSON Bomb Attack');
                }
            }
        }
        
        // XML Bomb
        if (PHP_FIREWALL_PROTECTION_XML_BOMB === true) {
            $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
            if (stripos($contentType, 'xml') !== false) {
                if (InputValidator::isXMLBomb($rawInput)) {
                    $firewall->block(_PHPF_PROTECTION_XML_BOMB, 'XML Bomb Attack');
                }
            }
        }
    }
    
    // Santy Saldirisi
    if (PHP_FIREWALL_PROTECTION_SANTY === true) {
        $santyRules = ['rush', 'highlight=%', 'perl', 'chr(', 'pillar', 'visualcoder', 'sess_'];
        $uri = strtolower($firewall->getUri());
        
        foreach ($santyRules as $rule) {
            if (strpos($uri, $rule) !== false) {
                $firewall->block(_PHPF_PROTECTION_SANTY, 'Santy Attack');
            }
        }
    }
    
    // URL Korumasi
    if (PHP_FIREWALL_PROTECTION_URL === true) {
        $urlRules = [
            'absolute_path', 'ad_click', 'alert(', 'basepath', 'bash_history',
            'cgi-', 'chmod(', 'chown(', 'chr(', 'cmd=', 'config.php',
            'document.cookie', 'document.location', 'drop%20', 'etc/passwd',
            'etc/shadow', 'exploit', 'file://', 'fopen', 'fwrite',
            'getenv', 'http_php', 'insert%20into', 'javascript://',
            'kill%20', 'load_file', 'outfile', 'password=', 'phpinfo()',
            'reboot%20', 'root_path', 'select%20', 'shell_exec', 'system(',
            'union%20', 'wget', 'window.open', 'xp_cmdshell', '<?php', '?>'
        ];
        
        foreach ($urlRules as $rule) {
            if (stripos($queryString, $rule) !== false) {
                $firewall->block(_PHPF_PROTECTION_URL, 'URL Attack');
            }
        }
    }
    
    // Click Saldirisi
    if (PHP_FIREWALL_PROTECTION_CLICK_ATTACK === true) {
        $clickRules = ['/*', 'c2nyaxb0', 'script', '<script', 'javascript:'];
        $decoded = strtolower(rawurldecode($queryString));
        
        foreach ($clickRules as $rule) {
            if (strpos($decoded, $rule) !== false) {
                $firewall->block(_PHPF_PROTECTION_CLICK, 'Click Attack');
            }
        }
    }
    
    // Sunucu IP Araligi Kontrolleri
    if (PHP_FIREWALL_PROTECTION_SERVER_OVH === true) {
        if (stripos($firewall->getHost(), 'ovh') !== false) {
            $firewall->block(_PHPF_PROTECTION_OVH, 'OVH Server');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_OVH_BY_IP === true) {
        if ($firewall->checkIPRange(['87.98', '91.121', '94.23', '213.186', '213.251'])) {
            $firewall->block(_PHPF_PROTECTION_OVH, 'OVH Server IP');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI === true) {
        if (stripos($firewall->getHost(), 'kimsufi') !== false) {
            $firewall->block(_PHPF_PROTECTION_KIMSUFI, 'Kimsufi Server');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI_BY_IP === true) {
        if ($firewall->checkIPRange(['91.121', '87.98'])) {
            $firewall->block(_PHPF_PROTECTION_KIMSUFI, 'Kimsufi Server IP');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX === true) {
        if (stripos($firewall->getHost(), 'dedibox') !== false) {
            $firewall->block(_PHPF_PROTECTION_DEDIBOX, 'Dedibox Server');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX_BY_IP === true) {
        if ($firewall->checkIPRange(['88.191'])) {
            $firewall->block(_PHPF_PROTECTION_DEDIBOX_IP, 'Dedibox Server IP');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE === true) {
        if (stripos($firewall->getHost(), 'digicube') !== false) {
            $firewall->block(_PHPF_PROTECTION_DIGICUBE, 'Digicube Server');
        }
    }
    
    if (PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE_BY_IP === true) {
        if ($firewall->checkIPRange(['95.130'])) {
            $firewall->block(_PHPF_PROTECTION_DIGICUBE_IP, 'Digicube Server IP');
        }
    }
    
    // Spam IP Kontrolu
    if (PHP_FIREWALL_PROTECTION_RANGE_IP_SPAM === true) {
        $spamRanges = ['24', '186', '189', '190', '200', '201', '202', '209', '212', '213', '217', '222'];
        $parts = explode('.', $firewall->getIP());
        
        if (isset($parts[0]) && in_array($parts[0], $spamRanges, true)) {
            $firewall->block(_PHPF_PROTECTION_SPAM, 'Spam IP Range');
        }
    }
    
    // Reserved IP Kontrolu
    if (PHP_FIREWALL_PROTECTION_RANGE_IP_DENY === true) {
        $denyRanges = ['0', '1', '2', '5', '10', '14', '23', '27', '31', '36', '37', '39', '42'];
        $parts = explode('.', $firewall->getIP());
        
        if (isset($parts[0]) && in_array($parts[0], $denyRanges, true)) {
            $firewall->block(_PHPF_PROTECTION_SPAM_IP, 'Reserved IP Range');
        }
    }
    
    // Bot Listesi Dosyasi Kontrolu
    if (PHP_FIREWALL_PROTECTION_BOTS === true) {
        $botFile = __DIR__ . '/firewall_bot_list.php';
        if (file_exists($botFile)) {
            $botList = include $botFile;
            if (is_array($botList)) {
                $ua = strtolower($firewall->getUA());
                foreach ($botList as $bot) {
                    if (stripos($ua, $bot) !== false) {
                        $firewall->block(_PHPF_PROTECTION_BOTS, 'Bot Attack');
                    }
                }
            }
        }
    }
}

// ===================== YARDIMCI FONKSIYONLAR =====================

/**
 * CSRF Token alani olustur
 */
function phpf_csrf_field(): string
{
    if (!defined('PHP_FIREWALL_PROTECTION_CSRF') || PHP_FIREWALL_PROTECTION_CSRF !== true) {
        return '';
    }
    
    $csrf = new CSRFProtection(PHP_FIREWALL_CSRF_TOKEN_NAME);
    return $csrf->getTokenField();
}

/**
 * Honeypot alani olustur
 */
function phpf_honeypot_field(): string
{
    if (!defined('PHP_FIREWALL_PROTECTION_HONEYPOT') || PHP_FIREWALL_PROTECTION_HONEYPOT !== true) {
        return '';
    }
    
    return sprintf(
        '<div style="position:absolute;left:-9999px;"><input type="text" name="%s" value="" tabindex="-1" autocomplete="off"></div>',
        htmlspecialchars(PHP_FIREWALL_HONEYPOT_FIELD_NAME, ENT_QUOTES, 'UTF-8')
    );
}

/**
 * Basarisiz giris denemesi kaydet (Brute Force icin)
 */
function phpf_record_failed_login(): void
{
    if (!defined('PHP_FIREWALL_PROTECTION_BRUTE_FORCE') || PHP_FIREWALL_PROTECTION_BRUTE_FORCE !== true) {
        return;
    }
    
    $firewall = PHPFirewall::getInstance();
    $bruteForce = new BruteForceProtection(
        PHP_FIREWALL_BRUTE_FORCE_MAX_ATTEMPTS,
        PHP_FIREWALL_BRUTE_FORCE_LOCKOUT_TIME
    );
    $bruteForce->recordAttempt($firewall->getIP());
}

/**
 * Basarili giris sonrasi brute force sayacini sifirla
 */
function phpf_reset_login_attempts(): void
{
    if (!defined('PHP_FIREWALL_PROTECTION_BRUTE_FORCE') || PHP_FIREWALL_PROTECTION_BRUTE_FORCE !== true) {
        return;
    }
    
    $firewall = PHPFirewall::getInstance();
    $bruteForce = new BruteForceProtection(
        PHP_FIREWALL_BRUTE_FORCE_MAX_ATTEMPTS,
        PHP_FIREWALL_BRUTE_FORCE_LOCKOUT_TIME
    );
    $bruteForce->resetAttempts($firewall->getIP());
}
