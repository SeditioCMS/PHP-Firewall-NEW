# PHP-Firewall-Script PHP 7.x - 8.x

PHP Firewall is a comprehensive, free PHP security script that protects all websites written in PHP.

**Requirements:**
- PHP 7.4+ or PHP 8.x
- No database required (flatfile system)
- No external dependencies

**Features:**
- Very small, simple, and easy to install
- Built-in logging system (JSON and TXT formats)
- Email alert system
- No .htaccess file required for better performance
- Object-Oriented Architecture with modern PHP standards

---

## Security Features

### Core Protection
1. **XSS Protection** - Cross-Site Scripting attack prevention
2. **SQL Injection Protection** - UNION, SELECT, INSERT, UPDATE, DELETE injection blocking
3. **Command Injection Protection** - Shell command execution prevention
4. **Path Traversal Protection** - Directory traversal attack blocking
5. **File Inclusion Protection** - LFI/RFI attack prevention
6. **Header Injection Protection** - HTTP header manipulation blocking

### Advanced Protection
7. **Rate Limiting** - Configurable request limits per minute
8. **Brute Force Protection** - Failed login attempt tracking and temporary lockout
9. **CSRF Protection** - Cross-Site Request Forgery token validation
10. **Honeypot Fields** - Bot detection using hidden form fields
11. **JSON/XML Bomb Protection** - Malicious payload structure detection
12. **File Upload Security** - Extension, MIME type, and PHP code validation

### Bot & Request Protection
13. **Bad Bots Protection** - SQLMap, Nikto, Nmap, and other scanner detection
14. **Bad Request Methods Protection** - Dangerous HTTP method blocking
15. **DOS Protection** - Basic denial-of-service mitigation
16. **Proxy Detection** - Proxy header identification
17. **User-Agent Validation** - Empty and suspicious user-agent blocking

### Input Sanitization
18. **URL Query Protection** - Malicious query string filtering
19. **Cookies Sanitize** - Cookie value validation
20. **POST Vars Sanitize** - POST data filtering
21. **GET Vars Sanitize** - GET parameter filtering
22. **Request Body Validation** - JSON and form data validation

### IP Protection
23. **IP Range Reserved Denied** - Private/reserved IP blocking
24. **IP Range Spam Denied** - Known spam IP range blocking
25. **IP Whitelist Support** - Trusted IP exemption
26. **IP Blacklist Support** - Permanent IP blocking
27. **CIDR Notation Support** - Flexible IP range definitions

### Server Protection
28. **Security Headers** - CSP, X-Frame-Options, X-Content-Type-Options
29. **Session Security** - Secure session configuration
30. **Error Handling** - Production-safe error management

---

## Installation

### Basic Installation

Add this code to the header section of your site (before any output):

```php
<?php
// Define constants before including firewall
define('PHP_FIREWALL_REQUEST_URI', filter_var($_SERVER['REQUEST_URI'] ?? '', FILTER_SANITIZE_URL));
define('PHP_FIREWALL_ACTIVATION', true);

// Include the firewall
include_once('firewall/firewall.php');
```

### Advanced Installation with Configuration

```php
<?php
// Firewall Configuration
define('PHP_FIREWALL_REQUEST_URI', filter_var($_SERVER['REQUEST_URI'] ?? '', FILTER_SANITIZE_URL));
define('PHP_FIREWALL_ACTIVATION', true);

// Optional: Custom configuration
define('PHP_FIREWALL_LOG_DIR', __DIR__ . '/logs');
define('PHP_FIREWALL_ADMIN_EMAIL', 'admin@example.com');
define('PHP_FIREWALL_RATE_LIMIT', 60);           // Requests per minute
define('PHP_FIREWALL_BRUTE_FORCE_LIMIT', 5);     // Failed attempts before lockout
define('PHP_FIREWALL_LOCKOUT_TIME', 900);        // Lockout duration in seconds

include_once('firewall/firewall.php');
```

---

## Configuration Options

### Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `PHP_FIREWALL_ACTIVATION` | `true` | Enable/disable firewall |
| `PHP_FIREWALL_LOG_DIR` | `__DIR__ . '/logs'` | Log directory path |
| `PHP_FIREWALL_ADMIN_EMAIL` | `''` | Admin email for alerts |
| `PHP_FIREWALL_RATE_LIMIT` | `60` | Max requests per minute |
| `PHP_FIREWALL_BRUTE_FORCE_LIMIT` | `5` | Max failed login attempts |
| `PHP_FIREWALL_LOCKOUT_TIME` | `900` | Lockout duration (seconds) |
| `PHP_FIREWALL_MAX_UPLOAD_SIZE` | `10485760` | Max file upload size (10MB) |

### Whitelist Configuration

Edit the `$whitelist_ips` array in firewall.php:

```php
private array $whitelist_ips = [
    '127.0.0.1',
    '::1',
    '192.168.1.0/24',  // CIDR notation supported
];
```

### Blacklist Configuration

Edit the `$blacklist_ips` array in firewall.php:

```php
private array $blacklist_ips = [
    '10.0.0.5',
    '203.0.113.0/24',
];
```

---

## Usage Examples

### CSRF Protection in Forms

```php
<?php
// In your form
?>
<form method="POST" action="/submit">
    <?php echo phpf_csrf_field(); ?>
    <?php echo phpf_honeypot_field(); ?>
    
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
```

### Recording Failed Login Attempts

```php
<?php
// In your login handler
if (!$login_successful) {
    phpf_record_failed_login($username);
}
```

### File Upload Validation

```php
<?php
// The firewall automatically validates uploads, but you can also use:
$firewall = PHPFirewall::getInstance();

if (isset($_FILES['upload'])) {
    // Firewall has already validated the file
    // Proceed with your upload logic
    move_uploaded_file($_FILES['upload']['tmp_name'], $destination);
}
```

### Manual IP Check

```php
<?php
$firewall = PHPFirewall::getInstance();

// Check if IP is whitelisted
if ($firewall->isWhitelisted($_SERVER['REMOTE_ADDR'])) {
    // Skip additional checks
}
```

---

## Bot Blocking (botlist.php)

The firewall includes a comprehensive bot blocking system with 200+ known bad bots.

### Basic Bot Blocking

```php
<?php
// Include botlist after firewall
include_once('firewall/firewall.php');
include_once('firewall/botlist.php');

// Check and block bad bots
if (check_bot_user_agent()) {
    // Bot detected - already logged, optionally redirect
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}
```

### Bot Categories

The botlist includes these categories:

| Category | Examples |
|----------|----------|
| **Vulnerability Scanners** | sqlmap, nikto, nuclei, wpscan, dirsearch, gobuster |
| **AI/LLM Scrapers** | GPTBot, ClaudeBot, Anthropic-AI, ByteSpider, Perplexity |
| **Modern Scrapers** | Scrapy, Puppeteer, Playwright, Selenium, PhantomJS |
| **SEO Bots** | AhrefsBot, SemrushBot, MJ12bot, DotBot, SimilarWeb |
| **Spam Bots** | XRumer, ScrapeBox, GSA Search Engine Ranker |
| **Proxy Services** | Brightdata, Oxylabs, Smartproxy |
| **Credential Tools** | Hydra, Medusa, CrackMapExec |

### Whitelist Good Bots

Allow legitimate bots (Google, Bing, etc.):

```php
<?php
// Define whitelist before including botlist
$bot_whitelist = [
    'Googlebot',
    'Bingbot', 
    'YandexBot',
    'DuckDuckBot',
    'Slurp',           // Yahoo
    'facebot',         // Facebook
    'Twitterbot',
    'LinkedInBot',
];

include_once('firewall/botlist.php');

// Check with whitelist support
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$is_bad_bot = false;

foreach ($bot_whitelist as $good_bot) {
    if (stripos($user_agent, $good_bot) !== false) {
        $is_bad_bot = false;
        break;
    }
}

if (!$is_bad_bot && check_bot_user_agent()) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}
```

### Custom Bot Rules

Add your own bot patterns:

```php
<?php
// Add custom patterns to the botlist array
$custom_bad_bots = [
    'MyCustomBot',
    'AnotherBadBot',
];

// Merge with existing list
$php_firewall_bad_bots = array_merge($php_firewall_bad_bots, $custom_bad_bots);
```

### Bot Statistics

Get information about blocked bots:

```php
<?php
$stats = get_bot_list_stats();

echo "Total bot patterns: " . $stats['total_patterns'];
echo "Categories: " . implode(', ', $stats['categories']);
echo "Last updated: " . $stats['last_updated'];
```

### .htaccess Alternative (Apache)

For Apache servers, you can also block bots via .htaccess:

```apache
# Block bad bots via .htaccess
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|nuclei|wpscan) [NC,OR]
RewriteCond %{HTTP_USER_AGENT} (GPTBot|ClaudeBot|Anthropic) [NC,OR]
RewriteCond %{HTTP_USER_AGENT} (AhrefsBot|SemrushBot|MJ12bot) [NC]
RewriteRule .* - [F,L]
```

### Nginx Alternative

For Nginx servers:

```nginx
# Block bad bots via nginx
if ($http_user_agent ~* (sqlmap|nikto|nuclei|wpscan|GPTBot|ClaudeBot|AhrefsBot)) {
    return 403;
}
```

---

## Log Files

The firewall creates logs in the configured log directory:

### firewall_log.txt
Human-readable log format:
```
[2024-01-15 10:30:45] BLOCKED | IP: 192.168.1.100 | Attack: SQL Injection | URI: /page?id=1' OR '1'='1
```

### firewall_log.json
Machine-readable JSON format:
```json
{
    "timestamp": "2024-01-15T10:30:45+00:00",
    "ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "uri": "/page?id=1' OR '1'='1",
    "user_agent": "Mozilla/5.0...",
    "blocked": true
}
```

---

## Security Headers

The firewall automatically sets these security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## Troubleshooting

### False Positives

If legitimate requests are being blocked:

1. Check the log files to identify the trigger
2. Add the IP to whitelist if trusted
3. Adjust the pattern matching in the respective validator class

### Performance

For high-traffic sites:

1. Consider using Redis/Memcached for rate limiting instead of file-based
2. Adjust `PHP_FIREWALL_RATE_LIMIT` based on your traffic patterns
3. Enable PHP OPcache for better performance

### PHP 8.x Compatibility

This version is fully compatible with:
- PHP 7.4
- PHP 8.0
- PHP 8.1
- PHP 8.2
- PHP 8.3

---

## Changelog

### Version 2.0.0 (PHP 7.4+ / 8.x)

**New Features:**
- Object-Oriented Architecture
- Rate Limiting
- Brute Force Protection
- CSRF Token Protection
- Honeypot Fields
- File Upload Validation
- JSON/XML Bomb Protection
- Command Injection Protection
- Path Traversal Protection
- Header Injection Protection
- Proxy Detection
- CIDR IP Range Support
- JSON Log Format
- Security Headers

**Improvements:**
- Type declarations (PHP 7.4+)
- Null coalescing operators
- Modern array syntax
- Singleton pattern
- Better error handling
- Improved performance

**Removed:**
- `register_globals` handling (removed in PHP 5.4)
- Deprecated `ereg` functions
- Legacy PHP 5.x support

---

## License

This project is free to use for personal and commercial projects.

## Credits

Original concept: https://seditio.com.tr

Updated for PHP 7.x/8.x with advanced security features.
