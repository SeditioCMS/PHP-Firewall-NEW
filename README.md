# PHP-Firewall-Script Php 5.x - 7.x
PHP Firewall is a small free PHP script, but secure all websites writen in PHP.

PHP Firewall required PHP 5.x
PHP Firewall doesn't use any database, but flatfile system.
It's very small, very simple, really easy to install and fastest.
PHP Firewall have is own logs system and email alert.
No .htaccess file required for betters performances.

1. Security listing
2. XSS protection
3. UNION SQL Injection protection
4. Bads bots protection
5. Bads requests methods protection
6. Small DOS protection
7. Inclusion files protection
8. Santy and others worms protection
9. Server Protection
10. URL Query protection
11. Cookies sanitize
12. Post vars sanitize
13. Get vars sanitize
14. IPs range reserved denied
15. IPs range spam denied
16. IPs range protected
17. PHP globals desctruction

https://dijitalsite.com.tr

We will add the code to the header section of your site.

define('PHP_FIREWALL_REQUEST_URI', filter_var($_SERVER['REQUEST_URI'], FILTER_SANITIZE_URL));
define('PHP_FIREWALL_ACTIVATION', true );
include_once('firewall/firewall.php');
