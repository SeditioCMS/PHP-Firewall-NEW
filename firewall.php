<?php
/** IP Protected */
$IP_ALLOW = array();

/** configuration define */
define('PHP_FIREWALL_LANGUAGE', 'turkish' );
define('PHP_FIREWALL_ADMIN_MAIL', '' );
define('PHP_FIREWALL_PUSH_MAIL', false );
define('PHP_FIREWALL_LOG_FILE', 'logs' );
define('PHP_FIREWALL_PROTECTION_UNSET_GLOBALS', true );
define('PHP_FIREWALL_PROTECTION_RANGE_IP_DENY', false );
define('PHP_FIREWALL_PROTECTION_RANGE_IP_SPAM', false );
define('PHP_FIREWALL_PROTECTION_URL', true );
define('PHP_FIREWALL_PROTECTION_REQUEST_SERVER', true );
define('PHP_FIREWALL_PROTECTION_SANTY', true );
define('PHP_FIREWALL_PROTECTION_BOTS', true );
define('PHP_FIREWALL_PROTECTION_REQUEST_METHOD', true );
define('PHP_FIREWALL_PROTECTION_DOS', true );
define('PHP_FIREWALL_PROTECTION_UNION_SQL', true );
define('PHP_FIREWALL_PROTECTION_CLICK_ATTACK', true );
define('PHP_FIREWALL_PROTECTION_XSS_ATTACK', true );
define('PHP_FIREWALL_PROTECTION_COOKIES', false );
define('PHP_FIREWALL_PROTECTION_POST', false );
define('PHP_FIREWALL_PROTECTION_GET', false );
define('PHP_FIREWALL_PROTECTION_SERVER_OVH', true );
define('PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI', true );
define('PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX', true );
define('PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE', true );
define('PHP_FIREWALL_PROTECTION_SERVER_OVH_BY_IP', true );
define('PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI_BY_IP', true );
define('PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX_BY_IP', true );
define('PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE_BY_IP', true );
/** end configuration */

/** IPS PROTECTED */
if ( @count( $IP_ALLOW ) > 0 ) {
	if ( in_array( $_SERVER['REMOTE_ADDR'], $IP_ALLOW ) ) return;
}
/** END IPS PROTECTED */


/** LANGUAGE */
if ( PHP_FIREWALL_LANGUAGE === 'turkish' ) {
	define('_PHPF_PROTECTION_DEDIBOX', 'DEDIBOX sunucularına karşı koruma aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_DEDIBOX_IP', 'DEDIBOX sunucularına karşı koruma aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_DIGICUBE', 'DIGICUBE sunucularına karşı koruma aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_DIGICUBE_IP', 'DIGICUBE sunucularına karşı koruma aktif, bu IPe yetki verilmedi !');
	define('_PHPF_PROTECTION_KIMSUFI', 'KIMSUFI sunucularına karşı koruma aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_OVH', 'OVH sunucularına karşı koruma aktif, bu IP aralığı yetkilendirilmemiş !');
	define('_PHPF_PROTECTION_BOTS', 'Bot saldırısı tespit edildi! yapma...');
	define('_PHPF_PROTECTION_CLICK', 'Tıklama saldırısı algılandı! yapma.....');
	define('_PHPF_PROTECTION_DOS', 'Geçersiz kullanıcı aracısı! Yapma...');
	define('_PHPF_PROTECTION_OTHER_SERVER', 'Başka bir sunucudan paylaşım yapmak yasaktır !');
	define('_PHPF_PROTECTION_REQUEST', 'Sorgu yöntemine izin verilmiyor! Yapma...');
	define('_PHPF_PROTECTION_SANTY', 'Santy tespit edildi! Yapma...');
	define('_PHPF_PROTECTION_SPAM', 'SPAM koruması aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_SPAM_IP', 'SPAM IP koruması aktif, bu IP aralığına izin verilmiyor !');
	define('_PHPF_PROTECTION_UNION', 'UNION saldırısı tespit edildi! yapma......');
	define('_PHPF_PROTECTION_URL', 'URL koruması etkin, dizeye izin verilmiyor !');
	define('_PHPF_PROTECTION_XSS', 'XSS saldırısı algılandı! yapma...');
} else {
	define('_PHPF_PROTECTION_DEDIBOX', 'Protection DEDIBOX Server active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_DEDIBOX_IP', 'Protection DEDIBOX Server active, this IP is not allowed !');
	define('_PHPF_PROTECTION_DIGICUBE', 'Protection DIGICUBE Server active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_DIGICUBE_IP', 'Protection DIGICUBE Server active, this IP is not allowed !');
	define('_PHPF_PROTECTION_KIMSUFI', 'Protection KIMSUFI Server active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_OVH', 'Protection OVH Server active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_BOTS', 'Bot attack detected ! stop it ...');
	define('_PHPF_PROTECTION_CLICK', 'Click attack detected ! stop it .....');
	define('_PHPF_PROTECTION_DOS', 'Invalid user agent ! Stop it ...');
	define('_PHPF_PROTECTION_OTHER_SERVER', 'Posting from another server not allowed !');
	define('_PHPF_PROTECTION_REQUEST', 'Invalid request method check ! Stop it ...');
	define('_PHPF_PROTECTION_SANTY', 'Attack Santy detected ! Stop it ...');
	define('_PHPF_PROTECTION_SPAM', 'Protection SPAM IPs active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_SPAM_IP', 'Protection died IPs active, this IP range is not allowed !');
	define('_PHPF_PROTECTION_UNION', 'Union attack detected ! stop it ......');
	define('_PHPF_PROTECTION_URL', 'Protection url active, string not allowed !');
	define('_PHPF_PROTECTION_XSS', 'XSS attack detected ! stop it ...');
}
/** END LANGUAGE*/


if ( PHP_FIREWALL_ACTIVATION === true ) {

function PHP_FIREWALL_unset_globals() {
    // Eski PHP sürümleri için register_globals kontrolü
    if (ini_get('register_globals')) {
        $allow = array(
            '_ENV' => 1,
            '_GET' => 1,
            '_POST' => 1,
            '_COOKIE' => 1,
            '_FILES' => 1,
            '_SERVER' => 1,
            '_REQUEST' => 1,
            'GLOBALS' => 1
        );

        // Küresel değişkenleri kontrol et ve izin verilmeyenleri temizle
        foreach ($GLOBALS as $key => $value) {
            // Sadece izin verilen anahtarlar bırakılır
            if (!isset($allow[$key])) {
                unset($GLOBALS[$key]);
            }
        }
    }
}

if ( PHP_FIREWALL_PROTECTION_UNSET_GLOBALS === true ) {
    PHP_FIREWALL_unset_globals();
}

	/** fonctions de base */
function PHP_FIREWALL_get_env($st_var) {
    // $_SERVER kullanımı daha güvenli ve yaygın
    if (isset($_SERVER[$st_var])) {
        return strip_tags($_SERVER[$st_var]);
    } 
    // $_ENV kümesi
    elseif (isset($_ENV[$st_var])) {
        return strip_tags($_ENV[$st_var]);
    } 
    // getenv() kullanımı (genel ortam değişkeni)
    elseif (getenv($st_var)) {
        return strip_tags(getenv($st_var));
    } 
    // Apache ortam değişkeni (Apache kullanıyorsanız)
    elseif (function_exists('apache_getenv') && apache_getenv($st_var, true)) {
        return strip_tags(apache_getenv($st_var, true));
    }
    
    // Değer bulunamazsa boş döndürülür
    return '';
}

function PHP_FIREWALL_get_referer() {
    // HTTP_REFERER var mı kontrol et
    $referer = PHP_FIREWALL_get_env('HTTP_REFERER');
    
    // Eğer referer varsa ve geçerliyse, temizleyerek geri döndür
    if ($referer) {
        return strip_tags($referer);
    }
    
    // Eğer referer yoksa, 'no referer' döndür
    return 'no referer';
}

	function PHP_FIREWALL_get_ip() {
    // HTTP_X_FORWARDED_FOR başlığını kontrol et
    $x_forwarded_for = PHP_FIREWALL_get_env('HTTP_X_FORWARDED_FOR');
    if ($x_forwarded_for) {
        // Eğer birden fazla IP adresi varsa, ilkini al
        $ips = explode(',', $x_forwarded_for);
        return trim($ips[0]);
    }
    // HTTP_CLIENT_IP başlığını kontrol et
    elseif (PHP_FIREWALL_get_env('HTTP_CLIENT_IP')) {
        return PHP_FIREWALL_get_env('HTTP_CLIENT_IP');
    } 
    // REMOTE_ADDR başlığını kontrol et
    else {
        return PHP_FIREWALL_get_env('REMOTE_ADDR');
    }
}

	
	function PHP_FIREWALL_get_user_agent() {
    // HTTP_USER_AGENT başlığını kontrol et
    $user_agent = PHP_FIREWALL_get_env('HTTP_USER_AGENT');
    
    // Eğer başlık mevcutsa, temizleyip döndür
    if ($user_agent) {
        return strip_tags($user_agent);
    }
    
    // Eğer başlık yoksa, 'none' döndür
    return 'none';
}

	function PHP_FIREWALL_get_query_string() {
    // QUERY_STRING'i al
    $query_string = PHP_FIREWALL_get_env('QUERY_STRING');
    
    // Eğer sorgu dizisi varsa, tab karakterlerini boşlukla değiştirip temizle
    if ($query_string) {
        // Tab karakterini (%09) boşlukla (%20) değiştir
        $query_string = str_replace('%09', '%20', $query_string);
        
        // Temizlik (güvenlik için HTML etiketlerini temizle)
        return strip_tags($query_string);
    }
    
    // Eğer sorgu dizisi yoksa, boş döndür
    return '';
}

	
	
	function PHP_FIREWALL_get_request_method() {
    // REQUEST_METHOD başlığını al
    $request_method = PHP_FIREWALL_get_env('REQUEST_METHOD');
    
    // Eğer başlık mevcutsa, olduğu gibi döndür
    if ($request_method) {
        return $request_method;  // Büyük-küçük harfe duyarlı şekilde döndürülür
    }
    
    // Eğer başlık yoksa, 'none' döndür
    return 'none';
}

	function PHP_FIREWALL_gethostbyaddr() {
    // Sunucu türlerine göre koruma bayraklarını kontrol et
    if ( PHP_FIREWALL_PROTECTION_SERVER_OVH === true || 
         PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI === true || 
         PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX === true || 
         PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE === true ) {
        
        // Eğer gethostbyaddr değeri oturumda saklanmamışsa, sorguyu çalıştır
        if (empty($_SESSION['PHP_FIREWALL_gethostbyaddr'])) {
            // gethostbyaddr sonucu al, hata mesajlarını gizlemek için @ kullanılabilir
            $hostname = @gethostbyaddr(PHP_FIREWALL_get_ip());
            
            // Eğer hostname alındıysa, sonucu sakla
            if ($hostname !== false) {
                $_SESSION['PHP_FIREWALL_gethostbyaddr'] = $hostname;
            } else {
                // DNS sorgusu başarısız olursa, geçici bir değer döndür
                $_SESSION['PHP_FIREWALL_gethostbyaddr'] = 'unknown';
            }
        }

        // Önceden saklanan sonucu döndür
        return strip_tags($_SESSION['PHP_FIREWALL_gethostbyaddr']);
    }
    
    // Eğer sunucu koruma bayrağı sağlanmazsa, fonksiyon null döner
    return null;
}


	/** bases define */
define('PHP_FIREWALL_GET_QUERY_STRING', strtolower(PHP_FIREWALL_get_query_string()));
define('PHP_FIREWALL_USER_AGENT', PHP_FIREWALL_get_user_agent());
define('PHP_FIREWALL_GET_IP', PHP_FIREWALL_get_ip());
define('PHP_FIREWALL_GET_HOST', PHP_FIREWALL_gethostbyaddr());
define('PHP_FIREWALL_GET_REFERER', PHP_FIREWALL_get_referer());
define('PHP_FIREWALL_GET_REQUEST_METHOD', PHP_FIREWALL_get_request_method());
define('PHP_FIREWALL_REGEX_UNION','#\w?\s?union\s\w*?\s?(select|all|distinct|insert|update|drop|delete)#is');

	
	FUNCTION PHP_FIREWALL_push_email( $subject, $msg ) {
		$headers = "From: PHP Firewall: ".PHP_FIREWALL_ADMIN_MAIL." <".PHP_FIREWALL_ADMIN_MAIL.">\r\n"
			."Reply-To: ".PHP_FIREWALL_ADMIN_MAIL."\r\n"
			."Priority: urgent\r\n"
			."Importance: High\r\n"
			."Precedence: special-delivery\r\n"
			."Organization: PHP Firewall\r\n"
			."MIME-Version: 1.0\r\n"
			."Content-Type: text/plain\r\n"
			."Content-Transfer-Encoding: 8bit\r\n"
			."X-Priority: 1\r\n"
			."X-MSMail-Priority: High\r\n"
			."X-Mailer: PHP/" . phpversion() ."\r\n"
			."X-PHPFirewall: 1.0 by PHPFirewall\r\n"
			."Date:" . date("D, d M Y H:s:i") . " +0100\n";
		if ( PHP_FIREWALL_ADMIN_MAIL != '' )
			@mail( PHP_FIREWALL_ADMIN_MAIL, $subject, $msg, $headers );
	}


function PHP_FIREWALL_LOGS($type) {
    // Log dosyasının bulunduğu dizini kontrol et
    $logFilePath = dirname(__FILE__) . '/' . PHP_FIREWALL_LOG_FILE . '.txt';
    
    // Dosyayı aç (append mode)
    $f = fopen($logFilePath, 'a');
    
    // Eğer dosya açılamazsa, hata mesajı yazdır
    if (!$f) {
        error_log("Error: Unable to open log file: " . $logFilePath);
        return; // Dosyaya yazmadan çık
    }
    
    // Log mesajı oluştur
    $msg = date('j-m-Y H:i:s') . " | $type | IP: " . PHP_FIREWALL_GET_IP . " ] | DNS: " . gethostbyaddr(PHP_FIREWALL_GET_IP) . " | Agent: " . PHP_FIREWALL_USER_AGENT . " | URL: " . PHP_FIREWALL_REQUEST_URI . " | Referer: " . PHP_FIREWALL_GET_REFERER . "\n\n";
    
    // Log dosyasına yaz
    fputs($f, $msg);
    fclose($f);

    // E-posta göndermek için bayrak kontrolü
    if (PHP_FIREWALL_PUSH_MAIL === true) {
        // E-posta gönder
        $subject = 'Alert PHP Firewall ' . strip_tags($_SERVER['SERVER_NAME']);
        $body = "PHP Firewall logs of " . strip_tags($_SERVER['SERVER_NAME']) . "\n" . str_replace('|', "\n", $msg);
        
        // Hata kontrolü eklemek faydalı olabilir
        $emailStatus = PHP_FIREWALL_push_email($subject, $body);
        
        if ($emailStatus === false) {
            error_log("Error: Failed to send email alert for PHP Firewall logs.");
        }
    }
}


if (PHP_FIREWALL_PROTECTION_SERVER_OVH === true) {
    // 'ovh' kelimesini host içinde büyük/küçük harfe duyarsız şekilde kontrol et
    if (stristr(PHP_FIREWALL_GET_HOST, 'ovh')) {
        // Log kaydını oluştur
        PHP_FIREWALL_LOGS('OVH Server list');
        
        // OVH sunucu tespiti sonrası işlem sonlandırılır
        die(_PHPF_PROTECTION_OVH);
    }
}

if (PHP_FIREWALL_PROTECTION_SERVER_OVH_BY_IP === true) {
    // IP'yi parçalarına ayır
    $ip = explode('.', PHP_FIREWALL_GET_IP);

    // İki oktetli IP aralıklarını kontrol et
    $ovh_ips = array('87.98', '91.121', '94.23', '213.186', '213.251');
    if (in_array($ip[0] . '.' . $ip[1], $ovh_ips)) {
        // Log kaydını oluştur
        PHP_FIREWALL_LOGS('OVH Server IP');

        // İşlemi sonlandır
        die(_PHPF_PROTECTION_OVH);
    }
}




	if ( PHP_FIREWALL_PROTECTION_SERVER_KIMSUFI === true ) {
		if ( stristr( PHP_FIREWALL_GET_HOST ,'kimsufi') ) {
			PHP_FIREWALL_LOGS( 'KIMSUFI Server list' );
			die( _PHPF_PROTECTION_KIMSUFI );
		}
	}

// DEDIBOX Server Kontrolü
if (PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX === true) {
    if (stristr(PHP_FIREWALL_GET_HOST, 'dedibox')) {
        PHP_FIREWALL_LOGS('DEDIBOX Server list');
        die(_PHPF_PROTECTION_DEDIBOX);
    }
}

// DEDIBOX IP Kontrolü
if (PHP_FIREWALL_PROTECTION_SERVER_DEDIBOX_BY_IP === true) {
    $ip = explode('.', PHP_FIREWALL_GET_IP);
    $dedibox_ips = ['88.191'];  // IP'leri diziye alıyoruz
    if (in_array($ip[0] . '.' . $ip[1], $dedibox_ips)) {
        PHP_FIREWALL_LOGS('DEDIBOX Server IP');
        die(_PHPF_PROTECTION_DEDIBOX_IP);
    }
}

// DIGICUBE Server Kontrolü
if (PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE === true) {
    if (stristr(PHP_FIREWALL_GET_HOST, 'digicube')) {
        PHP_FIREWALL_LOGS('DIGICUBE Server list');
        die(_PHPF_PROTECTION_DIGICUBE);
    }
}

// DIGICUBE IP Kontrolü
if (PHP_FIREWALL_PROTECTION_SERVER_DIGICUBE_BY_IP === true) {
    $ip = explode('.', PHP_FIREWALL_GET_IP);
    $digicube_ips = ['95.130'];  // IP'leri diziye alıyoruz
    if (in_array($ip[0] . '.' . $ip[1], $digicube_ips)) {
        PHP_FIREWALL_LOGS('DIGICUBE Server IP');
        die(_PHPF_PROTECTION_DIGICUBE_IP);
    }
}


	// Spam IP Kontrolü
if (PHP_FIREWALL_PROTECTION_RANGE_IP_SPAM === true) {
    $spam_ips = array('24', '186', '189', '190', '200', '201', '202', '209', '212', '213', '217', '222');
    $range_ip = explode('.', PHP_FIREWALL_GET_IP);
    if (in_array($range_ip[0], $spam_ips)) {
        PHP_FIREWALL_LOGS('IPs Spam list');
        die(_PHPF_PROTECTION_SPAM);
    }
}

// Deny IP Kontrolü
if (PHP_FIREWALL_PROTECTION_RANGE_IP_DENY === true) {
    $deny_ips = array('0', '1', '2', '5', '10', '14', '23', '27', '31', '36', '37', '39', '42', '46', '49', '50', '100', '101', '102', '103', '104', '105', '106', '107', '114', '172', '176', '177', '179', '181', '185', '192', '223', '224');
    $range_ip = explode('.', PHP_FIREWALL_GET_IP);
    if (in_array($range_ip[0], $deny_ips)) {
        PHP_FIREWALL_LOGS('IPs reserved list');
        die(_PHPF_PROTECTION_SPAM_IP);
    }
}


if ( PHP_FIREWALL_PROTECTION_COOKIES === true ) {
    $ct_rules = Array(
        'applet', 'base', 'bgsound', 'blink', 'embed', 'expression', 'frame', 'javascript', 'layer', 'link', 'meta', 
        'object', 'onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 
        'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 
        'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 
        'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 
        'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 
        'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 
        'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 
        'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresizeend', 'onresizestart', 'onrowenter', 
        'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 
        'onsubmit', 'onunload', 'script', 'style', 'title', 'vbscript', 'xml'
    );

    foreach($_COOKIE as $cookie_name => $value) {
        $check = str_replace($ct_rules, '*', $value);
        if($value !== $check) {
            PHP_FIREWALL_LOGS('Cookie protect');
            unset($_COOKIE[$cookie_name]);  // Cookie'yi kaldır
            setcookie($cookie_name, '', time() - 3600, '/'); // Geçersizleştir ve tarayıcıda sil
        }
    }
}


	if ( PHP_FIREWALL_PROTECTION_COOKIES === true ) {
    $ct_rules = Array(
        'applet', 'base', 'bgsound', 'blink', 'embed', 'expression', 'frame', 'javascript', 'layer', 'link', 'meta', 
        'object', 'onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 
        'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 
        'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 
        'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 
        'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 
        'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 
        'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 
        'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresizeend', 'onresizestart', 'onrowenter', 
        'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 
        'onsubmit', 'onunload', 'script', 'style', 'title', 'vbscript', 'xml'
    );
    
    // Cookie koruması
    foreach ($_COOKIE as $cookie_name => $value) {
        $check = str_replace($ct_rules, '*', $value);
        if ($value !== $check) {
            PHP_FIREWALL_LOGS('Cookie protect');
            unset($_COOKIE[$cookie_name]); // Cookie'yi kaldır
            setcookie($cookie_name, '', time() - 3600, '/'); // Tarayıcıdan sil
        }
    }

    // POST verisi koruması
    if (PHP_FIREWALL_PROTECTION_POST === true) {
        foreach ($_POST as $key => $value) {
            $check = str_replace($ct_rules, '*', $value);
            if ($value !== $check) {
                PHP_FIREWALL_LOGS('POST protect');
                unset($_POST[$key]); // POST verisinden kaldır
            }
        }
    }

    // GET verisi koruması
    if (PHP_FIREWALL_PROTECTION_GET === true) {
        foreach ($_GET as $key => $value) {
            $check = str_replace($ct_rules, '*', $value);
            if ($value !== $check) {
                PHP_FIREWALL_LOGS('GET protect');
                unset($_GET[$key]); // GET verisinden kaldır
            }
        }
    }
}


	/** protection de l'url */
	
	if ( PHP_FIREWALL_PROTECTION_URL === true ) {
    $ct_rules = array(
        'absolute_path', 'ad_click', 'alert(', 'alert%20', ' and ', 'basepath', 'bash_history', '.bash_history', 'cgi-', 
        'chmod(', 'chmod%20', '%20chmod', 'chmod=', 'chown%20', 'chgrp%20', 'chown(', '/chown', 'chgrp(', 'chr(', 'chr=', 
        'chr%20', '%20chr', 'chunked', 'cookie=', 'cmd', 'cmd=', '%20cmd', 'cmd%20', '.conf', 'configdir', 'config.php', 
        'cp%20', '%20cp', 'cp(', 'diff%20', 'dat?', 'db_mysql.inc', 'document.location', 'document.cookie', 'drop%20', 
        'echr(', '%20echr', 'echr%20', 'echr=', '}else{', '.eml', 'esystem(', 'esystem%20', '.exe', 'exploit', 'file\://', 
        'fopen', 'fwrite', '~ftp', 'ftp:', 'ftp.exe', 'getenv', '%20getenv', 'getenv%20', 'getenv(', 'grep%20', '_global', 
        'global_', 'global[', 'http:', '_globals', 'globals_', 'globals[', 'grep(', 'g\+\+', 'halt%20', '.history', '?hl=', 
        '.htpasswd', 'http_', 'http-equiv', 'http/1.', 'http_php', 'http_user_agent', 'http_host', '&icq', 'if{', 'if%20{', 
        'img src', 'img%20src', '.inc.php', '.inc', 'insert%20into', 'ISO-8859-1', 'ISO-', 'javascript\://', '.jsp', '.js', 
        'kill%20', 'kill(', 'killall', '%20like', 'like%20', 'locate%20', 'locate(', 'lsof%20', 'mdir%20', '%20mdir', 'mdir(', 
        'mcd%20', 'motd%20', 'mrd%20', 'rm%20', '%20mcd', '%20mrd', 'mcd(', 'mrd(', 'mcd=', 'mod_gzip_status', 'modules/', 
        'mrd=', 'mv%20', 'nc.exe', 'new_password', 'nigga(', '%20nigga', 'nigga%20', '~nobody', 'org.apache', '+outfile+', 
        '%20outfile%20', '*/outfile/*', ' outfile ', 'outfile', 'password=', 'passwd%20', '%20passwd', 'passwd(', 'phpadmin', 
        'perl%20', '/perl', 'phpbb_root_path', '*/phpbb_root_path/*', 'p0hh', 'ping%20', '.pl', 'powerdown%20', 'rm(', '%20rm', 
        'rmdir%20', 'mv(', 'rmdir(', 'phpinfo()', '<?php', 'reboot%20', '/robot.txt' , '~root', 'root_path', 'rush=', '%20and%20', 
        '%20xorg%20', '%20rush', 'rush%20', 'secure_site, ok', 'select%20', 'select from', 'select%20from', '_server', 'server_', 
        'server[', 'server-info', 'server-status', 'servlet', 'sql=', '<script', '<script>', '</script','script>', '/script', 
        'switch{','switch%20{', '.system', 'system(', 'telnet%20', 'traceroute%20', '.txt', 'union%20', '%20union', 'union(', 
        'union=', 'vi(', 'vi%20', 'wget', 'wget%20', '%20wget', 'wget(', 'window.open', 'wwwacl', ' xor ', 'xp_enumdsn', 
        'xp_availablemedia', 'xp_filelist', 'xp_cmdshell', '$_request', '$_get', '$request', '$get',  '&aim', '/etc/password',
        '/etc/shadow', '/etc/groups', '/etc/gshadow', '/bin/ps', 'uname\x20-a', '/usr/bin/id', '/bin/echo', '/bin/kill', '/bin/', 
        '/chgrp', '/usr/bin', 'bin/python', 'bin/tclsh', 'bin/nasm', '/usr/x11r6/bin/xterm', '/bin/mail', '/etc/passwd', 
        '/home/ftp', '/home/www', '/servlet/con', '?>', '.txt'
    );
    
    // URL parametresindeki zararlı içerikleri kontrol et
    $query_string = PHP_FIREWALL_GET_QUERY_STRING;
    foreach ($ct_rules as $rule) {
        if (stripos($query_string, $rule) !== false) {
            PHP_FIREWALL_LOGS('URL protect');
            die(_PHPF_PROTECTION_URL); // URL'deki zararlı içerik nedeniyle işlem durduruluyor
        }
    }
}


	/** Posting from other servers in not allowed */
	if ( PHP_FIREWALL_PROTECTION_REQUEST_SERVER === true ) {
    if ( PHP_FIREWALL_GET_REQUEST_METHOD == 'POST' ) {
        // Eğer REFERER başlığı varsa
        if (isset($_SERVER['HTTP_REFERER'])) {
            // REFERER başlığında, isteğin geldiği sunucunun ana domaini (HTTP_HOST) yer alıyorsa
            if ( stripos( $_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST'] ) === false ) {
                PHP_FIREWALL_LOGS( 'Posting another server' );
                die( _PHPF_PROTECTION_OTHER_SERVER );
            }
        }
    }
}


	/** protection contre le vers santy */
	if ( PHP_FIREWALL_PROTECTION_SANTY === true ) {
    $ct_rules = array('rush','highlight=%','perl','chr(','pillar','visualcoder','sess_');
    
    // Küçük harfe dönüştürülmüş URI'de belirtilen karakter dizilerinin olup olmadığını kontrol et
    $check = str_replace($ct_rules, '*', strtolower(PHP_FIREWALL_REQUEST_URI));
    
    if( strtolower(PHP_FIREWALL_REQUEST_URI) != $check ) {
        // Log mesajına daha fazla ayrıntı ekleyin
        PHP_FIREWALL_LOGS( 'Santy attack detected. URI: ' . PHP_FIREWALL_REQUEST_URI );
        die( _PHPF_PROTECTION_SANTY );
    }
}


	/** protection bots */
	if ( PHP_FIREWALL_PROTECTION_BOTS === true ) {
    define('PHP_FIREWALL_BOT_FILE', 'firewall_bot_list.php'); // Bot listesi buradan dahil ediliyor
	include(PHP_FIREWALL_BOT_FILE); // Bot listesi dahil ediliyor
	$user_agent = strtolower(PHP_FIREWALL_USER_AGENT);
    foreach ($ct_rules as $rule) {
        if (stripos($user_agent, $rule) !== false) {
            PHP_FIREWALL_LOGS('Bots attack: ' . PHP_FIREWALL_USER_AGENT);
            die(_PHPF_PROTECTION_BOTS);
        }
    }
}


	/** Invalid request method check */
	if ( PHP_FIREWALL_PROTECTION_REQUEST_METHOD === true ) {
	$allowed_methods = array('get', 'head', 'post', 'put');
	if (!in_array(strtolower(PHP_FIREWALL_GET_REQUEST_METHOD), $allowed_methods)) {
		PHP_FIREWALL_LOGS('Invalid request');
		die(_PHPF_PROTECTION_REQUEST);
	}
}


	/** protection dos attaque */
	if ( PHP_FIREWALL_PROTECTION_DOS === true ) {
	if ( !defined('PHP_FIREWALL_USER_AGENT')  || PHP_FIREWALL_USER_AGENT == '-' ) {
		PHP_FIREWALL_LOGS( 'Dos attack' );
		die( _PHPF_PROTECTION_DOS );
	}
}


	/** protection union sql attaque */
	if ( PHP_FIREWALL_PROTECTION_UNION_SQL === true ) {
    $stop = 0;
    
    $ct_rules = array(
        '*/from/*', '*/insert/*', '+into+', '%20into%20', '*/into/*', 'into ', 'into',
        '*/limit/*', 'not123exists*', '*/radminsuper/*', '*/select/*', '+select+', '%20select%20', 'select ',
        '+union+', '%20union%20', '*/union/*', 'union', '*/update/*', '*/where/*'
    );

    $check = str_replace($ct_rules, '*', PHP_FIREWALL_GET_QUERY_STRING );
    
    // Belirlenen zararlı ifadelerle birebir eşleşme varsa
    if( PHP_FIREWALL_GET_QUERY_STRING != $check ) $stop++;

    // Regex ile UNION içeren saldırı denemeleri
    if (preg_match(PHP_FIREWALL_REGEX_UNION, PHP_FIREWALL_GET_QUERY_STRING)) $stop++;

    // Garip karakter dizileri varsa (örnek: base64 benzeri)
    if (preg_match('/([OdWo5NIbpuU4V2iJT0n]{5}) /', rawurldecode( PHP_FIREWALL_GET_QUERY_STRING ))) $stop++;

    // Query string içinde yıldız (*) varsa — obfuscation işareti olabilir
    if (strstr(rawurldecode( PHP_FIREWALL_GET_QUERY_STRING ) ,'*')) $stop++;

    if ( !empty( $stop ) ) {
        PHP_FIREWALL_LOGS( 'Union attack' );
        die( _PHPF_PROTECTION_UNION );
    }
}

	

	/** protection click attack */
	if ( PHP_FIREWALL_PROTECTION_CLICK_ATTACK === true ) {
	$ct_rules = array(
		'/*', // JS/CSS yorum başlangıcı
		'c2nyaxb0', // base64 "script"
		'script', // düz 'script' kelimesi
		'<script', // HTML script tag başlangıcı
		'javascript:', // href vb. içerikler için
	);

	// GET query string'i önce decode edelim ki kodlanmış içerikleri de yakalayalım
	$decoded_query = rawurldecode(PHP_FIREWALL_GET_QUERY_STRING);

	// Zararlı içerik varsa * ile değiştirerek karşılaştır
	$check = str_replace($ct_rules, '*', strtolower($decoded_query));

	if ( strtolower($decoded_query) != $check ) {
		PHP_FIREWALL_LOGS( 'Click attack' );
		die( _PHPF_PROTECTION_CLICK );
	}
}




	/** protection XSS attack */
	if ( PHP_FIREWALL_PROTECTION_XSS_ATTACK === true ) {
	$ct_rules = array(
		'http://', 'https://',
		'ftp:', 'ftps:', './', '../',
		'cmd=', '&cmd', 'exec', 'concat', 'select', 'union', 'insert', 'drop', 'update', 'delete', 'alter', 'rename', 'create', 'from', 'into', 'load_file', 'outfile', 'grant', 'revoke', 'set', 'declare', 'show', 'table', 'database',

		// Obfuscated versiyonlar
		'h%20ttp:', 'ht%20tp:', 'htt%20p:', 'http%20:', '.php?url='
		'h%20ttps:', 'ht%20tps:', 'htt%20ps:', 'http%20s:', 'https%20:',
		'f%20tp:', 'ft%20p:', 'ftp%20:', 'f%20tps:', 'ft%20ps:', 'ftp%20s:', 'ftps%20:',

		// JS injection içerikleri
		'<script', '%3Cscript', '%3C%73cript', // encoded script tag
		'onerror', 'onload', 'onclick', 'onmouseover', // event handler'lar
		'document.cookie', 'document.location',
		'javascript:', 'vbscript:', 'data:',

		// Base64 encoded bazı yaygın örnekler
		'c2NyaXB0', // base64 "script"
		'amF2YXNjcmlwdA==', // base64 "javascript"
	);

	// Query string'i decode edip küçük harfe çeviriyoruz
	$decoded_query = strtolower(rawurldecode(PHP_FIREWALL_GET_QUERY_STRING));

	$check = str_replace($ct_rules, '*', $decoded_query);

	if ( $decoded_query !== $check ) {
		PHP_FIREWALL_LOGS( 'XSS attack' );
		die( _PHPF_PROTECTION_XSS );
	}
}


}