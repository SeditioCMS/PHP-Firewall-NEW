<?php
/**
 * PHP Firewall Bot List
 * Updated for 2024-2025
 * 
 * Categories:
 * - Malicious crawlers and scrapers
 * - Content theft bots
 * - Vulnerability scanners
 * - SEO spam bots
 * - AI/LLM scrapers
 * - Download managers
 * - Email harvesters
 */

$ct_rules = array(
    // === CLASSIC MALICIOUS BOTS ===
    'nonymouse', 'addresses.com', 'ideography.co.uk', 'adsarobot', 'ah-ha', 'aktuelles', 
    'alexibot', 'almaden', 'amzn_assoc', 'anarchie', 'art-online', 'aspseek', 'assort', 
    'asterias', 'attach', 'atomz', 'atspider', 'autoemailspider', 'backweb', 'backdoorbot', 
    'bandit', 'batchftp', 'bdfetch', 'big.brother', 'black.hole', 'blackwidow', 'blowfish', 
    'bmclient', 'boston project', 'botalot', 'bravobrian', 'buddy', 'bullseye', 'bumblebee', 
    'builtbottough', 'bunnyslippers', 'capture', 'cegbfeieh', 'cherrypicker', 'cheesebot', 
    'chinaclaw', 'cicc', 'civa', 'clipping', 'collage', 'collector', 'copyrightcheck', 'cosmos', 
    'crescent', 'custo', 'cyberalert', 'deweb', 'diagem', 'digger', 'digimarc', 'diibot', 
    'directupdate', 'disco', 'dittospyder', 'download accelerator', 'download demon', 
    'download wonder', 'downloader', 'drip', 'dsurf', 'dts agent', 'dts.agent', 'easydl', 
    'ecatch', 'echo extense', 'efp@gmx.net', 'eirgrabber', 'elitesys', 'emailsiphon', 'emailwolf', 
    'envidiosos', 'erocrawler', 'esirover', 'express webpictures', 'extrac', 'eyenetie', 
    'fastlwspider', 'favorg', 'favorites sweeper', 'fezhead', 'filehound', 'filepack.superbr.org', 
    'flashget', 'flickbot', 'fluffy', 'frontpage', 'foobot', 'galaxyBot', 'generic', 'getbot', 
    'getleft', 'getright', 'getsmart', 'geturl', 'getweb', 'gigabaz', 'girafabot', 'go-ahead-got-it', 
    'go!zilla', 'gornker', 'grabber', 'grabnet', 'grafula', 'green research', 'harvest', 'havindex', 
    'hhjhj@yahoo', 'hloader', 'hmview', 'homepagesearch', 'htmlparser', 'hulud', 'http agent', 
    'httpconnect', 'httpdown', 'http generic', 'httplib', 'httrack', 'humanlinks', 'ia_archiver', 
    'iaea', 'ibm_planetwide', 'image stripper', 'image sucker', 'imagefetch', 'incywincy', 'indy', 
    'infonavirobot', 'informant', 'interget', 'internet explore', 'infospiders', 'internet ninja', 
    'internetlinkagent', 'interneteseer.com', 'ipiumbot', 'iria', 'irvine', 'jbh', 'jeeves', 'jennybot', 
    'jetcar', 'joc web spider', 'jpeg hunt', 'justview', 'kapere', 'kdd explorer', 'kenjin.spider', 
    'keyword.density', 'kwebget', 'lachesis', 'larbin', 'laurion(dot)com', 'leechftp', 'lexibot', 
    'lftp', 'libweb', 'links aromatized', 'linkscan', 'link*sleuth', 'linkwalker', 'libwww', 
    'lightningdownload', 'likse', 'lwp', 'mac finder', 'mag-net', 'magnet', 'marcopolo', 'mass', 
    'mata.hari', 'mcspider', 'memoweb', 'microsoft url control', 'microsoft.url', 'midown', 'miixpc', 
    'minibot', 'mirror', 'missigua', 'mister.pix', 'mmmtocrawl', 'moget', 'mozilla/2', 
    'mozilla/3.mozilla/2.01', 'mozilla.*newt', 'multithreaddb', 'munky', 'msproxy', 'nationaldirectory', 
    'naverrobot', 'navroad', 'nearsite', 'netants', 'netcarta', 'netcraft', 'netfactual', 'netmechanic', 
    'netprospector', 'netresearchserver', 'netspider', 'net vampire', 'newt', 'netzip', 'nicerspro', 
    'npbot', 'octopus', 'offline.explorer', 'offline explorer', 'offline navigator', 'opaL', 
    'openfind', 'opentextsitecrawler', 'orangebot', 'packrat', 'papa foto', 'pagegrabber', 'pavuk', 
    'pbwf', 'pcbrowser', 'personapilot', 'pingalink', 'pockey', 'program shareware', 'propowerbot/2.14', 
    'prowebwalker', 'proxy', 'psbot', 'psurf', 'puf', 'pushsite', 'pump', 'qrva', 'quepasacreep', 
    'queryn.metasearch', 'realdownload', 'reaper', 'recorder', 'reget', 'replacer', 'repomonkey', 
    'rma', 'robozilla', 'rover', 'rpt-httpclient', 'rsync', 'rush=', 'searchexpress', 'searchhippo', 
    'searchterms.it', 'second street research', 'seeker', 'shai', 'sitecheck', 'sitemapper', 
    'sitesnagger', 'slysearch', 'smartdownload', 'snagger', 'spacebison', 'spankbot', 'spanner', 
    'spegla', 'spiderbot', 'spiderengine', 'sqworm', 'ssearcher100', 'star downloader', 'stripper', 
    'sucker', 'superbot', 'surfwalker', 'superhttp', 'surfbot', 'surveybot', 'suzuran', 'sweeper', 
    'szukacz/1.4', 'tarspider', 'takeout', 'teleport', 'telesoft', 'templeton', 'the.intraformant', 
    'thenomad', 'tighttwatbot', 'titan', 'tocrawl/urldispatcher', 'toolpak', 'traffixer', 'true_robot', 
    'turingos', 'turnitinbot', 'tv33_mercator', 'uiowacrawler', 'urldispatcherlll', 'url_spider_pro', 
    'urly.warning', 'utilmind', 'vacuum', 'vagabondo', 'vayala', 'vci', 'visualcoders', 'visibilitygap', 
    'vobsub', 'voideye', 'vspider', 'w3mir', 'webauto', 'webbandit', 'web.by.mail', 'webcapture', 
    'webcatcher', 'webclipping', 'webcollage', 'webcopier', 'webcopy', 'webcraft@bea', 'web data extractor', 
    'webdav', 'webdevil', 'webdownloader', 'webdup', 'webenhancer', 'webfetch', 'webgo', 'webhook', 
    'web.image.collector', 'web image collector', 'webinator', 'webleacher', 'webmasters', 
    'webmasterworldforumbot', 'webminer', 'webmirror', 'webmole', 'webreaper', 'websauger', 'websaver', 
    'website.quester', 'website quester', 'websnake', 'websucker', 'web sucker', 'webster', 'webreaper', 
    'webstripper', 'webvac', 'webwalk', 'webweasel', 'webzip', 'wget', 'widow', 'wisebot', 'whizbang', 
    'whostalking', 'wonder', 'wumpus', 'wweb', 'www-collector-e', 'wwwoffle', 'wysigot', 'xaldon', 'xenu', 
    'xget', 'x-tractor', 'zeus',

    // === VULNERABILITY SCANNERS & SECURITY TOOLS ===
    'sqlmap', 'nikto', 'nmap', 'nessus', 'openvas', 'acunetix', 'netsparker', 'burpsuite', 
    'burp scanner', 'owasp', 'zap', 'arachni', 'vega', 'w3af', 'skipfish', 'wapiti', 'whatweb',
    'nuclei', 'jaeles', 'xray', 'goby', 'afrog', 'vulmap', 'pocsuite', 'xsstrike', 'dalfox',
    'commix', 'tplmap', 'joomscan', 'wpscan', 'droopescan', 'cmsmap', 'dirsearch', 'dirb',
    'gobuster', 'ffuf', 'feroxbuster', 'rustbuster', 'dirbuster', 'wfuzz', 'subfinder',
    'amass', 'subfinder', 'assetfinder', 'findomain', 'massdns', 'dnsrecon', 'fierce',
    'subjack', 'subzy', 'nuclei-templates', 'httpx', 'katana', 'gau', 'waybackurls',
    'arjun', 'paramspider', 'x8', 'kiterunner', 'jaeles-signatures',

    // === MODERN SCRAPERS & CRAWLERS ===
    'scrapy', 'python-requests', 'python-urllib', 'aiohttp', 'httpx-client', 'go-http-client',
    'java/', 'okhttp', 'axios/', 'node-fetch', 'got/', 'superagent', 'request/', 
    'mechanize', 'beautifulsoup', 'selenium', 'puppeteer', 'playwright', 'phantomjs',
    'headlesschrome', 'chromeheadless', 'headless', 'splash', 'crawlergo', 'rad',
    'colly', 'ferret', 'crawlee', 'apify', 'scrapingbee', 'scrapingant', 'brightdata',
    'oxylabs', 'smartproxy', 'zyte', 'scraperapi', 'webscrapingapi', 'zenrows',
    'scrapestack', 'scrapeowl', 'scrapingdog', 'proxycrawl', 'crawlbase',

    // === AI/LLM DATA SCRAPERS (2023-2025) ===
    'gptbot', 'chatgpt-user', 'oai-searchbot', 'anthropic-ai', 'claude-web', 'claudebot',
    'cohere-ai', 'cohere-crawler', 'ai2bot', 'ai2bot-dolma', 'ccbot', 'common crawl',
    'diffbot', 'omgili', 'omgilibot', 'bytespider', 'bytedance', 'petalbot', 'amazonbot',
    'yandexbot', 'baiduspider', 'sogou', 'exabot', 'gigabot', 'dotbot', 'ahrefsbot',
    'semrushbot', 'mj12bot', 'blexbot', 'seznambot', 'yandexmobilebot', 'applebot-extended',
    'meta-externalagent', 'meta-externalfetcher', 'facebookexternalhit', 'facebookbot',
    'facebot', 'ia_archiver-web.archive.org', 'archive.org_bot', 'internetarchivebot',
    'perplexitybot', 'youbot', 'youcom', 'neeva', 'neevabot', 'kagibot', 'phind',
    'writesonic', 'jasper', 'copy.ai', 'rytr', 'shortly', 'peppertype', 'scalenut',
    'contentbot', 'kafkai', 'articleforge', 'wordai', 'spinrewriter', 'quillbot',
    'grammarly', 'languagetool', 'deepl', 'google-extended', 'googleother',
    'gemini-crawler', 'bardbot', 'palm-crawler', 'vertex-crawler',

    // === SEO & MARKETING BOTS ===
    'seokicks', 'seostar', 'seoscanners', 'seoprofiler', 'seomoz', 'seositecheckup',
    'serpstat', 'sistrix', 'spyfu', 'majestic', 'linkresearchtools', 'cognitiveseo',
    'monitorbacklinks', 'linkody', 'openlinkprofiler', 'linkminer', 'backlinkwatch',
    'ranksignals', 'similarweb', 'builtwith', 'wappalyzer', 'whatcms', 'cms detector',
    'domain re-animator', 'domaincrawler', 'domaintools', 'domainreanimator',
    'dnsdumpster', 'securitytrails', 'shodan', 'censys', 'zoomeye', 'fofa', 'hunter.io',
    'emailhunter', 'snov.io', 'voilanorbert', 'findthatlead', 'lusha', 'apollo.io',
    'clearbit', 'zoominfo', 'leadiq', 'seamless.ai', 'uplead', 'rocketreach',

    // === DOWNLOAD MANAGERS & ACCELERATORS ===
    'idm', 'internet download manager', 'freedownloadmanager', 'jdownloader', 'uget',
    'eagleget', 'xtreme download', 'orbit downloader', 'dap', 'mass downloader',
    'gigaget', 'flashgot', 'downloadthemall', 'aria2', 'axel', 'curl/', 'libcurl',
    'wget/', 'powershell', 'winhttp', 'weblient', 'wininet', 'urlgrabber',

    // === SPAM & COMMENT BOTS ===
    'xrumer', 'hrefer', 'gscraper', 'scrapebox', 'senuke', 'bookmarkingdemon',
    'socialmonkee', 'linkvana', 'buildmyrank', 'articlesubmitter', 'spinnerchief',
    'the best spinner', 'kontent machine', 'money robot', 'rankerx', 'gsabot',
    'gsa search engine ranker', 'ultimate demon', 'link emperor', 'linkbuildr',
    'seojet', 'authority builders', 'fatjoe', 'hoth', 'outreachmama',

    // === HEADLESS BROWSERS & AUTOMATION ===
    'phantomjs', 'slimerjs', 'casperjs', 'nightmare', 'zombie.js', 'jsdom',
    'cheerio', 'electron', 'nwjs', 'cefsharp', 'awesomium', 'webview',
    'chromium-headless', 'firefox-headless', 'webkit-headless', 'webdriver',
    'chromedriver', 'geckodriver', 'safaridriver', 'edgedriver', 'iedriver',
    'appium', 'winium', 'winappdriver', 'uiautomator', 'espresso', 'xcuitest',
    'detox', 'maestro', 'cypress', 'testcafe', 'protractor', 'nightwatch',
    'webdriverio', 'taiko', 'gauge', 'serenity', 'karate', 'rest-assured',

    // === PROXY & VPN IDENTIFIERS ===
    'luminati', 'brightdata-proxy', 'oxylabs-proxy', 'smartproxy-residential',
    'geosurf', 'netnut', 'iproyal', 'soax', 'proxy-seller', 'proxy6', 'proxy-cheap',
    'highproxies', 'buyproxies', 'stormproxies', 'blazingseollc', 'microleaves',
    'packetstream', 'ipburger', 'shifter', 'webshare', 'proxyempire',

    // === SOCIAL MEDIA BOTS ===
    'twitterbot', 'tweetmemebot', 'socialoomph', 'hootsuite', 'buffer', 'sproutsocial',
    'socialbee', 'later', 'planoly', 'tailwind', 'crowdfire', 'sendible', 'agorapulse',
    'socialpilot', 'eclincher', 'postplanner', 'meetedgar', 'recurpost', 'publer',
    'missinglettr', 'socialchamp', 'contentstudio', 'zoho social', 'hubspot social',

    // === KNOWN BAD PATTERNS ===
    'binlar', 'casper', 'checkprivacy', 'clshttp', 'cmsworldmap', 'comodo', 'diavol',
    'dotnetdotcom', 'feedfinder', 'flicky', 'g00g1e', 'harriscrawler', 'heritrix',
    'kmccrew', 'loadtimebot', 'lwp-trivial', 'massa', 'miner', 'morfeus', 'movabletype',
    'mshot', 'pcore-http', 'plagiarism', 'planetwork', 'pycurl', 'python', 'research',
    'scanner', 'skygrid', 'sucker', 'turnit', 'ua', 'unknown', 'user-agent', 
    'webalta', 'webshag', 'webtech', 'webvac', 'winhttprequest', 'yacybot',

    // === FAKE BROWSERS & SPOOFED USER AGENTS ===
    'fake', 'spoof', 'impersonate', 'disguise', 'cloak', 'anonym', 'stealth',
    'undetectable', 'antidetect', 'multilogin', 'gologin', 'dolphin', 'incogniton',
    'adspower', 'vmlogin', 'lalicat', 'bitbrowser', 'hubstudio', 'morelogin',
    'sessionbox', 'ghostbrowser', 'kameleo', 'linken sphere', 'octo browser',

    // === AGGRESSIVE CRAWLERS ===
    'aggressive', 'fast-crawler', 'turbo-crawler', 'speed-crawler', 'rapid-crawler',
    'megaindex', 'netpeakspider', 'screaming frog', 'deepcrawl', 'oncrawl', 'botify',
    'sitebulb', 'contentking', 'lumar', 'jetoctopus', 'ryte', 'searchmetrics',
    'conductor', 'brightedge', 'seomonitor', 'getstat', 'accuranker', 'serpwoo',
    'authoritylabs', 'proranker', 'ranktank', 'serprobot', 'serps', 'whatsmyserp',

    // === CLOUD FUNCTION & SERVERLESS IDENTIFIERS ===
    'aws-sdk', 'boto3', 'google-cloud', 'azure-sdk', 'vercel-functions', 
    'netlify-functions', 'cloudflare-workers', 'lambda', 'cloud-function',
    'firebase-functions', 'deno-deploy', 'fly.io', 'railway', 'render',

    // === ADDITIONAL 2024-2025 BOTS ===
    'claudebot', 'claude-web', 'anthropic', 'bingpreview', 'linkedinbot', 
    'slackbot', 'discordbot', 'telegrambot', 'whatsapp', 'signal-preview',
    'snapchat', 'pinterestbot', 'embedly', 'quora link preview', 'outbrain',
    'taboola', 'criteo', 'adroll', 'retargeter', 'perfectaudience',
    'tiktokbot', 'instagram-preview', 'threads-preview', 'mastodon',
    'bluesky', 'nostr', 'lemmy', 'kbin', 'misskey', 'pleroma', 'pixelfed',
    
    // === IOT & EMBEDDED DEVICE SCANNERS ===
    'iot-scanner', 'shodan-scanner', 'censys-scanner', 'masscan', 'zmap',
    'zgrab', 'zdns', 'lzr', 'ztee', 'ipscan', 'angry ip scanner', 'advanced ip scanner',
    'nmap scripting engine', 'nse', 'metasploit', 'exploit-db', 'searchsploit',

    // === CREDENTIAL STUFFING & BRUTE FORCE ===
    'hydra', 'medusa', 'patator', 'crowbar', 'thc-hydra', 'brutespray',
    'crackmapexec', 'kerbrute', 'spray', 'ruler', 'mailsniper', 'gosecretsdump',
    'impacket', 'bloodhound', 'sharphound', 'adpeas', 'powerview', 'mimikatz',

    // === EMPTY & SUSPICIOUS PATTERNS ===
    '-', '--', '---', '..', '...', 'null', 'undefined', 'none', 'n/a', 'na',
    'test', 'testing', 'debug', 'dev', 'staging', 'localhost', '127.0.0.1',
    'example', 'sample', 'demo', 'dummy', 'fake', 'mock', 'stub', 'placeholder'
);

// Exact match rules for bots that need precise matching
$ct_exact_rules = array(
    'curl', 'wget', 'python', 'java', 'perl', 'ruby', 'php', 'go-http-client',
    'http', 'bot', 'crawler', 'spider', 'scraper', 'fetch', 'scan', 'check',
    'monitor', 'probe', 'index', 'archive', 'preview', 'link', 'url'
);

// Whitelist for legitimate bots (optional - can be used to allow specific bots)
$ct_whitelist = array(
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'yandexbot', 'baiduspider',
    'facebot', 'facebookexternalhit', 'twitterbot', 'linkedinbot', 'pinterest',
    'applebot', 'telegrambot', 'whatsapp', 'discordbot', 'slackbot',
    // Add your own trusted bots here
);

/**
 * Check if user agent matches any bot pattern
 * 
 * @param string $user_agent The user agent string to check
 * @param bool $use_whitelist Whether to check whitelist first
 * @return bool|string False if no match, or the matched pattern
 */
function check_bot_user_agent(string $user_agent, bool $use_whitelist = false): bool|string {
    global $ct_rules, $ct_exact_rules, $ct_whitelist;
    
    $user_agent_lower = strtolower($user_agent);
    
    // Check whitelist first if enabled
    if ($use_whitelist) {
        foreach ($ct_whitelist as $allowed_bot) {
            if (stripos($user_agent_lower, $allowed_bot) !== false) {
                return false; // Allowed bot, don't block
            }
        }
    }
    
    // Check main rules
    foreach ($ct_rules as $rule) {
        if (stripos($user_agent_lower, $rule) !== false) {
            return $rule;
        }
    }
    
    // Check exact match rules (word boundaries)
    foreach ($ct_exact_rules as $rule) {
        if (preg_match('/\b' . preg_quote($rule, '/') . '\b/i', $user_agent_lower)) {
            return $rule;
        }
    }
    
    return false;
}

/**
 * Get statistics about the bot list
 * 
 * @return array Statistics array
 */
function get_bot_list_stats(): array {
    global $ct_rules, $ct_exact_rules, $ct_whitelist;
    
    return [
        'total_rules' => count($ct_rules),
        'exact_rules' => count($ct_exact_rules),
        'whitelist_count' => count($ct_whitelist),
        'last_updated' => '2025-02-05',
        'version' => '2.0.0'
    ];
}

?>
