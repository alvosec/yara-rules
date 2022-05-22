rule php_suspicious
{
    meta:
        Author = "Alvosec Security"
        filetype = "PHP"

    strings:

        $ftype = { 3c 3f }

        $ = ".bash_history"
        $ = /AddType\s+application\/x-httpd-(php|cgi)/ nocase
        $ = /php_value\s*auto_prepend_file/ nocase
        $ = /SecFilterEngine\s+Off/ nocase  // disable modsec
        $ = /Add(Handler|Type|OutputFilter)\s+[^\s]+\s+\.htaccess/ nocase
        $ = ".mysql_history"
        $ = ".ssh/authorized_keys"
        $ = "/(.*)/e"  // preg_replace code execution
        $ = "/../../../"
        $ = "/etc/passwd"
        $ = "/etc/proftpd.conf"
        $ = "/etc/resolv.conf"
        $ = "/etc/shadow"
        $ = "/etc/syslog.conf"
        $ = "/proc/cpuinfo" fullword
        $ = "/var/log/lastlog"
        $ = "/windows/system32/"
        $ = "LOAD DATA LOCAL INFILE" nocase
        $ = "WScript.Shell"
        $ = "WinExec"
        $ = "b374k" fullword nocase
        $ = "backdoor" fullword nocase
        $ = /(c99|r57|fx29)shell/
        $ = "powershell.exe" fullword nocase
        $ = /defac(ed|er|ement|ing)/ fullword nocase
        $ = "evilc0ders" fullword nocase
        $ = "exploit" fullword nocase
        $ = "find . -type f" fullword
        $ = "hashcrack" nocase
        $ = "id_rsa" fullword
        $ = "ipconfig" fullword nocase
        $ = "kernel32.dll" fullword nocase
        $ = "kingdefacer" nocase
        $ = "Wireghoul" nocase fullword
        $ = "LD_PRELOAD" fullword
        $ = "libpcprofile"  // CVE-2010-3856 local root
        $ = "locus7s" nocase
        $ = "ls -la" fullword
        $ = "meterpreter" fullword
        $ = "nc -l" fullword
        $ = "netstat -an" fullword
        $ = "php://"
        $ = "ps -aux" fullword
        $ = "rootkit" fullword nocase
        $ = "slowloris" fullword nocase
        $ = "suhosin" fullword
        $ = "sun-tzu" fullword nocase // Because quotes from the Art of War is mandatory for any cool webshell.
        $ = /trojan (payload)?/
        $ = "uname -a" fullword
        $ = "visbot" nocase fullword
        $ = "warez" fullword nocase
        $ = "whoami" fullword
        $ = /(r[e3]v[e3]rs[e3]|w[3e]b|cmd)\s*sh[e3]ll/ nocase
        $ = /-perm -0[24]000/ // find setuid files
        $ = /\/bin\/(ba)?sh/ fullword
        $ = /(safe_mode|open_basedir) bypass/ nocase
        $ = /xp_(execresultset|regenumkeys|cmdshell|filelist)/

    condition:
       $ftype at 0 and (3 of them)
}
