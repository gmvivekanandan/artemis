rule write_msr
{
    meta:
    description = "Writing MSR"

    
    strings:
    /* 
        mov ecx, [ebp+??]
        mov eax, [ebp+??]
        mov edx, [ebp+??]
        wrmsr 
    */
    $wr1 = {8B 4D ?? 8B 55 ?? 8B 45 ?? 0F 30}
    $wr2 = {8B 4D ?? 8B 45 ?? 8B 55 ?? 0F 30}
    $wr3 = {8B 55 ?? 8B 4D ?? 8B 45 ?? 0F 30}
    $wr4 = {8B 55 ?? 8B 45 ?? 8B 4D ?? 0F 30}
    $wr5 = {8B 45 ?? 8B 55 ?? 8B 4D ?? 0F 30}
    $wr6 = {8B 45 ?? 8B 4D ?? 8B 55 ?? 0F 30}
    /* 
        mov ecx, imm32
        mov eax, imm32
        mov edx, imm32
        wrmsr
    */
    $wr7 = {B8 ?? ?? ?? BA ?? ?? ?? B9 ?? ?? ?? 0F 30}
    $wr8 = {B8 ?? ?? ?? B9 ?? ?? ?? BA ?? ?? ?? 0F 30}
    $wr9 = {B9 ?? ?? ?? B8 ?? ?? ?? BA ?? ?? ?? 0F 30}
    $wra = {B9 ?? ?? ?? BA ?? ?? ?? B8 ?? ?? ?? 0F 30}
    $wrb = {BA ?? ?? ?? B8 ?? ?? ?? B9 ?? ?? ?? 0F 30}
    $wrc = {BA ?? ?? ?? B9 ?? ?? ?? B8 ?? ?? ?? 0F 30}
    
    condition:
    any of them
}

rule embedded_exe 
{
    meta:
    description = "Detects embedded executables"
    
    strings:
    $a = "This program cannot be run in DOS mode"
    
    condition:
    $a in (1024..filesize)
}

rule vmdetect 
{
    meta:
    description = "Indicates attempt to detect VMs"
    
    strings:
    $vm0 = "VIRTUAL HD" nocase
    $vm1 = "VMWARE VIRTUAL IDE HARD DRIVE" nocase
    $vm2 = "QEMU HARDDISK" nocase
    $vm3 = "VBOX HARDDRIVE" nocase
    $vm4 = "The Wireshark Network Analyzer" 
    $vm5 = "C:\\sample.exe"
    $vm6 = "C:\\windows\\system32\\sample_1.exe"
    $vm7 = "Process Monitor - Sysinternals: www.sysinternals.com" 
    $vm8 = "File Monitor - Sysinternals: www.sysinternals.com" 
    $vm9 = "Registry Monitor - Sysinternals: www.sysinternals.com"
    
    condition:
    any of them
}

rule encoding 
{ 
    meta: 
    description = "Indicates encryption/compression"
    
    strings:
    $zlib0 = "deflate" fullword
    $zlib1 = "Jean-loup Gailly"
    $zlib2 = "inflate" fullword
    $zlib3 = "Mark Adler"
    
    $ssl0 = "OpenSSL" fullword
    $ssl1 = "SSLeay" fullword
    
    condition:
    (all of ($zlib*)) or (all of ($ssl*))
}

rule irc
{
    meta:
    description = "Indicates use of IRC"
    
    strings:
    $irc0 = "join" nocase fullword
    $irc1 = "msg" nocase fullword
    $irc2 = "nick" nocase fullword
    $irc3 = "notice" nocase fullword
    $irc4 = "part" nocase fullword
    $irc5 = "ping" nocase fullword
    $irc6 = "quit" nocase fullword
    $irc7 = "chat" nocase fullword
    $irc8 = "privmsg" nocase fullword
    
    condition:
    4 of ($irc*)
}   

rule sniffer 
{ 
    meta:
    description = "Indicates network sniffer"
    
    strings:
    $sniff0 = "sniffer" nocase fullword
    $sniff1 = "rpcap:////" nocase
    $sniff2 = "wpcap.dll" nocase fullword
    $sniff3 = "pcap_findalldevs" nocase
    $sniff4 = "pcap_open" nocase
    $sniff5 = "pcap_loop" nocase
    $sniff6 = "pcap_compile" nocase
    $sniff7 = "pcap_close" nocase
 
    condition:
    any of them
}

rule spam 
{
    meta:
    description = "Indicates spam-related activity"
    
    strings:
    $spam0000 = "invitation card" nocase
    $spam0002 = "shipping documents" nocase
    $spam0003 = "e-cards@hallmark.com" nocase
    $spam0004 = "invitations@twitter.com" nocase
    $spam0005 = "invitations@hi5.com" nocase
    $spam0006 = "order-update@amazon.com" nocase
    $spam0007 = "hallmark e-card" nocase
    $spam0008 = "invited you to twitter" nocase
    $spam0009 = "friend on hi5" nocase
    $spam000a = "shipping update for your amazon.com" nocase
    $spam000b = "rcpt to:" nocase
    $spam000c = "mail from:" nocase
    $spam000d = "smtp server" nocase 
    $spam000e = "mx record" nocase
    $spam000f = "cialis" nocase fullword
    $spam0010 = "pharma" nocase fullword
    $spam0011 = "casino" nocase fullword
    $spam0012 = "ehlo " nocase fullword
    $spam0013 = "from: " nocase fullword
    $spam0014 = "subject: " nocase fullword
    $spam0015 = "Content-Disposition: attachment;" nocase
    $spam0016 = "postcard" nocase fullword
    
    condition:
    3 of ($spam*)
}

rule bruteforce
{
    meta:
    description = "Indicates attempt to brute force passwords"
    
    strings:
    $br0 = "winpass" fullword nocase
    $br1 = "orainstall" fullword nocase
    $br2 = "sqlpassoainstall" fullword nocase
    $br3 = "db1234" fullword nocase
    $br4 = "databasepassword" fullword nocase
    $br5 = "databasepass" fullword nocase
    $br6 = "dbpassword" fullword nocase
    $br7 = "dbpass" fullword nocase
    $br8 = "domainpassword" fullword nocase
    $br9 = "domainpass" fullword nocase
    $br10 = "exchange" fullword nocase
    $br11 = "loginpass" fullword nocase
    $br12 = "win2000" fullword nocase
    $br13 = "windows" fullword nocase
    $br14 = "oeminstall" fullword nocase
    $br15 = "accounting" fullword nocase
    $br16 = "accounts" fullword nocase
    $br17 = "letmein" fullword nocase
    $br18 = "outlook" fullword nocase
    $br19 = "qwerty" fullword nocase
    $br20 = "temp123" fullword nocase
    $br21 = "default" fullword nocase
    $br22 = "changeme" fullword nocase
    $br23 = "secret" fullword nocase
    $br24 = "payday" fullword nocase
    $br25 = "deadline" fullword nocase
    $br26 = "1234567890" fullword nocase
    $br27 = "123456789" fullword nocase
    $br28 = "12345678" fullword nocase
    $br29 = "1234567" fullword nocase
    $br30 = "123456" fullword nocase
    $br31 = "pass1234" fullword nocase
    $br32 = "passwd" fullword nocase
    $br33 = "password" fullword nocase
    $br34 = "password1" fullword nocase
    $br35 = "admin:" nocase
    $br36 = "admin:123456" nocase
    $br37 = "admin:password" nocase
    $br38 = "admin:admin" nocase
    $br39 = "!root:" nocase
    $br40 = "zxc:cascade" nocase
    $br41 = "11111:x-admin" nocase
    $br42 = "1234:1234" nocase
    $br43 = "1500:and" nocase
    $br45 = "1502:1502" nocase
    $br46 = ":12345" nocase
    $br47 = ":1234admin" nocase
    $br48 = ":3ascotel" nocase
    $br49 = ":4getme2" nocase
    $br50 = ":BRIDGE" nocase
    $br51 = ":Cisco" nocase
    $br52 = ":Intel" nocase
    $br54 = ":SUPER" nocase
    $br56 = ":TANDBERG" nocase
    $br57 = ":TENmanUFactOryPOWER" nocase
    $br58 = ":Telecom" nocase
    $br59 = ":_Cisco" nocase
    $br60 = ":access" nocase
    $br61 = ":admin" nocase
    $br62 = ":ascend" nocase
    $br63 = ":atc123" nocase
    $br64 = ":cisco" nocase
    $br65 = ":connect" nocase fullword
    $br66 = ":default" nocase fullword
    $br67 = ":enter" nocase
    $br68 = ":epicrouter" nocase
    $br69 = ":hs7mwxkk" nocase
    $br70 = ":letmein" nocase
    $br71 = ":medion" nocase
    $br72 = ":nokia" nocase
    $br73 = ":password" nocase fullword
    $br74 = ":pento" nocase
    $br75 = ":public" nocase fullword
    $br76 = ":secret" nocase fullword
    $br77 = ":sitecom" nocase
    $br78 = ":smcadmin" nocase
    $br79 = ":administrator" nocase
    $br80 = ":speedxess" nocase
    $br81 = ":sysadm" nocase
    $br82 = ":system" nocase fullword
    $br83 = "ADMINISTRATOR:ADMINISTRATOR" nocase
    $br84 = "ADMN:admn" nocase
    $br85 = "ADSL:expert03" nocase
    $br86 = "ADVMAIL:HP" nocase
    $br87 = "ADVMAIL:HPOFFICE" nocase
    $br89 = "Admin:" nocase
    $br90 = "Admin:123456" nocase
    $br91 = "Admin:admin" nocase
    $br92 = "Administrator:" nocase
    $br93 = "Administrator:3ware" nocase
    $br94 = "Administrator:admin" nocase
    $br95 = "Administrator:changeme" nocase
    $br96 = "Administrator:ganteng" nocase
    $br97 = "Administrator:password" nocase
    $br98 = "Administrator:pilou" nocase
    $br99 = "Administrator:smcadmin" nocase
    $br100 = "Any:12345" nocase
    $br101 = "CISCO15:otbu+1" nocase
    $br102 = "CSG:SESAME" nocase
    $br103 = "Cisco:Cisco" nocase
    $br104 = "FIELD:HPONLY" nocase
    $br105 = "FIELD:HPP187" nocase
    $br107 = "FIELD:HPWORD" nocase
    $br109 = "FIELD:LOTUS" nocase
    $br110 = "FIELD:MANAGER" nocase
    $br111 = "FIELD:MGR" nocase
    $br112 = "FIELD:SERVICE" nocase
    $br113 = "FIELD:SUPPORT" nocase
    $br114 = "Factory:56789" nocase
    $br115 = "GEN1:gen1" nocase
    $br116 = "GEN2:gen2" nocase
    $br117 = "Gearguy:Geardog" nocase
    $br118 = "HELLO:FIELD.SUPPORT" nocase
    $br119 = "HELLO:MANAGER.SYS" nocase
    $br120 = "HELLO:MGR.SYS" nocase
    $br121 = "HELLO:OP.OPERATOR" nocase
    $br122 = "HTTP:HTTP" nocase
    $br123 = "IntraStack:Asante" nocase
    $br124 = "IntraSwitch:Asante" nocase
    $br125 = "MAIL:HPOFFICE" nocase
    $br126 = "MAIL:MAIL" nocase
    $br127 = "MAIL:MPE" nocase
    $br128 = "MAIL:REMOTE" nocase
    $br129 = "MAIL:TELESUP" nocase
    $br130 = "MANAGER:COGNOS" nocase
    $br131 = "MANAGER:HPOFFICE" nocase
    $br132 = "MANAGER:ITF3000" nocase
    $br133 = "MANAGER:SECURITY" nocase
    $br134 = "MANAGER:SYS" nocase
    $br135 = "MANAGER:TCH" nocase
    $br136 = "MANAGER:TELESUP" nocase
    $br137 = "MDaemon:MServer" nocase
    $br138 = "MGR:CAROLIAN" nocase
    $br139 = "MGR:CCC" nocase
    $br140 = "MGR:CNAS" nocase
    $br141 = "MGR:COGNOS" nocase
    $br142 = "MGR:CONV" nocase
    $br143 = "MGR:HPDESK" nocase
    $br144 = "MGR:HPOFFICE" nocase
    $br145 = "MGR:HPONLY" nocase
    $br146 = "MGR:HPP187" nocase
    $br147 = "MGR:HPP189" nocase
    $br148 = "MGR:HPP196" nocase
    $br149 = "MGR:INTX3" nocase
    $br150 = "MGR:ITF3000" nocase
    $br151 = "MGR:NETBASE" nocase
    $br152 = "MGR:REGO" nocase
    $br153 = "MGR:RJE" nocase
    $br154 = "MGR:ROBELLE" nocase
    $br155 = "MGR:SECURITY" nocase
    $br156 = "MGR:SYS" nocase
    $br157 = "MGR:TELESUP" nocase
    $br158 = "MGR:VESOFT" nocase
    $br159 = "MGR:WORD" nocase
    $br160 = "MGR:XLSERVER" nocase
    $br161 = "MICRO:RSX" nocase
    $br162 = "Manager:" nocase
    $br163 = "Manager:friend" nocase
    $br164 = "NAU:NAU" nocase
    $br165 = "NICONEX:NICONEX" nocase
    $br166 = "OPERATOR:COGNOS" nocase
    $br167 = "OPERATOR:DISC" nocase
    $br168 = "OPERATOR:SUPPORT" nocase
    $br169 = "OPERATOR:SYS" nocase
    $br170 = "OPERATOR:SYSTEM" nocase
    $br171 = "PCUSER:SYS" nocase
    $br172 = "PRODDTA:PRODDTA" nocase
    $br173 = "Polycom:456" nocase
    $br174 = "Polycom:SpIp" nocase
    $br175 = "RMUser1:password" nocase
    $br176 = "RSBCMON:SYS" nocase
    $br177 = "SPOOLMAN:HPOFFICE" nocase
    $br178 = "SSA:SSA" nocase
    $br179 = "SYSADM:sysadm" nocase
    $br180 = "SYSDBA:masterkey" nocase
    $br181 = "Service:5678" nocase
    $br182 = "TMAR#HWMT8007079:" nocase
    $br183 = "USERID:PASSW0RD" nocase
    $br184 = "User:Password" nocase
    $br185 = "WP:HPOFFICE" nocase
    $br186 = "aaa:often" nocase
    $br188 = "admin2:changeme" nocase
    $br189 = "admin:" nocase
    $br190 = "admin:0" nocase
    $br191 = "admin:1111" nocase
    $br192 = "admin:123" nocase
    $br193 = "admin:1234" nocase
    $br194 = "admin:12345" nocase
    $br195 = "admin:123456" nocase
    $br196 = "admin:1234admin" nocase
    $br197 = "admin:2222" nocase
    $br198 = "admin:22222" nocase
    $br199 = "admin:Ascend" nocase
    $br200 = "admin:NetCache" nocase
    $br201 = "admin:NetSurvibox" nocase
    $br202 = "admin:OCS" nocase
    $br203 = "admin:OkiLAN" nocase
    $br204 = "admin:P@55w0rd!" nocase
    $br205 = "admin:Password" nocase
    $br206 = "admin:Protector" nocase
    $br207 = "admin:Sharp" nocase
    $br208 = "admin:access" nocase
    $br209 = "admin:admin" nocase
    $br210 = "admin:admin123" nocase
    $br211 = "admin:administrator" nocase
    $br212 = "admin:adslolitec" nocase
    $br213 = "admin:adslroot" nocase
    $br214 = "admin:articon" nocase
    $br215 = "admin:asante" nocase
    $br216 = "admin:asd" nocase
    $br217 = "admin:atlantis" nocase
    $br218 = "admin:barricade" nocase
    $br219 = "admin:bintec" nocase
    $br220 = "admin:changeme" nocase
    $br221 = "admin:comcomcom" nocase
    $br222 = "admin:default" nocase
    $br223 = "admin:draadloos" nocase
    $br224 = "admin:epicrouter" nocase
    $br225 = "admin:extendnet" nocase
    $br226 = "admin:hagpolm1" nocase
    $br227 = "admin:hello" nocase
    $br228 = "admin:hp.com" nocase
    $br229 = "admin:imss7.0" nocase
    $br230 = "admin:ironport" nocase
    $br231 = "admin:isee" nocase
    $br232 = "admin:leviton" nocase
    $br233 = "admin:linga" nocase
    $br234 = "admin:michelangelo" nocase
    $br235 = "admin:microbusiness" nocase
    $br236 = "admin:motorola" nocase
    $br237 = "admin:mu" nocase
    $br238 = "admin:my_DEMARC" nocase
    $br239 = "admin:netadmin" nocase
    $br240 = "admin:noway" nocase
    $br241 = "admin:operator" nocase
    $br242 = "admin:password" nocase
    $br243 = "admin:passwort" nocase
    $br244 = "admin:pfsense" nocase
    $br245 = "admin:rmnetlm" nocase
    $br246 = "admin:secure" nocase
    $br247 = "admin:setup" nocase
    $br248 = "admin:smallbusiness" nocase
    $br249 = "admin:smcadmin" nocase
    $br250 = "admin:switch" nocase
    $br251 = "admin:symbol" nocase
    $br252 = "admin:synnet" nocase
    $br253 = "admin:sysAdmin" nocase
    $br254 = "admin:w2402" nocase
    $br255 = "admin:x-admin" nocase
    $br256 = "administrator:" nocase
    $br257 = "adminstat:OCS" nocase
    $br258 = "adminstrator:changeme" nocase
    $br259 = "adminttd:adminttd" nocase
    $br260 = "adminuser:OCS" nocase
    $br261 = "adminview:OCS" nocase
    $br262 = "apc:apc" nocase
    $br263 = "cablecom:router" nocase
    $br264 = "cac_admin:cacadmin" nocase
    $br265 = "ccrusr:ccrusr" nocase
    $br266 = "cellit:cellit" nocase
    $br267 = "cisco:" nocase
    $br268 = "citel:password" nocase
    $br269 = "comcast:" nocase
    $br270 = "comcast:1234" nocase
    $br271 = "craft:" nocase
    $br272 = "cusadmin:highspeed" nocase
    $br273 = "customer:none" nocase
    $br274 = "dadmin:dadmin01" nocase
    $br275 = "davox:davox" nocase
    $br276 = "deskalt:password" nocase
    $br277 = "deskman:changeme" nocase
    $br278 = "desknorm:password" nocase
    $br279 = "deskres:password" nocase
    $br280 = "device:device" nocase
    $br281 = "diag:danger" nocase
    $br282 = "disttech:4tas" nocase
    $br283 = "e250:e250changeme" nocase
    $br284 = "e500:e500changeme" nocase
    $br285 = "guest:" nocase
    $br286 = "guest:guest" nocase
    $br287 = "helpdesk:OCS" nocase
    $br288 = "hsa:hsadb" nocase
    $br289 = "images:images" nocase
    $br290 = "install:secret" nocase
    $br291 = "installer:installer" nocase
    $br292 = "intel:intel" nocase
    $br293 = "intermec:intermec" nocase
    $br294 = "isp:isp" nocase
    $br295 = "jagadmin:" nocase
    $br296 = "login:access" nocase
    $br297 = "login:admin" nocase
    $br298 = "m1122:m1122" nocase
    $br299 = "maint:maint" nocase
    $br300 = "maint:ntacdmax" nocase
    $br301 = "manage:!manage" nocase
    $br302 = "manager:admin" nocase
    $br303 = "manager:friend" nocase
    $br304 = "manager:manager" nocase
    $br305 = "manuf:xxyyzz" nocase
    $br306 = "mediator:mediator" nocase
    $br307 = "mlusr:mlusr" nocase
    $br308 = "monitor:monitor" nocase
    $br309 = "mso:w0rkplac3rul3s" nocase
    $br310 = "naadmin:naadmin" nocase
    $br311 = "netadmin:nimdaten" nocase
    $br312 = "netman:" nocase
    $br313 = "netrangr:attack" nocase
    $br314 = "netscreen:netscreen" nocase
    $br315 = "none:0" nocase
    $br316 = "none:admin" nocase
    $br317 = "operator:" nocase
    $br318 = "operator:$chwarzepumpe" nocase
    $br319 = "operator:1234" nocase
    $br320 = "operator:operator" nocase
    $br321 = "patrol:patrol" nocase
    $br322 = "piranha:piranha" nocase
    $br323 = "piranha:q" nocase
    $br324 = "public:" nocase
    $br325 = "public:public" nocase
    $br326 = "radware:radware" nocase
    $br327 = "readonly:lucenttech2" nocase
    $br328 = "readwrite:lucenttech1" nocase
    $br329 = "replicator:replicator" nocase
    $br330 = "root:0P3N" nocase
    $br331 = "root:1234" nocase
    $br332 = "root:12345" nocase
    $br333 = "root:3ep5w2u" nocase
    $br334 = "root:Cisco" nocase
    $br335 = "root:Mau'dib" nocase
    $br336 = "root:admin" nocase
    $br337 = "root:admin_1" nocase
    $br338 = "root:ascend" nocase
    $br339 = "root:attack" nocase
    $br340 = "root:blender" nocase
    $br341 = "root:calvin" nocase
    $br342 = "root:changeme" nocase
    $br343 = "root:davox" nocase
    $br344 = "root:default" nocase
    $br345 = "root:fivranne" nocase
    $br346 = "root:iDirect" nocase
    $br347 = "root:pass" nocase
    $br348 = "root:password" nocase
    $br349 = "root:root" nocase
    $br350 = "root:tslinux" nocase
    $br351 = "rwa:rwa" nocase
    $br352 = "scmadmin:scmchangeme" nocase
    $br353 = "scout:scout" nocase
    $br354 = "security:security" nocase
    $br355 = "service:smile" nocase
    $br356 = "setup:changeme" nocase
    $br357 = "setup:setup" nocase
    $br358 = "smc:smcadmin" nocase
    $br359 = "storwatch:specialist" nocase
    $br360 = "stratacom:stratauser" nocase
    $br361 = "super.super:" nocase
    $br362 = "super.super:master" nocase
    $br363 = "super:5777364" nocase
    $br364 = "super:super" nocase
    $br365 = "superadmin:secret" nocase
    $br366 = "superman:21241036" nocase
    $br367 = "superman:talent" nocase
    $br368 = "superuser:admin" nocase
    $br369 = "supervisor:" nocase
    $br370 = "supervisor:PlsChgMe" nocase
    $br371 = "supervisor:supervisor" nocase
    $br372 = "support:h179350" nocase
    $br373 = "support:support" nocase
    $br374 = "sys:uplink" nocase
    $br375 = "sysadmin:PASS" nocase
    $br376 = "sysadmin:password" nocase
    $br377 = "system:sys" nocase
    $br378 = "manager:change_on_install" nocase
    $br379 = "system:password" nocase
    $br380 = "teacher:password" nocase
    $br381 = "telecom:telecom" nocase
    $br382 = "tellabs:tellabs#1" nocase
    $br383 = "temp1:password" nocase
    $br384 = "tiara:tiaranet" nocase
    $br385 = "tiger:tiger123" nocase
    $br386 = "topicalt:password" nocase
    $br387 = "topicnorm:password" nocase
    $br388 = "topicres:password" nocase
    $br389 = "user:password" nocase
    $br390 = "user:tivonpw" nocase
    $br391 = "user:user" nocase
    $br392 = "vcr:NetVCR" nocase
    $br393 = "vt100:public" nocase
    $br394 = "webadmin:1234" nocase
    $br395 = "webadmin:webadmin" nocase
    $br396 = "websecadm:changeme" nocase
    $br397 = "wlse:wlsedb" nocase
    $br398 = "wradmin:trancell" nocase
    
    condition:
    10 of ($br*)
}

rule antiav 
{
    meta:
    description = "Attempts to thwarts AV"
    
	strings:
    $anti02 = "vptray" nocase
    $anti03 = "KavStart" nocase
    $anti04 = "360Safebox" nocase
    $anti05 = "360Safetray" nocase
    $anti06 = "KSWebShield.EXE" nocase
    $anti08 = "Rtvscan.EXE" nocase
    $anti09 = "ccSetMgr.EXE" nocase
    $anti0a = "ccEvtMgr.EXE" nocase
    $anti0b = "naPrdMgr.EXE" nocase
    $anti0c = "VsTskMgr.EXE" nocase
    $anti0d = "kav32.EXE" nocase
    $anti0e = "kissvc.EXE" nocase
    $anti0f = "KPfwSvc.EXE" nocase
    $anti11 = "HijackThis.EXE" nocase
    $anti12 = "PFW.EXE" nocase
    $anti13 = "TrojDie.KXP" nocase
    $anti14 = "Trojanwall.EXE" nocase
    $anti15 = "TrojanDetector.EXE" nocase
    $anti16 = "QQDoctor.EXE" nocase
    $anti17 = "RSTray.EXE" nocase
    $anti18 = "ArSwp.EXE" nocase
    $anti19 = "SREngLdr.EXE" nocase
    $anti1a = "rfwsrv.EXE" nocase
    $anti1b = "rfwProxy.EXE" nocase
    $anti1c = "Rsaupd.EXE" nocase
    $anti1d = "RsMain.EXE" nocase
    $anti1e = "RsAgent.EXE" nocase
    $anti1f = "RavStub.EXE" nocase
    $anti20 = "rfwmain.EXE" nocase
    $anti21 = "Rfwstub.EXE" nocase
    $anti22 = "GFUpd.EXE" nocase
    $anti23 = "GuardField.EXE" nocase
    $anti24 = "Runiep.EXE" nocase
    $anti25 = "KAVPFW.EXE" nocase
    $anti26 = "kavstart.EXE" nocase
    $anti27 = "kmailmon.EXE" nocase
    $anti28 = "kwatch.EXE" nocase
    $anti29 = "KASARP.EXE" nocase
    $anti2a = "RAV.EXE" nocase
    $anti2b = "ANTIARP.EXE" nocase
    $anti2c = "VPTRAY.EXE" nocase
    $anti2d = "VPC32.EXE" nocase
    $anti2e = "AutoRunKiller.EXE" nocase
    $anti2f = "Regedit.EXE" nocase
    $anti30 = "WOPTILITIES.EXE" nocase
    $anti31 = "Ast.EXE" nocase
    $anti32 = "Mmsk.EXE" nocase
    $anti33 = "Frameworkservice.EXE" nocase
    $anti34 = "KRegEx.EXE" nocase
    $anti35 = "egui.EXE" nocase
    $anti36 = "ekrn.EXE" nocase
    $anti37 = "nod32krn.EXE" nocase
    $anti38 = "Nod32kui.EXE" nocase
    $anti39 = "Navapsvc.EXE" nocase
    $anti3a = "KVSrvXP.EXE" nocase
    $anti3b = "KVMonxp.KXP" nocase
    $anti3c = "KVWSC.EXE" nocase
    $anti3d = "Iparmor.EXE" nocase
    $anti3e = "IceSword.EXE" nocase
    $anti3f = "rsnetsvr.EXE" nocase
    $anti40 = "RavTask.EXE" nocase
    $anti41 = "RavMon.EXE" nocase
    $anti42 = "ScanFrm.EXE" nocase
    $anti43 = "RavMonD.EXE" nocase
    $anti44 = "CCenter.EXE" nocase
    $anti45 = "RAVTRAY.EXE" nocase
    $anti46 = "Ravservice.EXE" nocase
    $anti47 = "AvMonitor.EXE" nocase
    $anti48 = "safeboxTray.EXE" nocase
    $anti49 = "360safebox.EXE" nocase
    $anti4a = "360tray.EXE" nocase
    $anti4b = "360safe.EXE" nocase
    $anti4c = "LiveUpdate360.EXE" nocase
    $anti4d = "360rpt.EXE" nocase
    $anti4e = "RavCCenter" nocase
    $anti4f = "RsRavMon" nocase
    $anti51 = "RsScanSrv" nocase
    $anti52 = "Kingsoft" nocase
    $anti53 = "EsuSafeguard.exe" nocase
    $anti54 = "LiveUpdate360.exe" nocase
    $anti55 = "Iparmor.exe" nocase
    $anti56 = "KVWSC.ExE" nocase
    $anti57 = "kvsrvxp.exe" nocase
    $anti58 = "kvsrvxp.kxp" nocase
    $anti59 = "KvXP.kxp" nocase
    $anti5a = "KRegEx.exe" nocase
    $anti5b = "AntiArp.exe" nocase
    $anti5c = "Mctray.exe" nocase
    $anti5d = "ccApp.exe" nocase
    $anti5e = "VPTRAY.exe" nocase
    $anti5f = "VPC32.exe" nocase
    $anti60 = "scan32.exe" nocase
    $anti61 = "FrameworkService.exe" nocase
    $anti62 = "KASARP.exe" nocase
    $anti63 = "TBMon.exe" nocase
    $anti64 = "rfwmain.exe" nocase
    $anti65 = "RavStub.exe" nocase
    $anti66 = "Rfwstub.exe" nocase
    $anti67 = "rfwProxy.exe" nocase
    $anti68 = "rfwsrv.exe" nocase
    $anti69 = "UpdaterUI.exe" nocase
    $anti6b = "mfevtp" nocase
    $anti6c = "McTaskManager" nocase
    $anti6d = "McAfeeFramework" nocase
    $anti6e = "McAfeeEngineService" nocase
    $anti6f = "Kingsoft" nocase
    $anti70 = "KPfwSvc" nocase
    $anti71 = "KWhatchsvc" nocase
    $anti74 = "KSWebShield.exe" nocase
    $anti75 = "kissvc.exe" nocase
    $anti76 = "kav32.exe" nocase
    $anti77 = "kwatch.exe" nocase
    $anti78 = "kavstart.exe" nocase
    $anti79 = "kmailmon.exe" nocase
    $anti7a = "GFUpd.exe" nocase
    $anti7b = "Ravxp.exe" nocase
    $anti7c = "GuardField.exe" nocase
    $anti7d = "RsAgent.exe" nocase
    $anti7e = "RavTRAY.exe" nocase
    $anti7f = "rsnetsvr.exe" nocase
    $anti80 = "ScanFrm.exe" nocase
    $anti81 = "RavMonD.exe" nocase
    $anti82 = "RAVMON.exe" nocase
    $anti83 = "CCenter.exe" nocase
    $anti84 = "RSTray.exe" nocase
    $anti85 = "RAv.exe" nocase
    $anti86 = "Rsaupd.exe" nocase
    $anti87 = "Runiep.exe" nocase
    $anti88 = "\\\\.\\pipe\\acsipc_server"
    $anti89 = "____AVP.Root" fullword
    $anti8a = "avguard01" fullword
    $anti8b = "WDEnable" fullword
    $anti8c = "antivirscheduler" nocase
    $anti8d = "antivirservice" nocase
    $anti8e = "apvxdwin" nocase
    $anti8f = "aswupdsv" nocase
    $anti90 = "avast!" nocase
    $anti91 = "avast! antivirus" nocase
    $anti92 = "avg8_tray" nocase
    $anti93 = "avg8wd" nocase
    $anti94 = "bdagent" nocase
    $anti95 = "bdss" nocase
    $anti96 = "caccprovsp" nocase
    $anti97 = "cavrid" nocase
    $anti98 = "ccproxy" nocase
    $anti99 = "ccpwdsvc" nocase
    $anti9a = "cctray" nocase
    $anti9b = "drwebscheduler" nocase
    $anti9c = "ehttpsrv" nocase
    $anti9d = "emproxy" nocase
    $anti9e = "fpavserver" nocase
    $anti9f = "f-prot antivirus tray application" nocase
    $antia0 = "gwmsrv" nocase
    $antia1 = "istray" nocase
    $antia2 = "k7emlpxy" nocase
    $antia3 = "k7rtscan" nocase
    $antia4 = "k7systemtray" nocase
    $antia5 = "k7tsmngr" nocase
    $antia6 = "k7tsstart" nocase
    $antia7 = "livesrv" nocase
    $antia8 = "liveupdate notice service" nocase
    $antia9 = "mcafee hackerwatch service" nocase
    $antiaa = "mcenui" nocase
    $antiab = "mcmisupdmgr" nocase
    $antiac = "mcmscsvc" nocase
    $antiad = "mcnasvc" nocase
    $antiae = "mcods" nocase
    $antiaf = "mcpromgr" nocase
    $antib0 = "mcproxy" nocase
    $antib1 = "mcredirector" nocase
    $antib2 = "mcsysmon" nocase
    $antib3 = "mpfservice" nocase
    $antib4 = "mps9" nocase
    $antib5 = "msk80service" nocase
    $antib6 = "mskagentexe" nocase
    $antib7 = "officescannt monitor" nocase
    $antib8 = "panda software controller" nocase
    $antib9 = "pavfnsvr" nocase
    $antiba = "pavprsrv" nocase
    $antibb = "pavsvr" nocase
    $antibc = "pshost" nocase
    $antibd = "psimsvc" nocase
    $antibe = "psksvcretail" nocase
    $antibf = "rsccenter" nocase
    $antic0 = "savadminservice" nocase
    $antic1 = "savscan" nocase
    $antic2 = "savservice" nocase
    $antic3 = "sbamtray" nocase
    $antic4 = "scaninicio" nocase
    $antic5 = "sophos autoupdate service" nocase
    $antic6 = "spam blocker for outlook express" nocase
    $antic7 = "spamblocker" nocase
    $antic8 = "spidermail" nocase
    $antic9 = "symantec core lc" nocase
    $antica = "threatfire" nocase
    $anticb = "tpsrv" nocase
    $anticc = "vsserv" nocase
    $anticd = "IceSword" nocase fullword
    $antice = "Malwarebytes" nocase fullword
    $anticf = "outpost.exe" nocase fullword
    $antid0 = "zlclient.exe" nocase fullword
    $antid1 = "windefend" nocase fullword
    $antid2 = "wscsvc" nocase fullword
    $antid3 = "ersvc" nocase fullword
    $antid4 = "wersvc" nocase fullword
	$antid5 = "avg.com" nocase
    $antid6 = "virustotal.com" nocase
    $antid7 = "avast.com" nocase
    $antid8 = "symantec.com" nocase
    $antid9 = "mcafee.com" nocase
    $antida = "comodo.com" nocase
    $antidb = "kaspersky.com" nocase
    $antidc = "sophos.com" nocase
    $antidd = "pandasecurity.com" nocase
    $antide = "eset.com" nocase
    $antidf = "clamwin.com" nocase
    $antif0 = "bitdefender.com" nocase
    $antif1 = "trendmicro.com" nocase
    $antif2 = "us.mcafee.com" nocase
    $antif3 = "avira.com" nocase
    $antif4 = "freebyte.com" nocase
    $antif5 = "f-prot.com" nocase
    $antif6 = "threatinfo.trendmicro.com" nocase
    $antif7 = "sunbeltsoft" nocase
    $antif8 = "aladdin.com" nocase
    $antif9 = "authentium.com" nocase
    $antifa = "avp.com" nocase
    $antifb = "customer.symantec.com" nocase
    $antifc = "ewido.com" nocase
    $antifd = "f-secure.com" nocase
    $antife = "free-av.com" nocase
    $antiff = "global.ahnlab.com" nocase
    $anti001 = "grisoft.com" nocase
    $anti002 = "hispasec.com" nocase
    $anti003 = "ikarus-software.at" nocase
    $anti004 = "kaspersky-labs.com" nocase
    $anti005 = "my-etrust.com" nocase
    $anti006 = "nai.com" nocase
    $anti007 = "networkassociates.com" nocase
    $anti008 = "quickheal.com" nocase
    $anti009 = "virus-buster.com" nocase
    $anti00a = "viruslist.com" nocase
    $anti00b = "microsoft" nocase
    $anti00c = "windowsupdate" nocase
    $anti00d = "wilderssecurity" nocase
    $anti00e = "threatexpert" nocase
    $anti00f = "castlecops" nocase
    $anti010 = "spamhaus" nocase
    $anti011 = "cpsecure" nocase
    $anti012 = "arcabit" nocase
    $anti013 = "emsisoft" nocase
    $anti014 = "sunbelt" nocase
    $anti015 = "securecomputing" nocase
    $anti016 = "rising" nocase
    $anti017 = "pctools" nocase
    $anti018 = "norman" nocase
    $anti019 = "k7computing" nocase
    $anti01a = "ikarus" nocase
    $anti01b = "hacksoft" nocase
    $anti01c = "fortinet" nocase
    $anti01d = "clamav" nocase
    $anti01e = "comodo" nocase
    $anti01f = "quickheal" nocase
    $anti020 = "ahnlab" nocase
    $anti021 = "centralcommand" nocase
    $anti022 = "grisoft" nocase
    $anti023 = "f-prot" nocase
    $anti024 = "kaspersky" nocase
    $anti025 = "f-secure" nocase
    $anti026 = "computerassociates" nocase
    $anti027 = "networkassociates" nocase
    $anti028 = "etrust" nocase
    $anti029 = "sophos" nocase
    $anti02a = "trendmicro" nocase
    $anti02b = "mcafee" nocase
    $anti02c = "norton" nocase
    $anti02d = "symantec" nocase
    $anti02e = "defender" nocase
    $anti032 = "Antirootkit" nocase fullword
    $anti033 = "onecare" nocase fullword
    $anti034 = "McAfee\\VSCore\\On Access Scanner\\BehaviourBlocking" nocase 
    $anti035 = "AccessProtectionUserRules" nocase
    $anti036 = "McAfee\\Common Framework\\SiteList.xml" nocase

	condition:
	5 of ($anti*)
}

rule injection
{
    meta: 
    description = "Indicates attempt to inject code"
    
    strings:
    $a = "injector" fullword nocase
    $b = "injecter" fullword nocase
    $c = "injector" fullword nocase wide
    $d = "injecter" fullword nocase wide

    condition:
    any of them 
}

rule peertopeer
{
    meta:
    description = "Indicates P2P file sharing attempts"
    
	strings:
	$ptp1 = "BearShare" nocase
	$ptp2 = "iMesh" nocase fullword
	$ptp3 = "Shareaza" nocase
	$ptp4 = "Kazaa" nocase
	$ptp5 = "DC++" nocase
	$ptp6 = "eMule" nocase
	$ptp7 = "LimeWire" nocase

	condition:
	any of them
}

rule bankers 
{
    meta:
    description = "Indicates banker / passwd stealer"

	strings:
	
	$pass1 = "PK11_GetInternalKeySlot" fullword wide ascii
	$pass2 = "PK11_FreeSlot" fullword wide ascii
	$pass3 = "PK11SDR_Decrypt" fullword wide ascii
	$pass4 = "PL_Base64Decode" fullword wide ascii
	$pass5 = "#SharedObjects" nocase wide ascii
	$pass6 = "IE:Password-Protected" nocase wide ascii
	$pass7 = "IE AutoComplete" nocase wide ascii
	$pass8 = "POP3 Password2" fullword wide ascii
	$pass9 = "HTTPMail Password2" fullword wide ascii
	$pass10 = "IE Auto Complete" wide ascii
	$pass11 = "AutoComplete Passwords" wide ascii
	$pass12 = "CopyGlyphDataFrom" wide ascii
	$pass14 = "IE Cookies:" nocase wide ascii
	$pass15 = "ie_cookies" nocase wide ascii
	$pass16 = "Macromedia\\Flash Player" wide ascii
	$pass17 = "flashfxp" nocase wide ascii
	$pass18 = "wcx_ftp.ini" nocase wide ascii
	$pass19 = "Total Commander" wide ascii
	$pass20 = "software\\ipswitch\\ws_ftp" nocase wide ascii
	$pass21 = "FAR manager" nocase wide ascii
	$pass22 = "software\\martin prikryl\\winscp 2\\sessions" nocase wide ascii
    $pass23 = "software\\ftpware\\coreftp\\sites" nocase wide ascii
    $pass24 = "smartftp" nocase wide ascii
    $pass25 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide ascii
    $pass26 = "\\Ares\\My Shared Folder" wide ascii
    $pass27 = ":String" fullword wide ascii
    $pass28 = "StringIndex" fullword wide ascii
    $pass29 = "e161255a" fullword wide ascii
    $pass30 = "5e7e8100" fullword wide ascii
    $pass31 = "MS IE FTP Passwords" wide ascii
    $pass32 = "IE:AutoComplete" nocase wide ascii
    $pass34 = "wininetcachecredentials" nocase fullword wide ascii
    $pass35 = "inetcomm server passwords" nocase wide ascii
    $pass36 = "IMAP Password2" fullword wide ascii
    $pass37 = "SOFTWARE\\RIT\\The Bat" nocase wide ascii
    $pass38 = "Coffee Cup" nocase wide ascii
    $pass39 = "TransSoft Ltd\\FTP Control 4" nocase wide ascii
    $pass3a = "ControllFTP" nocase fullword wide ascii
    $pass3b = "FTPWare\\COREFTP" nocase wide ascii
    $pass3c = "GlobalSCAPE" nocase fullword wide ascii
    $pass3d = "CuteFTP" nocase fullword wide ascii
    $pass3e = "FileZilla" nocase fullword wide ascii
    $pass3f = "FTP Navigator" nocase wide ascii
    $pass40 = "NavigatorFTP" nocase wide ascii
    $pass41 = "totalcmd" nocase wide ascii
    $pass42 = "ghistler" nocase wide ascii
    $pass43 = "moz_logins" 
    $pass44 = "sqlite3_open"
	
	$logins0000 = "strmemberid="
	$logins0001 = "strpassword"
	$logins0002 = "&account="
	$logins0005 = "strEmail="
	$logins0006 = "strPassword="
	$logins0007 = "strNexonID="
	$logins0008 = "strPassword"
	$logins0009 = "&loginname=df"
	$logins000a = "hanpwd"
	$logins000d = "l_id="
	$logins000e = "l_pwd"
	$logins000f = "mgid_enc2="
	$logins0010 = "mgpwd_enc2"
	$logins0011 = "GET /login/"
	$logins0012 = "User_ID="
	$logins0013 = "&npw1"
	$logins0014 = "jumin2="
	$logins0015 = "wbUserid="
	$logins0016 = "&wbPasswd"
	$logins0017 = "strNexonID="
	$logins0018 = "strPassword"
	$logins0019 = "txtLoginName="
	$logins001a = "txtPassword"
	$logins001b = "strmemberid="
	$logins001c = "strpassword="
	$logins001d = "&login="
	$logins0021 = "uname="
	$logins0023 = "&Email="
	$logins0024 = "&Passwd"
	$logins0025 = "acctname="
	$logins0026 = "&passwd"
	$logins0028 = "&pass"
	$logins0029 = "&email="
	$logins002a = "&password"
	$logins002b = "&mail="
	$logins002d = "&pass="
	$logins002e = "internet banking" nocase
    $logins002f = "account overview" nocase
    $logins0030 = "viewstatement" nocase
    $logins0031 = "account balance" nocase
    $logins0032 = "available balance" nocase
    $logins0034 = "qzpassword" nocase
    $logins0035 = "accountnumber" nocase
    $logins0036 = "pinnumber" nocase
    $logins0037 = "tannumber" nocase
    $logins0038 = "logontextbox" nocase
    $logins0039 = "internetBanking" nocase
    $logins003a = "AccountDetails" nocase
    $logins003b = "balance details" nocase
    $logins003c = "bank accounts" nocase
    $logins003d = "security questions" nocase
    $logins003e = "Web Cashplus" nocase
    $logins003f = "injtoken" nocase
    $logins0040 = "cash management" nocase
    $logins0041 = "American Express" nocase
    $logins0042 = "Mastercard" nocase fullword
    $logins0043 = "Login confirmation" nocase
    $logins0044 = "activate your account" nocase
    $logins0045 = "wrong password" nocase
    $logins0046 = "UIN#" nocase
    $logins0047 = "login_email" 
    $logins0048 = "txtAccountNumber" 
    $logins0049 = "ecurityPin" 
    $logins004a = "sortCode" 
    $logins004b = "memorableAnswer" 
    $logins004c = "txtCustomerID" 
    $logins004d = "MBindexuserkey"
    $logins004e = "ctlLoginFirstStep"
    $logins004f = "__IDV_URL=hsbc.MyHSBC" 
    $logins0050 = "SignInWelcome"
    $logins0051 = "nputuserid" 
    $logins0052 = "PwdPad=IfYouAreReadingThis" 
    $logins0053 = "txtLoginPin" 
    $logins0054 = "inputmemorable"
    $logins0055 = "UserId1="
	$bank0000 = ".bcvs.ch"
	$bank0001 = ".dbs.com"
	$bank0002 = ".directnet.com"
	$bank0003 = ".inetbank.net.au"
	$bank0004 = ".netbanking.ch"
	$bank0005 = "adambanking.com"
	$bank0006 = "advisernet.com.au"
	$bank0007 = "alpha.gr"
	$bank0008 = "amp.com.au"
	$bank0009 = "apobank.de"
	$bank000a = "baloise.ch"
	$bank000b = "bam.it"
	$bank000c = "bancatoscana.it"
	$bank000d = "bancocaixageral.es"
	$bank000e = "bank.ubs.com"
	$bank000f = "bankatlantic.web-access.com"
	$bank0010 = "banking.bankofscotland.co.uk"
	$bank0011 = "banking.co.at"
	$bank0012 = "bankofcyprus.gr"
	$bank0013 = "bankofthewest.com"
	$bank0014 = "bbva.es"
	$bank0015 = "bbvanetoffice.com"
	$bank0016 = "bcge.ch"
	$bank0017 = "bonline.co.uk"
	$bank0018 = "boq.com.au"
	$bank0019 = "businesse-cashmanager.web-access.com"
	$bank001a = "caixagirona.es"
	$bank001b = "capitalone.com"
	$bank001c = "capitalonesavings.co.uk"
	$bank001d = "cashproweb.com"
	$bank001e = "cbbusinessonline.com"
	$bank001f = "citibank.ae"
	$bank0020 = "citibank.co.uk"
	$bank0021 = "citibank.com"
	$bank0022 = "citibank.com.au"
	$bank0023 = "citibank.com.ph"
	$bank0024 = "citibank.de"
	$bank0025 = "citibusinessonline.da-us.citibank.com"
	$bank0026 = "commercial.wachovia.com"
	$bank0027 = "cortalconsors.de"
	$bank0028 = "csebo.it"
	$bank0029 = "cua.com.au"
	$bank002a = "direct.53.com"
	$bank002b = "dollarbank.com"
	$bank002c = "ebank.emporiki.gr"
	$bank002d = "ebanking-services.com"
	$bank002e = "ebanking.millenniumbank.gr"
	$bank002f = "esgc.com"
	$bank0030 = "express.53.com"
	$bank0031 = "fbmedirect.com"
	$bank0032 = "haspa.de"
	$bank0033 = "homebank.nbg.gr"
	$bank0034 = "icicibank.co.uk"
	$bank0035 = "internet-banking.dbs.com.sg"
	$bank0036 = "laiki.com"
	$bank0037 = "lasallebank.com"
	$bank0038 = "mps.it"
	$bank0039 = "npbs.co.uk"
	$bank003a = "onlineservices.wachovia.com"
	$bank003b = "paco.cabel.it"
	$bank003c = "paypal.com"
	$bank003d = "postbank.de"
	$bank003e = "postfinance.ch"
	$bank003f = "probanx.net"
	$bank0040 = "raiffeisendirect.ch"
	$bank0041 = "reuschel.com"
	$bank0042 = "sanostra.es"
	$bank0043 = "sarasin.ch"
	$bank0044 = "sparkasse-bgl.de"
	$bank0045 = "sparkasse-nienburg.de"
	$bank0046 = ".suntrust.com"
	$bank0047 = "treasury.wamu.com"
	$bank0048 = "ubp.ch"
	$bank0049 = "ubs.com"
	$bank004a = "uno-e.com"
	$bank004b = "usb.com.cy"
	$bank004c = "vip.lasallebank.com"
	$bank004d = "vontobel.com"
	$bank004e = "wachovia.com"
	$bank0050 = "winbank.gr"
	$bank0051 = "www.53.com"
	$bank0052 = "zkb.ch"
	$bank0053 = "access.imb.com.au"
	$bank0054 = "accounts.key.com"
	$bank0055 = "achpayments.wachovia.com"
	$bank0056 = "areasegura.banif.es"
	$bank0057 = "bancae.bancoetcheverria.es"
	$bank0058 = "bank.netbanking.ch"
	$bank0059 = "banking..ch"
	$bank005a = "banking..de"
	$bank005b = "banking.apobank.de"
	$bank005c = "banking.bankofscotland.co.uk"
	$bank005d = "banking.bekb.ch"
	$bank005e = "banking.dkb.de"
	$bank005f = "banking.firsttennessee."
	$bank0060 = "banking.sparda.de"
	$bank0061 = "banking.uboc.com"
	$bank0062 = "banking.us.hsbc.com"
	$bank0063 = "bankingportal..de"
	$bank0064 = "banknet.columbiariverbank.com"
	$bank0065 = "bbvanetoffice.com"
	$bank0066 = "carenet.fnfismd.com"
	$bank0068 = "cib.ibanking-services.com"
	$bank0069 = "citibusinessonline.da-us.citibank.com"
	$bank006b = "corporate-internet-banking.dbs.com"
	$bank006c = "ctm.53.com"
	$bank006d = "dealonline.dbs.com"
	$bank006f = "e-banking.bcvs.ch"
	$bank0070 = "easylink.bankofbermuda.com"
	$bank0071 = "ebank.emporiki.gr"
	$bank0072 = "ebanker.arabbank.com.au"
	$bank0073 = "ebusiness.arabbank.ch"
	$bank0074 = ".openbank.com"
	$bank0075 = "essg.wachovia.com"
	$bank0076 = "etimebanker.bankofthewest.com"
	$bank0077 = "express.53.com"
	$bank0078 = "express.53.com"
	$bank0079 = "finanzportal.fiducia.de"
	$bank007a = "global1.onlinebank.com"
	$bank007b = "hbcibanking.apobank.de"
	$bank007c = "hbnet.cedacri.it"
	$bank007d = "home.cbonline.co.uk"
	$bank007e = "homebank.nbg.gr"
	$bank007f = "homebanking.cariparma.it"
	$bank0080 = "ib.bigsky.net.au"
	$bank0081 = "ib.national.com.au"
	$bank0082 = "ibank.anbusiness.com"
	$bank0083 = ".barclays.co.uk"
	$bank0084 = "ibank.cahoot.com"
	$bank0085 = "ibank.communityfirst.com.au"
	$bank0086 = "inba.lukb.ch"
	$bank0087 = "internet-banking.dbs.com.sg"
	$bank0088 = "internetbanking.gad.de"
	$bank0089 = "is2.cuviewpoint.net"
	$bank008a = "lbbwebclient.lehmanbank.com"
	$bank008b = "lo.lacaixa.es"
	$bank008c = "mcw.airforcefcu.com"
	$bank008d = "mfasa.chase.com"
	$bank008e = "mijn.postbank.nl"
	$bank0090 = "my.hypovereinsbank.de"
	$bank0091 = "my.screenname.aol.com"
	$bank0092 = "myonlineaccounts.abbeynational.co.uk"
	$bank0093 = "net.kutxa.net"
	$bank0094 = "oi.cajamadrid.es"
	$bank0095 = "oie.cajamadridempresas.es"
	$bank0096 = "okd5199.bcge.ch"
	$bank0097 = "onba.zkb.ch"
	$bank0098 = ".lloydstsb.co.uk"
	$bank0099 = "online.bankofcyprus.com"
	$bank009a = "online.bulbank.bg"
	$bank009b = "online.citibank.com"
	$bank009c = "online.mecu.com.au"
	$bank009d = "online.sainsburysbank.co.uk"
	$bank009e = "online.wamu.com"
	$bank009f = ".wellsfargo.com"
	$bank00a0 = "online.westpac.com.au"
	$bank00a1 = "onlineaccess.ncsecu.org"
	$bank00a3 = "onlinebanking.bankofoklahoma.com"
	$bank00a4 = "onlinebanking.capitalone.com"
	$bank00a5 = "onlinebanking.lasallebank.com"
	$bank00a6 = "onlinebanking.nationalcity.com"
	$bank00a7 = "onlineservices.amp.com.au"
	$bank00a8 = "onlineservices.wachovia.com"
	$bank00a9 = "onlineteller.cu.com.au"
	$bank00aa = "paylinks.cunet.org"
	$bank00ab = "portal.izb.de"
	$bank00ac = "portal..de"
	$bank00ad = "secure.accu.com.au"
	$bank00ae = "secure.alpha.gr"
	$bank00af = "secure.ampbanking.com"
	$bank00b0 = ".lloydstsb.com"
	$bank00b1 = "secure.esanda.com"
	$bank00b2 = "secure.tcfexpress.com"
	$bank00b3 = "seguro.cam.es"
	$bank00b4 = "service.oneaccount.com"
	$bank00b5 = "servizi.allianzbank.it"
	$bank00b6 = "servizi.atime.it"
	$bank00b7 = "signin.ebay.com"
	$bank00b8 = "bankofamerica.com"
	$bank00b9 = "sobanet.baloise.ch"
	$bank00ba = "ssl2.haspa.de"
	$bank00bb = "sso.uboc.com"
	$bank00bc = "tb.raiffeisendirect.ch"
	$bank00bd = "tcfexpressbusiness.com"
	$bank00be = "telebanking.hbl.ch"
	$bank00bf = "telemarch.bancamarch.es"
	$bank00c0 = "treasury.wamu.com"
	$bank00c1 = "trust.firsttennessee.com"
	$bank00c2 = "vs.absa.co.za"
	$bank00c3 = "wc.wachovia.com"
	$bank00c4 = "web.da-us.citibank.com"
	$bank00c5 = "webbanking.comerica.com"
	$bank00c6 = "webcmpr.bancopopular.com"
	$bank00c7 = ".co-operativebank.co.uk"
	$bank00c8 = ".smile.co.uk"
	$bank00c9 = ".440strand.com"
	$bank00ca = ".bancopopular.es"
	$bank00cb = ".fiibg.com"
	$bank00cc = ".usbank.com"
	$bank00cd = ".53.com"
	$bank00ce = ".asia.citibank.com"
	$bank00cf = ".bancatoscana.it"
	$bank00d0 = ".banking.co.at"
	$bank00d1 = ".halifax-online.co.uk"
	$bank00d2 = ".bv-i.bancodevalencia.es"
	$bank00d3 = ".caixacatalunya.es"
	$bank00d4 = ".cajacanarias.es"
	$bank00d5 = ".cbbusinessonline.com"
	$bank00d6 = ".citibank.com.au"
	$bank00d7 = ".citibank.com.my"
	$bank00d8 = ".citibank.com.ph"
	$bank00d9 = ".citibank.com.sg"
	$bank00da = ".citibank.de"
	$bank00db = ".citibankonline.ca"
	$bank00dc = ".csebanking.it"
	$bank00dd = ".ebank.us.hsbc.com"
	$bank00de = ".etradeaustralia.com.au"
	$bank00df = ".eurobank.gr"
	$bank00e0 = ".fibanc.es"
	$bank00e1 = ".firstib.com"
	$bank00e2 = ".hellenicbank.com"
	$bank00e3 = ".homebank.com.au"
	$bank00e4 = ".in-bank.net"
	$bank00e5 = ".inversis.com"
	$bank00e6 = ".isideonline.it"
	$bank00e7 = ".jpmorganinvest.com"
	$bank00e8 = ".laiki.com"
	$bank00e9 = ".linksimprese.sanpaoloimi.com"
	$bank00ea = ".mybank.alliance-leicester.co.uk"
	$bank00eb = ".mybusinessbank.co.uk"
	$bank00ec = ".nextbanking.it"
	$bank00ed = ".nwolb.com"
	$bank00ee = ".ocfcu.org"
	$bank00ef = ".onlinesefcu.com"
	$bank00f0 = ".rbsdigital.com"
	$bank00f1 = ".selectbenefit.com"
	$bank00f2 = ".sharebuilder.com"
	$bank00f3 = ".sparkasse.at"
	$bank00f4 = ".ubs.com"
	$bank00f5 = ".usaa.com"
	$bank00f6 = ".winbank.gr"
	$bank00f7 = ".maxisloans.com.au"
	$bank00f8 = ".citizensbankonline.com"
	$bank00f9 = ".site-secure.com"
	$bank00fa = ".commbank.com.au"
	$bank00fb = ".ameritrade.com"
	$bank00fc = "swedbank.com"
    $bank00fd = "hanza.net"
    $bank00fe = "hansa.lt"
    $bank00ff = "swedbankas.lt"
    $bank0100 = "swedbank.net"
    $bank0101 = "bbvapanama.com"
    $bank0102 = "banconal.com.pa"
    $bank0103 = "banconal.com"
    $bank0104 = "banvivienda.net"
    $bank0105 = "banvivienda.com"
    $bank0106 = "bancouno.com.pa"
    $bank0107 = "bancouno.com"
    $bank0108 = "credicorpbank.com"
    $bank0109 = "globalbank.com.pa"
    $bank010a = "globalbank.com"
    $bank010b = "swedbank.lt"
    $bank010c = "hsbc.com.pa"
    $bank010d = "multibank.com"
    $bank010e = "credicorpbank.com"
    $bank010f = "multibank.com.pa"
    $bank0110 = "bbvapanama.com"
    $bank0111 = "banconal.com.pa"
    $bank0112 = "banvivienda.net"
    $bank0113 = "banvivienda.com"
    $bank0114 = "globalbank.com.pa"
    $bank0115 = "globalbank.com"
    $bank0116 = "bancouno.com.pa"
    $bank0117 = "bancouno.com"
    $bank0118 = "banconal.com"
    $bank0119 = "bancopanama.com.pa"
    $bank011a = "bancopanama.com"
    $bank011b = "parex.lt"
    $bank011c = "kiwibank.co.nz"
    $bank011d = "kiwibank.com"
    $bank011e = "seb.lt"
    $bank011f = "kfh.com"
    $bank0120 = "kfh.com.kw"
    $bank0121 = "boq.com"
    $bank0122 = "boq.com.au"
    $bank0123 = "bankofqueensland.com"
    $bank0124 = "asb.co.nz"
    $bank0125 = "asb.com"
    $bank0126 = "tsb.co.nz"
    $bank0127 = "tsb.com"
    $bank0128 = "cahoot.com"
    $bank0129 = "cahoot.co.uk"
    $bank012a = ".ameriprise.com"
    $bank012b = ".ebay.com"
    $bank012c = ".e-gold.com"
    $bank012d = ".tdcanadatrust.com"
    $bank012e = ".banesto.es"
    $bank012f = ".gruposantander.es"
    $bank0130 = ".bancajaproximaempresas.com"
    $bank0131 = ".procreditbank.bg"
    $bank0132 = ".barclays.com"
    $bank0133 = ".dab-bank.com"
    $bank0134 = ".hsbc.co.uk"
    $bank0135 = ".ybonline.co.uk"
    $bank0136 = ".bancoherrero.com"
    $bank0137 = ".bancopastor.es"
    $bank0138 = ".cajamurcia.es"
    $bank0139 = ".caja-granada.es"
    $bank013a = ".fibancmediolanum.es"
    $bank013b = ".cajarioja.es"
    $bank013c = ".cajasoldirecto.es"
    $bank013d = ".caixalaietana.es"
    $bank013e = "areasegura.banif.es"
    $bank013f = ".bgnetplus.com"
    $bank0140 = ".caixagirona.es"
    $bank0141 = ".unicaja.es"
    $bank0142 = ".sabadellatlantico.com"
    $bank0143 = ".cajabadajoz.es"
    $bank0144 = ".banesto.es"
    $bank0145 = ".elmonte.es"
    $bank0146 = ".cajamadridempresas.es"
    $bank0147 = ".gruppocarige.it"
    $bank0148 = "bancopostaonline.poste.it"
    $bank0149 = ".internetbanking.bancaintesa.it"
    $bank014a = "hb.quiubi.it"
    $bank014b = ".iwbank.it"
    $bank014c = "web.secservizi.it"
    $bank014d = "scrigno.popso.it"
    $bank014e = "light.webmoney.ru"
    $bank014f = ".nationet.com"
    $bank0150 = ".banking.first-direct.com"
    $bank0151 = "cardsonline-consumer.com"
    $bank0152 = "internetbanking.aib.ie"
    $bank0153 = "lot-port.bcs.ru"
    $bank0154 = "rupay.com"
    $bank0155 = "ingbank.pl" nocase
    $bank0156 = "millenet.pl" nocase
    $bank0157 = "bph.pl" nocase
    $bank0158 = "centrum24.pl" nocase
    $bank0159 = "nationwide.co.uk" nocase
    $bank015a = "mbank.pl" nocase
    $bank015b = "mbank.com.pl" nocase
    $bank015c = "deutsche-bank.de" nocase
    $bank015d = "bankingportal.kreissparkasse-heilbronn.de" nocase
    $bank015e = "bankingportal.sparkasse-meschede.de" nocase
    $bank015f = "bankingportal.swn-online.de" nocase
    $bank0160 = "bankingportal.sparkasse-aachen.de" nocase
    $bank0161 = "natwest" nocase
    $bank0166 = "e-bullion" nocase
    $bank0167 = "login.hsbc.com" nocase
    $bank0168 = "gemoney" nocase
    $bank0169 = "webid2.gs.com" nocase
    $bank016a = "myworld.insinger.com" nocase
    $bank016b = "my.if.com" nocase
    $bank016c = "leedscitycreditunion.co.uk" nocase
    $bank016d = "libbackoffice.com" nocase
    $bank016e = "clearstream.com" nocase
    $bank016f = "financepilot-trans.mlp.de" nocase
    $bank0170 = "fidelity.co.uk" nocase
    $bank0171 = "selftrade.co.uk" nocase
    $bank0172 = "standardlife.com" nocase
    $bank0173 = "https://www.rbsdigital.com/default.aspx" nocase
    $bank0174 = "https://www.hsbc.co.uk/" nocase
    $bank0175 = "login.live.com" nocase
    $bank0176 = "google.com/accounts/servicelogin" nocase
    $bank0177 = "yahoo.com/config" nocase
    $bank0178 = ".idsonline.com" nocase
    $bank0179 = ".ctn.independent.co.za" nocase
    $bank017a = ".electric.co.za" nocase
    $bank017b = ".rmb.co.za" nocase
    $bank017c = ".great-china.net" nocase
    $bank017d = ".hangseng.com" nocase
    $bank017e = ".hsbcgroup.com" nocase
    $bank017f = ".iba.com.hk" nocase
    $bank0180 = ".bdni.com" nocase
    $bank0181 = ".bii.co.id" nocase
    $bank0182 = ".servitia.com" nocase
    $bank0183 = ".indoweb.com" nocase
    $bank0184 = ".sphere.ad.jp" nocase
    $bank0185 = ".infoweb.or.jp" nocase
    $bank0186 = ".ltcb.co.jp" nocase
    $bank0187 = ".csweb.co.jp" nocase
    $bank0188 = ".ahli.com" nocase
    $bank0189 = ".iworld.net" nocase
    $bank018a = ".cbk.co.kr" nocase
    $bank018b = ".wisedb.co.kr" nocase
    $bank018c = ".cybernet.co.kr" nocase
    $bank018d = ".dacom.co.kr" nocase
    $bank018e = ".kol.co.kr" nocase
    $bank018f = ".kfb.co.kr" nocase
    $bank0190 = ".nacf.co.kr" nocase
    $bank0191 = ".saradar.com.lb" nocase
    $bank0192 = ".bnm.gov.my" nocase
    $bank0193 = ".jaring.my" nocase
    $bank0194 = ".bpi.com.ph" nocase
    $bank0195 = ".pcib.com" nocase
    $bank0196 = ".anb.com.sa" nocase
    $bank0197 = ".isdb.org" nocase
    $bank0198 = ".citicorp.com" nocase
    $bank0199 = ".technet.sg" nocase
    $bank019a = ".chinatrust.com.tw" nocase
    $bank019b = ".bot.or.th" nocase
    $bank019c = ".ntb.co.th" nocase
    $bank019d = ".scb.co.th" nocase
    $bank019e = ".creditandorra.ad" nocase
    $bank019f = ".bawag.com" nocase
    $bank01a0 = ".hypo-alpe-adria.com" nocase
    $bank01a1 = ".kaerntnersparkasse.co.at" nocase
    $bank01a2 = ".hypotirol.at" nocase
    $bank01a3 = ".oenb.co.at" nocase
    $bank01a4 = ".psk.co.at" nocase
    $bank01a5 = ".wpf.at" nocase
    $bank01a6 = ".geocitdies.com" nocase
    $bank01a7 = ".stmk.raiffeisen.at" nocase
    $bank01a8 = ".bkkallincl.co.at" nocase
    $bank01a9 = ".rbs.co.at" nocase
    $bank01aa = ".rlb-tirol.at" nocase
    $bank01ab = ".raiffeisen.at" nocase
    $bank01ac = ".sparkasseleoben.at" nocase
    $bank01ad = ".smw.at" nocase
    $bank01ae = ".sparkasse-weiz.at" nocase
    $bank01af = ".weinviertler-spk.at" nocase
    $bank01b0 = ".bbl.be" nocase
    $bank01b1 = ".cger.be" nocase
    $bank01b2 = ".cbe.be" nocase
    $bank01b3 = ".banque-cortal.fr" nocase
    $bank01b4 = ".fortis.com" nocase
    $bank01b5 = ".iccs.acad.bg" nocase
    $bank01b6 = ".rzb.co.at" nocase
    $bank01b7 = ".centraleurope.com" nocase
    $bank01b8 = ".vol.cz" nocase
    $bank01b9 = ".koba.cz" nocase
    $bank01ba = ".union.cz" nocase
    $bank01bb = ".rzb.co.at" nocase
    $bank01bc = ".addgr.com" nocase
    $bank01bd = ".open.hr" nocase
    $bank01be = ".kaptol.hr" nocase
    $bank01bf = ".pbz.hr" nocase
    $bank01c0 = ".rzb.co.at" nocase
    $bank01c1 = ".enterprise.net" nocase
    $bank01c2 = ".ebs.ie" nocase
    $bank01c3 = ".sda.dk" nocase
    $bank01c4 = ".eyp.ee" nocase
    $bank01c5 = ".depo.ee" nocase
    $bank01c6 = ".forex.ee" nocase
    $bank01c7 = ".aktia.fi" nocase
    $bank01c8 = ".fuib.com" nocase
    $bank01c9 = ".ucb.crimea.ua" nocase
    $bank01ca = ".tcmb.gov.tr" nocase
    $bank01cb = ".osmanli.com.tr" nocase
    $bank01cc = ".falkenbergs-sparb.se" nocase
    $bank01cd = ".stadshypotek.se" nocase
    $bank01ce = ".abnamro.se" nocase
    $bank01cf = ".sb-koper.si" nocase
    $bank01d0 = ".bsi.si" nocase
    $bank01d1 = ".basl.sk" nocase
    $bank01d2 = ".slsp.sk" nocase
    $bank01d3 = ".rzb.co.at" nocase
    $bank01d4 = ".bancpost.ro" nocase
    $bank01d5 = ".kappa.ro" nocase
    $bank01d6 = ".bdk.lublin.pl" nocase
    $bank01d7 = ".pbks.pl" nocase
    $bank01d8 = ".ben.com.pl" nocase
    $bank01d9 = ".bswek.comew.pl" nocase
    $bank01da = ".pbks.pl" nocase
    $bank01db = ".cyf-kr.edu.pl" nocase
    $bank01dc = ".oslonett.no" nocase
    $bank01dd = ".sn.no" nocase
    $bank01de = ".kreditkassen.no" nocase
    $bank01df = ".novit.no" nocase
    $bank01e0 = ".novit.no" nocase
    $bank01e1 = ".novit.no" nocase
    $bank01e2 = ".smn.no" nocase
    $bank01e3 = ".novit.no" nocase
    $bank01e4 = ".novit.no" nocase
    $bank01e5 = ".megabyte.net" nocase
    $bank01e6 = ".bcee.lu" nocase
    $bank01e7 = ".creditlyonnais.lu" nocase
    $bank01e8 = ".innet.net" nocase
    $bank01e9 = ".kbl.lu" nocase
    $bank01ea = ".bil.lu" nocase
    $bank01eb = ".banqueucl.lu" nocase
    $bank01ec = ".swconsult.ch" nocase
    $bank01ed = ".llb.li" nocase
    $bank01ee = ".lanet.lv" nocase
    $bank01ef = ".rbu.vernet.lv" nocase
    $bank01f0 = ".lain.bkc.lv" nocase
    $bank01f1 = ".parexnet.lv" nocase
    $bank01f2 = ".tkb.lv" nocase
    $bank01f3 = ".dlb.bkc.lv" nocase
    $bank01f4 = ".mkb.hu" nocase
    $bank01f5 = ".tke.gr" nocase
    $bank01f6 = ".etba.gr" nocase
    $bank01f7 = ".kapatel.gr" nocase
    $bank01f8 = ".tinet.ch" nocase
    $bank01f9 = ".tinet.ch" nocase
    $bank01fa = ".juliusbaer.com" nocase
    $bank01fb = ".vontobel.ch" nocase
    $bank01fc = ".bcf.ch" nocase
    $bank01fd = ".bgl.ch" nocase
    $bank01fe = ".hottinger.com" nocase
    $bank01ff = ".cogeba.ch" nocase
    $bank0200 = ".mbczh.ch" nocase
    $bank0201 = ".swconsult.ch" nocase
    $bank0202 = ".ska.com" nocase
    $bank0203 = ".tgkb.ch" nocase
    $bank0204 = ".urkb.ch" nocase
    $bank0205 = ".zhkb.ch" nocase
    $bank0206 = ".bnu.pt" nocase
    $bank0207 = ".bpatlantico.pt" nocase
    $bank0208 = ".bcf.pt" nocase
    $bank0209 = ".bes.pt" nocase
    $bank020a = ".banif.pt" nocase
    $bank020b = ".barclays.pt" nocase
    $bank020c = ".cgd.pt" nocase
    $bank020d = ".cisf.pt" nocase
    $bank020e = ".mayo-ireland.ie" nocase
    $bank020f = ".webnet.ie" nocase
    $bank0210 = ".365online.com" nocase
    $bank0211 = ".ebs.ie" nocase
    $bank0212 = ".bga.it" nocase
    $bank0213 = ".carige.it" nocase
    $bank0214 = ".bci.it" nocase
    $bank0215 = ".bcoopimola.it" nocase
    $bank0216 = ".lavalsabbina.it" nocase
    $bank0217 = ".bcc.it" nocase
    $bank0218 = ".bcccst.it" nocase
    $bank0219 = ".val.it" nocase
    $bank021a = ".bcc.cremonese.it" nocase
    $bank021b = ".ets.it" nocase
    $bank021c = ".net1.it" nocase
    $bank021d = ".agrobresciano.it" nocase
    $bank021e = ".bccbarlassina.com" nocase
    $bank021f = ".bcc.it" nocase
    $bank0220 = ".bcc.carugate.mi.it" nocase
    $bank0221 = ".diel.it" nocase
    $bank0222 = ".bccgarda.numerica.it" nocase
    $bank0223 = ".romagna.com" nocase
    $bank0224 = ".bccfiuggi.it" nocase
    $bank0225 = ".bcc.it" nocase
    $bank0226 = ".bccsgv.it" nocase
    $bank0227 = ".media.it" nocase
    $bank0228 = ".bccsanteramo.it" nocase
    $bank0229 = ".bcctriuggio.it" nocase
    $bank022a = ".bccvdc.it" nocase
    $bank022b = ".bccfc.it" nocase
    $bank022c = ".bga.it" nocase
    $bank022d = ".biemmepro.it" nocase
    $bank022e = ".bnl.it" nocase
    $bank022f = ".bpam.it" nocase
    $bank0230 = ".bpci.it" nocase
    $bank0231 = ".bpf.it" nocase
    $bank0232 = ".bplazio.it" nocase
    $bank0233 = ".popvoba.it" nocase
    $bank0234 = ".bpa.it" nocase
    $bank0235 = ".bpb.it" nocase
    $bank0236 = ".meda.it" nocase
    $bank0237 = ".poplodi.it" nocase
    $bank0238 = ".bpm.it" nocase
    $bank0239 = ".bpn.it" nocase
    $bank023a = ".bpb.it" nocase
    $bank023b = ".bpv.it" nocase
    $bank023c = ".xnet.it" nocase
    $bank023d = ".popvi.it" nocase
    $bank023e = ".bpci.it" nocase
    $bank023f = ".bsp.it" nocase
    $bank0240 = ".ambro.it" nocase
    $bank0241 = ".bancodisicilia.it" nocase
    $bank0242 = ".cariverona.it" nocase
    $bank0243 = ".crtn.it" nocase
    $bank0244 = ".caribusiness.it" nocase
    $bank0245 = ".sgol.it" nocase
    $bank0246 = ".crcarpi.it" nocase
    $bank0247 = ".romagna.com" nocase
    $bank0248 = ".caricast.it" nocase
    $bank0249 = ".paginegialle.it" nocase
    $bank024a = ".crimola.it" nocase
    $bank024b = ".arcanet.it" nocase
    $bank024c = ".cariprpc.pr.it" nocase
    $bank024d = ".caripisa.it" nocase
    $bank024e = ".iper.net" nocase
    $bank024f = ".omniway.sm" nocase
    $bank0250 = ".carisa.it" nocase
    $bank0251 = ".carispe.it" nocase
    $bank0252 = ".start.it" nocase
    $bank0253 = ".cassalombarda.it" nocase
    $bank0254 = ".cracantu.it" nocase
    $bank0255 = ".cracastelgoffredo.it" nocase
    $bank0256 = ".crbvfbcc.it" nocase
    $bank0257 = ".sunrise.it" nocase
    $bank0258 = ".well.it" nocase
    $bank0259 = ".delta.it" nocase
    $bank025a = ".ruralerovereto.it" nocase
    $bank025b = ".crsbc.it" nocase
    $bank025c = ".cassamarca.it" nocase
    $bank025d = ".creberg.it" nocase
    $bank025e = ".credit.it" nocase
    $bank025f = ".bnl.it" nocase
    $bank0260 = ".bcc.it" nocase
    $bank0261 = ".ipacri.it" nocase
    $bank0262 = ".mbres.it" nocase
    $bank0263 = ".mediocredito.fvg.it" nocase
    $bank0264 = ".medioumbria.it" nocase
    $bank0265 = ".mfc.it" nocase
    $bank0266 = ".mediolanum.it" nocase
    $bank0267 = ".nbctkb.it" nocase
    $bank0268 = ".1822direkt.com" nocase
    $bank0269 = ".adig.de" nocase
    $bank026a = ".americanexpress.de" nocase
    $bank026b = ".maffei.de" nocase
    $bank026c = ".bkm.de" nocase
    $bank026d = ".schwaebisch-hall.de" nocase
    $bank026e = ".bbs-sachsen.de" nocase
    $bank026f = ".comdirect.de" nocase
    $bank0270 = ".dbresearch.com" nocase
    $bank0271 = ".dit.de" nocase
    $bank0272 = "pekao24.pl" nocase
    $bank0273 = ".gallinat.de" nocase
    $bank0274 = ".heimstatt.de" nocase
    $bank0275 = ".essenhyp.de" nocase
    $bank0276 = ".lrp.de" nocase
    $bank0277 = ".lbs-hamburg.de" nocase
    $bank0278 = ".lbs-wuertt.de" nocase
    $bank0279 = ".leonberger.de" nocase
    $bank027a = ".lhb.de" nocase
    $bank027b = ".nordlb.de" nocase
    $bank027c = ".olb.de" nocase
    $bank027d = ".raiba-beilngries.de" nocase
    $bank027e = ".dresdner-rb.kontodirekt.de" nocase
    $bank027f = ".rberding.de" nocase
    $bank0280 = ".rb-eschlkam-neukirchen.de" nocase
    $bank0281 = ".raiba-fluorn-winzeln.rwg.de" nocase
    $bank0282 = ".rb-frankenhardt-stimpfach.de" nocase
    $bank0283 = ".rbgarrel.de" nocase
    $bank0284 = ".rb-graefo.de" nocase
    $bank0285 = ".rbk-haag-gars.de" nocase
    $bank0286 = ".raiba-haibach.de" nocase
    $bank0287 = ".raiba-hoes.de" nocase
    $bank0288 = ".raiba-ichenhausen.de" nocase
    $bank0289 = ".direktpro.com" nocase
    $bank028a = ".rb-ismaning.de" nocase
    $bank028b = ".rb-kimi.de" nocase
    $bank028c = ".raiba-moembris.de" nocase
    $bank028d = ".raiba-neuler.rwg.de" nocase
    $bank028e = ".rb-nordspessart-freigericht.de" nocase
    $bank028f = ".raibaschleissheim.de" nocase
    $bank0290 = ".vb-rb-passau-freyung.de" nocase
    $bank0291 = ".rottaler-raiba.de" nocase
    $bank0292 = ".raiba-regenstauf.de" nocase
    $bank0293 = ".vb-rb-riedlingen.de" nocase
    $bank0294 = ".raiba-sob.de" nocase
    $bank0295 = ".raiba-voba.de" nocase
    $bank0296 = ".rvb-varel-zetel.de" nocase
    $bank0297 = ".sachsenlb.de" nocase
    $bank0298 = ".santander.de" nocase
    $bank0299 = ".socgen.de" nocase
    $bank029a = ".sparda-hh.de" nocase
    $bank029b = ".deka.de" nocase
    $bank029c = ".ksk-alzey.de" nocase
    $bank029d = ".ksk-bernkastel-wittlich.de" nocase
    $bank029e = ".kskcalw.de" nocase
    $bank029f = ".kskcochem-zell.de" nocase
    $bank02a0 = ".sparkasse-ebersberg.de" nocase
    $bank02a1 = ".es.ksk.de" nocase
    $bank02a2 = ".kreissparkasse-heinsberg.de" nocase
    $bank02a3 = ".ksk-koeln.de" nocase
    $bank02a4 = ".kskkusel.de" nocase
    $bank02a5 = ".sparkasse-lichtenfels.de" nocase
    $bank02a6 = ".snet.de" nocase
    $bank02a7 = ".ksk-stade.de" nocase
    $bank02a8 = ".ksk-tuebingen.de" nocase
    $bank02a9 = ".lzo.com" nocase
    $bank02aa = ".osgv.de" nocase
    $bank02ab = ".sparkasse-bad-hersfeld-rotenburg.de" nocase
    $bank02ac = ".sparkasse-radevormwald.de" nocase
    $bank02ad = ".sparkasse-ravensburg.de" nocase
    $bank02ae = ".sparkasse.net" nocase
    $bank02af = ".sparkasse-werra-meissner.de" nocase
    $bank02b0 = ".stadtsparkasse-aichach.de" nocase
    $bank02b1 = ".sskba.de" nocase
    $bank02b2 = "sskduesseldorf.de" nocase
    $bank02b3 = ".sparkasse-magdeburg.de" nocase
    $bank02b4 = ".stadtsparkasse-nuernberg.de" nocase
    $bank02b5 = ".stadtsparkasse-remscheid.de" nocase
    $bank02b6 = ".suedboden.de" nocase
    $bank02b7 = ".vbk-du.de" nocase
    $bank02b8 = ".vb-badfriedrichshall.de" nocase
    $bank02b9 = ".voba-bensheim.de" nocase
    $bank02ba = ".voba-bes-boe.de" nocase
    $bank02bb = ".bischofsheimer-vb.de" nocase
    $bank02bc = ".vb-bocholt.de" nocase
    $bank02bd = ".borkenervb.de" nocase
    $bank02be = ".voba-brv.de" nocase
    $bank02bf = ".vb-brilon.de" nocase
    $bank02c0 = "b-bruchsal.de" nocase
    $bank02c1 = ".vb-ammerland.de" nocase
    $bank02c2 = ".vb-eppingen.de" nocase
    $bank02c3 = ".cymagic.com" nocase
    $bank02c4 = ".mmedia-ge.de" nocase
    $bank02c5 = ".genoba-meckenbeuren.rwg.de" nocase
    $bank02c6 = ".vb-greven.de" nocase
    $bank02c7 = ".voba-gg.de" nocase
    $bank02c8 = ".vb-hamm.de" nocase
    $bank02c9 = ".vbhan.de" nocase
    $bank02ca = ".heidenheimer-voba.de" nocase
    $bank02cb = ".vbu.wgv.de" nocase
    $bank02cc = ".vbketsch.de" nocase
    $bank02cd = ".vb-lahr.de" nocase
    $bank02ce = ".vblehrte.genonord.de" nocase
    $bank02cf = ".voba-main-taunus.de" nocase
    $bank02d0 = ".voba-ober-moerlen.de" nocase
    $bank02d1 = ".vb-reutlingen.de" nocase
    $bank02d2 = ".vb-rheda-wd.de" nocase
    $bank02d3 = ".vb-rhein-wupper.de" nocase
    $bank02d4 = ".vbsauerland.de" nocase
    $bank02d5 = ".vb-spiesen-elversberg.de" nocase
    $bank02d6 = ".vbstadthagen.genonord.de" nocase
    $bank02d7 = ".hellwegeranzeiger.de" nocase
    $bank02d8 = ".vilstal.net" nocase
    $bank02d9 = ".wb-aktuell.com" nocase
    $bank02da = ".vb-wolfratshausen.de" nocase
    $bank02db = ".bristol-west.co.uk" nocase
    $bank02dc = ".cheltglos.co.uk" nocase
    $bank02dd = ".ebrd.com" nocase
    $bank02de = ".ftbni.com" nocase
    $bank02df = ".hdb.co.uk" nocase
    $bank02e0 = ".hsbcib.com" nocase
    $bank02e1 = ".hsbcgroup.com" nocase
    $bank02e2 = ".mhbs.co.uk" nocase
    $bank02e3 = ".natdsionwidde.co.auk" nocase
    $bank02e4 = ".natwest.co.uk" nocase
    $bank02e5 = ".rbos.co.uk" nocase
    $bank02e6 = ".sbil.co.uk" nocase
    $bank02e7 = ".careermosaic.com" nocase
    $bank02e8 = "kb24.pl" nocase
    $bank02e9 = ".abnamro.nl" nocase
    $bank02ea = ".bng.nl" nocase
    $bank02eb = ".friba.nl" nocase
    $bank02ec = ".vanlanschot.nl" nocase
    $bank02ed = ".veronica.nl" nocase
    $bank02ee = ".limbu.nl" nocase
    $bank02ef = ".bmo.com" nocase
    $bank02f0 = ".desjardins.com" nocase
    $bank02f1 = ".canadatrust.com" nocase
    $bank02f2 = ".citizenstrust.ca" nocase
    $bank02f3 = ".coopcb.com" nocase
    $bank02f4 = ".cdb.com.cy" nocase
    $bank02f5 = ".fbme.com" nocase
    $bank02f6 = ".sgcyprus.com" nocase
    $bank02f7 = ".frostbank.com" nocase
    $bank02f8 = ".mibank.com" nocase
    $bank02f9 = ".floridagulfbank.com" nocase
    $bank02fa = ".ebanking-services.com" nocase
    $bank02fb = "commerceonlinebanking.com" nocase
    $bank02fc = ".warwickcreditunion.com.au" nocase
    $bank02fd = ".qccu.com.au" nocase
    $bank02fe = "ib.boq.com.au" nocase
    $bank02ff = "secure.ampbanking.com" nocase
    $bank0300 = "internetbanking.suncorpmetway.com.au" nocase
    $bank0301 = "online.hbs.net.au" nocase
    $bank0302 = "online.mecu.com.au" nocase
    $bank0303 = "amp.com.au" nocase
    $bank0304 = ".tsw.com.au" nocase
    $bank0306 = ".rbsdigital.com" nocase
    $bank0307 = ".netspend.com" nocase
    $bank0308 = ".365online.co.uk" nocase
    $bank0309 = "ibanking.banksa.com.au" nocase
    $bank030b = "ibanking.stgeorge.com.au" nocase
    $bank030c = "westpac.com.au" nocase
    $bank030d = "probanking.procreditbank.bg" nocase
    $bank030e = ".citibank.de" nocase
    $bank030f = "arquia.es" nocase
    $bank0310 = ".uno-e.com" nocase
    $bank0311 = "privati.internetbanking.bancaintesa.it" nocase
    $bank0312 = ".gbw2.it" nocase
    $bank0313 = ".gruppocarige.it" nocase
    $bank0314 = "isideonline.it" nocase
    $bank0315 = "hb.quiubi.it" nocase
    $bank0316 = "mijn.postbank.nl" nocase
    $bank0319 = "kiwibank.co.nz" nocase
    $bank031a = "secure.inteligo.com.pl" nocase
    $bank031b = "inwestoronline.pl" nocase
    $bank031c = "ipko.pl" nocase
    $bank031f = "citibank.ru" nocase
    $bank0320 = "cardsonline-consumer.com" nocase
    $bank0321 = "home.cbonline.co.uk" nocase
    $bank0322 = ".co-operativebank.co.uk" nocase
    $bank0324 = ".banking.first-direct.com/" nocase
    $bank0325 = "halifax-online.co.uk" nocase
    $bank0326 = ".ebank.hsbc.co.uk" nocase
    $bank0329 = "moneybookers.com" nocase
    $bank032a = ".nationet.com" nocase
    $bank032f = "home.ybonline.co.uk" nocase
    $bank0330 = "altergold.com" nocase
    $bank0331 = "chaseonline.chase.com" nocase
    $bank0332 = "c-gold.com" nocase
    $bank0333 = "resources.chase.com" nocase
    $bank0336 = ".us.hsbc.com" nocase

	condition:
	any of them
}

rule browsers
{
    meta:
    description = "Indicates attempt to modify browser behavior"
    
    strings:
    $browser0 = "browser" nocase
    $browser1 = "avant" nocase
    $browser2 = "netscape" nocase fullword
    $browser3 = "flock" nocase
    $browser4 = "safari" nocase 
    $browser5 = "chrome" nocase
    $browser6 = "opera" nocase fullword
    $browser7 = "mozilla" nocase
    $browser8 = "firefox" nocase
    $browser9 = "GreenBrowser" fullword
    
    $adobe1 = "Adobe Systems Incorporated" 
    $adobe2 = "Adobe Systems Incorporated" wide
    
    condition:
    (4 of ($browser*)) and not $adobe1 and not $adobe2
}

/* CUSTOM YARA RULES */

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-10-04
	Identifier: Mirai
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_Botnet_Malware {
	meta:
		description = "Detects Mirai Botnet Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-10-04"
		hash1 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash2 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash3 = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
		hash4 = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
		hash5 = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
		hash6 = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
		hash7 = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
		hash8 = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
		hash9 = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
		hash10 = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
		hash11 = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
		hash12 = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
		hash13 = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"
	strings:
		$x1 = "POST /cdn-cgi/" fullword ascii
		$x2 = "/dev/misc/watchdog" fullword ascii
		$x3 = "/dev/watchdog" ascii
		$x4 = "\\POST /cdn-cgi/" fullword ascii
		$x5 = ".mdebug.abi32" fullword ascii

		$s1 = "LCOGQGPTGP" fullword ascii
		$s2 = "QUKLEKLUKVJOG" fullword ascii
		$s3 = "CFOKLKQVPCVMP" fullword ascii
		$s4 = "QWRGPTKQMP" fullword ascii
		$s5 = "HWCLVGAJ" fullword ascii
		$s6 = "NKQVGLKLE" fullword ascii
	condition:
		uint16(0) == 0x457f and filesize < 200KB and
		(
			( 1 of ($x*) and 1 of ($s*) ) or
			4 of ($s*)
		)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-12
   Identifier: Mirai
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_1_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
      hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
   strings:
      $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and all of them )
}

rule Miari_2_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
      $s2 = "GET /g.php HTTP/1.1" fullword ascii
      $s3 = "https://%[^/]/%s" fullword ascii
      $s4 = "pass\" value=\"[^\"]*\"" fullword ascii
      $s5 = "jbeupq84v7.2y.net" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them )
}

rule MAL_ELF_LNX_Mirai_Oct10_1 {
   meta:
      description = "Detects ELF Mirai variant"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
   strings:
      $x1 = " -r /vi/mips.bushido; "
      $x2 = "/bin/busybox chmod 777 * /tmp/" fullword ascii

      $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s2 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s3 = "POST /cdn-cgi/" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and (
         ( 1 of ($x*) and 1 of ($s*) ) or
         all of ($x*)
      )
}

rule MAL_ELF_LNX_Mirai_Oct10_2 {
   meta:
      description = "Detects ELF malware Mirai related"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
   strings:
      $c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and all of them
}

rule MAL_Mirai_Nov19_1 {
   meta:
      description = "Detects Mirai malware"
      author = "Florian Roth"
      reference = "https://twitter.com/bad_packets/status/1194049104533282816"
      date = "2019-11-13"
      hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
      hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
   strings:
      $s1 = "SERVZUXO" fullword ascii
      $s2 = "-loldongs" fullword ascii
      $s3 = "/dev/null" fullword ascii
      $s4 = "/bin/busybox" fullword ascii
      $sc1 = { 47 72 6F 75 70 73 3A 09 30 }
   condition:
      uint16(0) == 0x457f and filesize <= 100KB and 4 of them
}