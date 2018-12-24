#!/bin/bash
##############################################################################
# Descricao: Tools Kali Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# Configuração inicial do Kali Linux e Instalação de ferramentas 
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID              Date   version
# Roberto.Lima    20.12.2018 0.1  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################

if [ "$EUID" -ne 0 ]
  then echo "Favor executar como root"
  exit
fi

apt-get update ; apt-get upgrade -y

cd /opt

echo "========================================================"
echo "   #    ######   #####  ####### #     #    #    #       "
echo "  # #   #     # #     # #       ##    #   # #   #       "
echo " #   #  #     # #       #       # #   #  #   #  #       "
echo "#     # ######   #####  #####   #  #  # #     # #       "
echo "####### #   #         # #       #   # # ####### #       "
echo "#     # #    #  #     # #       #    ## #     # #       "
echo "#     # #     #  #####  ####### #     # #     # ####### "
echo "========================================================"

#4nonimizer
git clone https://github.com/Hackplayers/4nonimizer.git
#a2sv
git clone https://github.com/hahwul/a2sv.git
#admin-panel-finder
git clone https://github.com/bdblackhat/admin-panel-finder.git
#airbash
git clone https://github.com/tehw0lf/airbash.git
#angryFuzzer
git clone https://github.com/ihebski/angryFuzzer.git
#anonym8
git clone https://github.com/HiroshiManRise/anonym8.git
#apk-payload-generator
git clone https://github.com/MohamedNourTN/Terminator.git
#ARCANUS
git clone https://github.com/EgeBalci/ARCANUS.git
#astroid
git clone https://github.com/M4sc3r4n0/astroid.git
#ATSCAN
git clone https://github.com/AlisamTechnology/ATSCAN.git
#ATSCAN-V3
git clone https://github.com/samyoyo/ATSCAN-V3.git
#attackintel
https://github.com/gr4ym4ntx/attackintel.git
#authtool
#autocrack
#AutoNessus
#AutoNSE
#Autopwn
#autorelay
#AutoSploit
#AutoSQLi
#avet
#backdoor-apk
#backdoorme
#backdoorppt
#BadMod
#BAF
#baudline
#BeeLogger
#BinGoo
#blackeye
#blackowl
#BoopSuite
#Brosec
#Brutal
#BruteSploit
#brutespray
#BruteX
#BruteXSS
#burpa
#BurpBounty
#BurpSuite_Pro_v1.7.32
#cangibrina
#catphish
#CHAOS
#CloudFail
#cloudfrunt
#CMSeeK
#CMSmap
#cobaltstrike
#credmap
#Crips
#crowbar
#csrfpocmaker
#CVE-2017-0199
#CVE-2017-7494
#CyberScan
#Dagon
#Debinject
#dedsploit
#Devploit
#dirhunt-develop
#DKMC
#domainhunter
#DorkFinder
#DorkMe
#dotdotpwn
#doublepulsar-c2-traffic-decryptor
#doublepulsar-detection
#Dr0p1t-Framework
#Dracnmap
#drupwn
#D-TECT
#DumpsterDiver
#EagleEye
#EaST
#Easy-Binder
#Ebowla
#EggShell
#Empire-GUI
#Empire-GUI
#Eternalblue-Doublepulsar-Metasploit
#eternal_scanner
#Evil-Droid
#exploitdb
#ExploitOnCLI
#exploitpack
#exploits
#ezsploit
#FakeImageExploiter
#Findsploit
#fipy
#Galileo
#gasmask
#gcat
#getsploit
#GhostInTheNet
#Git_Pentesting_Toolkit
#Gloom-Framework
#Goohak
#Grok-backdoor
#GyoiThon
#hackbox
#hackerbot
#hakkuframework
#Hash-Buster
#hate_crack
#HTTPoxyScan
#Hydrator
#ID-entify
#Idisagree
#Infoga
#Injectorist
#Insanity-Framework
#InstaBrute
#isf
#isthisipbad
#JoomlaScan
#KatanaFramework
#killchain
#kimi
#koadic
#kwetza
#LALIN
#LaZagneForensic
#LaZagne
#leviathan
#LFiFreak
#LFISuite
#liffy
#LinDrop
#linux_screenshot_xwindows
#litesploit
#Log-killer
#MalScan
#MassBleed
#massExpConsole
#Matroschka
#Mercury
#metateta
#Meterpreter_Paranoid_Mode-SSL
#morpheus
#morphHTA
#mpc
#ms17
#msdat
#msfvenom_custom_encoding
#msploitego
#multitor
#Namechk
#netattack2
#netdiscover-0.3-pre-beta7
#netool-toolkit
#netpwn
#netsec-framework
#NetZapper
#nipe
#NoSQLMap-stable
#nps_payload
#NXcrypt
#oddjob
#omnibus
#One-Lin3r
#operative-framework
#OSPTF
#osrframework
#OWASP-Nettacker
#OWASP-ZSC
#PasteZort
#pasv-agrsv
#PAYLOAD-MAKER
#PenBox
#pentestly
#pentest-machine
#ph0neutria
#phpsploit
#PoizonProxyProcessor
#portSpider
#PortWitness
#PowerScript-KatanaFramework-ba1b7cd
#ptf-1.14
#pureblood
#pwnedOrNot
#Pybelt
#PyBozoCrack
#pydictor
#Pymap-Scanner
#python_gdork_sqli
#python-hacklib
#Quack
#RC-exploiter
#ReconCat
#ReconDog
#RED_HAWK
#RED_HAWK
#ReelPhish
#reGeorg
#ReverseAPK
#riwifshell
#RsaCtfTool
#sAINT
#Samurai
#scanless
#scythian
#SecLists
#SEF
#sharesniffer
#ShellPop
#shellsploit-framework
#shocker
#Shortcut-Payload-Generator
#SigPloit
#simple-ducky
#SleuthQL
#smap
#SMBrute
#smod
#Sn1per
#SPF
#SpookFlare
#sqli-scanner
#sqliv
#sqlivulscan
#sqltools
#Stitch
#Striker
#Struts2Shell
#Sublist3r
#SuperMicro-Password-Scanner
#TekDefense-Automater
#Terminator
#The-Auto-Pentest
#The-Axer
#TheDoc
#TheFatRat
#theharvester-gui
#TNscan
#TopHat
#torghost
#tor_ip_switcher
#toriptables2
#tplmap
#trape
#Trity
#TrustlookWannaCryToolkit
#tulpar
#uarfcn
#Umbrella
#V3n0M-Scanner
#Vanquish
#Veil-Ordnance
#venomdroid3
#venom
#virusmakers
#viSQL
#waidps
#WarChild
#WeBaCoo
#webkiller
#webpwn3r
#Webscan
#weeman
#wePWNise
#wifi
#Winpayloads
#wirespy
#wordlists
#wpCrack
#wsuxploit
#XAttacker
#xerosploit
#xerxes
#Xpath
#xsscrapy
#xss-payload-list
#XssPy
#XSSTracer
#XSStrike
#XSStrike
#zarp
#zirikatu
#Base64ImageEncoder-Decoder.exe
#BlackFilePumper.exe
#BTIHTMLEncoder-Decoder.exe
#BTIMultiSiteChecker.exe
#BTIReverseIPDomainCheck.exe
#clickjacking.py
#CloudFlareResolver.exe
#DefacePageCreated.exe
#EternalsExtensionSpoofer.exe
#Extension_Spoofer.exe
#ezDataBase_Defacer.exe
#frameworks.tar.bz2
#Halcyon_IDE_v2.0.jar
#HighLifeCrypter.exe
#Illusi0nCrypter.exe
#Image+TextFileBinder.exe
#InfamousTool.exe
#inspector.py
#ipscan-win32-3.2.exe
#Ip-Tool.jar
#LegionEliteProxiesGrabber.exe
#MooreRPortScanner.exe
#Potato.exe
#Pr0xYGrabber.exe
#ProPort.exe
#ProxyFinder.exe
#PwnScriptum_RCE_exploit.py
#replace.sh
#roothelper.sh
#ShockLabsFileBinder.exe
#SimpleBinder.exe
#SQL-nightmare.exe
#TripleX-Crypter.exe
#update_git_repos.sh
#ZeusCrypter.exe

echo "-----------------------------------"
echo "        Wireless Tools             "
echo "-----------------------------------"
#3vilTwinAttacker
#ADSLPT-WPA
#aircracktest
#airfree-wt
#airgeddon
#Airlin
#airodump_mod
#Airodump_Scan_Visualizer
#airport-sniffer
#airssl
#airstorm
#Airvengers
#apfucker
#autohsgui
#autopixie
#auto-reaver
#belkin4xx
#belkin-wpspin
#BrutusV4.7
#cewl
#chap2asleap
#chapcrack
#dlinkdecrypter
#eapmd5hcgen
#erratasec
#EvilAPDefender
#F.Society
#fakeAP
#fake-ap3.py
#fibercrunch
#fluxion
#generadorDiccio
#Ghost-Phisher
#gigawordlist
#HandShaker
#hashcatgui
#hccap
#Her0xDa-Wps-Cracker
#hostnamechanger
#hotspot_autologin
#HT-WPS-Breaker
#hydra-wizard
#Jazztel-StopGo
#mac2wepkey
#MITMf
#mitm-rogue-WiFi-AP
#MWF
#ONO_Netgear_WPA2_Hack
#Passthrough
#PiWAT
#PureNetworks
#pyxiewps_WPS
#pyxiewps_WPShack-Python
#pyxiewps_WPShack-Python
#reaver.rd
#reaver-spoof
#reaver-webui
#reaver-wps-fork-t6x
#ReVdK3-r3
#scapy-deauth
#TPLink-AttackDictionary
#U-Cracker
#varmacreaversav9-93
#varmacscan2-8
#VMR-MDK
#Wi-fEye
#wifiarnet
#WiFi-autopwner
#wifi_check
#wifi-contour
#wificurse
#wifi-hacker
#wifi-harvester
#wifi-linux-rssi
#Wifi_Metropolis
#wifimonster
#wifiphisher
#WifiScanAndMap
#wifite2
#wifite-mod-pixiewps
#wifite-ng
#wireless-ids
#wireless-info
#Wireless-Sniffer
#wlanreaver
#word-list-compress
#WPA2-HalfHandshake-Crack
#wpa-autopwn
#wpa-bruteforcer
#WpaExtractor
#wperf
#wps-connect
#wpscrack
#wpsdb
#WPSIG
#wpspin
#WPSPIN
#Wpspingenerator
#wps_scanner
#wwcleaner
#ejacoolas.sh
#ESSIDPROBEWPA3-21.sh
#reaver-wrapper.pl
#requirements.txt
#update_git_repos.sh
#WPSCrackGUI.gambas
#
# 
#
echo "-----------------------------------"
echo "       Exploits (to analyze):      "
echo "-----------------------------------"
#EARLYSHOVEL RedHat 7.0 – 7.1 Sendmail 8.11.x exploit
#EBBISLAND (EBBSHAVE) root RCE via RPC XDR overflow in Solaris 6, 7, 8, 9 & 10 (possibly newer) both SPARC and x86.
#ECHOWRECKER remote Samba 3.0.x Linux exploit.
#EASYBEE appears to be an MDaemon email server vulnerability
#EASYFUN EasyFun 2.2.0 Exploit for WDaemon / IIS MDaemon/WorldClient pre 9.5.6
#EASYPI is an IBM Lotus Notes exploit that gets detected as Stuxnet
#EWOKFRENZY is an exploit for IBM Lotus Domino 6.5.4 & 7.0.2
#EXPLODINGCAN is an IIS 6.0 exploit that creates a remote backdoor
#ETERNALROMANCE is a SMB1 exploit over TCP port 445 which targets XP, 2003, Vista, 7, Windows 8, 2008, 2008 R2, and gives SYSTEM privileges (MS17-010)
#EDUCATEDSCHOLAR is a SMB exploit (MS09-050)
#EMERALDTHREAD is a SMB exploit for Windows XP and Server 2003 (MS10-061)
#EMPHASISMINE is a remote IMAP exploit for IBM Lotus Domino 6.6.4 to 8.5.2
#ENGLISHMANSDENTIST sets Outlook Exchange WebAccess rules to trigger executable code on the client’s side to send an email to other users
#EPICHERO 0-day exploit (RCE) for Avaya Call Server
#ERRATICGOPHER is a SMBv1 exploit targeting Windows XP and Server 2003
#ETERNALSYNERGY is a SMBv3 remote code execution flaw for Windows 8 and Server 2012 SP0 (MS17-010)
#ETERNALBLUE is a SMBv2 exploit for Windows 7 SP1 (MS17-010)
#ETERNALCHAMPION is a SMBv1 exploit
#ESKIMOROLL is a Kerberos exploit targeting 2000, 2003, 2008 and 2008 R2 domain controllers
#ESTEEMAUDIT is an RDP exploit and backdoor for Windows Server 2003
#ECLIPSEDWING is an RCE exploit for the Server service in Windows Server 2008 and later (MS08-067)
#ETRE is an exploit for IMail 8.10 to 8.22
#ETCETERABLUE is an exploit for IMail 7.04 to 8.05
#FUZZBUNCH is an exploit framework, similar to MetaSploit
#ODDJOB is an implant builder and C&C server that can deliver exploits for Windows 2000 and later, also not detected by any AV vendors
#EXPIREDPAYCHECK IIS6 exploit
#EAGERLEVER NBT/SMB exploit for Windows NT4.0, 2000, XP SP1 & SP2, 2003 SP1 & Base Release
#EASYFUN WordClient / IIS6.0 exploit
#ESSAYKEYNOTE
#EVADEFRED
echo "------------------------------"
echo "      Utilities:              "
echo "------------------------------"
#PASSFREELY utility which “Bypasses authentication for Oracle servers”
#SMBTOUCH check if the target is vulnerable to samba exploits like ETERNALSYNERGY, ETERNALBLUE, ETERNALROMANCE
#ERRATICGOPHERTOUCH Check if the target is running some RPC
#IISTOUCH check if the running IIS version is vulnerable
#RPCOUTCH get info about windows via RPC
#DOPU used to connect to machines exploited by ETERNALCHAMPIONS
#NAMEDPIPETOUCH Utility to test for a predefined list of named pipes, mostly AV detection. User can add checks for custom named pipes.
#
# 
echo "------------------------------"
echo "      #Extra Tools:              "
echo "------------------------------"
#DandenSpritz
#FuzzBunch
echo "------------------------------"
echo "      #More tools:            "
echo "------------------------------"

#acccheck
#ace-voip
#Amap
#Automater
#bing-ip2hosts
#braa
#CaseFile
#CDPSnarf
#cisco-torch
#Cookie Cadger
#copy-router-config
#DMitry
#dnmap
#dnsenum
#dnsmap
#DNSRecon
#dnstracer
#dnswalk
#DotDotPwn
#enum4linux
#enumIAX
#Faraday
#Fierce
#Firewalk
#fragroute
#fragrouter
#Ghost Phisher
#GoLismero
#goofile
#hping3
#ident-user-enum
#InTrace
#iSMTP
#lbd
#Maltego Teeth
#masscan
#Metagoofil
#Miranda
#nbtscan-unixwiz
#Nmap
#ntop
#p0f
#Parsero
#Recon-ng
#SET
#smtp-user-enum
#snmp-check
#SPARTA
#sslcaudit
#SSLsplit
#sslstrip
#SSLyze
#THC-IPV6
#theHarvester
#TLSSLed
#twofi
#URLCrazy
#Wireshark
#WOL-E
#Xplico
echo "----------------------------"
echo "   Vulnerability Analysis   "
echo "----------------------------"
#BBQSQL
#BED
#cisco-auditing-tool
#cisco-global-exploiter
#cisco-ocs
#cisco-torch
#copy-router-config
#DBPwAudit
#Doona
#DotDotPwn
#HexorBase
#Inguma
#jSQL
#Lynis
#Nmap
#ohrwurm
#Oscanner
#Powerfuzzer
#sfuzz
#SidGuesser
#SIPArmyKnife
#sqlmap
#Sqlninja
#sqlsus
#THC-IPV6
#tnscmd10g
#unix-privesc-check
#Yersinia
#
echo "------------------------"
echo "   Exploitation Tools   "
echo "------------------------"
#Armitage
#Backdoor Factory
#BeEF
#cisco-auditing-tool
#cisco-global-exploiter
#cisco-ocs
#cisco-torch
#Commix
#crackle
#exploitdb
#jboss-autopwn
#Linux Exploit Suggester
#Maltego Teeth
#Metasploit Framework
#RouterSploit
#SET
#ShellNoob
#sqlmap
#THC-IPV6
#Yersinia
echo "------------------------"
echo "   Wireless Attacks     "
echo "------------------------"
#Aircrack-ng
#Asleap
#Bluelog
#BlueMaho
#Bluepot
#BlueRanger
#Bluesnarfer
#Bully
#coWPAtty
#crackle
#eapmd5pass
#Fern Wifi Cracker
#Ghost Phisher
#GISKismet
#Gqrx
#gr-scan
#hostapd-wpe
#kalibrate-rtl
#KillerBee
#Kismet
#mdk3
#mfcuk
#mfoc
#mfterm
#Multimon-NG
#PixieWPS
#Reaver
#redfang
#RTLSDR Scanner
#Spooftooph
#Wifi Honey
#wifiphisher
#Wifitap
#Wifite
echo "-----------------------"
echo "    #Forensics Tools   "
echo "-----------------------"
#Binwalk
#bulk-extractor
#Capstone
#chntpw
#Cuckoo
#dc3dd
#ddrescue
#DFF
#diStorm3
#Dumpzilla
#extundelete
#Foremost
#Galleta
#Guymager
#iPhone Backup Analyzer
#p0f
#pdf-parser
#pdfid
#pdgmail
#peepdf
#RegRipper
#Volatility
#Xplico
echo "---------------------"
echo "   Web Applications  "
echo "---------------------"
#apache-users
#Arachni
#BBQSQL
#BlindElephant
#Burp Suite
#CutyCapt
#DAVTest
#deblaze
#DIRB
#DirBuster
#fimap
#FunkLoad
#Gobuster
#Grabber
#jboss-autopwn
#joomscan
#jSQL
#Maltego Teeth
#PadBuster
#Paros
#Parsero
#plecost
#Powerfuzzer
#ProxyStrike
#Recon-ng
#Skipfish
#sqlmap
#Sqlninja
#sqlsus
#ua-tester
#Uniscan
#Vega
#w3af
#WebScarab
#Webshag
#WebSlayer
#WebSploit
#Wfuzz
#WPScan
#XSSer
#zaproxy
echo "------------------------"
echo "   #Stress Testing      "
echo "-------------------------"
#DHCPig
#FunkLoad
#iaxflood
#Inundator
#inviteflood
#ipv6-toolkit
#mdk3
#Reaver
#rtpflood
#SlowHTTPTest
#t50
#Termineter
#THC-IPV6
#THC-SSL-DOS
echo "-------------------------"
echo "  #Sniffing & Spoofing   "
echo "-------------------------"
#Burp Suite
#DNSChef
#fiked
#hamster-sidejack
#HexInject
#iaxflood
#inviteflood
#iSMTP
#isr-evilgrade
#mitmproxy
#ohrwurm
#protos-sip
#rebind
#responder
#rtpbreak
#rtpinsertsound
#rtpmixsound
#sctpscan
#SIPArmyKnife
#SIPp
#SIPVicious
#SniffJoke
#SSLsplit
#sslstrip
#THC-IPV6
#VoIPHopper
#WebScarab
#Wifi Honey
#Wireshark
#xspy
#Yersinia
#zaproxy
echo"----------------------"
echo "   #Password Attacks "
echo "---------------------"
#acccheck
#Burp Suite
#CeWL
#chntpw
#cisco-auditing-tool
#CmosPwd
#creddump
#crunch
#DBPwAudit
#findmyhash
#gpp-decrypt
#hash-identifier
#HexorBase
#THC-Hydra
#John the Ripper
#Johnny
#keimpx
#Maltego Teeth
#Maskprocessor
#multiforcer
#Ncrack
#oclgausscrack
#PACK
#patator
#phrasendrescher
#polenum
#RainbowCrack
#rcracki-mt
#RSMangler
#SQLdict
#Statsprocessor
#THC-pptp-bruter
#TrueCrack
#WebScarab
#wordlists
#zaproxy
echo "-----------------------"
echo "  #Maintaining Access  "
echo "------------------------"
#CryptCat
#Cymothoa
#dbd
#dns2tcp
#http-tunnel
#HTTPTunnel
#Intersect
#Nishang
#polenum
#PowerSploit
#pwnat
#RidEnum
#sbd
#U3-Pwn
#Webshells
#Weevely
#Winexe

echo "-----------------------"
echo "    #Hardware Hacking  "
echo "-----------------------"

#android-sdk
#apktool
#Arduino
#dex2jar
#Sakis3G
#smali
echo "------------------------------"
echo "      #Reverse Engineering    "
echo "------------------------------"
#apktool
#dex2jar
#diStorm3
#edb-debugger
#jad
#javasnoop
#JD-GUI
#OllyDbg
#smali
#Valgrind
#YARA
echo "----------------------------"
echo "      #Reporting Tools      "
echo "----------------------------"
#CaseFile
#CutyCapt
#dos2unix
#Dradis
#KeepNote
#MagicTree
#Metagoofil
#Nipper-ng
#pipal
