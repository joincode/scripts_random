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
git clone https://github.com/gr4ym4ntx/attackintel.git
#authtool
git clone https://github.com/fusionbox/django-authtools.git
#autocrack
git clone https://github.com/timbo05sec/autocrack.git
#AutoNessus
git clone https://github.com/redteamsecurity/AutoNessus.git
#AutoNSE
git clone https://github.com/m4ll0k/AutoNSE.git
#Autopwn
git clone https://github.com/nccgroup/autopwn.git
#autorelay
git clone https://github.com/DanMcInerney/autorelay.git
git clone https://github.com/DanMcInerney/autorelay/blob/master/autorelay.py
#AutoSploit
git clone https://github.com/NullArray/AutoSploit.git
#AutoSQLi
git clone https://github.com/jesuiscamille/AutoSQLi.git
#avet
git clone https://github.com/govolution/avet.git
#backdoor-apk
git clone https://github.com/dana-at-cp/backdoor-apk.git
#backdoorme
git clone https://github.com/Kkevsterrr/backdoorme.git
#backdoorppt
git clone https://github.com/r00t-3xp10it/backdoorppt.git
#BadMod
git clone https://github.com/MrSqar-Ye/BadMod.git
#git clone https://github.com/abdulowosho/BadMod.git
#BAF
git clone https://github.com/engMaher/BAF.git
#baudline
git clone https://github.com/balint256/gr-baz/blob/master/python/baudline.py
#BeeLogger
git clone https://github.com/4w4k3/BeeLogger.git
#BinGoo
git clone https://github.com/Hood3dRob1n/BinGoo.git
#blackeye |Phishing
git clone https://github.com/thelinuxchoice/blackeye.git
#blackowl
git clone https://github.com/samyoyo/blackowl.git
#BoopSuite
git clone https://github.com/wi-fi-analyzer/BoopSuite.git
#git clone https://github.com/MisterBianco/BoopSuite.git
#Brosec
git clone https://github.com/gabemarshall/Brosec.git
#Brutal
git clone https://github.com/Screetsec/Brutal.git
#BruteSploit
git clone https://github.com/Screetsec/Brutal.git
#brutespray
git clone https://github.com/x90skysn3k/brutespray
#BruteX
git clone https://github.com/1N3/BruteX.git
#BruteXSS
git clone https://github.com/shawarkhanethicalhacker/BruteXSS-1.git
#burpa
git clone https://github.com/0x4D31/burpa.git
#BurpBounty
git clone https://github.com/wagiro/BurpBounty.git
#BurpSuite_Pro_v1.7.32
git clone https://github.com/sumas/BurpSuite_Pro_v1.7.32.git
#cangibrina
git clone https://github.com/fnk0c/cangibrina.git
#catphish
git clone https://github.com/ring0lab/catphish.git
#CHAOS
git clone https://github.com/tiagorlampert/CHAOS.git
#CloudFail
git clone https://github.com/m0rtem/CloudFail.git
#cloudfrunt
git clone https://github.com/aws-samples/aws-cloudfront-samples.git
#CMSeeK
git clone https://github.com/Tuhinshubhra/CMSeeK.git
#CMSmap
git clone https://github.com/Dionach/CMSmap.git
#cobaltstrike
echo "CobaltStrike 404"
#credmap
git clone https://github.com/lightos/credmap.git
#Crips
git clone https://github.com/Manisso/Crips.git
#crowbar
git clone https://github.com/crowbar/crowbar.git
#csrfpocmaker
git clone https://github.com/merttasci/csrf-poc-generator.git
#CVE-2017-0199
git clone https://github.com/bhdresh/CVE-2017-0199.git
#CVE-2017-7494
git clone https://github.com/opsxcq/exploit-CVE-2017-7494.git
#CyberScan
git clone https://github.com/medbenali/CyberScan.git
#Dagon
git clone https://github.com/Ekultek/Dagon.git
#Debinject
git clone https://github.com/UndeadSec/Debinject.git
#dedsploit
git clone https://github.com/ex0dus-0x/dedsploit.git
#Devploit
git clone https://github.com/joker25000/Devploit.git
#dirhunt-develop
git clone https://github.com/ClavinJune/dirhunter.git
git clone https://github.com/Nekmo/dirhunt.git
#DKMC
git clone https://github.com/Mr-Un1k0d3r/DKMC.git
#domainhunter
git clone https://github.com/threatexpress/domainhunter.git
#DorkFinder
git clone https://github.com/raphaelland/Dork-Finder.git
#DorkMe
git clone https://github.com/blueudp/DorkMe.git
#dotdotpwn
git clone https://github.com/wireghoul/dotdotpwn.git
#doublepulsar-c2-traffic-decryptor
git clone https://github.com/countercept/doublepulsar-c2-traffic-decryptor.git
#doublepulsar-detection
git clone https://github.com/countercept/doublepulsar-detection-script.git
#Dr0p1t-Framework
git clone https://github.com/D4Vinci/Dr0p1t-Framework.git
#Dracnmap
git clone https://github.com/Screetsec/Dracnmap.git
#drupwn
git clone https://github.com/immunIT/drupwn.git
#D-TECT
git clone https://github.com/shawarkhanethicalhacker/D-TECT-1.git
#DumpsterDiver
git clone https://github.com/securing/DumpsterDiver.git
#EagleEye
git clone https://github.com/ThoughtfulDev/EagleEye.git
#EaST
git clone https://github.com/argman/EAST.git
#Easy-Binder
git clone https://github.com/ljessendk/easybinder.git
#Ebowla
git clone https://github.com/Genetic-Malware/Ebowla.git
#EggShell
git clone https://github.com/neoneggplant/EggShell.git
#Empire-GUI
git clone https://github.com/EmpireProject/Empire-GUI.git
#Eternalblue-Doublepulsar-Metasploit
git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git
#eternal_scanner
git clone https://github.com/peterpt/eternal_scanner.git
#Evil-Droid
git clone https://github.com/M4sc3r4n0/Evil-Droid.git
#exploitdb
git clone https://github.com/offensive-security/exploitdb.git
#ExploitOnCLI
git clone https://github.com/r00tmars/ExploitOnCLI.git
#exploitpack
git clone https://github.com/juansacco/exploitpack.git
#exploits
git clone https://github.com/WindowsExploits/Exploits.git
#ezsploit
git clone https://github.com/rand0m1ze/ezsploit.git
#FakeImageExploiter
git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git
#Findsploit
git clone https://github.com/1N3/Findsploit.git
#fipy
git clone https://github.com/usnistgov/fipy.git
#Galileo
git clone https://github.com/m4ll0k/Galileo.git
#gasmask |OSINT
git clone https://github.com/twelvesec/gasmask.git
#gcat
git clone https://github.com/byt3bl33d3r/gcat.git
#getsploit
git clone https://github.com/vulnersCom/getsploit.git
#GhostInTheNet
git clone https://github.com/cryptolok/GhostInTheNet.git
#Git_Pentesting_Toolkit
git clone https://github.com/ANK1036Official/Git_Pentesting_Toolkit.git
#Gloom-Framework
git clone https://github.com/StreetSec/Gloom-Framework.git
#Goohak
git clone https://github.com/1N3/Goohak.git
#Grok-backdoor
git clone https://github.com/deepzec/Grok-backdoor.git
#GyoiThon
git clone https://github.com/gyoisamurai/GyoiThon.git
#hackbox
git clone https://github.com/samhaxr/hackbox.git
#hackerbot
git clone https://github.com/omergunal/hackerbot.git
#hakkuframework
git clone https://github.com/4shadoww/hakkuframework.git
#Hash-Buster
git clone https://github.com/s0md3v/Hash-Buster.git
#hate_crack
git clone https://github.com/trustedsec/hate_crack.git
#HTTPoxyScan
git clone https://github.com/1N3/HTTPoxyScan.git
#Hydrator
git clone https://github.com/DocNow/hydrator.git
#ID-entify
git clone https://github.com/BillyV4/ID-entify.git
#Idisagree
git clone https://github.com/UndeadSec/Idisagree.git
#Infoga
git clone https://github.com/m4ll0k/Infoga.git
#Injectorist
git clone https://github.com/Enixes/Injectorist.git
#Insanity-Framework
git clone https://github.com/4w4k3/Insanity-Framework.git
#InstaBrute
git clone https://github.com/Ha3MrX/InstaBrute.git
#isf
git clone https://github.com/dark-lbp/isf.git
#isthisipbad
git clone https://github.com/jgamblin/isthisipbad.git
#JoomlaScan
git clone https://github.com/rezasp/joomscan.git
git clone https://github.com/drego85/JoomlaScan.git
#KatanaFramework
git clone https://github.com/PowerScript/KatanaFramework.git
#killchain
git clone https://github.com/ruped24/killchain.git
#kimi
git clone https://github.com/ChaitanyaHaritash/kimi.git
#koadic
git clone https://github.com/zerosum0x0/koadic.git
#kwetza
git clone https://github.com/sensepost/kwetza.git
#LALIN
git clone https://github.com/Screetsec/LALIN.git
#LaZagneForensic
git clone https://github.com/AlessandroZ/LaZagneForensic.git
#LaZagne
git clone https://github.com/AlessandroZ/LaZagne.git
#leviathan
git clone https://github.com/tearsecurity/leviathan.git
#LFiFreak
git clone https://github.com/OsandaMalith/LFiFreak.git
#LFISuite
git clone https://github.com/D35m0nd142/LFISuite.git
#liffy
git clone https://github.com/hvqzao/liffy.git
#LinDrop
git clone https://github.com/cys3c/LinDrop/blob/master/lindrop.py
#linux_screenshot_xwindows
git clone https://github.com/eurecom-s3/linux_screenshot_xwindows.git
#litesploit
git clone https://github.com/Exploit-install/litesploit.git
#Log-killer
git clone https://github.com/Rizer0/Log-killer.git
#MalScan
git clone https://github.com/malscan/malscan.git
#MassBleed
git clone https://github.com/1N3/MassBleed.git
#massExpConsole
git clone https://github.com/jm33-m0/mec.git
#Matroschka
git clone https://github.com/fbngrm/Matroschka.git
#Mercury
git clone https://github.com/MetaChar/Mercury.git
#metateta
git clone https://github.com/WazeHell/metateta.git
#Meterpreter_Paranoid_Mode-SSL
git clone https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL.git
#morpheus
git clone https://github.com/r00t-3xp10it/morpheus.git
#morphHTA
git clone https://github.com/vysec/morphHTA.git
#mpc
git clone https://github.com/orangeduck/mpc.git
#ms17
git clone https://github.com/worawit/MS17-010.git
#msdat
git clone https://github.com/quentinhardy/msdat.git
#msfvenom_custom_encoding
git clone https://github.com/offsecginger/msfvenom_custom_encoding.git
#msploitego
git clone https://github.com/shizzz477/msploitego.git
#multitor
git clone https://github.com/trimstray/multitor.git
#Namechk
git clone https://github.com/HA71/Namechk.git
#netattack2
git clone https://github.com/chrizator/netattack2.git
#netdiscover-0.3-pre-beta7
git clone https://github.com/alexxy/netdiscover.git
#netool-toolkit
git clone https://github.com/r00t-3xp10it/netool-toolkit.git
#netpwn
git clone https://github.com/3XPL017/netpwn.git
#netsec-framework
git clone https://github.com/sjbooher/netsec-framework.git
#NetZapper
git clone https://github.com/NetZapper/NetZapper.git
#nipe
git clone https://github.com/GouveaHeitor/nipe.git
#NoSQLMap-stable
git clone https://github.com/codingo/NoSQLMap.git
#nps_payload
git clone https://github.com/trustedsec/nps_payload
#NXcrypt
git clone https://github.com/Hadi999/NXcrypt.git
#oddjob
git clone https://github.com/robjg/oddjob.git
#omnibus
git clone https://github.com/chef/omnibus.git
#One-Lin3r
git clone https://github.com/D4Vinci/One-Lin3r.git
#operative-framework
git clone https://github.com/graniet/operative-framework.git
#OSPTF
git clone https://github.com/xSploited/OSPTF.git
#osrframework
git clone https://github.com/i3visio/osrframework.git
#OWASP-Nettacker
git clone https://github.com/zdresearch/OWASP-Nettacker.git
#OWASP-ZSC
git clone https://github.com/zdresearch/OWASP-ZSC.git
#PasteZort
git clone https://github.com/ZettaHack/PasteZort.git
#pasv-agrsv
git clone https://github.com/isaudits/pasv-agrsv.git
#PAYLOAD-MAKER
git clone https://github.com/g0tmi1k/mpc.git
#PenBox
git clone https://github.com/x3omdax/PenBox.git
#pentestly
git clone https://github.com/praetorian-inc/pentestly.git
#pentest-machine
git clone https://github.com/DanMcInerney/pentest-machine.git
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
