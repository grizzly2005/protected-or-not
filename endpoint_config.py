#!/usr/bin/env python3
"""
Génère les #define pour agent.exe - VERSION CORRIGÉE
"""

def generate_agent_config():
    print("="*60)
    print("config gen for node.c")
    print("="*60)
    
    host = input("\nHost/IP (ex: 18.184.107.63): ").strip().replace(" ", "")
    port = int(input("Port (ex: 12580): ").strip())
    
    if not host or not port:
        print("ERREUR: no host or port !")
        return
    
    xor_key = 0xFF
    
   
    # XOR seulement le host, PAS le null terminator!
    host_bytes = host.encode('ascii')
    xor_host = [b ^ xor_key for b in host_bytes]
    xor_host.append(0x00)  # ← Null terminator NON XOR'd!
    
    # Port XOR
    xor_port = port ^ 0xFFFF
    
    # Affichage
    print("\n" + "="*60)
    print("COPY IN node.c :")
    print("="*60 + "\n")
    
    host_hex = ", ".join(f"0x{b:02X}" for b in xor_host)
    print(f"#define WS_HOST_XOR {{{host_hex}}}")
    print(f"#define WS_PORT_OBF 0x{xor_port:04X}")
    
    # Vérification
    print("\n" + "="*60)
    print("VÉRIFICATION :")
    print("="*60)
    
    # Simule ce que le C va faire
    decoded = bytes([b ^ xor_key for b in xor_host[:-1]]).decode('ascii')
    print(f"Host decoded: [{decoded}]")
    print(f"Port decoded: {xor_port ^ 0xFFFF}")
    print(f"last byte: 0x{xor_host[-1]:02X} (need to be 0x00)")
    
    if xor_host[-1] == 0x00:
        print("\n✅ NULL TERMINATOR OK!")
    else:
        print("\n❌ ERREUR: Null terminator needed!")

if __name__ == "__main__":

    generate_agent_config()

