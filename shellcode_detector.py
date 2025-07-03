#!/usr/bin/env python3

import re
import math
import binascii
from collections import Counter

class ShellcodeDetector:
    
    def __init__(self):
        self.signatures = {
            "31c050682f2f7368682f62696e89e3505389e1cd80": {
                "name": "Linux execve /bin/sh",
                "platform": "Linux x86",
                "risk": "élevé"
            },
            "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ff": {
                "name": "Windows MessageBox",
                "platform": "Windows x86", 
                "risk": "moyen"
            },
            "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218": {
                "name": "Meterpreter reverse TCP",
                "platform": "Windows x64",
                "risk": "critique"
            }
        }
        
        self.dangerous_opcodes = {
            0x80: "Appel système Linux",
            0x2E: "Appel système Windows", 
            0xEB: "Saut court",
            0x33: "Opération XOR",
            0x90: "Instruction NOP",
            0x68: "Instruction PUSH"
        }
    
    def calculate_entropy(self, data):
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data)
            except:
                data = data.encode()
        
        if not data:
            return 0
            
        counts = Counter(data)
        length = len(data)
        
        entropy = 0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
            
        return entropy
    
    def detect_opcodes(self, hex_data):
        detected = []
        try:
            data = bytes.fromhex(hex_data.replace(" ", ""))
            for i, byte in enumerate(data):
                if byte in self.dangerous_opcodes:
                    detected.append({
                        'offset': i,
                        'opcode': f"0x{byte:02X}",
                        'description': self.dangerous_opcodes[byte]
                    })
        except:
            pass
        return detected
    
    def check_signatures(self, hex_data):
        hex_clean = hex_data.replace(" ", "").lower()
        for signature, info in self.signatures.items():
            if signature in hex_clean:
                return info
        return None
    
    def analyze(self, data):
        if isinstance(data, bytes):
            hex_data = data.hex()
        else:
            hex_data = data.replace(" ", "").replace("\n", "")
        
        # Vérifier les signatures connues
        signature_match = self.check_signatures(hex_data)
        
        # Calculer l'entropie
        entropy = self.calculate_entropy(hex_data)
        
        # Détecter les opcodes dangereux
        opcodes = self.detect_opcodes(hex_data)
        
        # Calculer le score de risque
        risk_score = 0
        
        if signature_match:
            risk_score = 1.0
        else:
            # Composante entropie (0-0.4)
            risk_score += min(entropy / 8.0, 0.4)
            
            # Composante opcodes (0-0.6)
            risk_score += min(len(opcodes) / 10.0, 0.6)
        
        risk_score = min(risk_score, 1.0)
        
        return {
            'signature': signature_match,
            'entropy': entropy,
            'opcodes': opcodes,
            'risk_score': risk_score,
            'is_malicious': risk_score > 0.7,
            'data_size': len(hex_data) // 2
        }
    
    def analyze_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            return self.analyze(data)
        except Exception as e:
            return {'error': str(e)}


def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Outil de détection de shellcode')
    parser.add_argument('--file', help='Analyser un fichier')
    parser.add_argument('--hex', help='Analyser une chaîne hexadécimale')
    parser.add_argument('--output', choices=['json', 'text'], default='text', help='Format de sortie')
    
    args = parser.parse_args()
    
    detector = ShellcodeDetector()
    
    if args.file:
        result = detector.analyze_file(args.file)
    elif args.hex:
        result = detector.analyze(args.hex)
    else:
        parser.print_help()
        return
    
    if args.output == 'json':
        import json
        print(json.dumps(result, indent=2))
    else:
        if 'error' in result:
            print(f"Erreur: {result['error']}")
            return
            
        print(f"Score de Risque: {result['risk_score']:.2f}")
        print(f"Entropie: {result['entropy']:.2f}")
        print(f"Taille des Données: {result['data_size']} octets")
        
        if result['signature']:
            sig = result['signature']
            print(f"Signature Connue: {sig['name']} ({sig['platform']})")
        
        if result['opcodes']:
            print(f"Opcodes Dangereux: {len(result['opcodes'])}")
            for op in result['opcodes'][:5]:
                print(f"  {op['opcode']} - {op['description']}")
        
        status = "MALVEILLANT" if result['is_malicious'] else "SAIN"
        print(f"Statut: {status}")


if __name__ == "__main__":
    main() 