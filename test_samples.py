#!/usr/bin/env python3

from shellcode_detector import ShellcodeDetector

def test_shellcode_detection():
    detector = ShellcodeDetector()
    
    # Échantillons de test
    samples = {
        "Shellcode Linux": "31c050682f2f7368682f62696e89e3505389e1cd80",
        "Shellcode Windows": "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ff",
        "Données normales": "41414141424242424343434344444444",
        "NOP sled": "90909090909090909090909090909090"
    }
    
    print("Résultats des Tests de Détection de Shellcode")
    print("=" * 50)
    
    for name, data in samples.items():
        result = detector.analyze(data)
        
        status = "MALVEILLANT" if result['is_malicious'] else "SAIN"
        score = result['risk_score']
        
        print(f"{name:<20} | Score: {score:.2f} | {status}")
        
        if result['signature']:
            sig = result['signature']
            print(f"  -> Détecté: {sig['name']} ({sig['platform']})")
    
    print("\nTest terminé.")

def create_test_file():
    """Créer un fichier de test avec du shellcode pour l'analyse de fichiers"""
    shellcode = "31c050682f2f7368682f62696e89e3505389e1cd80"
    
    with open("test_shellcode.bin", "wb") as f:
        f.write(bytes.fromhex(shellcode))
        f.write(b"\x00" * 100)  # remplissage
    
    print("Fichier test_shellcode.bin créé pour les tests d'analyse de fichiers")

if __name__ == "__main__":
    test_shellcode_detection()
    create_test_file() 