#!/usr/bin/env python3

from shellcode_detector import ShellcodeDetector

def demo():
    print("Démonstration du Détecteur de Shellcode")
    print("=" * 40)
    
    detector = ShellcodeDetector()
    
    # Tester un shellcode malveillant connu
    linux_shellcode = "31c050682f2f7368682f62696e89e3505389e1cd80"
    print(f"Analyse du shellcode Linux: {linux_shellcode[:20]}...")
    
    result = detector.analyze(linux_shellcode)
    
    print(f"Score de Risque: {result['risk_score']:.2f}")
    print(f"Statut: {'MALVEILLANT' if result['is_malicious'] else 'SAIN'}")
    
    if result['signature']:
        sig = result['signature']
        print(f"Détecté: {sig['name']} ({sig['platform']})")
    
    print(f"Entropie: {result['entropy']:.2f}")
    print(f"Opcodes Dangereux: {len(result['opcodes'])}")
    
    # Tester des données propres
    print("\n" + "=" * 40)
    clean_data = "41414141424242424343434344444444"
    print(f"Analyse de données propres: {clean_data[:20]}...")
    
    result = detector.analyze(clean_data)
    
    print(f"Score de Risque: {result['risk_score']:.2f}")
    print(f"Statut: {'MALVEILLANT' if result['is_malicious'] else 'SAIN'}")
    
    print("\nDémonstration terminée! Utilisez 'python test_samples.py' pour des tests complets.")

if __name__ == "__main__":
    demo() 