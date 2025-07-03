# Shellcode Killer 🛡️

**Un détecteur de shellcode avancé multi-méthodes pour l'analyse et la détection de codes malveillants**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)]()

## 🎯 Vue d'ensemble

**Shellcode Killer** est un outil léger de détection de shellcode pour l'analyse de sécurité. Identifie les motifs de shellcode malveillants dans la mémoire et les fichiers grâce à la correspondance de signatures, l'analyse d'entropie et la détection d'opcodes.

## Fonctionnalités

- **Détection par Signature**: Identifie les motifs de shellcode connus (Linux, Windows, Meterpreter)
- **Analyse d'Entropie**: Calcule l'entropie de Shannon pour détecter les charges utiles encodées
- **Analyse d'Opcodes**: Détecte les instructions d'assemblage dangereuses
- **Scanner Mémoire**: Analyse en temps réel de la mémoire des processus
- **Analyse de Fichiers**: Analyse les fichiers suspects pour détecter les shellcodes

## Installation

```bash
git clone https://github.com/votreusername/shellcode-killer
cd shellcode-killer
pip install -r requirements.txt
```

## Utilisation

### Analyse de Base

```bash
# Analyser une chaîne hexadécimale
python shellcode_detector.py --hex "31c050682f2f7368682f62696e89e3505389e1cd80"

# Analyser un fichier
python shellcode_detector.py --file fichier_suspect.bin

# Sortie JSON
python shellcode_detector.py --hex "31c050..." --output json
```

### Analyse Mémoire

```bash
# Analyse unique
python memory_scanner.py

# Surveillance continue
python memory_scanner.py --continuous --interval 30

# Analyser un processus spécifique
python memory_scanner.py --pid 1234
```

### Tests

```bash
python test_samples.py
```

## Exemple de Sortie

```
Score de Risque: 1.00
Entropie: 4.85
Taille des Données: 21 octets
Signature Connue: Linux execve /bin/sh (Linux x86)
Opcodes Dangereux: 8
Statut: MALVEILLANT
```

## Méthodes de Détection

- **Correspondance de Signatures**: Motifs de shellcode connus
- **Analyse d'Entropie**: Analyse statistique du caractère aléatoire des données
- **Détection d'Opcodes**: Instructions d'assemblage dangereuses (syscalls, sauts, XOR)
- **Notation Heuristique**: Évaluation combinée des risques

## Choix Techniques

### Architecture Modulaire
Le projet adopte une architecture séparée entre le moteur de détection (`ShellcodeDetector`) et le scanner mémoire (`MemoryScanner`). Cette approche permet une meilleure maintenabilité et facilite l'extension des fonctionnalités.

### Algorithme de Scoring
Le score de risque combine plusieurs métriques :
- **Signatures (poids: 100%)**: Détection immédiate des shellcodes connus
- **Entropie (poids: 40%)**: Normalisation sur 8 bits pour détecter l'encodage
- **Opcodes (poids: 60%)**: Pondération basée sur la fréquence d'apparition

### Signatures Choisies
Les signatures intégrées couvrent les vecteurs d'attaque les plus courants :
- Linux x86 execve: shellcode de base pour l'exécution de commandes
- Windows MessageBox: payload de démonstration fréquemment utilisé
- Meterpreter: framework d'exploitation post-compromise populaire

### Accès Mémoire
L'utilisation de `ctypes` et `ReadProcessMemory` permet un accès direct à la mémoire des processus sans dépendances externes lourdes. Le scan multi-adresses (0x400000, 0x10000000, 0x00010000) couvre les zones mémoire couramment utilisées.

### Gestion des Erreurs
Le système adopte une approche défensive avec gestion silencieuse des erreurs d'accès mémoire, évitant les crashes sur les processus protégés tout en maintenant la continuité du scan.

## Architecture

- `shellcode_detector.py`: Moteur de détection principal
- `memory_scanner.py`: Analyse de la mémoire des processus
- `test_samples.py`: Framework de test

## 🧪 Exemples concrets

### 1 : Création des différents shellcode (Shell-Storm, MetaSploit, Exploit-DB)

https://github.com/user-attachments/assets/d87fc4e8-ea97-4c7f-8b3b-134c91c0034f

### 2 : POC

https://github.com/user-attachments/assets/26d4158a-555f-4698-a5f7-003c0b516f25

### 3 : POC Scan Mémoire

https://github.com/user-attachments/assets/59f6e1cc-41d1-48cf-8de1-aa9f8231160b

## Licence

Licence MIT

## Contribution

1. Fork le dépôt
2. Créez votre branche de fonctionnalité
3. Commitez vos changements
4. Poussez vers la branche
5. Créez une Pull Request

## Note de Sécurité

Cet outil est destiné à des fins éducatives et de recherche en sécurité. Utilisez-le toujours sur des systèmes que vous possédez ou pour lesquels vous avez une autorisation explicite de test. 
