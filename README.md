# Shellcode Killer 🛡️

**Un détecteur de shellcode avancé multi-méthodes pour l'analyse et la détection de codes malveillants**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)]()

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture technique](#architecture-technique)
- [Méthodes de détection](#méthodes-de-détection)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Exemples concrets](#exemples-concrets)
- [Résultats de tests](#résultats-de-tests)
- [Performances](#performances)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contribution](#contribution)

## 🎯 Vue d'ensemble

**Shellcode Killer** est un système de détection avancé conçu pour identifier et analyser les shellcodes malveillants dans différents formats de données. Le projet utilise une approche multi-méthodes combinant :

- **Analyse par signatures** : Reconnaissance de shellcodes connus
- **Analyse entropique** : Détection de données chiffrées/encodées
- **Analyse d'opcodes** : Identification d'instructions dangereuses
- **Analyse heuristique** : Détection de patterns suspects

### 🔍 Shellcodes supportés

Le système détecte efficacement :
- **Linux x86/x64** : `/bin/sh`, `/bin/bash`, reverse shells
- **Windows x86/x64** : `WinExec`, `CreateProcess`, reverse shells
- **Meterpreter** : Payloads Metasploit
- **Cobalt Strike** : Beacons et payloads
- **Polymorphic shellcodes** : Codes auto-modifiants
- **NOP sleds** : Séquences de glissement

## 🏗️ Architecture technique

```
shellcode_killer/
├── 📁 src/                          # Modules principaux
│   ├── 🔍 detector.py              # Orchestrateur principal
│   ├── 🎯 patterns.py              # Moteur de signatures
│   ├── 📊 entropy.py               # Analyseur entropique
│   ├── ⚙️ opcodes.py               # Analyseur d'opcodes
│   └── 🛠️ utils.py                 # Fonctions utilitaires
├── 📁 signatures/                   # Bases de connaissances
│   ├── 📋 common_shellcodes.json   # Signatures de shellcodes
│   └── ⚠️ dangerous_opcodes.json   # Opcodes dangereux
├── 📁 tests/                       # Suite de tests
│   └── 📁 test_samples/            # Échantillons de test
├── 📁 logs/                        # Journaux d'analyse
├── 🐍 main.py                      # Point d'entrée CLI
├── 📄 requirements.txt             # Dépendances
└── 📖 USAGE.md                     # Guide détaillé
```

### 🔧 Composants principaux

#### 1. **ShellcodeDetector** (`src/detector.py`)
- Orchestrateur principal du système
- Gestion des différents formats d'entrée
- Calcul du score de risque composite
- Génération des rapports détaillés

#### 2. **PatternDetector** (`src/patterns.py`)
- Base de signatures de shellcodes connus
- Recherche de patterns hexadécimaux
- Détection de chaînes caractéristiques
- Support des expressions régulières

#### 3. **EntropyAnalyzer** (`src/entropy.py`)
- Calcul de l'entropie de Shannon
- Détection de données chiffrées/compressées
- Analyse de la randomité des données
- Seuils adaptatifs selon la taille

#### 4. **OpcodeAnalyzer** (`src/opcodes.py`)
- Reconnaissance d'instructions dangereuses
- Analyse des syscalls système
- Détection d'opcodes de contrôle de flux
- Pondération selon la criticité

## 🔬 Méthodes de détection

### 1. **Détection par signatures** 🎯
```python
# Exemple de signature Linux x86
{
    "name": "Linux /bin/sh shellcode",
    "description": "Exécute /bin/sh sur Linux x86",
    "pattern": "31c050682f2f7368682f62696e89e3505389e1cd80",
    "platform": "linux",
    "severity": "critical"
}
```

### 2. **Analyse entropique** 📊
- **Formule** : `H(X) = -Σ P(xi) * log2(P(xi))`
- **Seuil critique** : > 7.5 (sur 8.0 max)
- **Détection** : Données chiffrées, encodées, ou compressées

### 3. **Analyse d'opcodes** ⚙️
```python
# Opcodes dangereux détectés
{
    "0x80": {"name": "INT 0x80", "risk": "high"},    # Syscall Linux
    "0x2E": {"name": "INT 0x2E", "risk": "high"},    # Syscall Windows
    "0xEB": {"name": "JMP short", "risk": "medium"}, # Saut court
    "0x33": {"name": "XOR reg", "risk": "medium"}    # XOR register
}
```

### 4. **Analyse heuristique** 🧠
- Détection de patterns polymorphes
- Analyse de la densité d'instructions
- Reconnaissance de NOP sleds
- Détection de techniques d'obfuscation

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip (gestionnaire de paquets Python)

### Installation rapide
```bash
# Cloner le projet
git clone https://github.com/votre-username/shellcode_killer.git
cd shellcode_killer

# Installer les dépendances
pip install -r requirements.txt

# Vérifier l'installation
python main.py --help
```

### Dépendances
```
colorama==0.4.6    # Couleurs dans le terminal
argparse           # Parsing des arguments CLI (built-in)
json               # Manipulation JSON (built-in)
logging            # Système de logs (built-in)
base64             # Encodage/décodage base64 (built-in)
binascii           # Conversion binaire (built-in)
```

## 💻 Utilisation

### Interface en ligne de commande

```bash
# Analyser un fichier binaire
python main.py --file malware.exe

# Analyser du code hexadécimal
python main.py --hex "31c050682f2f7368682f62696e89e3505389e1cd80"

# Analyser du code base64
python main.py --base64 "McBQaC8vc2hoL2JpbonjUFOJ4c2A"

# Scanner un dossier complet
python main.py --scan /path/to/directory --recursive

# Ajuster le seuil de détection
python main.py --file sample.bin --threshold 0.8

# Sortie en format JSON
python main.py --hex "909090909090" --output json

# Mode verbeux avec détails
python main.py --file sample.bin --verbose
```

## 🧪 Exemples concrets

### 1 : Création des différents shellcode (Shell-Storm, MetaSploit, Exploit-DB)

https://github.com/user-attachments/assets/d87fc4e8-ea97-4c7f-8b3b-134c91c0034f

### 2 : POC

https://github.com/user-attachments/assets/26d4158a-555f-4698-a5f7-003c0b516f25

### 3 : POC Scan Mémoire

