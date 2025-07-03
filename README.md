# Shellcode Killer 🛡️

Un détecteur de shellcode avancé pour analyser et détecter les codes malveillants.

## Fonctionnalités

- ✅ Détection de patterns de shellcode connus
- ✅ Analyse entropique des données
- ✅ Détection d'instructions dangereuses
- ✅ Analyse de polymorphisme
- ✅ Support de multiples formats (binaires, hexadécimal, base64)
- ✅ Système de scoring et de rapports détaillés

## Structure du projet

```
shellcode_killer/
├── src/
│   ├── detector.py          # Module principal de détection
│   ├── patterns.py          # Signatures et patterns de shellcode
│   ├── entropy.py           # Analyse entropique
│   ├── opcodes.py           # Analyse des opcodes dangereux
│   └── utils.py             # Fonctions utilitaires
├── signatures/
│   ├── common_shellcodes.json
│   └── dangerous_opcodes.json
├── tests/
│   └── test_samples/
├── logs/
└── main.py                  # Point d'entrée principal
```

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python main.py --file <chemin_vers_fichier>
python main.py --hex <code_hex>
python main.py --scan <dossier>
```

## Exemples

```bash
# Analyser un fichier binaire
python main.py --file malware.exe

# Analyser du code hexadécimal
python main.py --hex "31c050682f2f7368682f62696e89e3505389e1cd80"

# Scanner un dossier complet
python main.py --scan /path/to/directory --recursive
``` 
