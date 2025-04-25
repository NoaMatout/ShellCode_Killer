+----------------------------------------------------------------+
|░█▀▀░█░█░█▀▀░█░░░█░░░█▀▀░█▀█░█▀▄░█▀▀░░░░░█░█░▀█▀░█░░░█░░░█▀▀░█▀▄|
|░▀▀█░█▀█░█▀▀░█░░░█░░░█░░░█░█░█░█░█▀▀░░░░░█▀▄░░█░░█░░░█░░░█▀▀░█▀▄|
|░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀|
+----------------------------------------------------------------+

🛡️ Un détecteur de shellcode en Python pour l'analyse statique et dynamique sous Linux.

# Objectif
Détecter la présence de shellcode dans un fichier binaire ou en mémoire vive d'un processus.

# Fonctionnalités
- Analyse statique de fichiers binaires
- Analyse dynamique de la mémoire d'un processus
- Détection basée sur signatures connues et heuristiques (entropie)
- CLI simple d'utilisation

# Installation

```bash
git clone https://github.com/NoaMatout/ShellCode_Killer.git
cd ShellCode_Killer
pip install -r requirements.txt
```

# Utilisation

## Analyse statique
python3 src/main.py --file chemin/vers/le/fichier

### Pour tester
python3 tests/fake.py

python3 src/main.py --file tests/fake_shellcode.bin

![image](https://github.com/user-attachments/assets/8d544ad4-f3d6-47bd-b642-a5887edf9943)
