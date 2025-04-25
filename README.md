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
```bash
python3 src/main.py --file chemin/vers/le/fichier
```

### Pour tester
```bash
python3 tests/fake_shellcode.py
python3 src/main.py --file tests/fake_shellcode.bin
```

![image](https://github.com/user-attachments/assets/47658f6a-ac31-46cf-8a97-e457c1a2693c)


## Analyse dynamique
```bash
sudo python3 src/main.py --pid <pid_du_processus>
```

### Pour tester
```bash
python3 tests/fake_process.py
sudo python3 src/main.py --pid <pid_du_processus>
```

![image](https://github.com/user-attachments/assets/c7e18300-4065-404d-bc46-f37ec4a79540)


## Analyse live

**Surveiller un processus toutes les 5 secondes** :

```bash
sudo python3 src/main.py --pid <pid_du_processus> --live
```


https://github.com/user-attachments/assets/b2d5eee2-093a-45b3-adc0-de572b7c0079


## Analyse globale

**Analyser tous les processus** :

```bash
sudo python3 src/main.py --scan-all
```
