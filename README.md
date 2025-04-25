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

![image](https://github.com/user-attachments/assets/0219b51d-f163-41c8-9ac8-df74b3197cf9)

## Analyse dynamique
```bash
sudo python3 src/main.py --pid <pid_du_processus>
```

### Pour tester
```bash
python3 tests/fake_process.py
sudo python3 src/main.py --pid <pid_du_processus>
```

![image](https://github.com/user-attachments/assets/c70b4819-ab18-4744-817d-9885860807b5)

## Analyse live

**Surveiller un processus toutes les 5 secondes** :

```bash
sudo python3 src/main.py --pid <pid_du_processus> --live
```


