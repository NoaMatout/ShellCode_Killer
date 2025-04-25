+----------------------------------------------------------------+
|░█▀▀░█░█░█▀▀░█░░░█░░░█▀▀░█▀█░█▀▄░█▀▀░░░░░█░█░▀█▀░█░░░█░░░█▀▀░█▀▄|
|░▀▀█░█▀█░█▀▀░█░░░█░░░█░░░█░█░█░█░█▀▀░░░░░█▀▄░░█░░█░░░█░░░█▀▀░█▀▄|
|░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀|
+----------------------------------------------------------------+

# 🛡️ ShellCode_Killer

> Hunt the shellcodes. Kill the threat.

**ShellCode_Killer** est un outil Python permettant de détecter la présence de shellcode dans :
- des fichiers binaires (`.bin`, ELF, etc.)
- la mémoire d’un processus Linux en cours d’exécution

Développé dans un contexte d’exploitation de binaire, il combine une **analyse statique**, une **analyse dynamique**, et des mécanismes heuristiques (signature + entropie) pour **évaluer le risque** de code injecté.

---

## 📦 Fonctionnalités

- 🧠 Analyse **statique** de fichiers binaires (recherche d'opcodes, chaînes typiques, entropie)
- 👀 Analyse **dynamique** d’un processus Linux via `/proc/<pid>/mem`
- 🔁 Mode **live** : surveillance continue d’un processus
- 🌐 Scan global : analyse de tous les processus actifs
- 📈 Score de dangerosité sur 100 basé sur les détections
- 📝 Génération automatique de rapports
- 🎨 Interface terminal colorée avec bannière ASCII

---

## ⚙️ Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/NoaMatout/ShellCode_Killer.git
cd ShellCode_Killer
pip install -r requirements.tx
pip install .
shellcode_killer --help
```

---

## 💻 Utilisation

### 🔍 Analyse statique
```bash
python3 src/main.py --file chemin/vers/le/fichier
```

### 🔬 Pour tester
```bash
python3 tests/fake_shellcode.py
python3 src/main.py --file tests/fake_shellcode_64.bin
python3 src/main.py --file tests/fake_shellcode_32.bin
```

![image](https://github.com/user-attachments/assets/47658f6a-ac31-46cf-8a97-e457c1a2693c)


### 🧠 Analyse dynamique
```bash
sudo python3 src/main.py --pid <pid_du_processus>
```

### 🔬 Pour tester
```bash
python3 tests/fake_process.py
sudo python3 src/main.py --pid <pid_du_processus>
```

![image](https://github.com/user-attachments/assets/c7e18300-4065-404d-bc46-f37ec4a79540)


### 🔁 Analyse live

**Surveiller un processus toutes les 5 secondes** :

```bash
sudo python3 src/main.py --pid <pid_du_processus> --live
```


https://github.com/user-attachments/assets/b2d5eee2-093a-45b3-adc0-de572b7c0079


### 🌐 Analyse globale

**Analyser tous les processus** :

```bash
sudo python3 src/main.py --scan-all
```
