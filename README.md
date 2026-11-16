# Enigma Chat

Messagerie en ligne de commande entre deux ordinateurs. Chaque message est chiffré
avec une Enigma (I, M3 ou M4) puis transporté dans un tunnel SSH.

> ⚠️ **La sécurité réelle vient de SSH.** Enigma est cassée depuis 1940 (Bletchley Park) :
> ici, c'est une couche pédagogique pour voir la machine travailler, pas une protection.

Python 3, bibliothèque standard uniquement. Fichiers : `enigma.py` (la machine),
`enigma_chat.py` (le chat), `test_enigma.py` et `test_chat.py` (les tests).

```bash
python3 test_enigma.py && python3 -m unittest -v test_chat
```

Principe : l'**hôte** lance `serve`, qui écoute uniquement sur `127.0.0.1:5555`
(aucun port de chat n'est ouvert sur le réseau). L'**invité** lance `connect --ssh`,
qui ouvre lui-même `ssh -N -L 5555:127.0.0.1:5555 user@hote`, discute, puis referme
le tunnel en quittant.

## 1. Activer SSH sur l'hôte

- **macOS** : Réglages Système > Général > Partage > **Session à distance**.
  Dans le (i), choisissez « Uniquement ces utilisateurs » et gardez seulement votre compte.
- **Linux** : `sudo apt install openssh-server` (ou `dnf install openssh-server`), puis
  `sudo systemctl enable --now ssh` (`sshd` sur Fedora/Arch).

L'invité n'a besoin que du **client** SSH : il est fourni avec macOS, presque toujours
avec Linux (`openssh-client`) et avec **Windows 10/11** (`ssh -V` dans PowerShell ;
sinon Paramètres > Applications > Fonctionnalités facultatives > Client OpenSSH).

## 2. Trouver l'adresse IP de l'hôte et tester

Sur l'hôte :

```bash
ipconfig getifaddr en0      # macOS (Wi-Fi ; en1 si besoin)
hostname -I                 # Linux
whoami                      # votre nom d'utilisateur
```

Sur l'invité, sur le même réseau local : `ssh alexis@192.168.1.20`. La connexion
doit réussir, puis tapez `exit`.

## 3. Utiliser une clé SSH plutôt qu'un mot de passe

Sur l'invité :

```bash
ssh-keygen -t ed25519                 # Entrée pour l'emplacement par défaut
ssh-copy-id alexis@192.168.1.20       # macOS / Linux
```

Sous **Windows** (PowerShell), `ssh-copy-id` n'existe pas :

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh alexis@192.168.1.20 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

**Recommandé** : sur l'hôte, limitez cette clé au seul tunnel du chat (pas de shell).
Éditez `~/.ssh/authorized_keys` et préfixez la ligne de la clé de l'invité :

```
restrict,port-forwarding,permitopen="127.0.0.1:5555",command="/usr/bin/true" ssh-ed25519 AAAA… bob@pc
```

Avec cette ligne, `ssh alexis@ip` rend la main aussitôt sans ouvrir de shell. C'est normal :
la clé ne sert plus qu'au tunnel vers `127.0.0.1:5555`, et tout autre tunnel est refusé
(« administratively prohibited »).

## 4. Générer et partager `cle.json`

Une seule personne génère la clé, puis la transmet à l'autre **à la main**
(clé USB, ou `scp cle.json bob@ip:`). Jamais par mail ni par messagerie.

```bash
python3 enigma_chat.py genkey --model M3 > cle.json                 # mode binaire (défaut)
python3 enigma_chat.py genkey --model M4 --mode historique > cle.json
```

Le fichier contient le modèle, les rotors, le réflecteur, la Ringstellung, le Steckerbrett
(10 paires), la Grundstellung et le mode de codage :

- **binaire** (défaut, sans perte) : UTF-8 → octets → 2 lettres A–P par octet. Les accents,
  les chiffres et les emojis passent ;
- **historique** : majuscules, espace → X, chiffres en allemand (5 → FUENF), le reste
  supprimé. Ce mode perd de l'information, c'est voulu.

Pour chaque message, le programme tire une **clé de message** aléatoire (3 lettres, 4 en M4)
et la chiffre en Grundstellung pour former l'**indicateur**. Le texte est chiffré avec les
rotors placés sur cette clé de message. Chaque message est donc indépendant : en perdre un ne
casse pas la suite. Sur le réseau ne circulent que `{"from", "indicator", "ct"}`, jamais le clair.

## 5. Lancer le chat

**Hôte** (ici le Mac d'Alexis) :

```bash
python3 enigma_chat.py serve --name Alexis --key cle.json
```

**Invité** (macOS / Linux) :

```bash
python3 enigma_chat.py connect --name Bob --key cle.json --ssh alexis@192.168.1.20
```

**Invité sous Windows** (PowerShell ou Windows Terminal, Python installé depuis python.org) :

```powershell
py enigma_chat.py connect --name Bob --key cle.json --ssh alexis@192.168.1.20
```

Options utiles :

- `--show-cipher` affiche l'indicateur et le chiffré en groupes de 5 ;
- `--no-ssh` permet un test sur une seule machine ;
- `--local-port 5556` change le port local du tunnel ;
- `--ssh-port 2222` indique un SSH qui n'écoute pas sur le port 22.

Dans le chat, `/help` affiche l'aide et `/quit` (ou Ctrl+C) quitte. L'invité ferme alors le tunnel.

Test sur une seule machine, dans deux terminaux :

```bash
python3 enigma_chat.py serve   --name A --key cle.json
python3 enigma_chat.py connect --name B --key cle.json --no-ssh
```

## 6. Dépannage

| Symptôme | Cause et solution |
|---|---|
| `impossible d'écouter sur 127.0.0.1:5555… déjà pris` | Un autre `serve` tourne déjà. Utilisez `lsof -i :5555` pour le trouver, ou changez de port avec `--port 5600` **des deux côtés**. |
| `le port local 5555 est déjà pris` (invité) | Ajoutez `--local-port 5556`. C'est le cas si l'invité fait aussi tourner un `serve`. |
| `ssh s'est arrêté (code 255) : tunnel refusé` | Testez `ssh user@ip` à la main. Vérifiez que la Session à distance est activée, que l'IP et l'utilisateur sont bons, et que vous êtes sur le même réseau. |
| `Host key verification failed` | Le premier contact SSH n'a jamais été validé. Lancez `ssh user@ip` une fois à la main et répondez `yes`. |
| `l'hôte n'a pas répondu ou a fermé la connexion` | Le tunnel est ouvert, mais `serve` n'est pas lancé sur l'hôte, ou pas sur ce `--port`. |
| `message indéchiffrable` (mode binaire) ou du charabia (mode historique) | Les deux `cle.json` sont différents. Recopiez le même fichier des deux côtés. |
| `hôte déjà en conversation` | `serve` n'accepte qu'un interlocuteur à la fois. |
