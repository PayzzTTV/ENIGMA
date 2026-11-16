#!/usr/bin/env python3
"""
enigma_chat.py — petite messagerie en ligne de commande, chiffrée avec Enigma,
transportée dans un tunnel SSH.

    python3 enigma_chat.py genkey  --model M3 > cle.json
    python3 enigma_chat.py serve   --name Alexis --key cle.json
    python3 enigma_chat.py connect --name Bob --key cle.json --ssh user@hote

Rappel : la confidentialité réelle vient de SSH. Enigma est cassée depuis 1940 ;
ici, c'est une couche pédagogique.

Bibliothèque standard uniquement. macOS et Linux (connect fonctionne aussi
sous Windows 10/11 avec le client OpenSSH intégré).
"""
from __future__ import annotations

import argparse
import codecs
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import unicodedata
from datetime import datetime

from enigma import ALPHA, MODELS, Enigma, groups

HOST = "127.0.0.1"          # on n'écoute JAMAIS sur 0.0.0.0
DEFAULT_PORT = 5555
MAX_LINE = 256 * 1024       # taille max d'une ligne réseau (octets)
MAX_TEXT = 4000             # taille max d'un message tapé (caractères)
MAX_NAME = 32
MODES = ("binaire", "historique")
KEY_FIELDS = ("model", "rotors", "reflector", "ringstellung",
              "steckerbrett", "grundstellung", "mode")
ALPHA_SET = frozenset(ALPHA)

_rng = secrets.SystemRandom()


class ChatError(Exception):
    """Erreur destinée à l'utilisateur (affichée sans trace Python)."""


class DecodeError(ValueError):
    """Message impossible à déchiffrer / décoder (clé différente ?)."""


# ---------------------------------------------------------------------------
# Clé partagée (cle.json)
# ---------------------------------------------------------------------------
def genkey(model: str = "M3", mode: str = "binaire", rng=_rng) -> dict:
    """Tire une clé du jour aléatoire et valide pour le modèle demandé
    (I, M3, M4, ou M6 : machine fictive à 6 rotors)."""
    if model not in MODELS:
        raise ChatError(f"modèle inconnu : {model} ({', '.join(MODELS)})")
    if mode not in MODES:
        raise ChatError(f"mode inconnu : {mode} (binaire ou historique)")
    spec = MODELS[model]
    rotors = rng.sample(sorted(spec["rotors"]), spec.get("count", 3))
    if spec["fourth"]:
        rotors.insert(0, rng.choice(["Beta", "Gamma"]))
    reflector = rng.choice(sorted(spec["reflectors"] - {"A"}))  # UKW A : retirée en 1937
    n = len(rotors)
    letters = rng.sample(ALPHA, 20)
    key = {
        "model": model,
        "rotors": rotors,
        "reflector": reflector,
        "ringstellung": "".join(rng.choice(ALPHA) for _ in range(n)),
        "steckerbrett": " ".join(letters[i] + letters[i + 1] for i in range(0, 20, 2)),
        "grundstellung": "".join(rng.choice(ALPHA) for _ in range(n)),
        "mode": mode,
    }
    return validate_key(key)


def validate_key(raw) -> dict:
    """Vérifie une clé (dict) et la renvoie normalisée. Lève ChatError."""
    if not isinstance(raw, dict):
        raise ChatError("la clé doit être un objet JSON")
    missing = [f for f in KEY_FIELDS if f not in raw]
    if missing:
        raise ChatError("champs manquants : " + ", ".join(missing))
    model, mode = raw["model"], raw["mode"]
    if model not in MODELS:
        raise ChatError(f"modèle inconnu : {model!r}")
    if mode not in MODES:
        raise ChatError(f"mode inconnu : {mode!r} (binaire ou historique)")
    rotors = raw["rotors"]
    if isinstance(rotors, str):
        rotors = rotors.split()
    if not isinstance(rotors, list) or not all(isinstance(r, str) for r in rotors):
        raise ChatError("rotors : liste de noms attendue, ex. [\"I\", \"IV\", \"II\"]")
    n = 4 if MODELS[model]["fourth"] else MODELS[model].get("count", 3)
    if len(rotors) != n:
        raise ChatError(f"{model} : {n} rotors attendus")

    def letters(field: str) -> str:
        v = raw[field]
        if not isinstance(v, str):
            raise ChatError(f"{field} : texte attendu")
        v = v.replace(" ", "").upper()
        if len(v) != n or not set(v) <= ALPHA_SET:
            raise ChatError(f"{field} : {n} lettres A–Z attendues, reçu {raw[field]!r}")
        return v

    if not isinstance(raw["steckerbrett"], str) or not isinstance(raw["reflector"], str):
        raise ChatError("steckerbrett et reflector : texte attendu")
    key = {
        "model": model,
        "rotors": list(rotors),
        "reflector": raw["reflector"],
        "ringstellung": letters("ringstellung"),
        "steckerbrett": " ".join(raw["steckerbrett"].upper().split()),
        "grundstellung": letters("grundstellung"),
        "mode": mode,
    }
    try:
        _machine(key, key["grundstellung"])     # contrôle complet par enigma.py
    except (ValueError, KeyError) as e:
        raise ChatError(f"réglage refusé par enigma.py : {e}") from None
    return key


def load_key(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ChatError(f"fichier de clé introuvable : {path}") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ChatError(f"{path} n'est pas un JSON valide ({e})") from None
    try:
        return validate_key(raw)
    except ChatError as e:
        raise ChatError(f"clé invalide dans {path} : {e}") from None


def _machine(key: dict, positions: str) -> Enigma:
    return Enigma(key["rotors"], key["reflector"], key["ringstellung"],
                  positions, key["steckerbrett"], key["model"])


# ---------------------------------------------------------------------------
# Codage du texte en lettres A–Z
# ---------------------------------------------------------------------------
HEX16 = ALPHA[:16]                       # A..P = 0..15
_HEX_INDEX = {c: i for i, c in enumerate(HEX16)}
DIGITS_DE = ("NULL", "EINS", "ZWEI", "DREI", "VIER",
             "FUENF", "SECHS", "SIEBEN", "ACHT", "NEUN")
_SPECIAL = {"ß": "SS", "ẞ": "SS", "Æ": "AE", "æ": "AE", "Œ": "OE", "œ": "OE",
            "Ø": "O", "ø": "O", "Đ": "D", "đ": "D", "Ł": "L", "ł": "L"}


def encode_text(text: str, mode: str) -> str:
    if mode == "binaire":
        # UTF-8 → octets → 2 lettres par octet (base 16, alphabet A..P). Sans perte.
        return "".join(HEX16[b >> 4] + HEX16[b & 15] for b in text.encode("utf-8"))
    if mode == "historique":
        # Majuscules, espace → X, chiffres en toutes lettres (allemand), reste supprimé.
        out = []
        for ch in text:
            if ch in "0123456789":
                out.append(DIGITS_DE[int(ch)])
            elif ch.isspace():
                out.append("X")
            else:
                for c in unicodedata.normalize("NFKD", _SPECIAL.get(ch, ch)).upper():
                    if c in ALPHA_SET:
                        out.append(c)
        return "".join(out)
    raise ValueError(f"mode inconnu : {mode}")


def decode_text(letters: str, mode: str) -> str:
    if mode == "binaire":
        if len(letters) % 2:
            raise DecodeError("longueur impaire")
        try:
            data = bytes(_HEX_INDEX[a] * 16 + _HEX_INDEX[b]
                         for a, b in zip(letters[::2], letters[1::2]))
            return data.decode("utf-8")
        except (KeyError, UnicodeDecodeError):
            raise DecodeError("lettres hors A–P ou UTF-8 invalide") from None
    if mode == "historique":
        return letters                   # mode avec perte : on rend les lettres telles quelles
    raise ValueError(f"mode inconnu : {mode}")


# ---------------------------------------------------------------------------
# Procédure de clé de message (une clé neuve par message)
# ---------------------------------------------------------------------------
def random_message_key(key: dict) -> str:
    return "".join(secrets.choice(ALPHA) for _ in key["rotors"])


def encrypt_message(key: dict, text: str, message_key: str | None = None) -> tuple[str, str]:
    """Renvoie (indicateur, chiffré).

    1. clé de message : une lettre par rotor (3, 4 en M4, 6 en M6) ;
    2. indicateur = clé de message chiffrée en Grundstellung ;
    3. texte chiffré avec les rotors placés sur la clé de message.
    """
    mk = message_key or random_message_key(key)
    indicator = _machine(key, key["grundstellung"]).encrypt(mk)
    ct = _machine(key, mk).encrypt(encode_text(text, key["mode"]))
    return indicator, ct


def decrypt_message(key: dict, indicator, ct) -> str:
    n = len(key["rotors"])
    if not isinstance(indicator, str) or len(indicator) != n or not set(indicator) <= ALPHA_SET:
        raise DecodeError("indicateur invalide")
    if not isinstance(ct, str) or not set(ct) <= ALPHA_SET:
        raise DecodeError("chiffré invalide")
    mk = _machine(key, key["grundstellung"]).decrypt(indicator)
    return decode_text(_machine(key, mk).decrypt(ct), key["mode"])


# ---------------------------------------------------------------------------
# Affichage sûr (le pair distant ne doit pas pouvoir piloter notre terminal)
# ---------------------------------------------------------------------------
_KEEP_CF = {"‌", "‍"}          # ZWNJ / ZWJ : utiles aux emojis composés


def clean(text, limit: int | None = None) -> str:
    text = str(text)
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cc":
            out.append(" ")              # ESC, retours chariot, etc.
        elif cat == "Cf" and ch not in _KEEP_CF:
            continue                     # ex. U+202E (inversion bidi)
        else:
            out.append(ch)
    s = "".join(out)
    return s[:limit] if limit else s


def clean_name(name) -> str:
    return clean(name, MAX_NAME).strip() or "?"


def now() -> str:
    return datetime.now().strftime("%H:%M")


# ---------------------------------------------------------------------------
# Console : lecture du clavier sans casser l'affichage des messages reçus
# ---------------------------------------------------------------------------
_ESC_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|O.|.)?", re.S)


class Console:
    """Petit éditeur de ligne. Quand un message arrive, on efface la ligne en
    cours, on affiche le message, puis on réécrit l'invite et la saisie."""

    def __init__(self, prompt: str = "> "):
        self.prompt = prompt
        self.interactive = sys.stdin.isatty() and sys.stdout.isatty()
        self.stop = threading.Event()   # posé par le réseau pour quitter
        self._lock = threading.RLock()
        self._buf = ""
        self._pending = ""
        self._editing = False
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._saved = None
        self._rows = 0                  # lignes physiques au-dessus du curseur (saisie repliée)

    # -- dessin de l'invite, y compris quand la saisie dépasse la largeur ----
    @staticmethod
    def _width(s: str) -> int:
        w = 0
        for ch in s:
            if unicodedata.combining(ch) or ch in _KEEP_CF or ch == "\ufe0f":
                continue
            w += 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        return w

    def _erase(self) -> str:
        """Séquence qui efface l'invite affichée, même repliée sur plusieurs lignes."""
        seq = "\r" + (f"\033[{self._rows}A" if self._rows else "") + "\033[J"
        self._rows = 0
        return seq

    def _draw(self) -> str:
        text = self.prompt + self._buf
        cols = max(shutil.get_terminal_size((80, 24)).columns, 1)
        self._rows = max(self._width(text) - 1, 0) // cols
        return text

    def __enter__(self):
        if self.interactive:
            if os.name == "nt":
                os.system("")            # chaîne vide constante : astuce connue qui active ANSI sous Windows
            else:
                import termios
                import tty
                fd = sys.stdin.fileno()
                self._saved = termios.tcgetattr(fd)
                tty.setcbreak(fd)        # touche par touche, sans écho ; Ctrl+C reste actif
        return self

    def __exit__(self, *exc):
        if self._saved is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
            self._saved = None
        if self.interactive:
            with self._lock:
                self._editing = False
                sys.stdout.write(self._erase())
                sys.stdout.flush()
        return False

    def show(self, text: str) -> None:
        with self._lock:
            if self.interactive and self._editing:
                sys.stdout.write(self._erase() + text + "\n" + self._draw())
            else:
                sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def _redraw(self) -> None:
        sys.stdout.write(self._erase() + self._draw())
        sys.stdout.flush()

    def _read_input(self):
        """Renvoie du texte tapé, "" (rien de complet), ou None (fin / arrêt)."""
        if os.name == "nt":
            import msvcrt
            while not self.stop.is_set():
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in "\x00\xe0":          # flèches, F1… : ignorées
                        msvcrt.getwch()
                        continue
                    return ch
                time.sleep(0.02)
            return None
        import select
        fd = sys.stdin.fileno()
        while not self.stop.is_set():
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                data = os.read(fd, 4096)
                if not data:
                    return None
                return self._decoder.decode(data)
        return None

    def read_line(self):
        """Une ligne tapée, ou None (fin de saisie, Ctrl+D, ou connexion close)."""
        if not self.interactive:
            return self._read_plain_line()
        with self._lock:
            self._buf = ""
            self._editing = True
            self._redraw()
        while True:
            if not self._pending:
                chunk = self._read_input()
                if chunk is None:
                    return None
                self._pending = _ESC_RE.sub("", chunk)
                continue
            ch, self._pending = self._pending[0], self._pending[1:]
            if ch == "\x03":
                raise KeyboardInterrupt
            with self._lock:
                if ch in "\r\n":
                    sys.stdout.write(self._erase())
                    line, self._buf, self._editing = self._buf, "", False
                    sys.stdout.flush()
                    return line
                if ch in "\x04\x1a" and not self._buf:     # Ctrl+D / Ctrl+Z
                    return None
                if ch in "\x7f\x08":
                    self._buf = self._buf[:-1]
                elif ch == "\x15":                         # Ctrl+U
                    self._buf = ""
                elif ch == "\t":
                    self._buf += " "
                elif ch.isprintable() or ch in _KEEP_CF:
                    self._buf += ch
                else:
                    continue
                self._redraw()

    def _read_plain_line(self):
        if os.name == "nt":
            line = sys.stdin.readline()
            return line.rstrip("\r\n") if line else None
        while "\n" not in self._pending:
            chunk = self._read_input()
            if chunk is None:
                if self.stop.is_set():
                    return None
                rest, self._pending = self._pending, ""
                return rest or None
            self._pending += chunk
        line, self._pending = self._pending.split("\n", 1)
        return line.rstrip("\r")


# ---------------------------------------------------------------------------
# Session de chat (protocole : une ligne JSON par message)
#   {"hello": "Alexis"}                                  présentation
#   {"from": "Alexis", "indicator": "QWE", "ct": "..."}  message chiffré
#   {"error": "..."}                                     refus (hôte occupé)
# Le texte en clair ne circule jamais.
# ---------------------------------------------------------------------------
HELP = """Commandes :
  /help     cette aide
  /quit     quitter (Ctrl+C marche aussi)
  //texte   envoyer un message qui commence par « / »
Tout le reste est chiffré avec Enigma (nouvelle clé de message à chaque fois) puis envoyé."""


def _line(obj: dict) -> bytes:
    return (json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii")


class ChatApp:
    def __init__(self, key: dict, name: str, console: Console,
                 show_cipher: bool = False, on_peer_closed=None):
        self.key, self.name, self.console = key, name, console
        self.show_cipher = show_cipher
        self.on_peer_closed = on_peer_closed
        self.peer_name: str | None = None
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._wlock = threading.Lock()

    # -- connexion ----------------------------------------------------------
    def attach(self, sock: socket.socket, rfile=None, first: dict | None = None) -> bool:
        with self._lock:
            if self._sock is not None:
                return False
            self._sock = sock
            self.peer_name = None
        rfile = rfile or sock.makefile("rb")
        try:
            self._send(sock, {"hello": self.name})
        except OSError:
            self._close(sock)
            return True
        if first is not None:
            self._handle(first)
        threading.Thread(target=self._receive, args=(sock, rfile), daemon=True).start()
        return True

    def disconnect(self) -> None:
        sock = self._sock
        if sock is not None:
            self.peer_name = None        # départ volontaire : pas d'annonce
            self._close(sock)

    def _close(self, sock: socket.socket, reason: str | None = None) -> None:
        with self._lock:
            if self._sock is not sock:
                return
            self._sock = None
            who, self.peer_name = self.peer_name, None
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        if who:
            self.console.show(f"*** {who} s'est déconnecté." + (f" ({reason})" if reason else ""))
        if self.on_peer_closed:
            self.on_peer_closed(bool(who))

    def _send(self, sock: socket.socket, obj: dict) -> None:
        with self._wlock:
            sock.sendall(_line(obj))

    # -- envoi --------------------------------------------------------------
    def send_text(self, text: str) -> None:
        sock = self._sock
        if sock is None:
            self.console.show("*** Personne n'est connecté : message non envoyé.")
            return
        if len(text) > MAX_TEXT:
            self.console.show(f"*** Message trop long ({len(text)} > {MAX_TEXT} caractères).")
            return
        mode = self.key["mode"]
        letters = encode_text(text, mode)
        if not letters:
            self.console.show("*** Rien à chiffrer (mode historique : seules les lettres, "
                              "espaces et chiffres passent).")
            return
        indicator, ct = encrypt_message(self.key, text)
        try:
            self._send(sock, {"from": self.name, "indicator": indicator, "ct": ct})
        except OSError:
            self.console.show("*** Envoi impossible : connexion perdue.")
            self._close(sock, "connexion perdue")
            return
        self._print_message(self.name, decode_text(letters, mode), indicator, ct)

    def _print_message(self, sender: str, text: str, indicator: str, ct: str) -> None:
        self.console.show(f"[{now()}] {sender} : {clean(text)}")
        if self.show_cipher:
            self.console.show(f"        indicateur {indicator} | chiffré {groups(ct)}")

    # -- réception ----------------------------------------------------------
    def _receive(self, sock: socket.socket, rfile) -> None:
        reason = None
        try:
            while True:
                raw = rfile.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    reason = "ligne réseau trop longue"
                    break
                try:
                    obj = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.console.show("*** Ligne réseau illisible ignorée.")
                    continue
                if isinstance(obj, dict):
                    self._handle(obj)
        except (OSError, ValueError):
            pass
        finally:
            self._close(sock, reason)

    def _handle(self, obj: dict) -> None:
        if "hello" in obj:
            self.peer_name = clean_name(obj["hello"])
            self.console.show(f"*** {self.peer_name} est en ligne.")
        elif "error" in obj:
            self.console.show(f"*** Refusé par l'hôte : {clean(obj['error'], 200)}")
        elif "indicator" in obj and "ct" in obj:
            sender = clean_name(obj.get("from", self.peer_name or "?"))
            indicator, ct = obj["indicator"], obj["ct"]
            try:
                text = decrypt_message(self.key, indicator, ct)
            except DecodeError:
                self.console.show(f"[{now()}] {sender} : *** message indéchiffrable "
                                  "(vos deux cle.json sont-ils identiques ?)")
                return
            self._print_message(sender, text, clean(indicator, 8), clean(ct))


def input_loop(console: Console, app: ChatApp) -> None:
    while True:
        line = console.read_line()
        if line is None:
            return
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            line = line[1:]
        elif line.startswith("/"):
            cmd = line.split()[0].lower()
            if cmd in ("/quit", "/exit", "/q"):
                return
            if cmd in ("/help", "/aide", "/?"):
                console.show(HELP)
            else:
                console.show(f"*** Commande inconnue : {cmd} (tapez /help)")
            continue
        app.send_text(line)


# ---------------------------------------------------------------------------
# Réseau : serveur local et tunnel SSH
# ---------------------------------------------------------------------------
def port_in_use(port: int) -> bool:
    """Vrai si quelque chose écoute déjà sur 127.0.0.1:port (sans s'y connecter)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            # ignore les connexions TIME_WAIT, mais échoue si un socket ÉCOUTE
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def open_tunnel(dest: str, local_port: int, remote_port: int,
                ssh_port: int | None, timeout: float) -> subprocess.Popen:
    exe = shutil.which("ssh")
    if not exe:
        raise ChatError("commande ssh introuvable (installez le client OpenSSH)")
    if not dest or dest.startswith("-"):
        raise ChatError(f"destination SSH invalide : {dest!r}")
    if port_in_use(local_port):
        raise ChatError(f"le port local {local_port} est déjà pris. Choisissez-en un autre : "
                        f"--local-port {local_port + 1}")
    cmd = [exe, "-N",
           "-o", "ExitOnForwardFailure=yes",
           "-o", "ServerAliveInterval=30",
           "-o", "ConnectTimeout=10",
           "-L", f"{HOST}:{local_port}:{HOST}:{remote_port}"]
    if ssh_port:
        cmd += ["-p", str(ssh_port)]
    cmd += ["--", dest]
    print("Ouverture du tunnel : " + " ".join(shlex.quote(c) for c in cmd),
          flush=True)
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + timeout
        while True:
            rc = proc.poll()
            if rc is not None:
                raise ChatError(
                    f"ssh s'est arrêté (code {rc}) : tunnel refusé.\n"
                    f"  • testez d'abord à la main : ssh {dest}\n"
                    f"  • l'hôte a-t-il activé SSH (Session à distance / openssh-server) ?\n"
                    f"  • le port {local_port} est-il libre ici ? sinon --local-port")
            if port_in_use(local_port):
                return proc
            if time.monotonic() > deadline:
                raise ChatError(f"le tunnel ne répond pas après {timeout:.0f} s")
            time.sleep(0.1)
    except BaseException:
        close_tunnel(proc)
        raise


def close_tunnel(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def handshake(port: int, timeout: float):
    """Se connecte à 127.0.0.1:port et attend le {"hello"} de l'hôte."""
    try:
        sock = socket.create_connection((HOST, port), timeout=timeout)
    except OSError as e:
        raise ChatError(f"connexion à {HOST}:{port} impossible ({e.strerror or e}). "
                        "« serve » est-il lancé ?") from None
    rfile = sock.makefile("rb")
    try:
        raw = rfile.readline(MAX_LINE + 1)
    except (socket.timeout, OSError):
        raw = None
    if not raw:
        sock.close()
        raise ChatError("l'hôte n'a pas répondu ou a fermé la connexion : « serve » n'est "
                        "sans doute pas lancé de l'autre côté (ou pas sur ce --port).")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        obj = None
    if not isinstance(obj, dict) or not ("hello" in obj or "error" in obj):
        sock.close()
        raise ChatError("réponse inattendue : ce n'est pas enigma_chat qui écoute sur ce port.")
    if "error" in obj:
        sock.close()
        raise ChatError(f"refusé par l'hôte : {clean(obj['error'], 200)}")
    sock.settimeout(None)
    return sock, rfile, obj


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------
def check_name(name: str) -> str:
    n = clean(name).strip()
    if not n or len(n) > MAX_NAME:
        raise ChatError(f"--name : 1 à {MAX_NAME} caractères")
    return n


def cmd_genkey(args) -> int:
    print(json.dumps(genkey(args.model, args.mode), indent=2, ensure_ascii=False))
    return 0


def banner(key: dict) -> str:
    return (f"Enigma {key['model']} · rotors {' '.join(key['rotors'])} · "
            f"UKW {key['reflector']} · mode {key['mode']}")


def cmd_serve(args) -> int:
    key, name = load_key(args.key), check_name(args.name)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, args.port))
        srv.listen(2)
    except OSError as e:
        srv.close()
        raise ChatError(f"impossible d'écouter sur {HOST}:{args.port} ({e.strerror or e}). "
                        f"Le port est sans doute déjà pris (autre « serve » ouvert ?) : "
                        f"`lsof -i :{args.port}` pour voir qui l'utilise, ou --port.") from None

    console = Console()

    def peer_closed(had_hello: bool) -> None:
        if had_hello:
            console.show("*** En attente d'un interlocuteur…")

    app = ChatApp(key, name, console, args.show_cipher, peer_closed)

    def acceptor() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            if not app.attach(conn):
                try:
                    conn.sendall(_line({"error": "hôte déjà en conversation"}))
                except OSError:
                    pass
                conn.close()

    with console:
        console.show(banner(key))
        console.show(f"En écoute sur {HOST}:{args.port} (local uniquement). "
                     "En attente d'un interlocuteur… (/help pour l'aide)")
        threading.Thread(target=acceptor, daemon=True).start()
        try:
            input_loop(console, app)
        finally:
            app.disconnect()
            srv.close()
    return 0


def cmd_connect(args) -> int:
    key, name = load_key(args.key), check_name(args.name)
    local_port = args.local_port or args.port
    tunnel = None
    try:
        if not args.no_ssh:
            tunnel = open_tunnel(args.ssh, local_port, args.port, args.ssh_port, args.ssh_timeout)
            print(f"Tunnel SSH ouvert : {HOST}:{local_port} → {args.ssh} → {HOST}:{args.port}",
                  flush=True)
        sock, rfile, first = handshake(local_port, args.timeout)
        console = Console()
        app = ChatApp(key, name, console, args.show_cipher,
                      on_peer_closed=lambda _had: console.stop.set())
        with console:
            console.show(banner(key))
            app.attach(sock, rfile, first)
            console.show("Connecté. /help pour l'aide, /quit pour quitter.")
            try:
                input_loop(console, app)
            finally:
                app.disconnect()
    finally:
        if tunnel is not None:
            close_tunnel(tunnel)
            print("Tunnel SSH fermé.", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="enigma_chat.py",
        description="Messagerie chiffrée Enigma (pédagogique) transportée par SSH.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkey", help="génère une clé partagée aléatoire (JSON sur la sortie)")
    g.add_argument("--model", choices=list(MODELS), default="M3")
    g.add_argument("--mode", choices=MODES, default="binaire",
                   help="codage du texte (défaut : binaire, sans perte)")
    g.set_defaults(func=cmd_genkey)

    def common(sp):
        sp.add_argument("--name", required=True, help="votre nom affiché")
        sp.add_argument("--key", required=True, help="fichier de clé partagé (cle.json)")
        sp.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port de « serve » sur l'hôte (défaut {DEFAULT_PORT})")
        sp.add_argument("--show-cipher", action="store_true",
                        help="affiche aussi l'indicateur et le chiffré (groupes de 5)")

    s = sub.add_parser("serve", help="attend un interlocuteur sur 127.0.0.1 (côté hôte)")
    common(s)
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("connect", help="se connecte à l'hôte via un tunnel SSH")
    common(c)
    how = c.add_mutually_exclusive_group(required=True)
    how.add_argument("--ssh", metavar="USER@HOTE", help="ouvre le tunnel SSH vers cet hôte")
    how.add_argument("--no-ssh", action="store_true", help="test local, sans SSH")
    c.add_argument("--local-port", type=int, default=None,
                   help="port local du tunnel (défaut : identique à --port)")
    c.add_argument("--ssh-port", type=int, default=None, help="port SSH de l'hôte (défaut 22)")
    c.add_argument("--ssh-timeout", type=float, default=60,
                   help="délai max d'ouverture du tunnel, mot de passe compris (défaut 60 s)")
    c.add_argument("--timeout", type=float, default=10,
                   help="délai max de réponse de « serve » (défaut 10 s)")
    c.set_defaults(func=cmd_connect)
    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ChatError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAu revoir.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
