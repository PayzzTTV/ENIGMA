"""
enigma.py — Implémentation de référence de la logique de chiffrement Enigma
(Enigma I, M3 et M4), issue du reverse engineering du chemin du signal.

Modélisation
------------
Toutes les lettres sont des entiers 0..25 (A=0). Chaque composant est une
permutation de Z/26. Pour un rotor de câblage W, en position p avec un anneau
(Ringstellung) r, le décalage effectif est d = p - r et :

    aller  : x -> W[(x + d) mod 26] - d   (mod 26)
    retour : x -> W⁻¹[(x + d) mod 26] - d (mod 26)

soit la conjugaison de W par la rotation ρ^d : ρ^-d · W · ρ^d.

Chemin d'une frappe (après le pas des rotors) :
    Stecker → ETW (identité sur I/M3/M4) → R → M → L (→ 4e) → UKW
            → (4e) → L → M → R → ETW⁻¹ → Stecker → lampe
"""
from __future__ import annotations

from dataclasses import dataclass, field
import string

ALPHA = string.ascii_uppercase


def a2i(c: str) -> int:
    return ord(c.upper()) - 65


def i2a(i: int) -> str:
    return chr(i % 26 + 65)


# ---------------------------------------------------------------------------
# Tables de câblage (contacts d'entrée A..Z → contacts de sortie)
# ---------------------------------------------------------------------------
ROTORS = {
    #  nom    câblage                         encoches (lettre visible AVANT le report)
    "I":    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":   ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III":  ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":   ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":    ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    "VI":   ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
    "VII":  ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
    "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
    # 4e roue M4 (« Zusatzwalze ») : ne tourne jamais, pas d'encoche
    "Beta":  ("LEYJVCNIXWPBQMDRTAKZGFUHOS", ""),
    "Gamma": ("FSOKANUERHMBTIYCWLQPZXVGJD", ""),
}

REFLECTORS = {
    "A":       "EJMZALYXVBWFCRQUONTSPIKHGD",  # avant 1937, pour mémoire
    "B":       "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C":       "FVPJIAOYEDRZXWGCTKUQSBNMHL",
    "B-thin":  "ENKQAUYWJICOPBLMDXZVFTHRGS",  # M4 uniquement
    "C-thin":  "RDOBJNTKVEHMLFCWZAXGYIPSUQ",  # M4 uniquement
}

# Pièces autorisées par modèle
MODELS = {
    "I":  {"rotors": {"I", "II", "III", "IV", "V"}, "reflectors": {"A", "B", "C"}, "fourth": False},
    "M3": {"rotors": {"I", "II", "III", "IV", "V", "VI", "VII", "VIII"}, "reflectors": {"B", "C"}, "fourth": False},
    "M4": {"rotors": {"I", "II", "III", "IV", "V", "VI", "VII", "VIII"}, "reflectors": {"B-thin", "C-thin"}, "fourth": True},
}


# ---------------------------------------------------------------------------
# Composants
# ---------------------------------------------------------------------------
@dataclass
class Rotor:
    name: str
    ring: int = 0      # Ringstellung, 0..25 (A/01 = 0)
    pos: int = 0       # Grundstellung / lettre visible dans la fenêtre, 0..25
    fwd: list[int] = field(init=False)
    bwd: list[int] = field(init=False)
    notches: set[int] = field(init=False)

    def __post_init__(self):
        wiring, notch = ROTORS[self.name]
        self.fwd = [a2i(c) for c in wiring]
        self.bwd = [0] * 26
        for i, o in enumerate(self.fwd):
            self.bwd[o] = i
        self.notches = {a2i(c) for c in notch}

    def at_notch(self) -> bool:
        # L'encoche est solidaire de l'anneau alphabétique : elle se repère à la
        # lettre VISIBLE, indépendamment de la Ringstellung.
        return self.pos in self.notches

    def step(self) -> None:
        self.pos = (self.pos + 1) % 26

    def forward(self, x: int) -> int:
        d = self.pos - self.ring
        return (self.fwd[(x + d) % 26] - d) % 26

    def backward(self, x: int) -> int:
        d = self.pos - self.ring
        return (self.bwd[(x + d) % 26] - d) % 26


@dataclass
class Reflector:
    name: str
    wiring: list[int] = field(init=False)

    def __post_init__(self):
        self.wiring = [a2i(c) for c in REFLECTORS[self.name]]

    def reflect(self, x: int) -> int:
        return self.wiring[x]


@dataclass
class Plugboard:
    pairs: str = ""
    table: list[int] = field(init=False)

    def __post_init__(self):
        self.table = list(range(26))
        seen: set[str] = set()
        for p in self.pairs.upper().split():
            if len(p) != 2 or p[0] == p[1] or seen & set(p):
                raise ValueError(f"Paire de Stecker invalide ou en double : {p}")
            seen |= set(p)
            a, b = a2i(p[0]), a2i(p[1])
            self.table[a], self.table[b] = b, a
        if len(seen) > 26:
            raise ValueError("Trop de paires")

    def swap(self, x: int) -> int:
        return self.table[x]


# ---------------------------------------------------------------------------
# Machine
# ---------------------------------------------------------------------------
def _parse_settings(s: str | list, n: int) -> list[int]:
    """Accepte 'AAA', 'A A A', '01 01 01' ou [0, 0, 0]."""
    if isinstance(s, (list, tuple)):
        vals = list(s)
    else:
        toks = s.split()
        if len(toks) == 1 and toks[0].isalpha():
            toks = list(toks[0])
        vals = [int(t) - 1 if t.isdigit() else a2i(t) for t in toks]
    if len(vals) != n:
        raise ValueError(f"{n} valeurs attendues, reçu {s!r}")
    return vals


class Enigma:
    """
    rotors     : de GAUCHE à DROITE, comme l'opérateur les lit (ex. ["I","II","III"],
                 ou ["Beta","II","IV","I"] pour la M4).
    reflector  : "B", "C", "B-thin", "C-thin" (ou "A").
    rings      : Ringstellung, gauche → droite ("AAA", "01 01 01"...).
    positions  : Grundstellung / clé de message, gauche → droite.
    plugboard  : paires séparées par des espaces ("AT BL DF").
    """

    def __init__(self, rotors, reflector="B", rings=None, positions=None,
                 plugboard="", model=None):
        n = len(rotors)
        if n not in (3, 4):
            raise ValueError("3 ou 4 rotors")
        rings = _parse_settings(rings or "A" * n, n)
        positions = _parse_settings(positions or "A" * n, n)
        self.rotors = [Rotor(name, r, p) for name, r, p in zip(rotors, rings, positions)]
        self.reflector = Reflector(reflector)
        self.plugboard = Plugboard(plugboard)
        if model:
            self._check_model(model)

    def _check_model(self, model: str) -> None:
        m = MODELS[model]
        names = [r.name for r in self.rotors]
        if m["fourth"]:
            if len(names) != 4 or names[0] not in ("Beta", "Gamma"):
                raise ValueError("M4 : 4 rotors, le premier = Beta ou Gamma")
            names = names[1:]
        elif len(names) != 3:
            raise ValueError(f"{model} : 3 rotors")
        if len(set(names)) != 3 or not set(names) <= m["rotors"]:
            raise ValueError(f"{model} : rotors non autorisés ou en double {names}")
        if self.reflector.name not in m["reflectors"]:
            raise ValueError(f"{model} : réflecteur {self.reflector.name} non autorisé")

    # -- pas des rotors -----------------------------------------------------
    def step(self) -> None:
        """
        Mécanisme à cliquets (Fortschaltklinken). Trois cliquets, testés AVANT
        tout mouvement :
          * cliquet droit  : pousse toujours le rotor rapide ;
          * cliquet milieu : s'engage si le rotor droit est sur son encoche ;
            il pousse alors le rotor du milieu ;
          * cliquet gauche : s'engage si le rotor du milieu est sur son encoche ;
            il pousse le rotor gauche ET (par son encoche) le rotor du milieu.
        Ce dernier point produit le « double pas » du rotor du milieu.
        La 4e roue (M4) n'est jamais poussée.
        """
        left, mid, right = self.rotors[-3:]
        if mid.at_notch():          # double pas
            mid.step()
            left.step()
        elif right.at_notch():
            mid.step()
        right.step()

    # -- une lettre ---------------------------------------------------------
    def press(self, c: str) -> str:
        self.step()
        x = self.plugboard.swap(a2i(c))
        for r in reversed(self.rotors):           # droite → gauche
            x = r.forward(x)
        x = self.reflector.reflect(x)
        for r in self.rotors:                     # gauche → droite
            x = r.backward(x)
        x = self.plugboard.swap(x)
        return i2a(x)

    def trace(self, c: str) -> list[tuple[str, str]]:
        """Comme press(), mais renvoie chaque étape du chemin du signal."""
        self.step()
        steps = [("touche", c.upper())]
        x = self.plugboard.swap(a2i(c)); steps.append(("Stecker", i2a(x)))
        for r in reversed(self.rotors):
            x = r.forward(x); steps.append((f"{r.name} →", i2a(x)))
        x = self.reflector.reflect(x); steps.append((f"UKW {self.reflector.name}", i2a(x)))
        for r in self.rotors:
            x = r.backward(x); steps.append((f"{r.name} ←", i2a(x)))
        x = self.plugboard.swap(x); steps.append(("Stecker / lampe", i2a(x)))
        return steps

    def encrypt(self, text: str) -> str:
        """Lettres A–Z uniquement ; tout le reste est ignoré (comme sur la machine)."""
        return "".join(self.press(c) for c in text.upper() if c in ALPHA)

    decrypt = encrypt  # la machine est réciproque

    @property
    def window(self) -> str:
        return "".join(i2a(r.pos) for r in self.rotors)


def groups(s: str, n: int = 5) -> str:
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Simulateur Enigma I / M3 / M4")
    ap.add_argument("--model", choices=MODELS, default=None)
    ap.add_argument("--rotors", required=True, help='ex. "I II III" ou "Beta II IV I"')
    ap.add_argument("--reflector", default="B")
    ap.add_argument("--rings", default=None, help='ex. "AAA" ou "01 01 01"')
    ap.add_argument("--pos", default=None, help='Grundstellung, ex. "AAA"')
    ap.add_argument("--plugs", default="", help='ex. "AT BL DF"')
    ap.add_argument("text")
    a = ap.parse_args()
    m = Enigma(a.rotors.split(), a.reflector, a.rings, a.pos, a.plugs, a.model)
    print(groups(m.encrypt(a.text)))
