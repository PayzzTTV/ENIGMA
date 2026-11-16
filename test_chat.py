"""Tests de enigma_chat.py — python3 -m unittest -v test_chat"""
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import enigma_chat as ec
from enigma import ALPHA, MODELS, Enigma

HERE = os.path.dirname(os.path.abspath(__file__))
CHAT = os.path.join(HERE, "enigma_chat.py")

SAMPLES = [
    "",
    "salut",
    "Ça va ? Élève, garçon, œuvre, Straße, naïve, à bientôt !",
    "emojis 🎉👋🏽 👨‍👩‍👧 et 日本語",
    "chiffres 0123456789 et ponctuation ;:!?«»",
    "tab\tet\nretour",
]


def random_unicode(rng, n):
    pools = [(0x20, 0x7E), (0xC0, 0x17F), (0x391, 0x3C9), (0x4E00, 0x4FFF), (0x1F300, 0x1F64F)]
    out = []
    for _ in range(n):
        a, b = rng.choice(pools)
        out.append(chr(rng.randint(a, b)))
    return "".join(out)


class Encoding(unittest.TestCase):
    def test_binaire_roundtrip(self):
        for s in SAMPLES:
            enc = ec.encode_text(s, "binaire")
            self.assertTrue(set(enc) <= set("ABCDEFGHIJKLMNOP"), s)
            self.assertEqual(len(enc), 2 * len(s.encode("utf-8")))
            self.assertEqual(ec.decode_text(enc, "binaire"), s)

    def test_binaire_roundtrip_random(self):
        rng = random.Random(5555)
        for _ in range(300):
            s = random_unicode(rng, rng.randint(0, 40))
            self.assertEqual(ec.decode_text(ec.encode_text(s, "binaire"), "binaire"), s)

    def test_binaire_rejects_garbage(self):
        for bad in ("A", "QZ", "ABQ", "PP"):    # impair, hors A..P, UTF-8 invalide (0xFF)
            with self.assertRaises(ec.DecodeError):
                ec.decode_text(bad, "binaire")

    def test_historique(self):
        self.assertEqual(ec.encode_text("Café à 5h 🎉", "historique"), "CAFEXAXFUENFHX")
        self.assertEqual(ec.encode_text("0123456789", "historique"),
                         "NULLEINSZWEIDREIVIERFUENFSECHSSIEBENACHTNEUN")
        self.assertEqual(ec.encode_text("Straße, œuvre !", "historique"), "STRASSEXOEUVREX")
        self.assertEqual(ec.encode_text("🎉👋", "historique"), "")

    def test_historique_roundtrip(self):
        # Mode avec perte : décoder(encoder(x)) = encoder(x), uniquement A–Z.
        for s in SAMPLES:
            enc = ec.encode_text(s, "historique")
            self.assertTrue(set(enc) <= set(ALPHA), s)
            self.assertEqual(ec.decode_text(enc, "historique"), enc)


class Keys(unittest.TestCase):
    def test_genkey_valid_for_each_model(self):
        for model in MODELS:
            for _ in range(50):
                k = ec.genkey(model)
                n = 4 if model == "M4" else 3
                self.assertEqual(len(k["rotors"]), n)
                self.assertEqual(len(set(k["rotors"])), n)
                self.assertIn(k["reflector"], MODELS[model]["reflectors"])
                if model == "M4":
                    self.assertIn(k["rotors"][0], ("Beta", "Gamma"))
                pairs = k["steckerbrett"].split()
                self.assertEqual(len(pairs), 10)
                self.assertEqual(len(set("".join(pairs))), 20)
                self.assertEqual(len(k["ringstellung"]), n)
                self.assertEqual(len(k["grundstellung"]), n)
                Enigma(k["rotors"], k["reflector"], k["ringstellung"], k["grundstellung"],
                       k["steckerbrett"], model=model)

    def test_genkey_cli_outputs_loadable_json(self):
        out = subprocess.run([sys.executable, CHAT, "genkey", "--model", "M4", "--mode", "historique"],
                             capture_output=True, text=True, check=True).stdout
        k = ec.validate_key(json.loads(out))
        self.assertEqual((k["model"], k["mode"]), ("M4", "historique"))

    def test_invalid_keys_rejected(self):
        good = ec.genkey("M3")
        for field, value in [("model", "M9"), ("mode", "morse"), ("rotors", ["I", "I", "II"]),
                             ("reflector", "B-thin"), ("grundstellung", "AB"),
                             ("ringstellung", "A1C"), ("steckerbrett", "AB AC")]:
            with self.assertRaises(ec.ChatError, msg=field):
                ec.validate_key({**good, field: value})
        with self.assertRaises(ec.ChatError):
            ec.validate_key({k: v for k, v in good.items() if k != "mode"})


class MessageKeyProcedure(unittest.TestCase):
    def test_100_random_messages_I_M3_M4(self):
        rng = random.Random(1940)
        for model in ("I", "M3", "M4"):
            n = 4 if model == "M4" else 3
            for i in range(100):
                mode = "binaire" if i % 4 else "historique"
                key = ec.genkey(model, mode)
                text = random_unicode(rng, rng.randint(1, 60))
                indicator, ct = ec.encrypt_message(key, text)
                self.assertEqual(len(indicator), n)
                self.assertTrue(set(indicator + ct) <= set(ALPHA))
                expected = text if mode == "binaire" else ec.encode_text(text, "historique")
                self.assertEqual(ec.decrypt_message(key, indicator, ct), expected,
                                 f"{model} {mode} #{i}")

    def test_indicator_follows_the_procedure(self):
        key = ec.genkey("M3")
        indicator, ct = ec.encrypt_message(key, "bonjour", message_key="QWE")
        m = lambda pos: Enigma(key["rotors"], key["reflector"], key["ringstellung"], pos,
                               key["steckerbrett"], key["model"])
        self.assertEqual(indicator, m(key["grundstellung"]).encrypt("QWE"))
        self.assertEqual(ct, m("QWE").encrypt(ec.encode_text("bonjour", "binaire")))

    def test_same_message_twice_gives_two_ciphertexts(self):
        for model in ("I", "M3", "M4"):
            key = ec.genkey(model)
            a = ec.encrypt_message(key, "message identique")
            b = ec.encrypt_message(key, "message identique")
            self.assertNotEqual(a, b)
            self.assertNotEqual(a[1], b[1])
            self.assertEqual(ec.decrypt_message(key, *a), ec.decrypt_message(key, *b))

    def test_messages_are_independent(self):
        key = ec.genkey("M4")
        msgs = [f"message {i} é🎉" for i in range(10)]
        wire = [ec.encrypt_message(key, m) for m in msgs]
        # ordre inversé, un sur deux « perdu » : chaque message se déchiffre seul
        for i in reversed(range(0, 10, 2)):
            self.assertEqual(ec.decrypt_message(key, *wire[i]), msgs[i])

    def test_wrong_key_is_detected_in_binary_mode(self):
        k1, k2 = ec.genkey("M3"), ec.genkey("M3")
        ind, ct = ec.encrypt_message(k1, "un message assez long pour être sûr")
        with self.assertRaises(ec.DecodeError):
            ec.decrypt_message(k2, ind, ct)

    def test_bad_wire_fields_rejected(self):
        key = ec.genkey("M3")
        for ind, ct in [("QW", "ABC"), ("QWE", "abc"), (123, "ABC"), ("QWE", None)]:
            with self.assertRaises(ec.DecodeError):
                ec.decrypt_message(key, ind, ct)


class Clean(unittest.TestCase):
    def test_terminal_escapes_are_neutralised(self):
        s = ec.clean("a\x1b[2J\x1b]0;pwn\x07b\u202ec")
        self.assertNotIn("\x1b", s)
        self.assertNotIn("\x07", s)
        self.assertNotIn("\u202e", s)
        self.assertEqual(ec.clean("👨‍👩‍👧"), "👨‍👩‍👧")   # ZWJ conservé


# ---------------------------------------------------------------------------
# Bout en bout : vrais processus
# ---------------------------------------------------------------------------
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Proc:
    def __init__(self, *args):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self.p = subprocess.Popen([sys.executable, CHAT, *args], cwd=HERE, env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        self.lines = []
        self.cond = threading.Condition()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for raw in self.p.stdout:
            with self.cond:
                self.lines.append(raw.decode("utf-8", "replace"))
                self.cond.notify_all()

    @property
    def output(self):
        with self.cond:
            return "".join(self.lines)

    def wait_for(self, needle, timeout=15, after=0):
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for line in self.lines[after:]:
                    if needle in line:
                        return line
                left = deadline - time.monotonic()
                if left <= 0:
                    raise AssertionError(f"« {needle} » absent :\n{''.join(self.lines)}")
                self.cond.wait(left)

    def send(self, text):
        self.p.stdin.write((text + "\n").encode("utf-8"))
        self.p.stdin.flush()

    def stop(self):
        if self.p.poll() is None:
            try:
                self.send("/quit")
            except OSError:
                pass
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self.p.stdin.close()
        self.p.stdout.close()


class ChatHarness(unittest.TestCase):
    """Clé temporaire, port libre, et processus arrêtés en fin de test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keyfile = os.path.join(self.tmp.name, "cle.json")
        self.key = ec.genkey("M4")
        with open(self.keyfile, "w") as f:
            json.dump(self.key, f)
        self.port = free_port()
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.stop()
        self.tmp.cleanup()

    def start(self, *args):
        p = Proc(*args)
        self.procs.append(p)
        return p

    def serve(self, *extra):
        s = self.start("serve", "--name", "Alexis", "--key", self.keyfile,
                       "--port", str(self.port), *extra)
        s.wait_for("En écoute sur 127.0.0.1")
        return s

    def connect_no_ssh(self, *extra):
        return self.start("connect", "--name", "Bob", "--key", self.keyfile,
                          "--port", str(self.port), "--no-ssh", *extra)


class EndToEnd(ChatHarness):
    def test_two_processes_chat_both_ways(self):
        alexis = self.serve("--show-cipher")
        bob = self.connect_no_ssh()
        alexis.wait_for("Bob est en ligne")
        bob.wait_for("Alexis est en ligne")

        bob.send("Salut Alexis, ça va ? 👋 é")
        alexis.wait_for("] Bob : Salut Alexis, ça va ? 👋 é")
        alexis.wait_for("indicateur ")            # --show-cipher
        alexis.send("Très bien 🎉 et toi ? 42")
        bob.wait_for("] Alexis : Très bien 🎉 et toi ? 42")
        for i in range(5):                        # rafale dans les deux sens
            bob.send(f"b{i}")
            alexis.send(f"a{i}")
        for i in range(5):
            alexis.wait_for(f"] Bob : b{i}")
            bob.wait_for(f"] Alexis : a{i}")

        bob.send("/help")
        bob.wait_for("/quit")
        bob.send("/quit")
        self.assertEqual(bob.p.wait(5), 0)
        alexis.wait_for("En attente d'un interlocuteur")
        self.assertNotIn("Traceback", alexis.output + bob.output)

        # l'hôte reste disponible pour une nouvelle connexion
        bob2 = self.connect_no_ssh()
        alexis.wait_for("Bob est en ligne", after=len(alexis.lines) - 1)
        bob2.send("de retour")
        alexis.wait_for("] Bob : de retour")

    def test_client_exits_when_host_quits(self):
        alexis = self.serve()
        bob = self.connect_no_ssh()
        bob.wait_for("Alexis est en ligne")
        alexis.send("/quit")
        self.assertEqual(alexis.p.wait(5), 0)
        self.assertEqual(bob.p.wait(5), 0)

    def test_wire_carries_only_ciphertext(self):
        alexis = self.serve()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            f = raw.makefile("rb")
            self.assertEqual(json.loads(f.readline()), {"hello": "Alexis"})
            raw.sendall(b'{"hello": "Espion"}\n')
            alexis.wait_for("Espion est en ligne")
            alexis.send("message tres secret")
            line = f.readline().decode()
            self.assertNotIn("secret", line.lower())
            obj = json.loads(line)
            self.assertEqual(set(obj), {"from", "indicator", "ct"})
            self.assertEqual(ec.decrypt_message(self.key, obj["indicator"], obj["ct"]),
                             "message tres secret")
            # données hostiles : ignorées sans planter
            raw.sendall(b"pas du json\n")
            raw.sendall(b'{"from": "x", "indicator": "ZZ", "ct": "\\u001b[2J"}\n')
            ind, ct = ec.encrypt_message(self.key, "toujours vivant")
            raw.sendall(json.dumps({"from": "Espion", "indicator": ind, "ct": ct}).encode() + b"\n")
            alexis.wait_for("] Espion : toujours vivant")
        self.assertNotIn("\x1b[2J", alexis.output)

    def test_second_client_refused_while_busy(self):
        self.serve()
        bob = self.connect_no_ssh()
        bob.wait_for("Alexis est en ligne")
        carol = self.start("connect", "--name", "Carol", "--key", self.keyfile,
                           "--port", str(self.port), "--no-ssh")
        self.assertEqual(carol.p.wait(10), 1)
        self.assertIn("déjà en conversation", carol.output)

    def test_serve_listens_on_loopback_only(self):
        self.serve()
        out = subprocess.run(["lsof", "-nP", f"-iTCP:{self.port}", "-sTCP:LISTEN"],
                             capture_output=True, text=True).stdout if shutil_which("lsof") else ""
        if out:
            self.assertIn(f"127.0.0.1:{self.port}", out)
            self.assertNotIn(f"*:{self.port}", out)

    def test_port_already_taken(self):
        with socket.socket() as squatter:
            squatter.bind(("127.0.0.1", self.port))
            squatter.listen()
            s = self.start("serve", "--name", "A", "--key", self.keyfile, "--port", str(self.port))
            self.assertEqual(s.p.wait(10), 1)
            self.assertIn("déjà pris", s.output)

    def test_connect_without_server(self):
        bob = self.connect_no_ssh()
        self.assertEqual(bob.p.wait(10), 1)
        self.assertIn("serve", bob.output)

    def test_tunnel_refused_is_reported(self):
        # port SSH 1 : connexion refusée immédiatement
        bob = self.start("connect", "--name", "Bob", "--key", self.keyfile,
                         "--port", str(self.port), "--ssh", "personne@127.0.0.1",
                         "--ssh-port", "1", "--local-port", str(free_port()))
        self.assertEqual(bob.p.wait(30), 1)
        self.assertIn("tunnel refusé", bob.output)


def shutil_which(cmd):
    import shutil
    return shutil.which(cmd)


def ssh_localhost_works():
    try:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                            "localhost", "true"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return r.returncode == 0, r.stderr.strip()


class OverSSH(ChatHarness):
    """Même échange, mais à travers un vrai tunnel `ssh -L` vers localhost."""

    @classmethod
    def setUpClass(cls):
        ok, why = ssh_localhost_works()
        if not ok:
            raise unittest.SkipTest(f"ssh localhost indisponible ({why}) — test SSH NON exécuté")

    def test_chat_through_ssh_tunnel(self):
        alexis = self.serve()
        local = free_port()
        bob = self.start("connect", "--name", "Bob", "--key", self.keyfile,
                         "--port", str(self.port), "--ssh", "localhost",
                         "--local-port", str(local))
        bob.wait_for("Tunnel SSH ouvert", timeout=30)
        alexis.wait_for("Bob est en ligne")
        bob.send("via SSH 🔐 ça marche")
        alexis.wait_for("] Bob : via SSH 🔐 ça marche")
        alexis.send("bien reçu")
        bob.wait_for("] Alexis : bien reçu")
        bob.send("/quit")
        self.assertEqual(bob.p.wait(10), 0)
        bob.wait_for("Tunnel SSH fermé")
        time.sleep(0.5)
        self.assertFalse(ec.port_in_use(local), "le tunnel ssh tourne encore")


if __name__ == "__main__":
    unittest.main()
