"""Tests de validation de enigma.py — python3 -m unittest -v test_enigma"""
import random
import unittest

from enigma import Enigma, REFLECTORS, ROTORS, a2i

BARBAROSSA_CT = (
    "EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM "
    "YLKLT TDEIS MDICA GYKUA CTCDO MOHWX MUUIA UBSTS LRNBZ SZWNR FXWFY SSXJZ "
    "VIJHI DISHP RKLKA YUPAD TXQSP INQMA TLPIF SVKDA SCTAC DPBOP VHJK"
)
BARBAROSSA_PT = (
    "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGER"
    "STRASZERIQTUNGXDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLX"
    "UHRANGETRETENXANGRIFFXINFXRGTX"
)
U264_CT = (
    "NCZW VUSX PNYM INHZ XMQX SFWX WLKJ AHSH NMCO CCAK UQPM KCSM HKSE INJU SBLK "
    "IOSX CKUB HMLL XCSJ USRR DVKO HULX WCCB GVLI YXEO AHXR HKKF VDRE WEZL XOBA "
    "FGYU JQUK GRTV UKAM EURB VEKS UHHV OYHA BCJW MAKL FKLM YFVN RIZR VVRT KOFD "
    "ANJM OLBG FFLE OPRG TFLV RHOW OPBE KVWM UQFM PWPA RMFH AGKX IIBG"
)
U264_PT = (
    "VONVONJLOOKSJHFFTTTEINSEINSDREIZWOYYQNNSNEUNINHALTXXBEIANGRIFFUNTERWASSER"
    "GEDRUECKTYWABOSXLETZTERGEGNERSTANDNULACHTDREINULUHRMARQUANTONJOTANEUNACHT"
    "SEYHSDREIYZWOZWONULGRADYACHTSMYSTOSSENACHXEKNSVIERMBFAELLTYNNNNNNOOOVIER"
    "YSICHTEINSNULL"
)


class HistoricalVectors(unittest.TestCase):
    def test_canonical_AAAAA(self):
        m = Enigma(["I", "II", "III"], "B", "AAA", "AAA", model="I")
        self.assertEqual(m.encrypt("AAAAA"), "BDZGO")

    def test_barbarossa_1941_enigma_I(self):
        plugs = "AV BS CG DL FU HZ IN KM OW RX"
        # 1) l'indicateur KCH chiffré en Grundstellung WXC donne la clé BLA
        m = Enigma(["II", "IV", "V"], "B", "02 21 12", "WXC", plugs, model="I")
        self.assertEqual(m.encrypt("KCH"), "BLA")
        # 2) le message, chiffré en BLA
        m = Enigma(["II", "IV", "V"], "B", "02 21 12", "BLA", plugs, model="I")
        self.assertEqual(m.decrypt(BARBAROSSA_CT), BARBAROSSA_PT)

    def test_u264_1942_enigma_M4(self):
        m = Enigma(["Beta", "II", "IV", "I"], "B-thin", "AAAV", "VJNA",
                   "AT BL DF GJ HM NW OP QY RZ VX", model="M4")
        self.assertEqual(m.decrypt(U264_CT), U264_PT)


class Stepping(unittest.TestCase):
    def seq(self, rotors, start, n):
        m = Enigma(rotors, "B", positions=start)
        out = [m.window]
        for _ in range(n):
            m.step()
            out.append(m.window)
        return out

    def test_double_step_I_II_III(self):
        self.assertEqual(self.seq(["I", "II", "III"], "ADU", 3), ["ADU", "ADV", "AEW", "BFX"])

    def test_double_notch_VI_VII_VIII(self):
        r = ["VI", "VII", "VIII"]
        self.assertEqual(self.seq(r, "ZYY", 3), ["ZYY", "ZYZ", "ZZA", "AAB"])
        self.assertEqual(self.seq(r, "MLL", 3), ["MLL", "MLM", "MMN", "NNO"])
        self.assertEqual(self.seq(r, "ZZY", 3), ["ZZY", "AAZ", "ABA", "ABB"])
        self.assertEqual(self.seq(r, "ZZZ", 2), ["ZZZ", "AAA", "AAB"])
        self.assertEqual(self.seq(r, "YZY", 2), ["YZY", "ZAZ", "ZBA"])

    def test_fourth_rotor_never_moves(self):
        m = Enigma(["Gamma", "VI", "VII", "VIII"], "C-thin", positions="QAAA")
        for _ in range(20000):
            m.step()
        self.assertEqual(m.window[0], "Q")

    def test_period_is_16900(self):
        # 26 × 25 × 26 : le double pas « vole » une position au rotor du milieu
        m = Enigma(["I", "II", "III"], "B")
        start, n = m.window, 0
        while True:
            m.step(); n += 1
            if m.window == start:
                break
        self.assertEqual(n, 16900)

    def test_ring_setting_does_not_move_turnover(self):
        # La Ringstellung change le câblage vu, pas la lettre de report
        for ring in ("AAA", "AAM", "AAZ"):
            m = Enigma(["I", "II", "III"], "B", rings=ring, positions="AAV")
            m.step()
            self.assertEqual(m.window, "ABW")


class Properties(unittest.TestCase):
    def test_reciprocal_and_no_fixed_point(self):
        rng = random.Random(1939)
        for _ in range(200):
            rot = rng.sample(["I", "II", "III", "IV", "V", "VI", "VII", "VIII"], 3)
            four = rng.random() < 0.5
            if four:
                rot = [rng.choice(["Beta", "Gamma"])] + rot
                refl = rng.choice(["B-thin", "C-thin"])
            else:
                refl = rng.choice(["B", "C"])
            n = len(rot)
            letters = [chr(65 + i) for i in rng.sample(range(26), 20)]
            plugs = " ".join(letters[i] + letters[i + 1] for i in range(0, 20, 2))
            rings = "".join(chr(65 + rng.randrange(26)) for _ in range(n))
            pos = "".join(chr(65 + rng.randrange(26)) for _ in range(n))
            pt = "".join(chr(65 + rng.randrange(26)) for _ in range(300))
            ct = Enigma(rot, refl, rings, pos, plugs).encrypt(pt)
            self.assertEqual(Enigma(rot, refl, rings, pos, plugs).decrypt(ct), pt)
            self.assertTrue(all(a != b for a, b in zip(pt, ct)), "point fixe trouvé")

    def test_reflectors_are_fixed_point_free_involutions(self):
        for name, w in REFLECTORS.items():
            for i, c in enumerate(w):
                j = a2i(c)
                self.assertNotEqual(i, j, name)
                self.assertEqual(a2i(w[j]), i, name)

    def test_rotor_wirings_are_permutations(self):
        for name, (w, _) in ROTORS.items():
            self.assertEqual(sorted(w), [chr(65 + i) for i in range(26)], name)

    def test_M4_with_Beta_A_and_B_thin_equals_M3_with_B(self):
        # Compatibilité descendante : Beta en A + UKW B-mince ≡ UKW B (idem Gamma + C-mince ≡ C)
        rng = random.Random(42)
        pt = "".join(chr(65 + rng.randrange(26)) for _ in range(500))
        for fourth, thin, thick in (("Beta", "B-thin", "B"), ("Gamma", "C-thin", "C")):
            m3 = Enigma(["I", "II", "III"], thick, "CDE", "XYZ", "AB CD EF")
            m4 = Enigma([fourth, "I", "II", "III"], thin, "ACDE", "AXYZ", "AB CD EF")
            self.assertEqual(m3.encrypt(pt), m4.encrypt(pt))

    def test_model_validation(self):
        with self.assertRaises(ValueError):
            Enigma(["VI", "II", "III"], "B", model="I")       # VI absent de l'Enigma I
        with self.assertRaises(ValueError):
            Enigma(["Beta", "I", "II", "III"], "B", model="M4")  # M4 = réflecteur mince
        with self.assertRaises(ValueError):
            Enigma(["I", "I", "III"], "B", model="M3")        # rotor en double
        with self.assertRaises(ValueError):
            Enigma(["I", "II", "III"], "B", plugboard="AB AC")  # lettre en double


if __name__ == "__main__":
    unittest.main()
