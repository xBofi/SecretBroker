"""Password generator and strength estimate.

Everything random comes from `secrets` (the OS CSPRNG). The app asks for passwords to fill in the
editor or to copy; the service uses `strength` to find weak passwords without sending them anywhere.
"""

import math
import re
import secrets

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
# No quotes, backslash, space, ';' or '|': the password still works pasted in a shell, a .env or a URL form.
SYMBOLS = "!#$%&*+-.:=?@^_~"
AMBIGUOUS = set("Il1O0o")
MIN_LENGTH, MAX_LENGTH = 12, 128
MIN_WORDS, MAX_WORDS = 3, 12
SEPARATORS = ("-", ".", "_", " ", ",", "")

# Short, common words in Spanish and English (ASCII only: no accents to type on a phone or another
# keyboard). Duplicates and words outside 3-8 letters are dropped when the list is built.
_ES = """
abeja abrigo acero adobe agua aguila aire ajo ala alba album alerta alma almendra alpaca altar alto amapola
amigo ancho ancla angel anillo anis arbol arco arena arpa arroz arte asado asno astro atlas atun aula ave
avena avion ayer azucar azul bahia baile bala balsa ballena bambu banco barba barco barro base baston bate
bebida bello beso bici bigote boda bolero bolsa borde bosque bota botella botin brazo brisa brocha broma
bruja bueno bufanda buho burro caballo cabello cabra cacao cactus cadena cafe caja cal calma calor calle
cama camino camisa campo canal canela canoa canto capa cara caracol carbon carne carro carta casa casco
castillo cazo cebolla cebra cedro cena centro cereal cerdo cereza cerro cesta chispa cielo cine cinta circo
cisne ciudad clave clima cobre coche codo cohete cola colina collar color comida cometa concha conejo copa
coral cordero corona correo corte cortina cosa costa crema cruz cubo cuchara cuello cuento cuerda cueva
cultura cuna dado dama danza dedo delfin diente dinero disco dragon ducha dulce duna eco edad eje elfo
enano enebro enero error escala escoba esfera espada espejo espiga establo estrella falda faro farol felpa
fideo fiesta firma flauta flor foca foco fogata fondo forma foto fresa fresno fruta fuego fuente gafas
galleta gallo gamba ganso garza gato gemelo genio gesto gigante girasol globo gloria golpe gorila gorra
gota granja grano grifo grillo grupo gruta guante guisante haba hacha hada hamaca harina helado hielo
hierba hierro higo hilo hoja hombre hongo hora hormiga horno hotel huella huerto hueso huevo humo idea
iglesia iman isla jabon jaguar jamon jardin jarra jefe jirafa joven joya juego jugo juglar junio kiwi
ladrillo lagarto lago lampara lana lanza lapiz largo lata laurel lazo leche lechuza lema lengua leon letra
libro lienzo lima limon linea lino lirio llama llave lluvia lobo lodo lomo loro luna lunes luz madera
madre maiz malla mango mano manta manzana mapa mar marco marea martillo melon menta mesa metro miel mimo
mina mirlo mochila moda molino moneda mono monte mora morado mosca mostaza motor mundo muro museo musica
nabo naranja nariz nave navaja nectar niebla nieve nido noche nogal norte nota nube nuez numero nutria
oasis oca ocaso ocho oeste ola olivo olla olmo onda orca oreja oro ortiga oso otono oveja padre paja
pajaro palabra palma paloma pan panal pantera papaya papel parque pasillo pastel pasto pata patio pato paz
pecho peine pelota pepino pera perdiz perla perro pez piano pie piedra pimienta pino pinta pista pizarra
planeta platano plata playa pluma plaza pollo polvo pomada pomelo poncho postre potro prado primo pueblo
puente puerta pulpo pulsera punto queso quinoa rabano radio raiz rama rana raton rayo red refugio regla
reina reloj remo retama rio robot roble roca rocio rojo romero rosa rubi rueda ruido sabio sal salsa salto
sandia sapo sardina sarten sauce seda selva semilla senda sierra silla sirena sobre sofa sol soga sombra
sopa suelo tabla taco tambor tapiz tarde taza techo tejado tela telar tema tetera tierra tigre tijera
tinta tio tomate toro torre tortuga trigo trineo trueno tubo tulipan tuna turron urna uva vaca valija
valle vapor vasija vaso vela velero verano verde vereda viaje vida viento vino violeta violin volcan vuelo
yate yegua yema yogur yunque zapato zorro zumo
"""
_EN = """
acid acorn actor agent alarm alley alpine amber anchor angle ankle apple apron arena armor arrow attic
audio autumn avocado bacon badge bagel baker banjo barn basil basket beach beacon beard beaver berry bison
blade blanket blaze bloom board boat bonus booth bottle boulder bowl brave bread breeze brick bridge brook
broom brush bubble bucket buffalo bugle bunny butter button cabin cable camel camera candle canvas canyon
carpet carrot castle cedar cello chalk charm cherry chess chicken chimney cider cinema clay cliff clock
cloud clover coast cobalt cobra cocoa coffee comet copper cotton cougar cousin cowboy crane crayon creek
cricket crown crystal cupcake curtain cycle daisy dancer delta desert diamond dinner dolphin donkey dream
drum duck dune dusk eagle earth eclipse elbow ember engine fable falcon feather fence fern ferry fiddle
field finch fjord flag flame flute forest fossil fox frost galaxy garden garlic gecko ginger glacier glove
glow goat gold goose grape gravel grove guitar hammer harbor harp harvest hawk hazel heron hill hollow
honey horizon horse igloo island ivory ivy jacket jade jasper jelly jewel jungle karma kayak kettle kitten
koala ladder lagoon lake lantern laptop lark lava lemon lemur lily lime linen lion lizard lobster locket
lotus lunar magnet maple marble meadow mesa meteor mint mirror monkey moose mosaic moss mountain muffin
mural needle nest nimbus noodle north nova nutmeg oak ocean olive onion opal orange orbit orchard orchid
otter owl oyster paddle palace panda paper parrot pasta peach peanut pearl pebble pecan pepper pickle
pigeon pillow pilot pine pirate pixel planet plum pocket poem polar pony poppy potato prairie prism
pumpkin puzzle quartz quest quill quiver rabbit radar radish rain rapids raven reef rhythm ribbon river
robin rocket rose ruby saddle sail salmon sand saturn scarf school sea seal season shadow shark shell
silver sketch sky sloth snow socket solar sonnet spark sphinx spider spoon spring squid star stone storm
straw stream summer summit sun swan table tango teapot thistle thunder tiger timber toast topaz torch
tower tractor trail train tree trumpet tulip tundra turtle twig umber valley velvet vista wagon walnut
walrus water wave whale wheat willow window winter wizard wolf wood wren xenon yacht yarn yeti yodel
zebra zenith zephyr zero zinc
"""
WORDS = tuple(sorted({w for w in (_ES + _EN).split() if 3 <= len(w) <= 8 and w.isalpha() and w.isascii()}))

# Passwords people pick: a password whose core is one of these (or a dictionary word) is guessed first.
COMMON = frozenset("""
password passw0rd contrasena clave secreto qwerty qwertz azerty asdf asdfgh zxcvbn letmein welcome
admin administrator root toor login master monkey dragon football baseball soccer futbol princess
sunshine shadow superman batman iloveyou teamo abc abcd abcdef abcdefg 123456 1234567 12345678 123456789
1234567890 111111 000000 654321 123123 121212 666666 7777777 hello hola test prueba guest invitado
changeme cambiar default secret access trustno1 freedom whatever charlie michael jordan jennifer hunter
ranger buster tigger killer pepper ginger cookie chocolate summer winter spring autumn verano invierno
primavera otono madrid barcelona espana spain mexico argentina amor amigo familia casa perro gato
""".split())
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"})
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "azertyuiop", "qwertzuiop")
STRENGTH_LABELS = ("Muy débil", "Débil", "Aceptable", "Buena", "Excelente")

DEFAULTS = {"mode": "random", "length": 20, "lower": True, "upper": True, "digits": True, "symbols": True,
            "avoid_ambiguous": False, "words": 5, "separator": "-", "capitalize": True, "number": True}
# Named starting points for the app: a database password goes in a connection URL, SQL and shells.
PRESETS = {
    "default": {},
    "url_safe": {"length": 32, "symbols": False},
    "passphrase": {"mode": "passphrase"},
}


class GeneratorError(ValueError):
    pass


def _options(options):
    options = dict(options or {})
    preset = PRESETS.get(options.pop("preset", None) or "default", {})
    merged = {**DEFAULTS, **preset, **{k: v for k, v in options.items() if k in DEFAULTS and v is not None}}
    if merged["mode"] not in ("random", "passphrase"):
        raise GeneratorError("Tipo de contraseña no válido")
    try:
        merged["length"] = int(merged["length"])
        merged["words"] = int(merged["words"])
    except (TypeError, ValueError):
        raise GeneratorError("La longitud debe ser un número") from None
    if not MIN_LENGTH <= merged["length"] <= MAX_LENGTH:
        raise GeneratorError(f"La longitud va de {MIN_LENGTH} a {MAX_LENGTH} caracteres")
    if not MIN_WORDS <= merged["words"] <= MAX_WORDS:
        raise GeneratorError(f"Entre {MIN_WORDS} y {MAX_WORDS} palabras")
    if merged["separator"] not in SEPARATORS:
        raise GeneratorError("Separador no válido")
    for key in ("lower", "upper", "digits", "symbols", "avoid_ambiguous", "capitalize", "number"):
        merged[key] = bool(merged[key])
    return merged


def _classes(options):
    chosen = [chars for key, chars in (("lower", LOWER), ("upper", UPPER), ("digits", DIGITS), ("symbols", SYMBOLS)) if options[key]]
    if options["avoid_ambiguous"]:
        chosen = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in chosen]
    if not chosen:
        raise GeneratorError("Elige al menos un tipo de carácter")
    return chosen


def random_password(options):
    """At least one character of each chosen class, the rest from all of them, shuffled."""
    classes = _classes(options)
    pool = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(pool) for _ in range(options["length"] - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), round(options["length"] * math.log2(len(pool)))


def passphrase(options):
    words = [secrets.choice(WORDS) for _ in range(options["words"])]
    bits = options["words"] * math.log2(len(WORDS))
    if options["capitalize"]:
        words = [w.capitalize() for w in words]
    if options["number"]:
        index = secrets.randbelow(len(words))
        words[index] += str(secrets.randbelow(10))
        bits += math.log2(10) + math.log2(len(words))
    return options["separator"].join(words), round(bits)


def generate(options=None):
    """{"value", "bits", "mode", "strength"} for the given options (see DEFAULTS and PRESETS)."""
    options = _options(options)
    value, bits = (random_password if options["mode"] == "random" else passphrase)(options)
    return {"value": value, "bits": bits, "mode": options["mode"], "strength": _score(bits)}


# --------------------------------------------------------------------------- strength


def _pool(text):
    size = 0
    size += 26 if re.search(r"[a-z]", text) else 0
    size += 26 if re.search(r"[A-Z]", text) else 0
    size += 10 if re.search(r"\d", text) else 0
    size += 33 if re.search(r"[^A-Za-z0-9]", text) else 0
    return max(size, 2)


def _predictable(text):
    """How many characters only continue a run (aaaa, abcd, 4321, qwerty): they add almost nothing."""
    lowered = text.lower()
    count = 0
    for i in range(2, len(lowered)):
        a, b, c = lowered[i - 2], lowered[i - 1], lowered[i]
        repeat = a == b == c
        step = ord(b) - ord(a) == ord(c) - ord(b) and abs(ord(c) - ord(b)) == 1
        keyboard = any(a + b + c in row or c + b + a in row for row in KEYBOARD_ROWS)
        count += repeat or step or keyboard
    # A password made of one short block repeated (abcabcabc) is as strong as the block.
    for size in range(1, len(text) // 2 + 1):
        if len(text) % size == 0 and text[:size] * (len(text) // size) == text:
            return max(count, len(text) - size)
    return count


def estimate_bits(password):
    """A rough, conservative estimate of how many guesses (2^bits) a password resists."""
    if not password:
        return 0
    lowered = password.lower()
    if lowered in COMMON or lowered.translate(LEET) in COMMON:
        return 4
    # One or two words with some digits or symbols around them (Summer2024!, MiPerro2015, P@ssw0rd1):
    # guessed word by word first, then the extras.
    prefix, core, suffix = re.match(r"^([^a-z]*)(.*?)([^a-z]*)$", lowered).groups()
    words = _dictionary_words(core.translate(LEET))
    if words and len(core) >= len(password) / 3:
        extras = prefix + suffix
        bits = words * math.log2(len(COMMON) + len(WORDS)) + len(extras) * math.log2(_pool(extras) if extras else 2)
        if password[:1].isupper():
            bits += 1
        return round(bits)
    effective = len(password) - _predictable(password)
    return round(max(effective, 1) * math.log2(_pool(password)))


def _known(word):
    return word in COMMON or word in WORDS or len(word) <= 2


def _dictionary_words(core):
    """1 or 2 if `core` is one dictionary word or two joined, else 0."""
    if not core:
        return 0
    if _known(core) or len(core) <= 3:
        return 1
    return 2 if any(_known(core[:i]) and _known(core[i:]) for i in range(1, len(core))) else 0


def _score(bits):
    return 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4


def strength(password):
    """{"score": 0-4, "bits", "label"}; score 0-1 is weak."""
    bits = estimate_bits(password)
    score = _score(bits)
    if len(password or "") < 8:
        score = 0
    return {"score": score, "bits": bits, "label": STRENGTH_LABELS[score]}


def is_weak(password):
    return strength(password)["score"] <= 1
