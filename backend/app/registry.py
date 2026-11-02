"""
UAE brand registry: brand keyword -> (display name, official registered domains).

Any subdomain of an official domain is treated as official (api.emiratespost.ae).
TODO before the demo (Module A): verify every domain on the entity's official website,
add Arabic names, verification source and date (moving to data/registry.json).

Keys of 4 letters or fewer (rta, adcb, eim, tdra) only match as a whole word.
"""

UAE_BRANDS = {
    "salik":        ("Salik", ["salik.ae"]),
    "uaepass":      ("UAE PASS", ["uaepass.ae"]),
    "dubaipolice":  ("Dubai Police", ["dubaipolice.gov.ae"]),
    "adpolice":     ("Abu Dhabi Police", ["adpolice.gov.ae"]),
    "emiratespost": ("Emirates Post", ["emiratespost.ae"]),
    "etisalat":     ("Etisalat (e&)", ["etisalat.ae", "eand.com"]),
    "eim":          ("Etisalat (e&) webmail", ["eim.ae"]),
    "aramex":       ("Aramex", ["aramex.com"]),
    "emiratesnbd":  ("Emirates NBD", ["emiratesnbd.com"]),
    "adcb":         ("ADCB", ["adcb.com"]),
    "mashreq":      ("Mashreq", ["mashreq.com", "mashreqbank.com"]),
    "rta":          ("RTA", ["rta.ae"]),
    "tdra":         ("TDRA", ["tdra.gov.ae"]),
}

# Other spellings people (and scammers) use, mostly Arabic transliterations.
# Each alias matches like the brand itself and shares its official domains.
ALIASES = {
    "etisalat": ["itisalat", "etisalaat", "ettisalat"],
    "emiratespost": ["emiratepost", "emaratpost", "emiratesposts"],
    "mashreq": ["mashriq", "mashrek", "mashreqbank"],
    "salik": ["saleek"],
    "dubaipolice": ["dubaipolis", "shurtadubai"],
    "adpolice": ["abudhabipolice"],
    "emiratesnbd": ["enbd"],
}
for _key, _alts in ALIASES.items():
    for _alt in _alts:
        UAE_BRANDS.setdefault(_alt, UAE_BRANDS[_key])
