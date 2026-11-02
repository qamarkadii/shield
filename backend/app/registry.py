"""
UAE brand registry: brand keyword -> (display name, official registered domains).

Any subdomain of an official domain is treated as official (api.emiratespost.ae).
TODO before the demo (Module A): verify every domain on the entity's official website,
add Arabic names, verification source and date (moving to data/registry.json).
Entries marked "v2" were added on Nov 2 2026 to find more real UAE fakes in public
phishing data; their official domains are well known but still need that check.

Keys of 4 letters or fewer (rta, adcb, eim, tdra) only match as a whole word.
Keys that are ordinary words or names elsewhere ("emirates", "noon", "fab", "du",
"mofa", "dha") are left out on purpose: they would flag many legitimate sites.
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
    # v2: government services
    "uaeicp":       ("ICP (Identity and Citizenship)", ["icp.gov.ae"]),   # bare 'icp' = crypto coin
    "gdrfa":        ("GDRFA Dubai", ["gdrfad.gov.ae"]),
    "mohre":        ("MOHRE", ["mohre.gov.ae"]),
    "mohap":        ("MOHAP", ["mohap.gov.ae"]),
    "dewa":         ("DEWA", ["dewa.gov.ae"]),
    "addc":         ("ADDC", ["addc.ae"]),
    "tamm":         ("TAMM Abu Dhabi", ["tamm.abudhabi"]),
    "dubaicustoms": ("Dubai Customs", ["dubaicustoms.gov.ae"]),
    "dubaimunicipality": ("Dubai Municipality", ["dm.gov.ae"]),
    "dubaitaxi":    ("Dubai Taxi", ["dubaitaxi.ae"]),
    "seha":         ("SEHA", ["seha.ae"]),
    # v2: banks and exchanges
    "bankfab":      ("First Abu Dhabi Bank", ["bankfab.com"]),
    "adib":         ("ADIB", ["adib.ae"]),
    "dib":          ("Dubai Islamic Bank", ["dib.ae"]),
    "rakbank":      ("RAKBANK", ["rakbank.ae"]),
    "emiratesislamic": ("Emirates Islamic", ["emiratesislamic.ae"]),
    "ajmanbank":    ("Ajman Bank", ["ajmanbank.ae"]),
    "cbuae":        ("Central Bank of the UAE", ["centralbank.ae"]),
    "alansari":     ("Al Ansari Exchange", ["alansariexchange.com"]),
    "luluexchange": ("LuLu Exchange", ["luluexchange.com"]),
    # v2: national companies often used as lures
    "adnoc":        ("ADNOC", ["adnoc.ae", "adnocdistribution.ae"]),
    "enoc":         ("ENOC", ["enoc.com"]),
    "etihad":       ("Etihad", ["etihad.com", "etihadrail.ae", "etihadwe.ae", "etihadguest.com"]),
    "flyemirates":  ("Emirates (airline)", ["emirates.com"]),
    "dubaidutyfree": ("Dubai Duty Free", ["dubaidutyfree.com"]),
    "careem":       ("Careem", ["careem.com"]),
    "talabat":      ("Talabat", ["talabat.com"]),
    "emaar":        ("Emaar", ["emaar.com"]),
}

# Other spellings people (and scammers) use, mostly Arabic transliterations.
# Each alias matches like the brand itself and shares its official domains.
ALIASES = {
    "etisalat": ["itisalat", "etisalaat", "ettisalat", "eand"],
    "emiratespost": ["emiratepost", "emaratpost", "emiratesposts"],
    "mashreq": ["mashriq", "mashrek", "mashreqbank"],
    "salik": ["saleek"],
    "dubaipolice": ["dubaipolis", "shurtadubai"],
    "adpolice": ["abudhabipolice"],
    "emiratesnbd": ["enbd"],
    "uaeicp": ["icpuae", "emiratesid", "icpgov"],
    "gdrfa": ["gdrfad"],
    "bankfab": ["firstabudhabibank"],
    "flyemirates": ["emiratesairline", "emiratesairlines", "emiratesskywards"],
    "etihad": ["etihadairways"],
    "dubaidutyfree": ["dubaidutyfrees"],
}
for _key, _alts in ALIASES.items():
    for _alt in _alts:
        UAE_BRANDS.setdefault(_alt, UAE_BRANDS[_key])
