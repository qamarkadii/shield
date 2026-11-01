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
