"""
Arabic versions of Shield's explanations, for the public citizen site.

Each English line produced by scoring.py / linkcheck.py is matched against a
pattern and rewritten in Arabic. Anything without a pattern stays in English,
so a new English message never disappears.
"""

import re

HOW_AR = {
    "the name is re-spelled": "الاسم مكتوب بتهجئة مختلفة",
    "the name is combined with a lure word": "الاسم مقرون بكلمة استدراج",
    "the name is placed in front of an unrelated domain": "الاسم موضوع أمام نطاق لا علاقة له به",
    "the name is written with look-alike characters": "الاسم مكتوب بحروف أو أرقام مشابهة",
    "'.ae' is placed inside a foreign domain": "وُضعت '.ae' داخل نطاق أجنبي",
}

BRAND_AR = {
    "Salik": "سالك", "UAE PASS": "الهوية الرقمية (UAE PASS)", "Dubai Police": "شرطة دبي",
    "Abu Dhabi Police": "شرطة أبوظبي", "Emirates Post": "بريد الإمارات", "Etisalat (e&)": "اتصالات (e&)",
    "Etisalat (e&) webmail": "البريد الإلكتروني لاتصالات", "Aramex": "أرامكس", "Emirates NBD": "بنك الإمارات دبي الوطني",
    "ADCB": "بنك أبوظبي التجاري", "Mashreq": "بنك المشرق", "RTA": "هيئة الطرق والمواصلات",
    "TDRA": "هيئة تنظيم الاتصالات والحكومة الرقمية",
    "ICP (Identity and Citizenship)": "الهيئة الاتحادية للهوية والجنسية", "GDRFA Dubai": "الإقامة وشؤون الأجانب - دبي",
    "MOHRE": "وزارة الموارد البشرية والتوطين", "MOHAP": "وزارة الصحة ووقاية المجتمع", "DEWA": "هيئة كهرباء ومياه دبي",
    "ADDC": "شركة أبوظبي للتوزيع", "TAMM Abu Dhabi": "منصة تم - أبوظبي", "Dubai Customs": "جمارك دبي",
    "Dubai Municipality": "بلدية دبي", "Dubai Taxi": "تاكسي دبي", "SEHA": "صحة",
    "First Abu Dhabi Bank": "بنك أبوظبي الأول", "ADIB": "مصرف أبوظبي الإسلامي", "Dubai Islamic Bank": "بنك دبي الإسلامي",
    "RAKBANK": "بنك رأس الخيمة الوطني", "Emirates Islamic": "الإمارات الإسلامي", "Ajman Bank": "مصرف عجمان",
    "Central Bank of the UAE": "مصرف الإمارات العربية المتحدة المركزي", "Al Ansari Exchange": "الأنصاري للصرافة",
    "LuLu Exchange": "لولو للصرافة", "ADNOC": "أدنوك", "ENOC": "إينوك", "Etihad": "الاتحاد", "Emirates (airline)": "طيران الإمارات",
    "Dubai Duty Free": "السوق الحرة دبي", "Careem": "كريم", "Talabat": "طلبات", "Emaar": "إعمار",
}

PATTERNS = [
    (r"^Official (.+) domain \(registry\)$", "الموقع الرسمي لـ {0} (حسب سجل درع)"),
    (r"^Rule: imitates (.+), a registered UAE brand \((.+); this site: (.+), official: (.+)\)\. Always sent for analyst review\.$",
     "قاعدة: ينتحل اسم {0}، وهي جهة إماراتية مسجلة ({1}؛ هذا الموقع: {2}، الموقع الرسمي: {3}). يُرسل دائماً لمراجعة المحلل."),
    (r"^Rule: puts '\.ae' / 'gov' inside a foreign domain to look official\. Sent for analyst review\.$",
     "قاعدة: يضع '.ae' أو 'gov' داخل نطاق أجنبي ليبدو رسمياً. يُرسل لمراجعة المحلل."),
    (r"^Fact: listed in a public phishing database \(Phishing\.Database / OpenPhish\)$",
     "حقيقة: مدرج في قاعدة بيانات عامة لمواقع التصيّد الاحتيالي"),
    (r"^Fact: uses foreign look-alike letters; it displays as '(.+)'$",
     "حقيقة: يستخدم حروفاً أجنبية مشابهة؛ يظهر بالشكل '{0}'"),
    (r"^Fact: uses foreign letters \(punycode\) in the name$", "حقيقة: يستخدم حروفاً أجنبية في الاسم"),
    (r"^Rule: foreign letters make it look like (.+) \('(.+)'\)\. Impersonation by design\.$",
     "قاعدة: الحروف الأجنبية تجعله يبدو مثل {0} ('{1}'). انتحال متعمّد."),
    (r"^Rule: uses a raw IP address instead of a website name\. Official UAE services always use their own named domain\.$",
     "قاعدة: يستخدم عنوان IP مباشرةً بدلاً من اسم موقع. الخدمات الرسمية في الإمارات تستخدم دائماً نطاقها المسمّى."),
    (r"^Rule: the link's path names (.+), but the site is (.+), not (.+)\. Real (.+) pages are only on its own domain\.$",
     "قاعدة: مسار الرابط يذكر {0}، لكن الموقع هو {1} وليس {2}. صفحات {3} الحقيقية موجودة على نطاقها فقط."),
    (r"^Rule: the link starts with '(.+)@', a trick: the browser actually goes to (.+)\.$",
     "قاعدة: الرابط يبدأ بـ '{0}@' وهي خدعة: المتصفح يذهب فعلياً إلى {1}."),
    (r"^Fact: shortened link\. The real destination is hidden, so Shield cannot check it \(Shield never opens links to find out\)\.$",
     "حقيقة: رابط مختصر. الوجهة الحقيقية مخفية، لذلك لا يستطيع درع فحصها (درع لا يفتح الروابط أبداً)."),
    (r"^No warning signs found in the name\. This does not prove the site is safe\.$",
     "لم نجد علامات تحذيرية في الاسم. هذا لا يثبت أن الموقع آمن."),
    (r"^Its text patterns resemble known phishing domains \(ML text model\): (\d+)% phishing-like$",
     "أنماط حروفه تشبه مواقع تصيّد معروفة (نموذج الذكاء الاصطناعي): تشابه {0}%"),
    (r"^Is the (.+) name re-spelled on a domain .+ does not own \((.+)\)$",
     "اسم {0} مكتوب بتهجئة مختلفة على نطاق لا تملكه الجهة ({1})"),
    (r"^Combines the (.+) name with a lure word \(pay, login, bill\.\.\.\) on a domain .+ does not own$",
     "يجمع اسم {0} مع كلمة استدراج (دفع، تسجيل دخول، فاتورة...) على نطاق لا تملكه الجهة"),
    (r"^Puts the (.+) name in front of an unrelated domain \((.+)\)$",
     "يضع اسم {0} أمام نطاق لا علاقة له به ({1})"),
    (r"^Imitates the (.+) name with look-alike characters \(e\.g\. 1 for l, 0 for o\)$",
     "يقلّد اسم {0} بحروف أو أرقام مشابهة (مثل 1 بدلاً من l و0 بدلاً من o)"),
    (r"^Imitates the (.+) name with look-alike characters \(e\.g\. 1 for l, 0 for o, Cyrillic letters\)$",
     "يقلّد اسم {0} بحروف أو أرقام مشابهة (مثل 1 بدلاً من l و0 بدلاً من o، أو حروف سيريلية)"),
    (r"^Uses the (.+) name on a domain .+ does not own \(no lure words; could be a fan or partner site\)$",
     "يستخدم اسم {0} على نطاق لا تملكه الجهة (دون كلمات استدراج؛ قد يكون موقع شريك أو معجبين)"),
    (r"^Puts '\.ae' or 'gov' inside the name to look official, but the real domain is (.+)$",
     "يضع '.ae' أو 'gov' داخل الاسم ليبدو رسمياً، لكن النطاق الحقيقي هو {0}"),
    (r"^Uses an ending often abused by scammers \(\.(.+)\)$", "يستخدم امتداداً يكثر استغلاله من المحتالين (.{0})"),
    (r"^Uses an ending or host \(\.(.+)\) that is common among phishing domains in the training data$",
     "يستخدم امتداداً أو مستضيفاً (.{0}) شائعاً بين مواقع التصيّد في بيانات التدريب"),
    (r"^Uses a common, lower-risk ending \(\.(.+)\)$", "يستخدم امتداداً شائعاً منخفض الخطورة (.{0})"),
    (r"^Uses non-Latin letters in the name \(shown as (.+)\)$", "يستخدم حروفاً غير لاتينية في الاسم (يظهر بالشكل {0})"),
    (r"^The name looks randomly generated$", "يبدو الاسم مولَّداً عشوائياً"),
    (r"^Unusually long name$", "اسم طويل بشكل غير معتاد"),
    (r"^Long run of consonants \(looks machine-generated\)$", "سلسلة طويلة من الحروف الساكنة (يبدو مولَّداً آلياً)"),
    (r"^Belongs to a popular, established website \(Tranco rank (.+)\)$",
     "يتبع موقعاً معروفاً وراسخاً (ترتيبه في قائمة Tranco: {0})"),
    (r"^Hosted on a free hosting or site-builder service$", "مستضاف على خدمة استضافة أو بناء مواقع مجانية"),
    (r"^Unusually many hyphens$", "عدد غير معتاد من الشرطات"),
    (r"^Contains a lure word \(login, pay, verify, refund\.\.\.\)$", "يحتوي على كلمة استدراج (تسجيل دخول، دفع، تحقق، استرداد...)"),
    (r"^Many layers in front of the real domain$", "طبقات كثيرة أمام النطاق الحقيقي"),
    (r"^Many digits in the name$", "أرقام كثيرة في الاسم"),
    (r"^The link points to a login, payment or verification page$", "الرابط يقود إلى صفحة تسجيل دخول أو دفع أو تحقق"),
    # domain facts (enrich.py) and page check (pagecheck.py)
    (r"^Domain registered (\d+) days ago \((.+)\)$", "سُجّل النطاق قبل {0} يوماً ({1})"),
    (r"^Domain registered (\d+) days ago \((.+)\) at (.+)$", "سُجّل النطاق قبل {0} يوماً ({1}) لدى {2}"),
    (r"^Domain registered in the last 30 days \((\d+) days ago\)$", "سُجّل النطاق خلال آخر 30 يوماً (قبل {0} يوماً)"),
    (r"^Domain registered less than a year ago \((\d+) days ago\)$", "سُجّل النطاق قبل أقل من سنة (قبل {0} يوماً)"),
    (r"^Registered for one year only \(typical of throw-away domains\)$", "مسجّل لسنة واحدة فقط (شائع في النطاقات المؤقتة)"),
    (r"^Set up to receive e-mail \(MX record\)$", "مُعدّ لاستقبال البريد الإلكتروني (سجل MX)"),
    (r"^Free automated certificate \((.+)\)$", "شهادة أمان مجانية آلية ({0})"),
    (r"^Certificate issued in the last 7 days$", "صدرت شهادة الأمان خلال آخر 7 أيام"),
    (r"^Certificate issued (\d+) days ago by (.+)$", "صدرت شهادة الأمان قبل {0} يوماً من {1}"),
    (r"^Certificate shared by many names \((\d+)\)$", "شهادة أمان مشتركة بين أسماء كثيرة ({0})"),
    (r"^No working HTTPS$", "لا يعمل الاتصال المشفّر HTTPS"),
    (r"^Registration date is public$", "تاريخ التسجيل معلن"),
    (r"^The page asks for a password$", "الصفحة تطلب كلمة مرور"),
    (r"^The page asks for card details$", "الصفحة تطلب بيانات البطاقة"),
    (r"^The page asks for a one-time code \(OTP\)$", "الصفحة تطلب رمز تحقق لمرة واحدة (OTP)"),
    (r"^The page asks for an Emirates ID / passport / IBAN number$", "الصفحة تطلب رقم الهوية الإماراتية أو الجواز أو الآيبان"),
    (r"^The page presents itself as (.+), but this is not an official (.+) domain$", "الصفحة تقدّم نفسها على أنها {0}، لكن هذا ليس نطاقاً رسمياً لـ {1}"),
    (r"^The page looks (\d+)% like the official (.+) site and uses its exact icon$", "الصفحة تشبه موقع {1} الرسمي بنسبة {0}% وتستخدم أيقونته نفسها"),
    (r"^The page looks (\d+)% like the official (.+) site$", "الصفحة تشبه موقع {1} الرسمي بنسبة {0}%"),
    (r"^The form sends what you type to another site: (.+)$", "النموذج يرسل ما تكتبه إلى موقع آخر: {0}"),
    (r"^The link redirects to another site: (.+)$", "الرابط يحوّلك إلى موقع آخر: {0}"),
    (r"^The page tried to reach (\d+) private/local addresses \(blocked\)$", "حاولت الصفحة الوصول إلى {0} عناوين داخلية (تم الحظر)"),
    (r"^No warning signs found in the name or the domain's records\. This does not prove the site is safe\.$",
     "لم نجد علامات تحذيرية في الاسم أو في سجلات النطاق. هذا لا يثبت أن الموقع آمن."),
    (r"^Not encrypted \(http instead of https\)$", "غير مشفّر (http بدلاً من https)"),
]
_COMPILED = [(re.compile(p), t) for p, t in PATTERNS]

EFFECT = re.compile(r" \(learned effect: x([\d.]+) odds\)$")
EFFECT_DOWN = re.compile(r" \(learned effect: /([\d.]+) odds\)$")
EFFECT_NONE = " (learned effect: little or none)"


def to_ar(line: str) -> str:
    suffix = ""
    m = EFFECT.search(line)
    if m:
        suffix = f" (الأثر المتعلَّم: يضاعف الاحتمال ×{m.group(1)})"
        line = line[:m.start()]
    elif EFFECT_DOWN.search(line):
        m = EFFECT_DOWN.search(line)
        suffix = f" (الأثر المتعلَّم: يقسم الاحتمال ÷{m.group(1)})"
        line = line[:m.start()]
    elif line.endswith(EFFECT_NONE):
        suffix = " (الأثر المتعلَّم: ضئيل)"
        line = line[: -len(EFFECT_NONE)]
    for rx, tpl in _COMPILED:
        mm = rx.match(line)
        if mm:
            groups = [HOW_AR.get(g, BRAND_AR.get(g, g)) for g in mm.groups()]
            return tpl.format(*groups) + suffix
    return line + suffix          # no translation yet: keep English rather than hide it


ADVICE_AR = {
    "high risk": "لا تفتح هذا الرابط ولا تُدخل أي بيانات. إذا ادّعى أنه خدمة حكومية فافتح التطبيق الرسمي أو اكتب عنوان الموقع الرسمي بنفسك، وأبلغ عن الرسالة.",
    "suspicious": "انتبه: هذا الرابط فيه علامات تحذيرية. لا تُدخل كلمات مرور أو بيانات بطاقة أو رموز تحقق (OTP). استخدم التطبيق أو الموقع الرسمي بدلاً منه.",
    "unknown": "لا يستطيع درع معرفة وجهة هذا الرابط الحقيقية. لا تفتحه إلا إذا كنت تثق بالمرسل، واستخدم التطبيق أو الموقع الرسمي بدلاً منه.",
    "no warning signs": "لم يجد درع علامات تحذيرية، لكن هذا لا يثبت أن الرابط آمن. لا تشارك أبداً رموز التحقق أو بيانات البطاقة عبر رابط في رسالة.",
    "official": "هذا هو الموقع الرسمي حسب سجل درع. ومع ذلك لا تشارك رموز التحقق أبداً، وتأكد أن العنوان في المتصفح مطابق تماماً.",
}
