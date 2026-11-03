"""
Shield's built-in assistant: answers without any outside AI service.

Used whenever DeepSeek is switched off, busy or unreachable. It understands the usual ways people
start (hi, salam, thanks), follow-ups ("why?", "is it real?"), common scam questions (how to spot a
fake link, what to do after clicking, how to report) and explains Shield's check of every link.
Replies in Arabic when the user writes in Arabic. Verdicts always come from Shield's own check.
"""

import random
import re

AR_CHARS = re.compile(r"[؀-ۿ]")


def _has(text: str, *patterns: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def is_arabic(text: str) -> bool:
    return bool(AR_CHARS.search(text or ""))


# ---------- what the user is asking ----------
INTENTS = [
    ("clicked", [r"\b(i|i've|ive|already|accidentally)\s+(clicked|opened|pressed|tapped|entered|paid|gave|shared|sent)\b",
                 r"\b(entered|gave|shared|typed)\s+(my|the)\s+(card|otp|code|password|details|info|emirates id|pin)\b",
                 r"\bhacked\b", r"\b(stole|stolen|lost)\s+(my\s+)?money\b",
                 r"ضغطت", r"فتحت الرابط", r"دخلت (بيانات|معلومات|رقم)", r"ادخلت", r"أدخلت", r"دفعت", r"اخترق", r"انسرق", r"سرق"]),
    ("report", [r"\breport\b", r"\bcomplain", r"\becrime\b", r"\bpolice\b", r"who (do|should) i (tell|contact|call)",
                r"بلاغ", r"ابلغ", r"أبلغ", r"الشرطة", r"اشتكي", r"شكوى"]),
    ("otp", [r"\botp\b", r"verification code", r"\bpin\b", r"bank (called|is calling|call)", r"called me .*bank",
             r"رمز (التحقق|التأكيد|السري)", r"الرمز", r"البنك (اتصل|يتصل)", r"اتصل (بي|علي) .*بنك"]),
    ("why", [r"^\W*(why|how come|explain|really|are you sure|how so|what do you mean)\W*\??\W*$",
             r"\bwhy (is|was|it|this|that)\b", r"\bexplain (it|this|that|why|more)\b", r"what('?s| is) wrong with (it|this|that)",
             r"^\W*(لماذا|ليش|ليه|اشرح|وضح|متأكد|كيف يعني)", r"ليش (هو|هذا|الرابط)", r"لماذا (هو|هذا|الرابط)"]),
    ("spot", [r"how (to|do i|can i|do you|would i) (know|tell|check|spot|identify|recogni[sz]e|detect|verify)",
              r"\b(fake|real|legit|legitimate|genuine|scam|fraud|phishing|safe)\b.*\?", r"is (it|this|that) (real|fake|legit|a scam|safe)",
              r"signs? of (a )?(scam|fraud|phishing|fake)", r"\bphishing\b", r"what is (a )?(scam|fraud|phishing)",
              r"كيف (اعرف|أعرف|أتأكد|اتأكد|افرق|أفرق|اكتشف)", r"(احتيال|نصب|مزيف|مزور|وهمي|تصيد|حقيقي)"]),
    ("fines", [r"\bsalik\b", r"\brta\b", r"\bfines?\b", r"\bparking\b", r"\btraffic\b", r"سالك", r"مخالف", r"غرامة", r"مواقف"]),
    ("delivery", [r"\b(parcel|package|delivery|shipment|courier|customs|aramex|emirates post|dhl|fedex)\b",
                  r"طرد", r"شحن", r"شحنة", r"توصيل", r"البريد", r"ارامكس", r"أرامكس", r"جمارك"]),
    ("prize", [r"\b(won|winner|prize|lottery|reward|gift|free|giveaway|job offer|part[- ]time|work from home|investment|crypto)\b",
               r"ربحت", r"فزت", r"جائزة", r"سحب", r"هدية", r"وظيفة", r"عمل من المنزل", r"استثمار"]),
    ("whatsapp", [r"\bwhatsapp\b", r"\bsms\b", r"\btext message\b", r"\bmessage from\b", r"واتساب", r"رسالة", r"مسج"]),
    ("about", [r"who are you", r"what are you", r"what is shield", r"what('?s| is) aida", r"what can you do", r"how (does|do) (shield|you|this) work",
               r"help me", r"^\W*help\W*$", r"من (انت|أنت)", r"ما هو درع", r"ماذا تفعل", r"كيف (يعمل|تشتغل|تعمل)", r"ساعدني"]),
    ("thanks", [r"\b(thanks|thank you|thx|ty|appreciate|great|perfect|awesome|ok thanks)\b", r"شكرا", r"شكراً", r"مشكور", r"يعطيك العافية", r"تسلم"]),
    ("bye", [r"\b(bye|goodbye|see you|good night)\b", r"مع السلامة", r"باي", r"تصبح على خير"]),
    ("greet", [r"^\W*(hi|hello|hey|hiya|yo|salam|salaam|assalam|as-salamu|marhaba|hala|good (morning|afternoon|evening))\b",
               r"السلام عليكم", r"مرحبا", r"أهلا", r"اهلا", r"هلا", r"صباح الخير", r"مساء الخير", r"هاي"]),
]


def intents_of(text: str) -> list[str]:
    return [name for name, pats in INTENTS if _has(text, *pats)]


# ---------- link explanations ----------
VERDICT_AR = {"high risk": "خطر مرتفع", "suspicious": "مشبوه", "no warning signs": "لا توجد علامات تحذيرية",
              "official": "رسمي", "unknown": "غير معروف"}


def explain_link(view: dict, ar: bool) -> str:
    v, d, score = view.get("verdict", "unknown"), view.get("domain", "this link"), view.get("score")
    lang = view.get("ar" if ar else "en") or {}
    reasons = (lang.get("rules", []) + lang.get("facts", []) + lang.get("signals", []))[:4]
    brand = view.get("brand_ar" if ar else "brand")
    official = ", ".join(view.get("official_sites") or [])
    sc = f" ({score}/100)" if score is not None else ""
    out = []
    if ar:
        head = {
            "high risk": f"**الرابط {d} يبدو احتيالياً: {VERDICT_AR[v]}{sc}.**",
            "suspicious": f"**الرابط {d} فيه علامات تحذيرية: {VERDICT_AR[v]}{sc}.**",
            "no warning signs": f"**لم يجد درع علامات تحذيرية في {d}.** هذا لا يعني بالضرورة أنه آمن.",
            "official": f"**{d} موقع رسمي** حسب سجل درع للجهات الإماراتية.",
            "unknown": f"**لا يستطيع درع معرفة وجهة {d} الحقيقية** (مثل روابط الاختصار).",
        }[v]
        out.append(head)
        if brand and v in ("high risk", "suspicious"):
            out.append(f"يحاول أن يبدو وكأنه **{brand}**" + (f"، لكن الموقع الرسمي هو **{official}**." if official else "."))
        if reasons:
            out.append("**لماذا:**\n" + "\n".join(f"- {r}" for r in reasons))
        if lang.get("advice"):
            out.append(lang["advice"])
        if v == "high risk":
            out.append("إذا سبق وأدخلت بيانات بطاقتك، اتصل ببنكك فوراً لإيقافها، وأبلغ عن الرسالة عبر منصة **ecrime.ae**.")
    else:
        head = {
            "high risk": f"**{d} looks like a scam: high risk{sc}.**",
            "suspicious": f"**{d} has warning signs: suspicious{sc}.**",
            "no warning signs": f"**Shield found no warning signs in {d}.** That doesn't prove it's safe, though.",
            "official": f"**{d} is an official site** in Shield's registry of UAE services.",
            "unknown": f"**Shield can't tell where {d} really leads** (for example, a shortened link).",
        }[v]
        out.append(head)
        if brand and v in ("high risk", "suspicious"):
            out.append(f"It's trying to look like **{brand}**" + (f", but the real site is **{official}**." if official else "."))
        if reasons:
            out.append("**Why:**\n" + "\n".join(f"- {r}" for r in reasons))
        if lang.get("advice"):
            out.append(lang["advice"])
        if v == "high risk":
            out.append("If you already entered card details, call your bank now to block the card, and report the message at **ecrime.ae**.")
    return "\n\n".join(out)


def why_answer(view: dict, ar: bool) -> str:
    """Follow-up about a link checked earlier: focus on the reasons and how the trick works."""
    v, d = view.get("verdict", "unknown"), view.get("domain", "")
    lang = view.get("ar" if ar else "en") or {}
    reasons = (lang.get("rules", []) + lang.get("facts", []) + lang.get("signals", []))[:5]
    brand = view.get("brand_ar" if ar else "brand")
    official = ", ".join(view.get("official_sites") or [])
    if ar:
        if v in ("high risk", "suspicious"):
            txt = f"حكم درع على **{d}** هو **{VERDICT_AR[v]}** للأسباب التالية:\n" + "\n".join(f"- {r}" for r in reasons or ["نمط الاسم يشبه مواقع احتيال معروفة."])
            if brand:
                txt += f"\n\n**كيف تعمل الحيلة:** المحتال يضع اسم **{brand}** في عنوان لا تملكه الجهة، ليبدو الرابط رسمياً في رسالة سريعة. الجهات الرسمية تستخدم عنوانها الخاص فقط" + (f" (**{official}**)." if official else ".")
            txt += "\n\nالأفضل دائماً: لا تفتح الرابط، وافتح التطبيق الرسمي أو اكتب العنوان الرسمي بنفسك."
            return txt
        if v == "official":
            return f"**{d}** مسجل في سجل درع كموقع رسمي" + (f" لـ **{brand}**" if brand else "") + ". مع ذلك تأكد أن العنوان في المتصفح مطابق تماماً، ولا تشارك رمز التحقق مع أي شخص."
        if v == "unknown":
            return f"لا يظهر من **{d}** إلى أين يقود فعلاً، مثل روابط الاختصار التي تخفي العنوان الحقيقي. لذلك لا يستطيع درع الحكم عليه. لا تفتحه إلا إذا كنت تثق بالمرسل."
        return f"لم يجد درع في اسم **{d}** أي حيلة معروفة: لا تقليد لجهة إماراتية، ولا حروف مزيفة، ولا نهاية مشبوهة. لكن درع يقرأ العنوان فقط ولا يفتح الصفحة، فلا تُدخل رموز تحقق أو بيانات بطاقة عبر رابط وصلك في رسالة."
    if v in ("high risk", "suspicious"):
        txt = f"Shield rated **{d}** as **{v}** because:\n" + "\n".join(f"- {r}" for r in reasons or ["The name follows patterns seen in known scam sites."])
        if brand:
            txt += f"\n\n**How the trick works:** the scammer puts **{brand}**'s name into an address {brand} doesn't own, so it looks official at a glance in a quick SMS. Real services only use their own address" + (f" (**{official}**)." if official else ".")
        txt += "\n\nSafest move: don't open it. Open the official app or type the official address yourself."
        return txt
    if v == "official":
        return f"**{d}** is listed in Shield's registry as an official site" + (f" of **{brand}**" if brand else "") + ". Still, check the address bar matches exactly, and never share a one-time code with anyone."
    if v == "unknown":
        return f"**{d}** hides where it really goes (shortened links do this), so Shield can't judge it. Only open it if you trust the sender, and prefer the official app or website."
    return f"Shield found no known trick in **{d}**: it doesn't copy a UAE brand, has no look-alike letters and no risky ending. But Shield reads the address only and never opens the page, so still don't enter codes or card details through a link from a message."


# ---------- general answers ----------
EN = {
    "greet": ["Hi! I'm Shield, AIDA's scam-check assistant. Paste any link from an SMS, WhatsApp or email and I'll tell you if it's official, or ask me anything about scams in the UAE.",
              "Hello! Got a message or link you're not sure about? Paste it here and I'll check it without opening it. You can also ask me how to spot a fake link or how to report a scam."],
    "thanks": ["You're welcome! Stay safe, and paste any other link you're not sure about.",
               "Happy to help. Remember: when in doubt, open the official app instead of the link."],
    "bye": ["Take care! If another suspicious message comes in, you know where to find me."],
    "about": ["I'm **Shield**, built by the AIDA team. Here's what I can do:\n\n"
              "- **Check a link:** paste it and I'll say if it's official, suspicious or high risk, and why. I never open it.\n"
              "- **Explain the trick:** ask \"why?\" after a check and I'll show how the scam works.\n"
              "- **Answer questions:** how to spot fake messages, what to do if you clicked, and how to report fraud in the UAE.\n\n"
              "My verdicts come from a model trained on hundreds of thousands of real scam and genuine sites, plus a registry of official UAE addresses."],
    "spot": ["Here's how to tell a fake link from a real one:\n\n"
             "- **Check the address, not the text.** Real UAE services use their own domain (e.g. salik.ae, rta.ae). Fakes add words like **-pay**, **-fine**, **-update** or use endings like .com, .top or .xyz.\n"
             "- **Look-alike letters:** \"emirat3s\", \"rnoi\" instead of \"moi\", or foreign letters that look Latin.\n"
             "- **Urgency or fear:** \"pay within 24 hours\", \"your account is blocked\", \"last warning\".\n"
             "- **Asking for card details, OTP or Emirates ID** through a link. Official services won't ask for your OTP.\n"
             "- **Shortened links** (bit.ly etc.) hide the real address.\n\n"
             "The safest habit: don't tap the link. Open the official app or type the address yourself. Or paste the link here and I'll check it."],
    "clicked": ["Don't panic. Act quickly:\n\n"
                "1. **If you entered card details:** call your bank's number (on the back of the card) now and ask them to block it.\n"
                "2. **If you shared an OTP or password:** change the password straight away, starting with email and banking, and turn on two-step verification.\n"
                "3. **If you only opened the link** and typed nothing, close it and clear your browser history. The risk is low, but don't install anything it asks for.\n"
                "4. **Report it** at **ecrime.ae**. In Abu Dhabi you can also call Aman on **8002626**; in Dubai, police non-emergency **901**.\n\n"
                "If you still have the link, paste it here and I'll show you what it was imitating."],
    "report": ["You can report scam messages and fake sites here:\n\n"
               "- **ecrime.ae**: the UAE's online platform for reporting cybercrime.\n"
               "- **Aman service, Abu Dhabi Police:** 8002626\n"
               "- **Dubai Police:** 901 (non-emergency)\n"
               "- **Your bank's fraud line** if money or card details are involved.\n"
               "- The **official channels** of the brand being imitated (e.g. Salik, RTA, Emirates Post).\n\n"
               "Keep a screenshot of the message and the sender's number. They help the investigation."],
    "otp": ["**Never share a one-time code (OTP)** with anyone, even someone who says they're from your bank, the police or a government office. Banks and official services don't ask for it by phone, SMS or link.\n\n"
            "If someone is asking for it right now, hang up, then call your bank yourself using the number on your card. If you already shared it, call the bank immediately to block the card."],
    "fines": ["Fake fine messages are one of the most common UAE scams: \"Unpaid Salik/RTA fine, pay now\" with a link like salik-pay.com.\n\n"
              "- Real fines are checked and paid in the **official Salik / RTA apps** or on the official sites (salik.ae, rta.ae).\n"
              "- The fake sites copy the logo and ask for your card details and OTP.\n\n"
              "Paste the link from your message and I'll check it."],
    "delivery": ["Delivery scams say your parcel is held and ask for a small fee (often a few dirhams) through a link. The goal is your card details.\n\n"
                 "- Track parcels only in the courier's **official app or website**, typed in yourself.\n"
                 "- Couriers don't charge surprise fees through an SMS link.\n\n"
                 "Paste the link and I'll tell you if it's the courier's real site."],
    "prize": ["Messages about prizes, easy jobs, part-time \"tasks\" or quick investments are almost always scams. They ask for a fee, your bank details, or for you to send money first.\n\n"
              "- A real prize never needs you to pay to receive it.\n"
              "- Don't move money to \"unlock\" earnings.\n\n"
              "Paste any link from the message and I'll check it."],
    "whatsapp": ["For any SMS or WhatsApp message with a link:\n\n"
                 "- **Don't tap it.** Paste it here, and I'll check it without opening it.\n"
                 "- Check the sender: official services use registered sender names, not random mobile numbers.\n"
                 "- Watch for urgency, threats, or requests for card details or OTP.\n\n"
                 "Copy the link (long-press it) and send it to me."],
    "fallback": ["I'm best at scams and suspicious links. I can:\n\n"
                 "- **Check a link:** paste it here.\n"
                 "- Tell you **how to spot** a fake message.\n"
                 "- Explain **what to do** if you clicked a link or shared details.\n"
                 "- Show you **how to report** a scam in the UAE.\n\n"
                 "What would you like to do?"],
}

AR = {
    "greet": ["أهلاً! أنا **درع**، مساعد فريق AIDA لكشف الاحتيال. أرسل أي رابط وصلك في رسالة نصية أو واتساب أو بريد، وسأخبرك إذا كان رسمياً، أو اسألني أي سؤال عن الاحتيال في الإمارات.",
              "مرحباً! هل وصلتك رسالة أو رابط ولست متأكداً منه؟ الصقه هنا وسأفحصه دون أن أفتحه. ويمكنك أيضاً أن تسألني كيف تكتشف الروابط المزيفة أو كيف تبلغ عن عملية احتيال."],
    "thanks": ["العفو! انتبه لنفسك، وأرسل أي رابط آخر تشك فيه.", "بكل سرور. وتذكّر: عند الشك، افتح التطبيق الرسمي بدلاً من الرابط."],
    "bye": ["في أمان الله! إذا وصلتك رسالة مشبوهة أخرى، أنا هنا."],
    "about": ["أنا **درع**، من تطوير فريق AIDA. أستطيع:\n\n"
              "- **فحص الرابط:** الصقه وسأخبرك إذا كان رسمياً أو مشبوهاً أو عالي الخطورة، ولماذا. لا أفتح الرابط أبداً.\n"
              "- **شرح الحيلة:** اسألني \"لماذا؟\" بعد الفحص وسأوضح كيف تعمل عملية الاحتيال.\n"
              "- **الإجابة عن أسئلتك:** كيف تكتشف الرسائل المزيفة، وماذا تفعل إذا ضغطت على رابط، وكيف تبلغ عن الاحتيال.\n\n"
              "أحكامي تأتي من نموذج تدرب على مئات الآلاف من مواقع الاحتيال والمواقع الحقيقية، ومن سجل للعناوين الرسمية في الإمارات."],
    "spot": ["هكذا تميّز الرابط المزيف من الحقيقي:\n\n"
             "- **انظر إلى العنوان نفسه:** الجهات الإماراتية تستخدم عناوينها الخاصة (مثل salik.ae و rta.ae). المواقع المزيفة تضيف كلمات مثل **-pay** أو **-fine** أو تنتهي بـ .com أو .top أو .xyz.\n"
             "- **حروف متشابهة:** مثل emirat3s، أو حروف أجنبية تشبه الحروف اللاتينية.\n"
             "- **الاستعجال والتهديد:** \"ادفع خلال 24 ساعة\"، \"تم إيقاف حسابك\".\n"
             "- **طلب بيانات البطاقة أو رمز التحقق أو الهوية** عبر رابط. الجهات الرسمية لا تطلب رمز التحقق.\n"
             "- **الروابط المختصرة** (مثل bit.ly) تخفي العنوان الحقيقي.\n\n"
             "أسلم عادة: لا تضغط على الرابط، وافتح التطبيق الرسمي أو اكتب العنوان بنفسك. أو الصق الرابط هنا وسأفحصه."],
    "clicked": ["لا تقلق، لكن تصرّف بسرعة:\n\n"
                "1. **إذا أدخلت بيانات البطاقة:** اتصل ببنكك فوراً على الرقم المكتوب خلف البطاقة واطلب إيقافها.\n"
                "2. **إذا شاركت رمز تحقق أو كلمة مرور:** غيّر كلمة المرور فوراً، وابدأ بالبريد والبنك، وفعّل التحقق بخطوتين.\n"
                "3. **إذا فتحت الرابط فقط** ولم تكتب شيئاً: أغلقه، ولا تثبّت أي شيء يطلبه. الخطر هنا منخفض.\n"
                "4. **أبلغ** عبر منصة **ecrime.ae**، أو خدمة أمان في أبوظبي **8002626**، أو شرطة دبي **901**.\n\n"
                "إذا كان الرابط ما زال عندك، الصقه هنا وسأوضح لك ماذا كان يقلّد."],
    "report": ["يمكنك الإبلاغ عن رسائل ومواقع الاحتيال عبر:\n\n"
               "- منصة **ecrime.ae** للإبلاغ عن الجرائم الإلكترونية في الإمارات.\n"
               "- **خدمة أمان، شرطة أبوظبي:** 8002626\n"
               "- **شرطة دبي:** 901 (لغير الطوارئ)\n"
               "- **خط الاحتيال في بنكك** إذا تعلق الأمر بأموال أو بيانات بطاقة.\n"
               "- **القنوات الرسمية** للجهة التي يتم تقليدها (مثل سالك أو هيئة الطرق والمواصلات أو بريد الإمارات).\n\n"
               "احتفظ بصورة للرسالة ورقم المرسل، فهي تساعد في التحقيق."],
    "otp": ["**لا تشارك رمز التحقق (OTP) مع أي شخص**، حتى لو قال إنه من البنك أو الشرطة أو جهة حكومية. البنوك والجهات الرسمية لا تطلبه بالهاتف أو الرسائل أو الروابط.\n\n"
            "إذا كان أحد يطلبه منك الآن، أغلق المكالمة واتصل ببنكك بنفسك على الرقم المكتوب على البطاقة. وإذا سبق وشاركته، اتصل بالبنك فوراً لإيقاف البطاقة."],
    "fines": ["رسائل المخالفات المزيفة من أشهر عمليات الاحتيال في الإمارات: \"لديك مخالفة سالك غير مدفوعة، ادفع الآن\" مع رابط مثل salik-pay.com.\n\n"
              "- المخالفات الحقيقية تُدفع من **تطبيقات سالك وهيئة الطرق والمواصلات الرسمية** أو من المواقع الرسمية (salik.ae و rta.ae).\n"
              "- المواقع المزيفة تنسخ الشعار وتطلب بيانات البطاقة ورمز التحقق.\n\n"
              "الصق الرابط الذي وصلك وسأفحصه."],
    "delivery": ["رسائل التوصيل المزيفة تقول إن طردك محتجز وتطلب رسوماً بسيطة عبر رابط، والهدف بيانات بطاقتك.\n\n"
                 "- تتبّع الشحنات فقط من **تطبيق أو موقع شركة الشحن الرسمي** بكتابة العنوان بنفسك.\n"
                 "- شركات الشحن لا تطلب رسوماً مفاجئة عبر رابط في رسالة.\n\n"
                 "الصق الرابط وسأخبرك إذا كان موقع الشركة الحقيقي."],
    "prize": ["رسائل الجوائز والوظائف السهلة و\"المهام\" بدوام جزئي والاستثمارات السريعة غالباً احتيال، فهي تطلب رسوماً أو بيانات بنكية أو تحويل أموال أولاً.\n\n"
              "- الجائزة الحقيقية لا تتطلب أن تدفع لتستلمها.\n"
              "- لا تحوّل أموالاً لـ\"فك\" أرباحك.\n\n"
              "الصق أي رابط في الرسالة وسأفحصه."],
    "whatsapp": ["مع أي رسالة نصية أو واتساب فيها رابط:\n\n"
                 "- **لا تضغط عليه.** الصقه هنا وسأفحصه دون أن أفتحه.\n"
                 "- انتبه للمرسل: الجهات الرسمية تستخدم أسماء مرسلين معتمدة، لا أرقام هواتف عشوائية.\n"
                 "- احذر من الاستعجال والتهديد وطلب بيانات البطاقة أو رمز التحقق.\n\n"
                 "انسخ الرابط (اضغط عليه مطولاً) وأرسله لي."],
    "fallback": ["تخصصي الاحتيال والروابط المشبوهة. أستطيع:\n\n"
                 "- **فحص أي رابط:** الصقه هنا.\n"
                 "- شرح **كيف تكتشف** الرسائل المزيفة.\n"
                 "- إخبارك **ماذا تفعل** إذا ضغطت على رابط أو شاركت بياناتك.\n"
                 "- توضيح **كيف تبلغ** عن الاحتيال في الإمارات.\n\n"
                 "بماذا أساعدك؟"],
}

GREET_PREFIX = {False: ["Hi! ", "Hello! "], True: ["أهلاً! ", "مرحباً! "]}
ORDER = ["clicked", "report", "otp", "spot", "fines", "delivery", "prize", "whatsapp", "about", "thanks", "bye", "greet"]


def reply(text: str, views: list[dict], earlier: dict | None) -> str:
    """text: the user's latest message. views: Shield's checks of links in it. earlier: last link checked before."""
    ar = is_arabic(text)
    found = intents_of(text)
    greet = "greet" in found
    lead = random.choice(GREET_PREFIX[ar]) if greet else ""
    bank = AR if ar else EN

    if views:                                         # a link in this message: explain Shield's check
        body = "\n\n---\n\n".join(explain_link(v, ar) for v in views)
        extra = next((i for i in ("clicked", "report", "otp") if i in found), None)
        if extra:
            body += "\n\n" + random.choice(bank[extra])
        return lead + body

    if earlier and ("why" in found or ("spot" in found and len(text) < 80 and not _has(text, r"how (to|do i|can i)", r"كيف"))):
        return lead + why_answer(earlier, ar)         # "why?" / "is it real?" about the last link

    for name in ORDER:
        if name in found and name != "greet":
            return lead + random.choice(bank[name])
    if greet:
        return random.choice(bank["greet"])
    if earlier and len(text.split()) <= 4:            # short follow-up like "and now?" / "so?"
        return why_answer(earlier, ar)
    return random.choice(bank["fallback"])
