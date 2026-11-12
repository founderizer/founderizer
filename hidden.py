"""Hidden characters in text that reaches an agent: one rule for the hub's exits and for the helper's hook.

A tag character (U+E0000 to U+E007F), a run of variation selectors or a run of zero-width characters draws nothing on
a screen, and a model can still read it. So a mail, a web page or a stranger's issue can carry words that no person
sees in it. strip_hidden removes them and counts what it removed. It never gives the hidden text: a mark that showed
the decoded words would put them in clear text in front of the model.

The rule:

1. Remove every tag character, except inside the flag sequences of England, Scotland and Wales.
2. Remove each run of two or more invisible characters (category Cf, variation selectors, Hangul fillers and the other
   default ignorable code points), except the joiners and selectors inside one emoji sequence, and a run of at most
   three bidi controls only.
3. Remove a single invisible character, except where text puts one: a ZWJ between two emoji (PICTOGRAPHS), or a ZWJ
   or a ZWNJ between two letters of a script that joins its letters (Arabic, the Indic scripts and their neighbours;
   not Thai, Lao or Tibetan, which use no joiner); one variation selector after the kind of character that takes it
   (U+FE0E or U+FE0F after a pictograph or in a keycap, U+FE00 to U+FE0D after a symbol or a letter that is not
   Latin, an ideographic selector after an ideograph, a Mongolian one after a Mongolian letter); a bidi control that
   is not inside a Latin word. The two overrides (U+202D, U+202E) always go, alone or in a run: they reverse what a
   person reads, as in a file name. So hidden words cannot be spread one character at a time between the letters of
   an ordinary text.
4. Limits for a whole text, over what the runs kept, for the same reason: more than VARIATION_MOST glyph selectors
   (not U+FE0E, U+FE0F) and all of them go, and the text keeps its ideographs in their default form; bidi controls go
   when the text has no right-to-left letter, or more of them than BIDI_FREE and one for each four such letters; more
   than EMOJI_JOINERS_MOST joiners between emoji and all of them go; more joiners between letters than
   JOINED_FREE or one for each four letters of the joining scripts, whichever is more, and all of them go.
5. Apply the same rule to the JSON escape forms (\\uXXXX, and a surrogate pair of two), because some answers are JSON.
   One escape alone is kept, except a tag character: source code writes "\\u200b" when it is about such a character,
   and an escape form is in plain sight of the model, so the limits of rule 4 do not count it. With escapes=False
   (the helper's hook, which reads parsed JSON: there an escape form is text that a person sees as well) only the
   escape forms of tag characters go, and every other one stays as text.
6. A text with more than DENSE raw invisible characters loses all of them in one substitution, tags among them, and
   the rule then goes on with what is left (the escape forms). The rule for each run costs about 1 to 3 seconds for
   1 MB of them, and the hook has 10 seconds before Claude Code keeps the original output.

skeleton(text) is for the search of a login only: the text with every raw invisible character and every control
character (category Cc, but tab, line feed and carriage return) removed, so that a character which the rule keeps
cannot split a login.

No rule ends hiding: a writer can still choose words, spaces or look-alike letters. This one removes the characters
that a model reads as words with no work (tag characters) and the dense carriers that need only a small program.

Standard library only, and no import of the hub: the helper's hook (hook_clean.py) imports this module at each tool
call, so it must load fast.
"""
import re
import unicodedata

TAGS = range(0xE0000, 0xE0080)
VARIATION = frozenset([*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0), 0x180B, 0x180C, 0x180D, 0x180F])
JOINERS = frozenset([0x200C, 0x200D])
ZWJ = 0x200D
BIDI = frozenset([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
OVERRIDES = frozenset([0x202D, 0x202E])     # left-to-right and right-to-left override: they always go (rule 3)
FILLERS = frozenset([0x115F, 0x1160, 0x3164, 0xFFA0])
# What rule 3 removes when it stands alone: zero-width space, word joiner, the invisible operators, soft hyphen, the
# fillers and the byte order mark.
ALONE_GONE = frozenset([0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x00AD, 0xFEFF]) | FILLERS
# Every character that the rule reads as invisible. Category Cf (Unicode 15), without the prepended concatenation
# marks (U+0600 to U+0605, U+06DD, U+070F, U+0890, U+0891, U+08E2, U+110BD, U+110CD), which draw a sign; the
# variation selectors (category Mn), the Hangul fillers (category Lo) and the combining grapheme joiner (Mn); and the
# rest of what Unicode calls default ignorable (DerivedCoreProperties), which a renderer draws as nothing also where
# no character is assigned: the two Khmer inherent vowels, U+2065, U+FFF0 to U+FFF8, and all of U+E0080 to U+E0FFF.
# Also the Khitan small script filler (U+16FE4) and the musical null notehead (U+1D159), which draw nothing.
INVISIBLE = frozenset([
    0x00AD, 0x034F, 0x061C, 0x17B4, 0x17B5, 0x180E, *range(0x200B, 0x2010), *range(0x202A, 0x202F),
    *range(0x2060, 0x2070), 0xFEFF, *range(0xFFF0, 0xFFFC), *range(0x13430, 0x13440), 0x16FE4, *range(0x1BCA0, 0x1BCA4),
    0x1D159, *range(0x1D173, 0x1D17B), *TAGS, *range(0xE0080, 0xE1000)]) | VARIATION | FILLERS
# The flag sequences of England, Scotland and Wales: a black flag, then "gbeng", "gbsct" or "gbwls" and a cancel tag.
VARIATION_MOST = 12     # glyph selectors that one text may keep (rule 4)
BIDI_FREE = 4           # bidi controls that a text with right-to-left letters may keep, plus one for each four letters
EMOJI_JOINERS_MOST = 24     # joiners between emoji that one text may keep (rule 4)
JOINED_FREE = 8         # joiners between letters that one text may keep, or one for each four letters if more
DENSE = 20000           # raw invisible characters above which all of them go in one substitution (rule 6)
EMOJI_SELECTORS = (0xFE0E, 0xFE0F)
# The characters that an emoji sequence is made of (rule 3): a fixed set of ranges of pictographs, skin tones among
# them. A symbol outside them (a line of a box, a caret, a backtick) takes no joiner and no presentation selector.
PICTOGRAPHS = ((0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
               (0x2139, 0x2139), (0x2190, 0x21FF), (0x2300, 0x23FF), (0x2460, 0x24FF), (0x25A0, 0x27BF),
               (0x2900, 0x297F), (0x2B00, 0x2BFF), (0x3030, 0x3030), (0x303D, 0x303D), (0x3297, 0x3297),
               (0x3299, 0x3299), (0x1F000, 0x1FAFF))
# The letters that bidi controls are for: Hebrew, Arabic and the other right-to-left scripts.
_RTL = re.compile("[֐-ࣿיִ-﷿ﹰ-ﻼ\U00010800-\U00010fff\U0001e800-\U0001efff]")
# The scripts whose letters a ZWJ or a ZWNJ changes: Arabic and its neighbours, the Indic scripts to Sinhala, Myanmar
# to Mongolian, the scripts of South-East Asia, and the forms of Arabic. Not Thai, Lao or Tibetan (U+0E00 to U+0FFF).
_JOINED = ((0x0600, 0x08FF), (0x0900, 0x0DFF), (0x1000, 0x18AF), (0x1900, 0x1CFF), (0xA800, 0xABFF),
           (0xFB50, 0xFDFF), (0xFE70, 0xFEFF), (0x10A00, 0x10FFF), (0x11000, 0x11FFF))
_LATIN = ((0x0041, 0x024F), (0x1E00, 0x1EFF), (0x2C60, 0x2C7F), (0xA720, 0xA7FF), (0xFF21, 0xFF5A))
_CJK = ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x323AF))
FLAG_BASE = 0x1F3F4
FLAGS = tuple(tuple(0xE0000 + ord(c) for c in code) + (0xE007F,) for code in ("gbeng", "gbsct", "gbwls"))


def _ranges(points):
    points, out, i = sorted(points), [], 0
    while i < len(points):
        j = i
        while j + 1 < len(points) and points[j + 1] == points[j] + 1:
            j += 1
        out.append(re.escape(chr(points[i])) + ("-" + re.escape(chr(points[j])) if j > i else ""))
        i = j + 1
    return "".join(out)


_CLASS = _ranges(INVISIBLE)
_PAIR = r"\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}"
_ONE = r"\\u[0-9a-fA-F]{4}"
# The fast first test: no invisible character and no escape means nothing to do.
FIRST = re.compile(f"[{_CLASS}]|\\\\u")
UNIT = re.compile(f"[{_CLASS}]|{_PAIR}|{_ONE}")
RAW = re.compile(f"[{_CLASS}]")
_RAW_TAG = re.compile("[\U000E0000-\U000E007F]")
_BEFORE = re.compile(f"(?:{_PAIR}|{_ONE})$")
_AFTER = re.compile(f"{_PAIR}|{_ONE}")
_JOINED_CHAR = re.compile("[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _JOINED) + "]")
# skeleton: the raw invisible characters and the control characters but tab, line feed and carriage return
_CONTROL = r"\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
_SKELETON = re.compile(f"[{_CLASS}{_CONTROL}]")
_ASCII_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _escape_point(piece):
    """The code point of one escape form: \\uXXXX, or \\uD8xx\\uDCxx as one."""
    if len(piece) == 12:
        high, low = int(piece[2:6], 16), int(piece[8:12], 16)
        return 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
    return int(piece[2:6], 16)


def _escaped(text, at):
    """True when the backslash at `at` starts an escape: an even number of backslashes stands before it."""
    n = 0
    while at - n - 1 >= 0 and text[at - n - 1] == "\\":
        n += 1
    return n % 2 == 0


def _before(text, at, escapes=True):
    """The code point of the character that ends at `at`, an escape form read as its character, or None."""
    if at <= 0:
        return None
    if escapes:
        m = _BEFORE.search(text, max(0, at - 12), at)
        if m and _escaped(text, m.start()):
            return _escape_point(m.group())
    return ord(text[at - 1])


def _after(text, at, escapes=True):
    """The code point of the character that starts at `at`, an escape form read as its character, or None."""
    if at >= len(text):
        return None
    if escapes:
        m = _AFTER.match(text, at)
        if m:
            return _escape_point(m.group())
    return ord(text[at])


def _kind(point):
    return unicodedata.category(chr(point)) if point is not None and point < 0x110000 else ""


def _shown(point):
    """A character that draws: not whitespace, not a control, not the start or end of the text."""
    return _kind(point)[:1] not in ("", "Z", "C")


def _within(point, ranges):
    return point is not None and any(low <= point <= high for low, high in ranges)


def _pictograph(point):
    """A character that an emoji sequence is made of (PICTOGRAPHS)."""
    return _within(point, PICTOGRAPHS)


def _emoji(point):
    """A character that a ZWJ of an emoji sequence joins: a pictograph, or the end of a flag."""
    return _pictograph(point) or point == 0xE007F


def _joined_letter(point):
    """A letter or a mark of a script that joins its letters, which a ZWJ or a ZWNJ changes for the reader."""
    return _kind(point)[:1] in ("L", "M") and _within(point, _JOINED)


def _latin_letter(point):
    return _kind(point)[:1] == "L" and _within(point, _LATIN)


def _joins(point, before, after):
    """A ZWJ or a ZWNJ is where text puts one: a ZWJ between two emoji, or either between two letters of a joining
    script. A ZWNJ never joins emoji."""
    return (point == ZWJ and _emoji(before) and _emoji(after)) or (_joined_letter(before) and _joined_letter(after))


def _selector_fits(point, before, after):
    """One variation selector is where text puts one: U+FE0E or U+FE0F after a pictograph, or U+FE0F in a keycap;
    U+FE00 to U+FE0D after a symbol or a letter that is not Latin; after an ideograph, an ideographic selector; after a
    Mongolian letter, a Mongolian one. After a Latin letter, a digit or ASCII punctuation no selector changes anything,
    so there it only carries data."""
    if not _shown(before):
        return False
    if before < 0x80:
        return point == 0xFE0F and chr(before) in "0123456789#*" and after == 0x20E3
    if point in EMOJI_SELECTORS:
        return _pictograph(before)
    if _latin_letter(before):
        return False
    if 0xFE00 <= point <= 0xFE0D:
        return True
    if 0xE0100 <= point <= 0xE01EF:
        return _within(before, _CJK)
    return 0x1800 <= before <= 0x18AF


def _gone(run, before, after):
    """The indexes of one run of invisible characters (code points, with a flag for an escape form) to remove."""
    points = [p for p, _ in run]
    if before == FLAG_BASE and tuple(points[:6]) in FLAGS:
        return [6 + i for i in _gone(run[6:], 0xE007F, after)] if len(run) > 6 else []
    if not run:
        return []
    if len(run) == 1:
        p, escape = run[0]
        if p in TAGS:
            return [0]
        if escape:
            return []
        if p in VARIATION:
            return [] if _selector_fits(p, before, after) else [0]
        if p in JOINERS:
            return [] if _joins(p, before, after) else [0]
        if p in OVERRIDES:
            return [0]
        if p in BIDI:
            return [0] if _latin_letter(before) and _latin_letter(after) else []
        return [0]                              # every other invisible character alone carries only data
    if len(run) == 2 and points[0] in EMOJI_SELECTORS and points[1] == ZWJ and _pictograph(before) and _emoji(after):
        return []                               # an emoji, its presentation selector, a joiner, the next emoji
    if len(run) <= 3 and all(p in BIDI for p in points) and not (_latin_letter(before) and _latin_letter(after)):
        return [i for i, p in enumerate(points) if p in OVERRIDES]  # nested bidi marks, as right-to-left text writes
    return list(range(len(run)))


def _rule(text, escapes):
    """Rules 1 to 5 on one text: (clean text, characters removed, tag characters among them)."""
    units = []                                  # (start, end, code point, escape form) of each invisible character
    for m in UNIT.finditer(text):
        piece = m.group()
        if piece[0] == "\\":
            if not _escaped(text, m.start()):
                continue
            point = _escape_point(piece)
            if point not in INVISIBLE or (not escapes and point not in TAGS):
                continue
            units.append((m.start(), m.end(), point, True))
        else:
            units.append((m.start(), m.end(), ord(piece), False))
    if not units:
        return text, 0, 0
    runs, run = [], [units[0]]
    for unit in units[1:]:
        if unit[0] == run[-1][1]:
            run.append(unit)
        else:
            runs.append(run)
            run = [unit]
    runs.append(run)
    drop, at = set(), 0                         # the units to remove, as indexes of `units`
    for run in runs:
        drop.update(at + i for i in _gone([(u[2], u[3]) for u in run], _before(text, run[0][0], escapes),
                                          _after(text, run[-1][1], escapes)))
        at += len(run)
    # Rule 4, over what the runs kept, without the escape forms: they are in plain sight of the model.
    kept = [i for i in range(len(units)) if i not in drop and not units[i][3]]
    selectors = [i for i in kept if units[i][2] in VARIATION and units[i][2] not in EMOJI_SELECTORS]
    if len(selectors) > VARIATION_MOST:
        drop.update(selectors)
    marks = [i for i in kept if units[i][2] in BIDI]
    if marks:
        # U+061C, the Arabic letter mark, is in the range and draws nothing: a letter is what a reader sees
        letters = sum(1 for c in _RTL.findall(text) if ord(c) not in INVISIBLE and _kind(ord(c))[:1] == "L")
        if not letters or len(marks) > BIDI_FREE + letters // 4:
            drop.update(marks)
    joins = [i for i in kept if units[i][2] in JOINERS]
    if joins:
        # a kept joiner stands before the emoji or the letter that it joins
        emoji = [i for i in joins if _emoji(_after(text, units[i][1], escapes))]
        set_of_emoji = set(emoji)
        if len(emoji) > EMOJI_JOINERS_MOST:
            drop.update(emoji)
        between = [i for i in joins if i not in set_of_emoji]
        if len(between) > JOINED_FREE:
            letters = sum(1 for c in _JOINED_CHAR.findall(text) if _kind(ord(c))[:1] == "L")
            if len(between) > max(JOINED_FREE, letters // 4):
                drop.update(between)
    if not drop:
        return text, 0, 0
    out, last, tags = [], 0, 0
    for i in sorted(drop):
        start, end, point, _ = units[i]
        out.append(text[last:start])
        last = end
        tags += point in TAGS
    out.append(text[last:])
    return "".join(out), len(drop), tags


def strip_hidden(text, escapes=True):
    """(clean text, characters removed, tag characters among them). Text with nothing to remove comes back as it is,
    the same object: ASCII text with no backslash-u after two checks in C, other text after one regular expression
    search. escapes=False: of the escape forms only those of tag characters go (rule 5)."""
    if text.isascii() and "\\u" not in text:   # isascii reads a flag of the string, at no cost
        return text, 0, 0
    if not FIRST.search(text):
        return text, 0, 0
    removed = tags = 0
    if len(text) > DENSE and not text.isascii():
        clean, n = RAW.subn("", text)           # rule 6: a text that is mostly hidden characters
        if n > DENSE:
            tags = len(text) - len(_RAW_TAG.sub("", text))
            removed, text = n, clean
    clean, n, t = _rule(text, escapes)
    return clean, removed + n, tags + t


def skeleton(text):
    """The text with every raw invisible character and every control character but tab, line feed and carriage
    return removed: what the search of a login reads besides the text itself, so that a character which strip_hidden
    keeps cannot split a login. ASCII text with no control character comes back as the same object, and so does any
    text with nothing to remove."""
    if text.isascii():
        if not _ASCII_CONTROL.search(text):
            return text
    elif not _SKELETON.search(text):
        return text
    return _SKELETON.sub("", text)


def count_line(removed, tags, who="The hub", what="this text"):
    """The one line that says what was removed. It never quotes the removed characters."""
    return (f"{who} removed {removed} hidden character{'' if removed == 1 else 's'} from {what} "
            f"(tag characters: {tags}).")
