#!/usr/bin/env python3
"""Точное превью интерфейса VeloxVPN для Windows.

Координаты, цвета и размеры совпадают с ui_windows.go 1:1, поэтому картинка
показывает именно то, что будет на экране. Шрифт — DejaVu Sans (на Windows
используется Segoe UI, метрики близкие).
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 620, 720

BG = (0x0E, 0x11, 0x18)
CARD = (0x17, 0x1C, 0x26)
CARD2 = (0x1E, 0x24, 0x31)
TEXT = (0xEC, 0xF1, 0xF8)
SUB = (0x8C, 0x97, 0xA8)
ACCENT = (0x3B, 0x82, 0xF6)
OK = (0x2E, 0xC4, 0x8A)
WARN = (0xF2, 0xB0, 0x2E)
ERR = (0xE5, 0x4D, 0x4D)
RING = (0x22, 0x2A, 0x38)

REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

f_title = ImageFont.truetype(BOLD, 22)
f_big = ImageFont.truetype(BOLD, 27)
f_body = ImageFont.truetype(REG, 15)
f_small = ImageFont.truetype(REG, 13)
f_tiny = ImageFont.truetype(REG, 11)
f_badge = ImageFont.truetype(BOLD, 12)


def render(state="connected", busy=False, tun=False, servers=None,
           exit_ip="15.204.34.43", sub="", active_name=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # ---------------- заголовок
    d.text((32, 22), "VeloxVPN", font=f_title, fill=TEXT)
    d.text((34, 54), "Windows · VLESS / Reality / XHTTP", font=f_small, fill=SUB)

    label, col = "не подключено", SUB
    if busy:
        label, col = "работаю…", WARN
    elif state == "connected":
        label, col = "защищено", OK
    tw = d.textlength(label, font=f_badge)
    d.rounded_rectangle((W - 34 - tw - 22, 28, W - 32, 54), 13, fill=(col[0] // 5, col[1] // 5, col[2] // 5))
    d.text((W - 34 - tw - 11, 34), label, font=f_badge, fill=col)

    # ---------------- карточка статуса
    d.rounded_rectangle((32, 84, W - 32, 332), 16, fill=CARD)

    ring_col = OK if state == "connected" else (WARN if busy else RING)
    icon_col = OK if state == "connected" else (WARN if busy else SUB)
    cx, cy = 310, 180
    d.ellipse((cx - 50, cy - 50, cx + 50, cy + 50), outline=ring_col, width=6)
    d.arc((cx - 33, cy - 33, cx + 33, cy + 33), start=-60, end=240, fill=icon_col, width=5)
    d.rounded_rectangle((cx - 3, cy - 37, cx + 3, cy - 3), 3, fill=icon_col)

    headline = "Защищено" if state == "connected" else ("Подготовка…" if busy else "Не подключено")
    hw = d.textlength(headline, font=f_big)
    d.text(((W - hw) / 2, 244), headline, font=f_big, fill=TEXT)

    cap = ("выход " + exit_ip) if (state == "connected" and exit_ip) else (
        "нажмите кнопку ниже" if not busy else "проверяю серверы…")
    cw = d.textlength(cap, font=f_small)
    d.text(((W - cw) / 2, 296), cap, font=f_small, fill=SUB)

    # ---------------- ряд кнопок: Обновить + TUN
    d.rounded_rectangle((40, 352, 300, 396), 14, fill=ACCENT)
    lbl = "Найти серверы"
    lw = d.textlength(lbl, font=f_body)
    d.text((170 - lw / 2, 364), lbl, font=f_body, fill=(255, 255, 255))

    tun_bg = OK if tun else CARD2
    d.rounded_rectangle((320, 352, 580, 396), 14, fill=tun_bg)
    tun_txt = "TUN: включён (весь ПК)" if tun else "TUN: выкл · прокси 127.0.0.1"
    tw2 = d.textlength(tun_txt, font=f_small)
    d.text((450 - tw2 / 2, 366), tun_txt, font=f_small, fill=TEXT)

    # ---------------- список серверов
    d.text((40, 418), "СЕРВЕРЫ", font=f_badge, fill=SUB)
    y = 474
    shown = 0
    for name, ms, act in (servers or []):
        if shown >= 5 or y + 30 > H - 40:
            break
        d.rounded_rectangle((32, y, W - 32, y + 30), 10, fill=CARD2 if act else CARD)
        if act:
            d.rounded_rectangle((32, y + 8, 36, y + 22), 2, fill=OK)
        d.text((48, y + 7), name, font=f_small, fill=OK if act else TEXT)
        if ms > 0:
            ms_txt = f"{ms} мс"
            mcol = OK if ms < 100 else (WARN if ms < 250 else ERR)
        else:
            ms_txt, mcol = "—", SUB
        mw = d.textlength(ms_txt, font=f_small)
        d.text((W - 44 - mw, y + 7), ms_txt, font=f_small, fill=mcol)
        y += 36
        shown += 1

    if not servers:
        d.text((48, y + 4), "Список пуст — нажмите «Обновить»", font=f_small, fill=SUB)

    # ---------------- нижняя строка
    if sub:
        d.text((40, H - 26), sub, font=f_tiny, fill=SUB)

    return img


connected = render(
    state="connected",
    servers=[
        ("US · Reston | Белые списки", 18, True),
        ("US · Hillsboro | Белые списки", 17, False),
        ("CA · Vancouver | Белые списки", 20, False),
        ("DE · Frankfurt", 143, False),
        ("NL · Amsterdam", 156, False),
        ("FI · Helsinki", 171, False),
    ],
    sub="Подключено · US · Reston (18 мс) · порт 7890 · 6 серверов",
)

idle = render(
    state="idle",
    servers=[],
    exit_ip="",
    sub="Нажмите «Обновить» — приложение найдёт серверы и покажет задержки",
)

busy = render(
    state="idle",
    busy=True,
    servers=[
        ("US · Reston | Белые списки", 18, False),
        ("US · Hillsboro | Белые списки", 17, False),
    ],
    exit_ip="",
    sub="Загружаю списки: 14/25 источников · найдено 12 480 узлов",
)

connected.save("/home/user/velox-vpn/pc/preview/velox-ui-connected.png")
idle.save("/home/user/velox-vpn/pc/preview/velox-ui-idle.png")
busy.save("/home/user/velox-vpn/pc/preview/velox-ui-busy.png")
print("saved 3 previews")
