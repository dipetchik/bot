import logging
import sqlite3
import aiohttp
import asyncio
import hashlib
from datetime import datetime

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest
from aiogram.enums import ContentType

# ==================== НАСТРОЙКИ ====================
BOT_TOKEN = "8717763658:AAFZ7SKbdF_oQvZER2WKZY_F9iP8Udg7mHo"
ADMIN_ID = 5166531049
HYBRID_API_KEY = "e33vs2cxc9f1b18fz9mub70pbf580369qd41k2f9b0ea4d1bd3os52aj6a06b58d"

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot=bot, storage=storage)

# ==================== HYBRID ANALYSIS КЛИЕНТ ====================
class HybridAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": api_key,
            "user-agent": "Falcon Sandbox",
            "accept": "application/json"
        }

    async def get_report(self, sha256):
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(f"{self.base_url}/report/{sha256}/summary") as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        return {"not_found": True}
                    else:
                        return {"error": f"HTTP {resp.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def scan_file(self, file_content, filename):
        sha256 = hashlib.sha256(file_content).hexdigest()
        report = await self.get_report(sha256)

        if report.get('not_found'):
            return {"success": True, "sha256": sha256, "classification": "not_found", "family": None}

        if "error" in report:
            return {"success": False, "error": f"Ошибка: {report.get('error')}"}

        verdict = report.get('verdict', '').lower()
        threat_level = report.get('threat_level', 0)

        if verdict == 'malicious' or threat_level >= 2:
            classification = "malicious"
        elif verdict == 'suspicious' or threat_level == 1:
            classification = "suspicious"
        elif verdict in ('clean', 'no specific threat'):
            classification = "clean"
        else:
            classification = "unknown"

        family = report.get('threat_family')

        return {
            "success": True,
            "sha256": sha256,
            "classification": classification,
            "family": family
        }


analyzer = HybridAnalyzer(HYBRID_API_KEY)

# ==================== БАЗА ДАННЫХ ====================
def init_db():
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE,
            user_id INTEGER,
            username TEXT,
            first_message TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            closed_at TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ticket_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT,
            sender_id INTEGER,
            sender_type TEXT,
            message TEXT,
            sent_at TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets (ticket_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            tickets_count INTEGER DEFAULT 0,
            scans_count INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            filesize INTEGER,
            sha256 TEXT,
            classification TEXT,
            family TEXT,
            scan_date TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    conn.commit()
    conn.close()
    print("База данных инициализирована")


init_db()

# ==================== ФУНКЦИИ БД ====================
def create_ticket_db(user_id, username, message):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM tickets")
    count = cursor.fetchone()[0] + 1
    ticket_id = f"TICKET-{count:04d}"
    now = datetime.now()

    cursor.execute('''
        INSERT INTO tickets (ticket_id, user_id, username, first_message, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (ticket_id, user_id, username, message, now, now))

    cursor.execute('''
        INSERT INTO ticket_messages (ticket_id, sender_id, sender_type, message, sent_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (ticket_id, user_id, 'user', message, now))

    cursor.execute('''
        INSERT OR REPLACE INTO users (user_id, username, first_seen, last_seen, tickets_count)
        VALUES (?, ?, COALESCE((SELECT first_seen FROM users WHERE user_id=?), ?), ?,
                COALESCE((SELECT tickets_count FROM users WHERE user_id=?), 0) + 1)
    ''', (user_id, username, user_id, now, now, user_id))

    conn.commit()
    conn.close()
    return ticket_id


def add_message_to_ticket_db(ticket_id, sender_id, sender_type, message):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    now = datetime.now()

    cursor.execute('''
        INSERT INTO ticket_messages (ticket_id, sender_id, sender_type, message, sent_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (ticket_id, sender_id, sender_type, message, now))

    cursor.execute('UPDATE tickets SET updated_at=? WHERE ticket_id=?', (now, ticket_id))
    conn.commit()
    conn.close()


def get_ticket_messages_db(ticket_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT sender_type, message, sent_at FROM ticket_messages WHERE ticket_id=? ORDER BY sent_at ASC', (ticket_id,))
    messages = cursor.fetchall()
    conn.close()
    return messages


def get_user_tickets_db(user_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ticket_id, first_message, status, created_at, updated_at FROM tickets WHERE user_id=? ORDER BY updated_at DESC', (user_id,))
    tickets = cursor.fetchall()
    conn.close()
    return tickets


def get_open_tickets_db():
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ticket_id, user_id, username, first_message, created_at, updated_at FROM tickets WHERE status='open' ORDER BY updated_at DESC")
    tickets = cursor.fetchall()
    conn.close()
    return tickets


def get_ticket_info_db(ticket_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tickets WHERE ticket_id=?', (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    return ticket


def close_ticket_db(ticket_id):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE tickets SET status="closed", closed_at=? WHERE ticket_id=?', (datetime.now(), ticket_id))
    cursor.execute('SELECT user_id FROM tickets WHERE ticket_id=?', (ticket_id,))
    result = cursor.fetchone()
    conn.commit()
    conn.close()
    return result[0] if result else None


def save_scan_result_db(user_id, filename, filesize, sha256, classification, family):
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (user_id, filename, filesize, sha256, classification, family, scan_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, filename, filesize, sha256, classification, family, datetime.now()))

    cursor.execute('''
        UPDATE users SET scans_count = COALESCE(scans_count, 0) + 1, last_seen = ?
        WHERE user_id = ?
    ''', (datetime.now(), user_id))

    conn.commit()
    conn.close()


def get_stats_db():
    conn = sqlite3.connect('bot_database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM tickets'); total_tickets = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE status='open'"); open_tickets = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(DISTINCT user_id) FROM tickets'); unique_users = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM ticket_messages'); total_messages = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM scans'); total_scans = cursor.fetchone()[0]

    conn.close()
    return total_tickets, open_tickets, unique_users, total_messages, total_scans

# ==================== СОСТОЯНИЯ ====================
class States(StatesGroup):
    ticket_message = State()
    ticket_reply = State()
    admin_reply = State()
    waiting_file = State()

# ==================== КЛАВИАТУРЫ ====================
def main_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton("📝 Создать обращение", callback_data="create_ticket")],
        [InlineKeyboardButton("📋 Мои обращения", callback_data="my_tickets")],
        [InlineKeyboardButton("🔍 Сканировать файл", callback_data="scan_file")],
        [InlineKeyboardButton("ℹ️ Инфо", callback_data="info")]
    ])


def admin_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton("📋 Открытые обращения", callback_data="admin_open")],
        [InlineKeyboardButton("📊 Статистика", callback_data="admin_stats")],
        [InlineKeyboardButton("ℹ️ Инфо", callback_data="info")]
    ])


def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")]
    ])


def ticket_actions_kb(ticket_id, is_admin=True):
    if is_admin:
        row1 = [
            InlineKeyboardButton("✏️ Ответить", callback_data=f"admin_reply:{ticket_id}"),
            InlineKeyboardButton("✅ Закрыть", callback_data=f"close:{ticket_id}")
        ]
    else:
        row1 = [
            InlineKeyboardButton("✏️ Ответить", callback_data=f"user_reply:{ticket_id}"),
            InlineKeyboardButton("🔄 Обновить", callback_data=f"refresh:{ticket_id}")
        ]
    return InlineKeyboardMarkup(inline_keyboard=[
        row1,
        [InlineKeyboardButton("◀️ Назад", callback_data="back_list")]
    ])


def user_tickets_kb(user_id):
    tickets = get_user_tickets_db(user_id)
    inline_kb = []
    for t in tickets:
        emoji = "✅" if t[2] == "closed" else "🟢"
        inline_kb.append([InlineKeyboardButton(f"{emoji} {t[0]}", callback_data=f"view_ticket:{t[0]}")])
    inline_kb.append([InlineKeyboardButton("◀️ Назад", callback_data="back_main")])
    return InlineKeyboardMarkup(inline_keyboard=inline_kb)


def scan_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton("🔍 Ещё", callback_data="scan_file"),
            InlineKeyboardButton("📝 Создать обращение", callback_data="create_ticket")
        ],
        [InlineKeyboardButton("◀️ Главное меню", callback_data="back_main")]
    ])

# ==================== ГЛОБАЛЬНЫЕ ОБРАБОТЧИКИ "НАЗАД" ====================
@dp.callback_query(F.data == "back_main")
async def global_back_main(callback: types.CallbackQuery, state: FSMContext):
    await state.clear()
    text = "Главное меню:"
    markup = admin_kb() if callback.from_user.id == ADMIN_ID else main_kb()
    try:
        await callback.message.edit_text(text, reply_markup=markup)
    except TelegramBadRequest as e:
        if "message is not modified" in e.message.lower():
            pass
    await callback.answer()


@dp.callback_query(F.data == "back_list")
async def global_back_list(callback: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if callback.from_user.id == ADMIN_ID:
        await show_open_tickets(callback)
    else:
        await show_my_tickets(callback)
    await callback.answer()

# ==================== ОСНОВНЫЕ ОБРАБОТЧИКИ ====================
@dp.message(Command("start"))
async def start(message: types.Message):
    text = "👋 Добро пожаловать!\n\nФункции:\n• Сканирование файлов\n• Создание обращений\n• Просмотр истории"
    markup = admin_kb() if message.from_user.id == ADMIN_ID else main_kb()
    await message.answer(text + ("\n\n(Админ-панель)" if message.from_user.id == ADMIN_ID else ""), reply_markup=markup)


@dp.callback_query(F.data == "info")
async def info(callback: types.CallbackQuery):
    text = "CoreDebuging Bot\n\nВерсия: 4.2\nКоманда: @CoreDebuging\nAPI: Hybrid Analysis"
    await callback.message.edit_text(text, reply_markup=back_kb())
    await callback.answer()

# ==================== ОБРАЩЕНИЯ ====================
@dp.callback_query(F.data == "create_ticket")
async def create_ticket(callback: types.CallbackQuery):
    await callback.message.edit_text(
        "📝 Опишите вашу проблему:",
        reply_markup=back_kb()
    )
    await States.ticket_message.set()
    await callback.answer()


@dp.message(States.ticket_message)
async def process_ticket(m: types.Message, state: FSMContext):
    if len(m.text or "") < 10:
        await m.answer("❌ Слишком короткое сообщение. Минимум 10 символов.", reply_markup=back_kb())
        return

    ticket_id = create_ticket_db(m.from_user.id, m.from_user.username or "NoName", m.text)

    await m.answer(
        f"✅ Обращение {ticket_id} создано!\n\nАдминистратор ответит вам.",
        reply_markup=main_kb()
    )

    if ADMIN_ID:
        await bot.send_message(
            ADMIN_ID,
            f"🆕 Новое обращение {ticket_id}\nОт: @{m.from_user.username or 'NoName'}\n\n{m.text}",
            reply_markup=ticket_actions_kb(ticket_id, True)
        )
    await state.clear()


@dp.callback_query(F.data == "my_tickets")
async def show_my_tickets(callback: types.CallbackQuery):
    tickets = get_user_tickets_db(callback.from_user.id)
    if not tickets:
        await callback.message.edit_text("📭 У вас нет обращений.", reply_markup=back_kb())
        await callback.answer()
        return

    await callback.message.edit_text("📋 Ваши обращения:", reply_markup=user_tickets_kb(callback.from_user.id))
    await callback.answer()


@dp.callback_query(F.data.startswith('view_ticket:'))
async def view_ticket(callback: types.CallbackQuery):
    ticket_id = callback.data.split(':')[1]
    ticket = get_ticket_info_db(ticket_id)
    if not ticket:
        await callback.answer("❌ Обращение не найдено", show_alert=True)
        return

    msgs = get_ticket_messages_db(ticket_id)
    status = "✅ Закрыто" if ticket[5] == "closed" else "🟢 Открыто"

    text = f"ОБРАЩЕНИЕ {ticket_id}\nСтатус: {status}\n\nПЕРЕПИСКА:\n"
    for s, msg, dt in msgs:
        who = "Вы" if s == "user" else "Админ"
        text += f"\n{who} ({dt[:16]}):\n{msg}\n"

    is_admin = callback.from_user.id == ADMIN_ID
    kb = ticket_actions_kb(ticket_id, is_admin)

    try:
        await callback.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest as e:
        if "message is not modified" in e.message.lower():
            await callback.message.edit_reply_markup(reply_markup=kb)
        else:
            await callback.message.answer(text, reply_markup=kb)
    except Exception:
        await callback.message.answer(text, reply_markup=kb)

    await callback.answer()


@dp.callback_query(F.data.startswith('user_reply:'))
async def user_reply(callback: types.CallbackQuery, state: FSMContext):
    ticket_id = callback.data.split(':')[1]
    ticket = get_ticket_info_db(ticket_id)
    if not ticket or ticket[5] == "closed":
        await callback.answer("❌ Обращение закрыто", show_alert=True)
        return

    await state.update_data(ticket=ticket_id)
    await callback.message.edit_text(
        f"✏️ Введите ваш ответ для обращения {ticket_id}:",
        reply_markup=back_kb()
    )
    await States.ticket_reply.set()
    await callback.answer()


@dp.message(States.ticket_reply)
async def process_user_reply(m: types.Message, state: FSMContext):
    data = await state.get_data()
    ticket_id = data.get("ticket")

    add_message_to_ticket_db(ticket_id, m.from_user.id, 'user', m.text)

    await m.answer("✅ Сообщение добавлено в обращение.", reply_markup=main_kb())

    if ADMIN_ID:
        await bot.send_message(
            ADMIN_ID,
            f"📨 Новое сообщение в {ticket_id}\nОт: @{m.from_user.username or 'NoName'}\n\n{m.text}",
            reply_markup=ticket_actions_kb(ticket_id, True)
        )
    await state.clear()


@dp.callback_query(F.data.startswith('refresh:'))
async def refresh(callback: types.CallbackQuery):
    await view_ticket(callback)


# ==================== АДМИН ФУНКЦИИ ====================
@dp.callback_query(F.data == "admin_open")
async def show_open_tickets(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Нет доступа", show_alert=True)
        return

    tickets = get_open_tickets_db()
    if not tickets:
        await callback.message.edit_text("✅ Нет открытых обращений.", reply_markup=back_kb())
        await callback.answer()
        return

    text = "ОТКРЫТЫЕ ОБРАЩЕНИЯ:\n\n"
    buttons = []
    for t in tickets:
        ticket_id, _, username, _, created_at, updated_at = t
        text += f"🟢 {ticket_id}\nОт: @{username}\nОбновлено: {updated_at[:16]}\n\n"
        buttons.append(InlineKeyboardButton(f"📌 {ticket_id}", callback_data=f"admin_view:{ticket_id}"))

    kb = InlineKeyboardMarkup(inline_keyboard=[[btn] for btn in buttons] + [[InlineKeyboardButton("◀️ Назад", callback_data="back_main")]])

    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query(F.data.startswith('admin_view:'))
async def admin_view(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Нет доступа", show_alert=True)
        return

    ticket_id = callback.data.split(':')[1]
    ticket = get_ticket_info_db(ticket_id)
    if not ticket:
        await callback.answer("❌ Обращение не найдено", show_alert=True)
        return

    msgs = get_ticket_messages_db(ticket_id)
    status = "✅ Закрыто" if ticket[5] == "closed" else "🟢 Открыто"

    text = f"ОБРАЩЕНИЕ {ticket_id}\nСтатус: {status}\nОт: @{ticket[3]}\n\nПЕРЕПИСКА:\n"
    for s, msg, dt in msgs:
        who = "Пользователь" if s == "user" else "Вы"
        text += f"\n{who} ({dt[:16]}):\n{msg}\n"

    await callback.message.edit_text(text, reply_markup=ticket_actions_kb(ticket_id, True))
    await callback.answer()


@dp.callback_query(F.data.startswith('admin_reply:'))
async def admin_reply(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Нет доступа", show_alert=True)
        return

    ticket_id = callback.data.split(':')[1]
    ticket = get_ticket_info_db(ticket_id)
    if not ticket or ticket[5] == "closed":
        await callback.answer("❌ Обращение закрыто", show_alert=True)
        return

    await state.update_data(ticket=ticket_id)
    await callback.message.edit_text(
        f"✏️ Введите ответ для обращения {ticket_id}:",
        reply_markup=back_kb()
    )
    await States.admin_reply.set()
    await callback.answer()


@dp.message(States.admin_reply)
async def process_admin_reply(m: types.Message, state: FSMContext):
    if m.from_user.id != ADMIN_ID:
        await m.answer("❌ Нет прав")
        await state.clear()
        return

    data = await state.get_data()
    ticket_id = data.get("ticket")
    ticket = get_ticket_info_db(ticket_id)

    add_message_to_ticket_db(ticket_id, ADMIN_ID, 'admin', m.text)

    try:
        await bot.send_message(
            ticket[2],
            f"📨 Ответ на {ticket_id}:\n\n{m.text}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton("📋 К обращению", callback_data=f"view_ticket:{ticket_id}")
            ]])
        )
        await m.answer(f"✅ Ответ отправлен @{ticket[3]}", reply_markup=admin_kb())
    except Exception:
        await m.answer("❌ Не удалось отправить", reply_markup=admin_kb())

    await state.clear()


@dp.callback_query(F.data.startswith('close:'))
async def close(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Нет доступа", show_alert=True)
        return

    ticket_id = callback.data.split(':')[1]
    user_id = close_ticket_db(ticket_id)

    if user_id:
        try:
            await bot.send_message(user_id, f"✅ Обращение {ticket_id} закрыто.")
        except Exception:
            pass
        await callback.message.edit_text(f"✅ Обращение {ticket_id} закрыто", reply_markup=admin_kb())
    else:
        await callback.message.edit_text("❌ Ошибка", reply_markup=admin_kb())
    await callback.answer()


@dp.callback_query(F.data == "admin_stats")
async def stats(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Нет доступа", show_alert=True)
        return

    t, o, u, msg, scans = get_stats_db()
    closed = t - o

    text = f"📊 СТАТИСТИКА\n\nОбращения: {t}\nОткрытых: {o}\nЗакрытых: {closed}\nСообщений: {msg}\nСканирований: {scans}\nПользователей: {u}"
    await callback.message.edit_text(text, reply_markup=back_kb())
    await callback.answer()

# ==================== СКАНИРОВАНИЕ ====================
@dp.callback_query(F.data == "scan_file")
async def scan_start(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.edit_text(
        "🔍 Отправьте файл (до 20 МБ):",
        reply_markup=back_kb()
    )
    await States.waiting_file.set()
    await callback.answer()


@dp.message(States.waiting_file, F.document)
async def scan_file(m: types.Message, state: FSMContext):
    doc = m.document
    if doc.file_size > 20 * 1024 * 1024:
        await m.answer("❌ Файл >20 МБ", reply_markup=back_kb())
        await state.clear()
        return

    status_msg = await m.answer("📥 Скачиваю файл...")

    try:
        file_info = await bot.get_file(doc.file_id)
        file_content = await bot.download_file(file_info.file_path)
        file_bytes = await file_content.read()

        sha256 = hashlib.sha256(file_bytes).hexdigest()

        await status_msg.edit_text(
            f"🔍 Проверяю...\nФайл: {doc.file_name}\nSHA256: {sha256}\n\nОжидайте..."
        )

        result = await analyzer.scan_file(file_bytes, doc.file_name)

        if not result.get("success"):
            await status_msg.edit_text(f"❌ Ошибка: {result.get('error')}", reply_markup=back_kb())
            await state.clear()
            return

        classification = result.get("classification", "unknown")
        family = result.get("family")

        save_scan_result_db(
            m.from_user.id,
            doc.file_name,
            doc.file_size,
            result["sha256"],
            classification,
            family
        )

        if classification == "malicious":
            emoji, status_text, rec = "🔴", "ВРЕДОНОСНЫЙ", "🚨 НЕ ОТКРЫВАЙТЕ!"
        elif classification == "suspicious":
            emoji, status_text, rec = "🟡", "ПОДОЗРИТЕЛЬНЫЙ", "⚠️ Осторожно"
        elif classification == "clean":
            emoji, status_text, rec = "🟢", "БЕЗОПАСНЫЙ", "✅ Чисто"
        elif classification == "not_found":
            emoji, status_text, rec = "⚪", "НЕ НАЙДЕН", "Нет в базе"
        else:
            emoji, status_text, rec = "❓", "НЕИЗВЕСТНО", "Неизвестно"

        result_text = f"{emoji} РЕЗУЛЬТАТ\n\nФайл: {doc.file_name}\nSHA256: {result['sha256']}\nСтатус: {status_text}"
        if family:
            result_text += f"\nСемейство: {family}"
        result_text += f"\n\n{rec}"

        await status_msg.edit_text(result_text, reply_markup=scan_kb())

    except Exception as e:
        await status_msg.edit_text(f"❌ Ошибка: {str(e)}", reply_markup=back_kb())

    await state.clear()


@dp.message(States.waiting_file)
async def invalid_file(m: types.Message):
    await m.answer("❌ Отправьте файл", reply_markup=back_kb())

# ==================== ЗАПУСК ====================
async def main():
    print("=" * 50)
    print("CoreDebuging Bot — ЗАПУЩЕН")
    print(f"Админ ID: {ADMIN_ID}")
    print("=" * 50)
    await dp.start_polling(bot, skip_updates=True)


if __name__ == '__main__':
    asyncio.run(main())
