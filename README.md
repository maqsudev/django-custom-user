# django-custom-user

## Gmail orqali OTP

Gmail SMTP uchun `.env` faylida Gmail App Password qiymatini sozlang:

```env
DEFAULT_FROM_EMAIL=your-gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
```

Gmail hisobida 2-Step Verification yoqib, App Password yarating. Oddiy Gmail parolingizni ishlatmang.
`DEFAULT_FROM_EMAIL` App Password yaratilgan Gmail akkaunti bilan bir xil bo'lishi kerak.

Brauzerda `/` yoki `/accounts/register/` orqali ro'yxatdan o'ting. Emailga yuborilgan
kodni `/accounts/verify-email/` sahifasida tasdiqlang; keyin `/accounts/login/` orqali
kiring. Himoyalangan profil `/accounts/account/` da, chiqish tugmasi shu sahifada.

## Auth API

Kod kelmasa, `/accounts/verify-email/` sahifasidagi qayta yuborish tugmasidan foydalaning.

`POST /api/auth/register/` foydalanuvchi yaratib, emailiga 6 xonali kod yuboradi:

```json
{
	"email": "user@example.com",
	"username": "user",
	"password": "strong-password"
}
```

Telefon raqami (`phone_number`) ixtiyoriy; berilsa, `+998901234567` kabi E.164 formatida bo'lishi kerak.

`POST /api/auth/verify-email/` email va kodni tekshiradi. Kod 10 daqiqada tugaydi va IP manziliga soatiga 5 urinish ruxsat etiladi:

```json
{"email": "user@example.com", "otp": "123456"}
```

`POST /api/auth/login/` tasdiqlangan email va parol uchun token qaytaradi:

```json
{"email": "user@example.com", "password": "strong-password"}
```

Token bilan himoyalangan so'rovlarda `Authorization: Token <token>` yuboring. `POST /api/auth/logout/` tokenni bekor qiladi.

Admin panelda **Users** bo'limidagi **Gmailga kod yuborish** havolasi orqali ixtiyoriy emailga kod jo'natish mumkin. Email bazadagi userga tegishli bo'lsa, yangi kod uning tasdiqlash yozuviga ham saqlanadi.

Lokal ishga tushirish:

```sh
uv sync
uv run python manage.py migrate
uv run python manage.py createsuperuser
uv run python manage.py runserver
```

Testlar:

```sh
uv run python manage.py test
```