# Mkolani POS

Mfumo wa POS wa biashara nyingi (multi-tenant) wenye risiti, stoko, wateja, madeni/mikopo, SMS (Beem), ripoti,
wafanyakazi na **Master Dashboard** ya ndani.

## Kuweka kwenye Render
1. Pakia faili hizi kwenye GitHub (hakikisha `.env` na `*.db` haviko).
2. Render > Web Service > unganisha repo. Build: `pip install -r requirements.txt`. Start: `gunicorn app:app --preload --workers 2 --timeout 60`.
   (au tumia `render.yaml` kama Blueprint)
3. Weka **Environment Variables**:
   - `SECRET_KEY` (lazima, herufi ndefu za nasibu), `PYTHON_VERSION=3.12.7`
   - `DATABASE_URL` (PostgreSQL ya Render, lazima ili data isipotee)
   - `MASTER_EMAIL`, `MASTER_PASSWORD` (inaunda Master mara ya kwanza; **kisha ondoa MASTER_PASSWORD**)
   - `MASTER_PATH` (hiari, njia ya siri ya Master, mfano `ops-9f3k`; chaguo-msingi `_master`)
   - `BEEM_API_KEY`, `BEEM_SECRET_KEY`, `BEEM_SENDER_ID` (funguo za jukwaa zima)
   - hiari: `TRIAL_DAYS`, `STARTER_SMS_CREDITS`, `SUPPORT_PHONE`, `SUPPORT_EMAIL`
4. Ingia kwa `MASTER_EMAIL`, kisha fungua `/<MASTER_PATH>` (mfano `/_master`) na uthibitishe nywila.

## Kujaribu kwenye kompyuta
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export FLASK_DEBUG=1 MASTER_EMAIL=wewe@example.com MASTER_PASSWORD=Nywila123
python app.py
```

## Muundo
- `app.py` njia za biashara, `master.py` Master Dashboard, `models.py` meza, `helpers.py` SMS/muda/ruhusa.
- Pesa ni TZS nzima (Integer). Muda umehifadhiwa UTC, unaonyeshwa EAT (UTC+3).
- Hakuna kufuta kwa kudumu kwa bidhaa/wateja (zinafichwa). Risiti hubatilishwa, hazifutwi.
