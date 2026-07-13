@echo off
REM Telegraph launcher — starts the relay and its Cloudflare tunnel.
REM Registered as a logon scheduled task so a reboot brings the relay back.
set TELEGRAPH_TRUST_PROXY=1
set STRIPE_WEBHOOK_SECRET=whsec_ON5LSNab5nhBTGya9YusOkfe9X6wSqxW
set TELEGRAPH_CHECKOUT_URL=https://buy.stripe.com/14AcN40IW7n84ZT4w5dAk00
set TELEGRAPH_CHECKOUT_URLS=1=https://buy.stripe.com/14AcN40IW7n84ZT4w5dAk00,19=https://buy.stripe.com/4gM3cu0IWbDo1NH2nXdAk01,499=https://buy.stripe.com/00wdR80IW7n8781faJdAk02
cd /d C:\Users\dutch\.openclaw\workspace\arthur-morgan\telegraph
start "" /b node bin\telegraph.js serve --port 7787 --data .\data
timeout /t 2 /nobreak >nul
start "" /b "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --config C:\Users\dutch\.cloudflared\telegraph-config.yml run
