# RPM Rentals - agreement signing app

Admin: https://YOUR-SITE/admin    Customer: https://YOUR-SITE/s/<private-token>

## Settings (Render > Environment)
- ADMIN_PASSWORD   your admin login
- SESSION_SECRET   long random string
- DATABASE_URL     connection string from neon.tech (stores cars, bookings and photos)
- NODE_VERSION     22
- Optional email (alerts to you + signed copy to the customer): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, NOTIFY_EMAIL, and SMTP_FROM (the "from" address, optional)
Start command: npm start    Build command: npm install

## Notes
- All data is kept in the Neon database, so redeploying or restarting does not erase it.
- Photos are shrunk in the browser before upload to save database space.
- Licence photos are personal information. Check Neon's current free limits and terms, and
  get advice on where ID photos may be stored (clause 21 of your agreement).
- Edit agreement.txt (cars) and agreement-jetski.txt (jet skis) to change the terms.

## Booking features
- One booking can hold several vehicles (two cars, or a car and a jet ski). The customer signs once and gets the matching agreement(s).
- Returning customers: search in New booking to pre-fill their details (and re-use their licence photos on file).
- Links expire after the number of days you choose (default 7). Use "Extend link 7 days" on a booking to renew one.
- Condition reports are one per stage per booking, so note each vehicle's readings in the notes.

## Public website
- The home page (/) is now the customer website: fleet, availability check and booking requests.
- Optional env vars shown on the site: PUBLIC_PHONE, PUBLIC_EMAIL.
- Requests appear in the admin app (Requests tab) with a buzz and an email if configured.
- In Fleet, use "Hide from website" for vehicles that should not be bookable online.
