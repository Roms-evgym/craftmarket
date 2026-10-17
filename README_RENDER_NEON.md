
# CraftMarket auf Render + Neon

## Render-Einstellungen

- Runtime: Node
- Build Command: npm install
- Start Command: npm start
- Node-Version: mindestens 22

## Environment Variables

Diese Variablen in Render unter Service → Environment anlegen:

- NODE_ENV = production
- DATABASE_URL = dein Neon-Connection-String
- SESSION_SECRET = zufälliger geheimer Wert mit mindestens 32 Zeichen
- ADMIN_PASSWORD = starkes Startpasswort mit mindestens 12 Zeichen

Die Werte niemals in GitHub veröffentlichen.

## Neon

1. Öffne dein Neon-Projekt.
2. Klicke auf Connect.
3. Kopiere den PostgreSQL-Connection-String.
4. Hinterlege ihn in Render als DATABASE_URL.
5. Achte darauf, dass die Verbindung SSL verwendet.

## GitHub

Lade die Projektdateien hoch, aber niemals die .env-Datei.

## Datenbank

Beim ersten Start werden die Tabellen in Neon angelegt. Da im ursprünglichen ZIP keine SQLite-Datenbankdatei enthalten war, werden alte Benutzer und Aufträge nicht automatisch übernommen.

## Test

Nach dem Deployment:

1. Öffne deine Render-URL.
2. Melde dich als Admin an.
3. Teste Benutzerverwaltung und Aufträge.
4. Prüfe bei Problemen die Render-Logs.

