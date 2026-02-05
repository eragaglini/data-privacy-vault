🛡️ Data Privacy Vault

Un microservizio sicuro progettato per la tokenizzazione e l'archiviazione di dati sensibili (PII - Personally Identifiable Information).

Il sistema isola le informazioni critiche dal resto dell'infrastruttura, restituendo token sicuri alle applicazioni client.

✨ Caratteristiche Principali

Crittografia Forte: Utilizza AES-GCM (Authenticated Encryption) per garantire sia la confidenzialità che l'integrità dei dati a riposo.

Tokenizzazione Idempotente: Implementa un meccanismo di hashing (SHA-256) per evitare duplicati nel vault; lo stesso dato in input restituisce sempre lo stesso token.

Access Control (RBAC): Sistema di autorizzazione basato su ruoli (writer per tokenizzare, reader per detokenizzare, admin per entrambi).

High Performance: Costruito su Flask e Redis per garantire latenze minime nelle operazioni di lettura e scrittura.

🛠️ Architettura

Il sistema segue un approccio a "Vault":

L'applicazione client invia un dato sensibile (es. email).

Il Vault cifra il dato e lo salva su Redis.

Il Vault restituisce un token casuale (UUID parziale) al client.

Il client salva solo il token nel proprio database, mantenendo il dato sensibile fuori dal proprio perimetro.

🚀 Guida all'Installazione

Segui questi passaggi per avviare il progetto in locale.

1. Clona il repository

git clone [https://github.com/TUO_UTENTE/TUO_REPOS_NAME.git](https://github.com/TUO_UTENTE/TUO_REPOS_NAME.git)
cd TUO_REPOS_NAME


2. Configura l'ambiente virtuale (Python)

È raccomandato utilizzare un ambiente virtuale per isolare le dipendenze.

# Crea l'ambiente virtuale
python -m venv venv

# Attiva l'ambiente
# Su macOS/Linux:
source venv/bin/activate
# Su Windows:
# venv\Scripts\activate

# Installa le dipendenze
pip install -r requirements.txt


3. Configura le Variabili d'Ambiente

Il progetto utilizza un file .env per gestire i segreti.

Copia il file di esempio:

cp .env.example .env


Apri il file .env e imposta una chiave di crittografia sicura. Puoi generarne una da terminale con:

# Genera una stringa esadecimale da 32 byte (256 bit)
openssl rand -hex 32


Incolla il risultato nella variabile ENCRYPTION_KEY dentro il file .env.

4. Avvia Redis

Il servizio richiede un'istanza Redis funzionante. Il modo più veloce è usare Docker:

docker run -p 6379:6379 -d redis


5. Esegui l'Applicazione

Avvia il server Flask (di default sulla porta 8008):

python app.py


🧪 Utilizzo (Esempi API)

Ecco come interagire con il Vault usando curl.

Tokenizzazione

(Richiede ruolo: writer)

Sostituisci il token Bearer con quello configurato nel tuo sistema (es. writer-token-abc-123 o admin-token-xyz-789).

curl -X POST http://localhost:8008/tokenize \
     -H "Authorization: Bearer admin-token-xyz-789" \
     -H "Content-Type: application/json" \
     -d '{
           "id": "req_001", 
           "data": {
             "email": "mario.rossi@example.com",
             "cc": "4111222233334444"
           }
         }'


Risposta attesa:

{
  "id": "req_001",
  "data": {
    "email": "a1b2c3d",
    "cc": "x9y8z7w"
  }
}


De-tokenizzazione

(Richiede ruolo: reader)

Usa i token ricevuti nel passaggio precedente per recuperare i dati originali.

curl -X POST http://localhost:8008/detokenize \
     -H "Authorization: Bearer admin-token-xyz-789" \
     -H "Content-Type: application/json" \
     -d '{
           "id": "req_002", 
           "data": {
             "email_field": "a1b2c3d",
             "cc_field": "x9y8z7w"
           }
         }'


🔒 Note di Sicurezza

⚠️ Attenzione: Questo codice è un Proof of Concept (PoC). Per un utilizzo in produzione, considerare:

Key Management System (KMS): Non salvare le chiavi nel file .env in produzione; utilizzare servizi come AWS KMS, HashiCorp Vault o Azure Key Vault.

TLS/SSL: Abilitare HTTPS per proteggere i dati in transito.

Audit Logs: Implementare un sistema di logging immutabile per tracciare chi accede ai dati in chiaro.

Rotazione delle Chiavi: Implementare una strategia per la rotazione periodica della chiave di crittografia (Key Rotation).

📄 Licenza

Distribuito sotto Licenza MIT. Vedere il file LICENSE per maggiori dettagli.
