# FrigoTrack – Relazione tecnica

## Obiettivo

Il prototipo trasmette le misure di temperatura dei sensori di FrigoTrack a una piattaforma centrale e rispetta i tre vincoli del cliente. Il canale resta HTTP. La chiave di cifratura non viaggia mai in rete. Ogni messaggio ha un formato rigoroso, verificato con JSON Schema. La soluzione è composta da due programmi indipendenti, un **server** di raccolta e un **client** che simula i sensori, scritti in C# con .NET 8.

## Scelte tecniche

**Architettura.** Server e client sono due progetti separati, ognuno con la propria soluzione; condividono solo la cartella `schemas/`. Il server usa `HttpListener`, il server HTTP già incluso in .NET, ed espone quattro endpoint POST: `handshake`, `telemetry`, `readings` e `close`. Ho scelto un'applicazione console senza framework web per avere tutto il comportamento del server visibile in un solo file, nell'ordine in cui viene eseguito.

**Scambio della chiave (Diffie-Hellman).** Ho usato il gruppo 14 dell'RFC 3526: un primo `p` da 2048 bit con generatore `g = 2`. È un gruppo standard e verificato, quindi non c'è bisogno di generare un primo sicuro, operazione lenta e soggetta a errori. Client e server scelgono un segreto casuale da 256 bit con `RandomNumberGenerator`, il generatore crittografico di .NET. Poi calcolano `A = g^a mod p` e `K = B^a mod p` con `BigInteger.ModPow`, unica funzione di libreria usata per il calcolo. Il segreto condiviso `K` è lungo 2048 bit, mentre AES-256 richiede 32 byte: la chiave simmetrica è quindi `SHA-256(K)`. I numeri grandi viaggiano nel JSON come testo esadecimale, perché i numeri JSON perdono precisione oltre le 15 cifre circa.

**Cifratura (AES-256-GCM).** GCM è una modalità *autenticata*: oltre al testo cifrato produce un tag di 16 byte. Un solo bit modificato in rete fa fallire la decifratura, quindi la stessa operazione garantisce riservatezza e integrità. Il nonce di 12 byte è casuale e diverso per ogni messaggio, come GCM richiede, e viaggia in testa al testo cifrato. Così la busta ha esattamente i tre campi della specifica: `session_id`, `ciphertext` e `tag`, gli ultimi due in Base64. In rete l'unico dato applicativo in chiaro è il `session_id`.

**Validazione (JSON Schema).** Ho scritto dieci schemi (draft 2020-12), uno per ogni tipo di messaggio. Usano `type`, `required`, `enum`, `const`, `minimum`/`maximum`, `pattern`, `format: date-time` e `additionalProperties: false`. La validazione la esegue la libreria **JsonSchema.Net**, così le regole stanno solo negli schemi e il codice non contiene controlli sui singoli campi. Per cambiare una regola basta modificare un file. Anche il vincolo «gruppo noto» è nello schema: `const` su `p` e `g` impedisce che un client imponga un gruppo debole. In caso di errore la libreria indica il campo sbagliato e il motivo, che il server restituisce come `{"error": ..., "field": ...}`. Il client valida ogni messaggio prima di cifrarlo; il server lo valida dopo averlo decifrato.

**Ordine dei controlli sul server.** Per ogni richiesta cifrata il server esegue, nell'ordine:
1. schema della busta (400);
2. esistenza della sessione (404) e sua scadenza dopo 10 minuti di inattività (401);
3. decifratura con verifica del tag (400 senza elaborare nulla);
4. schema del messaggio decifrato (400 con il campo sbagliato);
5. elaborazione.

Gli errori dei passi 1-3 sono in chiaro, perché non esiste ancora una chiave affidabile con cui cifrarli; dal passo 4 in poi tutte le risposte sono cifrate.

**Sessioni e concorrenza.** Ogni client ha una sessione con identificativo casuale e chiave propria. Ogni richiesta viene gestita in un `Task` separato, quindi più sensori lavorano contemporaneamente. Le sessioni e l'elenco delle misure sono condivisi tra i thread e sono protetti da un `lock`. Con `/api/close` il server elimina la sessione e azzera la chiave in memoria.

**Allarmi e salvataggio.** Il server confronta la temperatura con l'intervallo di sicurezza della merce: cibo 0…4 °C, farmaci 2…8 °C, surgelati −25…−18 °C. Se è fuori intervallo, l'ack contiene `alarm: true` e il motivo. Ogni misura accettata viene salvata nel file `Server/data/readings.json` insieme all'ora di arrivo e all'esito del controllo. Il file viene ricaricato al riavvio ed è la fonte di `/api/readings`, che filtra per sensore e intervallo di tempo.

**Verifica.** Il client contiene sei test automatici eseguiti contro il server reale:
- handshake riuscito;
- messaggio valido;
- messaggio non valido, con l'indicazione del campo;
- busta manomessa;
- sessione inesistente;
- salvataggio e rilettura delle misure.

Ho inoltre verificato, intercettando il traffico tra client e server, che in rete non compaiano dati dei sensori in chiaro.

## Limiti noti

1. **Man-in-the-middle.** Diffie-Hellman senza autenticazione protegge da chi ascolta, non da chi si interpone e fa due handshake separati. *Soluzione:* il server firma `B` con una chiave privata nota ai sensori, oppure ogni sensore ha una chiave pre-condivisa.
2. **Replay.** Una busta catturata può essere reinviata ed è accettata di nuovo, perché resta valida. *Soluzione:* il server memorizza i tag già ricevuti nella sessione, oppure ogni messaggio porta un contatore crescente.
3. **Metadati visibili.** Restano in chiaro endpoint, dimensioni dei messaggi, orari, `session_id` e gli errori che precedono la decifratura.
4. **Identità del sensore non verificata.** Il `sensor_id` non è legato alla sessione: un dispositivo con una sessione valida può dichiararsi un altro sensore.
5. **Nessun limite di risorse.** Non c'è un limite al numero di sessioni né alla dimensione delle richieste, e le sessioni scadute restano in memoria finché non vengono usate. Il server è quindi esposto a sovraccarichi (denial of service).
6. **Persistenza semplificata.** Il file JSON viene riscritto per intero a ogni misura: va bene per un prototipo, non per migliaia di sensori, dove servirebbe un database.
7. **Codice duplicato.** `Crypto.cs` e `SchemaValidator.cs` sono copiati nei due progetti e vanno mantenuti uguali; in un progetto reale andrebbero in una libreria comune.
