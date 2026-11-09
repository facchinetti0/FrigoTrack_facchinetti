# FrigoTrack

Dei sensori di temperatura (il **client**) mandano le loro misure a un **server**.
I messaggi viaggiano cifrati, così nessuno può leggerli o modificarli.
Il server controlla ogni misura, avvisa se la temperatura è fuori dai limiti e la salva in un file.

## Cosa c'è nella cartella

- **Server**: il programma che riceve e salva le misure.
- **Client**: il programma che simula 3 sensori.
- **schemas**: le regole che ogni messaggio deve rispettare.

## Come si avvia

1. Apri `Server/Server.sln` con Visual Studio e premi **F5**.
2. Apri `Client/Client.sln` in un'altra finestra di Visual Studio e premi **F5**.
3. Nel client scegli dal menu:
   - **1** fa partire i 3 sensori;
   - **2** fa una prova con una misura giusta e una sbagliata;
   - **3** esegue i test.

La prima volta serve Internet: Visual Studio scarica da solo una libreria.

Le misure ricevute si trovano nel file `Server/data/readings.json`.

## Come funziona

**1. Il client e il server si accordano su una chiave segreta (Diffie-Hellman).**
Ognuno sceglie un numero segreto e manda all'altro solo un numero calcolato da quello.
Con i numeri ricevuti, tutti e due ottengono la stessa chiave, senza che la chiave passi mai in rete.

```
Client                                  Server
  |  ---- p, g, A (numero pubblico) --->  |
  |  <--- session_id, B (numero pubbl.) - |
  |                                       |
  entrambi calcolano la stessa chiave segreta
```

**2. Il client manda le misure cifrate con quella chiave.**
In rete passa solo una "busta" con tre campi:
- `session_id`: dice al server quale chiave usare;
- `ciphertext`: la misura cifrata;
- `tag`: serve a scoprire se qualcuno ha modificato il messaggio.

**3. Il server apre la busta e controlla la misura.**
Se la misura non rispetta le regole risponde con un errore che dice quale campo è sbagliato.
Se va bene, la salva e risponde «ok», segnalando un **allarme** se la temperatura è fuori dai limiti:
- cibo: da 0 a 4 °C;
- farmaci: da 2 a 8 °C;
- surgelati: da −25 a −18 °C.

## I messaggi

**Una misura** (prima di essere cifrata):
```json
{ "sensor_id": "CELLA-BG-007", "timestamp": "2026-11-02T08:15:30Z", "cargo_type": "pharma",
  "temperature_c": 4.6, "humidity": 55, "battery": 87 }
```

**La risposta del server**:
```json
{ "status": "ok", "sensor_id": "CELLA-BG-007", "received_at": "2026-11-02T08:15:31Z", "alarm": false }
```

**Un errore**:
```json
{ "error": "99 è maggiore di 40", "field": "temperature_c" }
```

## Gli indirizzi del server

- `/api/handshake`: accordo sulla chiave;
- `/api/telemetry`: invio di una misura;
- `/api/readings`: richiesta delle misure salvate di un sensore;
- `/api/close`: fine della sessione, il server cancella la chiave.

## Le risposte possibili

- **200**: tutto bene;
- **400**: messaggio sbagliato o modificato;
- **401**: sessione scaduta;
- **404**: sessione inesistente.

## I test

1. L'accordo sulla chiave riesce.
2. Una misura giusta viene accettata.
3. Una misura sbagliata viene rifiutata.
4. Un messaggio modificato viene rifiutato.
5. Una sessione inesistente viene rifiutata.
6. La misura viene salvata e si può rileggere.
