using System.Globalization;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// =====================================================================================
//  SERVER FrigoTrack
//  Riceve le misure dei sensori su HTTP, le decifra, le valida con JSON Schema,
//  controlla gli allarmi e le salva nel file Server/data/readings.json.
//
//  Endpoint (tutti POST):
//    /api/handshake  in chiaro: scambio Diffie-Hellman, crea la sessione
//    /api/telemetry  cifrato:   riceve e salva una misura
//    /api/readings   cifrato:   restituisce le misure salvate di un sensore
//    /api/close      cifrato:   chiude la sessione e cancella la chiave
// =====================================================================================

// Una sessione = un client che ha fatto l'handshake. Ogni client ha la sua chiave.
class Session
{
    public string Id;                         // session_id: l'unico dato che viaggia in chiaro
    public byte[] Key;                        // chiave AES ricavata con Diffie-Hellman
    public DateTime LastUse = DateTime.Now;   // ultimo messaggio ricevuto (per la scadenza -> 401)
}

class Program
{
    // Indirizzo su cui il server ascolta. Se lo cambi, cambialo anche nel Client.
    const string Url = "http://localhost:5000/";

    // Dati condivisi da tutte le richieste. Le richieste vengono gestite IN PARALLELO, quindi
    // chi legge o modifica questi dati lo fa dentro lock(locker): un thread alla volta.
    static readonly object locker = new object();
    static Dictionary<string, Session> sessions = new Dictionary<string, Session>();   // session_id -> sessione
    static JsonArray readings = new JsonArray();   // tutte le misure ricevute (copia in memoria del file)
    static string dataFile;                        // percorso di readings.json

    static void Main()
    {
        // Numeri con il punto decimale (4.6) anche se Windows e' impostato in italiano (4,6)
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;

        // Il file delle misure e' Server/data/readings.json.
        // Il programma gira in Server/bin/Debug/net8.0: risalgo di 3 cartelle per arrivare a Server/
        dataFile = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "data", "readings.json"));
        Directory.CreateDirectory(Path.GetDirectoryName(dataFile));
        // Se il file esiste gia' (server riavviato) ricarico le misure salvate in precedenza
        if (File.Exists(dataFile)) readings = JsonNode.Parse(File.ReadAllText(dataFile)).AsArray();

        // HttpListener e' il server HTTP gia' incluso in .NET
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add(Url);
        try { listener.Start(); }
        catch (Exception ex)
        {
            Console.WriteLine("Server non avviato: " + ex.Message + " (porta occupata? Cambia Url qui e nel Client)");
            Console.ReadLine();
            return;
        }
        Console.WriteLine("Server in ascolto su " + Url);
        Console.WriteLine("Misure salvate in " + dataFile);

        // Ciclo infinito: GetContext() aspetta la prossima richiesta, Task.Run la fa gestire
        // a un altro thread e il ciclo torna subito ad aspettare. Cosi' piu' client lavorano insieme.
        while (true)
        {
            HttpListenerContext context = listener.GetContext();
            Task.Run(() => Handle(context));
        }
    }

    // Smista ogni richiesta in base all'indirizzo
    static void Handle(HttpListenerContext context)
    {
        string path = context.Request.Url.AbsolutePath;                            // es. "/api/telemetry"
        string body = new StreamReader(context.Request.InputStream).ReadToEnd();   // corpo della richiesta (JSON)
        try
        {
            if (path == "/api/handshake") Handshake(context, body);
            else if (path == "/api/telemetry" || path == "/api/readings" || path == "/api/close") Encrypted(context, path, body);
            else Send(context, 404, Error("endpoint non trovato", ""));
        }
        catch (Exception ex)
        {
            Log("ERRORE: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------------------------
    //  POST /api/handshake  -  in chiaro, perche' la chiave non esiste ancora
    //  Riceve {p, g, A}, risponde {session_id, B}
    // ---------------------------------------------------------------------------------
    static void Handshake(HttpListenerContext context, string body)
    {
        // 1) Validazione con lo schema handshake-request: controlla che ci siano p, g, A,
        //    che p e g siano quelli del gruppo 14 ("const") e che A sia esadecimale ("pattern")
        SchemaError error = SchemaValidator.Validate(body, "handshake-request");
        if (error != null) { Send(context, 400, Error(error.Message, error.Field)); return; }

        // 2) Unico controllo nel codice: A deve essere minore di p-1, altrimenti il segreto
        //    sarebbe prevedibile. JSON Schema non sa confrontare numeri da 2048 bit.
        BigInteger A = Crypto.FromHex((string)JsonNode.Parse(body)["A"]);
        if (A >= Crypto.P - 1) { Send(context, 400, Error("A troppo grande", "A")); return; }

        // 3) Diffie-Hellman lato server
        BigInteger b = Crypto.NewSecret();      // segreto del server: non esce mai da qui
        BigInteger B = Crypto.PublicKey(b);     // B = g^b mod p, da mandare al client

        // 4) Nuova sessione: id casuale (8 byte = 16 caratteri esadecimali) e chiave K = A^b mod p
        Session session = new Session();
        session.Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLower();
        session.Key = Crypto.SharedKey(A, b);
        lock (locker) sessions[session.Id] = session;

        // 5) Risposta in chiaro: session_id e B (B e' pubblico, la chiave no)
        JsonObject response = new JsonObject();
        response["session_id"] = session.Id;
        response["B"] = Crypto.ToHex(B);
        Send(context, 200, response.ToJsonString());
        Log("handshake: nuova sessione " + session.Id);
    }

    // ---------------------------------------------------------------------------------
    //  Richieste cifrate: /api/telemetry, /api/readings, /api/close
    //  Regola di sicurezza: PRIMA si decifra, POI si valida; se il tag non torna -> 400
    // ---------------------------------------------------------------------------------
    static void Encrypted(HttpListenerContext context, string path, string body)
    {
        // 1) La busta {session_id, ciphertext, tag} ha la forma giusta? (schema envelope)
        SchemaError error = SchemaValidator.Validate(body, "envelope");
        if (error != null) { Send(context, 400, Error(error.Message, error.Field)); return; }
        JsonNode envelope = JsonNode.Parse(body);

        // 2) La sessione esiste? (404) E' scaduta, cioe' nessun messaggio da 10 minuti? (401)
        Session session;
        lock (locker) sessions.TryGetValue((string)envelope["session_id"], out session);
        if (session == null) { Send(context, 404, Error("sessione inesistente", "")); return; }
        if (DateTime.Now - session.LastUse > TimeSpan.FromMinutes(10)) { Send(context, 401, Error("sessione scaduta", "")); return; }

        // 3) PRIMA decifro con la chiave della sessione. Se il tag non torna la busta e' stata
        //    manomessa: rispondo 400 e non elaboro nulla. (Errori 1-3 in chiaro: manca una chiave fidata)
        string json = Crypto.Open(session.Key, envelope);
        if (json == null) { Send(context, 400, Error("busta manomessa", "")); return; }
        session.LastUse = DateTime.Now;

        // 4) POI valido il messaggio decifrato con lo schema del suo endpoint.
        //    Da qui in poi le risposte sono cifrate (Reply), anche gli errori.
        string schemaName = "close-request";
        if (path == "/api/telemetry") schemaName = "telemetry";
        if (path == "/api/readings") schemaName = "readings-request";
        error = SchemaValidator.Validate(json, schemaName);
        if (error != null) { Reply(context, 400, session, Error(error.Message, error.Field)); return; }

        // 5) Il messaggio e' integro e valido: lo elaboro
        JsonObject message = JsonNode.Parse(json).AsObject();
        if (path == "/api/telemetry") Telemetry(context, session, message);
        if (path == "/api/readings") Readings(context, session, message);
        if (path == "/api/close") Close(context, session);
    }

    // ---------------------------------------------------------------------------------
    //  /api/telemetry: controlla l'allarme, SALVA la misura nel file e risponde con l'ack
    // ---------------------------------------------------------------------------------
    static void Telemetry(HttpListenerContext context, Session session, JsonObject measure)
    {
        string cargo = (string)measure["cargo_type"];
        double temperature = (double)measure["temperature_c"];

        // Intervallo di sicurezza della temperatura per ogni tipo di merce (gradi Celsius)
        double min = 0, max = 4;                          // food: 0..4
        if (cargo == "pharma") { min = 2; max = 8; }      // farmaci: 2..8
        if (cargo == "frozen") { min = -25; max = -18; }  // surgelati: -25..-18

        // Se c'e' un allarme ne scrivo il motivo; stringa vuota = nessun allarme.
        // Per aggiungere un altro allarme basta un altro "if" che scrive alarmMessage.
        string alarmMessage = "";
        if (temperature < min || temperature > max)
            alarmMessage = "temperatura " + temperature + " C fuori intervallo " + min + ".." + max + " (" + cargo + ")";

        // SALVATAGGIO: alla misura inviata dal client aggiungo ora di arrivo ed esito dell'allarme,
        // la metto nell'elenco e riscrivo tutto il file readings.json (indentato, leggibile).
        string now = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        measure["received_at"] = now;
        measure["alarm"] = alarmMessage != "";
        lock (locker)
        {
            readings.Add(measure);
            File.WriteAllText(dataFile, readings.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        Log(measure["sensor_id"] + ": " + temperature + " C salvata  " + alarmMessage);

        // Risposta (ack), cifrata. Deve rispettare schemas/telemetry-ack.schema.json
        JsonObject ack = new JsonObject();
        ack["status"] = "ok";
        ack["sensor_id"] = (string)measure["sensor_id"];
        ack["received_at"] = now;
        ack["alarm"] = alarmMessage != "";
        if (alarmMessage != "") ack["alarm_message"] = alarmMessage;
        Reply(context, 200, session, ack.ToJsonString());
    }

    // ---------------------------------------------------------------------------------
    //  /api/readings: restituisce le misure salvate di un sensore, eventualmente
    //  solo quelle tra "from" e "to" (se mancano, nessun limite)
    // ---------------------------------------------------------------------------------
    static void Readings(HttpListenerContext context, Session session, JsonObject request)
    {
        string sensorId = (string)request["sensor_id"];
        DateTimeOffset from = request["from"] == null ? DateTimeOffset.MinValue : DateTimeOffset.Parse((string)request["from"]);
        DateTimeOffset to = request["to"] == null ? DateTimeOffset.MaxValue : DateTimeOffset.Parse((string)request["to"]);

        JsonArray found = new JsonArray();
        lock (locker)
        {
            foreach (JsonNode r in readings)
            {
                DateTimeOffset time = DateTimeOffset.Parse((string)r["timestamp"]);
                // DeepClone: un nodo JSON puo' stare in un solo elenco, quindi aggiungo una copia
                if ((string)r["sensor_id"] == sensorId && time >= from && time <= to) found.Add(r.DeepClone());
            }
        }

        // Risposta cifrata. Deve rispettare schemas/readings-response.schema.json
        JsonObject response = new JsonObject();
        response["sensor_id"] = sensorId;
        response["count"] = found.Count;
        response["readings"] = found;
        Reply(context, 200, session, response.ToJsonString());
    }

    // ---------------------------------------------------------------------------------
    //  /api/close: chiude la sessione e cancella la chiave
    // ---------------------------------------------------------------------------------
    static void Close(HttpListenerContext context, Session session)
    {
        lock (locker) sessions.Remove(session.Id);                 // da ora la sessione non esiste (404)
        Reply(context, 200, session, "{\"status\":\"closed\"}");   // cifro la risposta PRIMA di cancellare la chiave
        Array.Clear(session.Key);                                  // azzero la chiave in memoria
        Log("sessione " + session.Id + " chiusa");
    }

    // ---------------------------------------------------------------------------------
    //  Invio delle risposte
    // ---------------------------------------------------------------------------------

    // Risposta IN CHIARO: usata solo quando non c'e' una chiave valida (handshake, errori 1-3)
    static void Send(HttpListenerContext context, int status, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        context.Response.StatusCode = status;   // 200, 400, 401, 404
        context.Response.ContentType = "application/json";
        context.Response.OutputStream.Write(bytes, 0, bytes.Length);
        context.Response.Close();
    }

    // Risposta CIFRATA: il JSON viene messo nella busta con la chiave della sessione
    static void Reply(HttpListenerContext context, int status, Session session, string json)
    {
        Send(context, status, Crypto.Seal(session.Id, session.Key, json));
    }

    // Messaggio di errore {"error": "...", "field": "..."} (field solo se si conosce il campo sbagliato)
    static string Error(string message, string field)
    {
        JsonObject error = new JsonObject();
        error["error"] = message;
        if (field != "") error["field"] = field;
        return error.ToJsonString();
    }

    // Scrive una riga nella console del server con l'ora
    static void Log(string text)
    {
        Console.WriteLine(DateTime.Now.ToString("HH:mm:ss") + "  " + text);
    }
}
