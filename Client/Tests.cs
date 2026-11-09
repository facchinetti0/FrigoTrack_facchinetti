using System.Text.Json.Nodes;

// =====================================================================================
//  Tests.cs - i 5 test richiesti dalla consegna, piu' uno sul salvataggio.
//  Il server deve essere acceso. Ogni test e' una funzione: se una condizione di
//  Check() e' falsa viene lanciata un'eccezione e il test risulta FALLITO.
// =====================================================================================
static class Tests
{
    public static void RunAll()
    {
        Run("1. handshake riuscito", () =>
        {
            Connection c = new Connection();
            c.Handshake();
            // Se le chiavi di client e server fossero diverse, il server non riuscirebbe
            // a decifrare la misura e risponderebbe 400: quindi 200 = stessa chiave.
            c.Send("/api/telemetry", Program.NewMeasure("CELLA-BG-001", "pharma", 5), "telemetry", out int status);
            Check(status == 200, "HTTP " + status);
        });

        Run("2. messaggio valido -> 200", () =>
        {
            Connection c = new Connection();
            c.Handshake();
            JsonNode ack = c.Send("/api/telemetry", Program.NewMeasure("CELLA-BG-002", "pharma", 4.6), "telemetry", out int status);
            Check(status == 200 && (string)ack["status"] == "ok", "HTTP " + status);
            // la risposta del server deve rispettare il suo schema
            Check(SchemaValidator.Validate(ack.ToJsonString(), "telemetry-ack") == null, "ack non conforme allo schema");
        });

        Run("3. messaggio non valido -> 400 con il campo sbagliato", () =>
        {
            Connection c = new Connection();
            c.Handshake();
            // 99 gradi: oltre il massimo dello schema (40). schemaName = null: lo invio senza validarlo nel client
            JsonNode error = c.Send("/api/telemetry", Program.NewMeasure("CELLA-BG-003", "pharma", 99), null, out int status);
            Check(status == 400 && (string)error["field"] == "temperature_c", "HTTP " + status + " " + error.ToJsonString());
        });

        Run("4. busta manomessa -> 400", () =>
        {
            Connection c = new Connection();
            c.Handshake();
            // Preparo una busta corretta, poi cambio un bit del testo cifrato (come un attaccante)
            JsonNode envelope = JsonNode.Parse(Crypto.Seal(c.SessionId, c.Key, Program.NewMeasure("CELLA-BG-004", "pharma", 5).ToJsonString()));
            byte[] data = Convert.FromBase64String((string)envelope["ciphertext"]);
            data[data.Length - 1] ^= 1;   // ^= 1 inverte l'ultimo bit
            envelope["ciphertext"] = Convert.ToBase64String(data);
            c.Post("/api/telemetry", envelope.ToJsonString(), out int status);
            Check(status == 400, "HTTP " + status);   // il tag non torna: il server rifiuta
        });

        Run("5. sessione inesistente -> 404", () =>
        {
            Connection c = new Connection();
            c.SessionId = "0000000000000000";   // nessun handshake: il server non conosce questa sessione
            c.Send("/api/telemetry", Program.NewMeasure("CELLA-BG-005", "pharma", 5), "telemetry", out int status);
            Check(status == 404, "HTTP " + status);
        });

        Run("6. la misura viene salvata e si rilegge con /api/readings", () =>
        {
            Connection c = new Connection();
            c.Handshake();
            c.Send("/api/telemetry", Program.NewMeasure("CELLA-BG-006", "food", 3), "telemetry", out _);
            JsonObject request = new JsonObject();
            request["sensor_id"] = "CELLA-BG-006";
            JsonNode list = c.Send("/api/readings", request, "readings-request", out int status);
            Check(status == 200 && (int)list["count"] >= 1, "nessuna misura salvata");
            Check(SchemaValidator.Validate(list.ToJsonString(), "readings-response") == null, "risposta non conforme allo schema");
        });
    }

    // Esegue un test e stampa OK oppure FALLITO con il motivo
    static void Run(string name, Action test)
    {
        try { test(); Console.WriteLine("[OK]       " + name); }
        catch (Exception ex) { Console.WriteLine("[FALLITO]  " + name + "  ->  " + ex.Message); }
    }

    // Se la condizione e' falsa, il test fallisce con questo messaggio
    static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
