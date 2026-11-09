using System.Globalization;
using System.Text.Json.Nodes;

// =====================================================================================
//  CLIENT FrigoTrack - simula i sensori di temperatura
//  Menu:  1) 3 sensori in parallelo   2) demo per l'interrogazione   3) test
// =====================================================================================
class Program
{
    public const string Url = "http://localhost:5000";   // indirizzo del server: se lo cambi, cambialo anche nel Server
    const int Measures = 10;       // quante misure invia ogni sensore
    const int IntervalMs = 2000;   // pausa tra due misure (millisecondi)

    static void Main()
    {
        // Numeri con il punto decimale (4.6) anche se Windows e' impostato in italiano (4,6)
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

        while (true)
        {
            Console.WriteLine("\n1) avvia i 3 sensori   2) demo misura valida e non valida   3) test   0) esci");
            Console.Write("Scelta: ");
            string choice = Console.ReadLine();
            try
            {
                if (choice == "1") Sensors();
                else if (choice == "2") Demo();
                else if (choice == "3") Tests.RunAll();
                else return;
            }
            catch (Exception ex) { Console.WriteLine("ERRORE: " + ex.Message + " (il server e' acceso?)"); }
        }
    }

    // ---------------------------------------------------------------------------------
    //  1) Tre sensori che lavorano IN PARALLELO (un Task ciascuno).
    //     Ognuno fa il suo handshake, quindi ha la sua sessione e la sua chiave.
    //     Parametri: identificativo, tipo di merce, temperatura "normale" del sensore.
    // ---------------------------------------------------------------------------------
    static void Sensors()
    {
        Task t1 = Task.Run(() => RunSensor("CELLA-BG-001", "pharma", 5));
        Task t2 = Task.Run(() => RunSensor("CAMION-MI-002", "food", 2));
        Task t3 = Task.Run(() => RunSensor("CELLA-RM-003", "frozen", -20));
        Task.WaitAll(t1, t2, t3);   // aspetto che finiscano tutti e tre
    }

    // Il lavoro di un sensore: handshake, misure a intervalli regolari, consultazione, chiusura
    static void RunSensor(string sensorId, string cargo, double normalTemperature)
    {
        // Handshake: prima di inviare qualsiasi dato
        Connection connection = new Connection();
        connection.Handshake();
        Console.WriteLine(sensorId + ": handshake fatto, sessione " + connection.SessionId);

        Random random = new Random();
        for (int n = 1; n <= Measures; n++)
        {
            // Temperatura normale +/- 0,5 gradi; ogni 4 misure +6 gradi, per far scattare l'allarme
            double temperature = normalTemperature + random.NextDouble() - 0.5;
            if (n % 4 == 0) temperature += 6;
            temperature = Math.Round(temperature, 1);

            // Send valida con lo schema "telemetry", cifra, invia e decifra la risposta (ack)
            JsonNode ack = connection.Send("/api/telemetry", NewMeasure(sensorId, cargo, temperature), "telemetry", out int status);
            Console.WriteLine(sensorId + ": misura " + n + " = " + temperature + " C -> HTTP " + status + " " + ack["alarm_message"] + ack["error"]);
            if (status != 200) return;   // per esempio 401: sessione scaduta, il sensore si ferma
            Thread.Sleep(IntervalMs);
        }

        // Chiedo al server le misure che ha salvato per questo sensore
        JsonObject request = new JsonObject();
        request["sensor_id"] = sensorId;
        JsonNode list = connection.Send("/api/readings", request, "readings-request", out _);
        Console.WriteLine(sensorId + ": il server ha salvato " + list["count"] + " misure");

        // Chiudo la sessione: il server cancella la chiave
        JsonObject close = new JsonObject();
        close["action"] = "close";
        connection.Send("/api/close", close, "close-request", out _);
        Console.WriteLine(sensorId + ": sessione chiusa");
    }

    // ---------------------------------------------------------------------------------
    //  2) Demo per l'interrogazione: handshake, una misura valida e una non valida,
    //     stampando cosa viaggia davvero in rete (solo buste cifrate)
    // ---------------------------------------------------------------------------------
    static void Demo()
    {
        Connection connection = new Connection();
        connection.Handshake();
        connection.Show = true;   // da qui Send stampa le buste in rete
        Console.WriteLine("session_id " + connection.SessionId + ", chiave (non viaggia in rete): " + Convert.ToHexString(connection.Key));

        // Misura valida: 200 e ack
        JsonObject good = NewMeasure("CELLA-BG-007", "pharma", 4.6);
        Console.WriteLine("\nMISURA VALIDA: " + good.ToJsonString());
        JsonNode ack = connection.Send("/api/telemetry", good, "telemetry", out int status);
        Console.WriteLine("   risposta decifrata: HTTP " + status + " " + ack.ToJsonString());

        // Misura non valida (99 gradi, lo schema ammette al massimo 40).
        // Lo schema la blocca gia' nel client; la invio lo stesso (schemaName = null) per vedere il 400 del server.
        JsonObject bad = NewMeasure("CELLA-BG-007", "pharma", 99);
        Console.WriteLine("\nMISURA NON VALIDA: " + bad.ToJsonString());
        SchemaError error = SchemaValidator.Validate(bad.ToJsonString(), "telemetry");
        Console.WriteLine("   lo schema la rifiuta nel client: campo '" + error.Field + "' " + error.Message);
        JsonNode answer = connection.Send("/api/telemetry", bad, null, out status);
        Console.WriteLine("   risposta del server: HTTP " + status + " " + answer["error"] + " (campo " + answer["field"] + ")");
    }

    // Crea il messaggio di una misura, nello stesso formato dell'esempio della consegna.
    // Deve rispettare schemas/telemetry.schema.json.
    public static JsonObject NewMeasure(string sensorId, string cargo, double temperature)
    {
        JsonObject measure = new JsonObject();
        measure["sensor_id"] = sensorId;                                               // es. CELLA-BG-001
        measure["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");   // ora attuale, formato date-time
        measure["cargo_type"] = cargo;                                                 // food, pharma, frozen
        measure["temperature_c"] = temperature;
        measure["humidity"] = Random.Shared.Next(40, 70);                              // umidita' casuale 40..69 %
        measure["battery"] = 87;
        return measure;
    }
}
