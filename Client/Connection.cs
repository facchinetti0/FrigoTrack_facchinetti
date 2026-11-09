using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;

// =====================================================================================
//  Connection.cs - il collegamento cifrato con il server
//  Prima si chiama Handshake() (Diffie-Hellman), poi Send() per ogni messaggio.
//  Ogni sensore crea la sua Connection: ha quindi la sua sessione e la sua chiave.
// =====================================================================================
class Connection
{
    static readonly HttpClient http = new HttpClient();   // client HTTP di .NET, uno per tutto il programma

    public string SessionId = "";       // ricevuto dal server con l'handshake
    public byte[] Key = new byte[32];   // chiave AES calcolata con Diffie-Hellman
    public bool Show = false;           // se true stampa cio' che viaggia davvero in rete (usato dalla demo)

    // ---------------------------------------------------------------------------------
    //  Handshake Diffie-Hellman: va fatto PRIMA di inviare qualsiasi dato
    // ---------------------------------------------------------------------------------
    public void Handshake()
    {
        BigInteger a = Crypto.NewSecret();     // segreto del client: non esce mai da qui
        BigInteger A = Crypto.PublicKey(a);    // A = g^a mod p: questo si puo' inviare

        // Invio {p, g, A} in chiaro (sono valori pubblici)
        JsonObject request = new JsonObject();
        request["p"] = Crypto.ToHex(Crypto.P);
        request["g"] = Crypto.ToHex(Crypto.G);
        request["A"] = Crypto.ToHex(A);
        string answer = Post("/api/handshake", request.ToJsonString(), out int status);

        // Controllo la risposta con lo schema handshake-response
        SchemaError error = SchemaValidator.Validate(answer, "handshake-response");
        if (status != 200 || error != null) throw new Exception("handshake fallito: " + answer);

        // Dalla risposta prendo session_id e B, e calcolo la chiave K = B^a mod p
        JsonNode response = JsonNode.Parse(answer);
        SessionId = (string)response["session_id"];
        Key = Crypto.SharedKey(Crypto.FromHex((string)response["B"]), a);
    }

    // ---------------------------------------------------------------------------------
    //  Invio di un messaggio: valida con lo schema -> cifra -> invia -> decifra la risposta.
    //  "status" restituisce il codice HTTP (200, 400, 401, 404).
    //  Con schemaName = null il messaggio NON viene validato: serve solo alla demo e ai
    //  test, per far arrivare al server un messaggio sbagliato e vedere il suo 400.
    // ---------------------------------------------------------------------------------
    public JsonNode Send(string path, JsonObject message, string schemaName, out int status)
    {
        // 1) Validazione PRIMA di cifrare: un messaggio sbagliato non parte nemmeno
        if (schemaName != null)
        {
            SchemaError error = SchemaValidator.Validate(message.ToJsonString(), schemaName);
            if (error != null) throw new Exception("il client non la invia: campo '" + error.Field + "' " + error.Message);
        }

        // 2) Cifro, metto nella busta e invio
        string envelope = Crypto.Seal(SessionId, Key, message.ToJsonString());
        string answer = Post(path, envelope, out status);
        if (Show) Console.WriteLine("   in rete ->  " + envelope + "\n   in rete <-  HTTP " + status + " " + answer);

        // 3) La risposta e' una busta cifrata da aprire, oppure un errore in chiaro
        //    (per esempio "sessione inesistente": il server non ha una chiave per cifrarlo)
        JsonNode node = JsonNode.Parse(answer);
        if (node["ciphertext"] == null) return node;
        return JsonNode.Parse(Crypto.Open(Key, node));
    }

    // POST di un testo JSON al server: restituisce il corpo della risposta e il codice HTTP.
    // .Result aspetta la fine della richiesta (cosi' il codice resta semplice, senza async/await).
    public string Post(string path, string body, out int status)
    {
        HttpResponseMessage response = http.PostAsync(Program.Url + path, new StringContent(body, Encoding.UTF8, "application/json")).Result;
        status = (int)response.StatusCode;
        return response.Content.ReadAsStringAsync().Result;
    }
}
