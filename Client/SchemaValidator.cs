using System.Globalization;
using System.Text.Json.Nodes;
using Json.Schema;   // libreria JsonSchema.Net (pacchetto NuGet, vedi il file .csproj)

// =====================================================================================
//  SchemaValidator.cs - validazione dei messaggi con JSON Schema
//
//  Le regole (campi obbligatori, tipi, valori ammessi, minimi e massimi...) NON sono
//  scritte nel codice: stanno nei file della cartella schemas/. Questo file carica lo
//  schema giusto e chiede alla libreria JsonSchema.Net di controllare il messaggio.
//  Per cambiare una regola si modifica lo schema, non questo file.
//
//  Questo file e' IDENTICO nel Server e nel Client: se lo modifichi, copia la modifica.
// =====================================================================================

// Il risultato di una validazione fallita: quale campo e' sbagliato e perche'
class SchemaError
{
    public string Field = "";     // es. "temperature_c" (vuoto se l'errore riguarda tutto il messaggio)
    public string Message = "";   // es. "99 e' maggiore di 40"
}

static class SchemaValidator
{
    // Cartella degli schemi. Il programma gira in <progetto>/bin/Debug/net8.0, quindi risalgo
    // di 4 cartelle ("..") per arrivare alla cartella principale FrigoTrack ed entro in "schemas".
    static readonly string Folder = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "schemas");

    // Controlla il testo "json" con il file schemas/<schemaName>.schema.json.
    // Restituisce null se il messaggio e' valido, altrimenti il primo errore trovato.
    // Esempio: Validate(testo, "telemetry") usa schemas/telemetry.schema.json
    public static SchemaError Validate(string json, string schemaName)
    {
        // 1) carico lo schema dal file (lo rileggo ogni volta: se modifichi lo schema vale subito)
        JsonSchema schema = JsonSchema.FromFile(Path.Combine(Folder, schemaName + ".schema.json"));

        // 2) opzioni della libreria
        EvaluationOptions options = new EvaluationOptions();
        options.OutputFormat = OutputFormat.List;             // tutti i risultati in un unico elenco
        options.RequireFormatValidation = true;              // controlla anche "format": "date-time"
        options.Culture = CultureInfo.GetCultureInfo("it");   // messaggi di errore in italiano

        // 3) la libreria confronta il JSON con lo schema (se il testo non e' JSON, Parse lancia un'eccezione)
        EvaluationResults result;
        try { result = schema.Evaluate(JsonNode.Parse(json), options); }
        catch { return new SchemaError { Message = "il testo non e' un JSON valido" }; }

        if (result.IsValid) return null;   // nessun errore

        // 4) cerco il primo punto del messaggio che ha errori:
        //    InstanceLocation dice DOVE, per esempio "/temperature_c" (tolgo la "/" iniziale)
        //    Errors dice PERCHE', per esempio "99 e' maggiore di 40"
        foreach (EvaluationResults detail in result.Details)
        {
            if (detail.HasErrors)
                return new SchemaError { Field = detail.InstanceLocation.ToString().TrimStart('/'), Message = detail.Errors.Values.First() };
        }
        return new SchemaError { Message = "messaggio non valido" };
    }
}
