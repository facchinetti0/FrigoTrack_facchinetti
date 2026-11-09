using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

// =====================================================================================
//  Crypto.cs - Diffie-Hellman (scambio della chiave) e AES-GCM (cifratura dei messaggi)
//
//  Questo file e' IDENTICO nel Server e nel Client: client e server devono fare
//  esattamente gli stessi calcoli. Se lo modifichi, copia la modifica nell'altro progetto.
// =====================================================================================
static class Crypto
{
    // ---------------------------------------------------------------------------------
    //  DIFFIE-HELLMAN
    //  Idea: client e server ottengono lo stesso numero segreto K senza mai spedirlo.
    //    client: sceglie a (segreto) e invia A = g^a mod p
    //    server: sceglie b (segreto) e invia B = g^b mod p
    //    client: K = B^a mod p        server: K = A^b mod p
    //  I due K sono uguali perche' (g^b)^a = (g^a)^b = g^(ab).
    //  Chi ascolta la rete vede p, g, A, B ma non a e b: per ricavarli dovrebbe risolvere
    //  il "logaritmo discreto", impossibile in tempi utili con un p da 2048 bit.
    // ---------------------------------------------------------------------------------

    // p: numero primo da 2048 bit del gruppo 14 dell'RFC 3526 (uno standard pubblico).
    // E' lungo apposta: piu' e' grande, piu' e' difficile risalire ai segreti. Non va modificato.
    public static readonly BigInteger P = FromHex(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");

    // g: il generatore del gruppo 14
    public static readonly BigInteger G = 2;

    // Segreto casuale: "a" per il client, "b" per il server.
    // 32 byte casuali = un numero da 256 bit. RandomNumberGenerator e' il generatore
    // crittografico di .NET (a differenza di Random, non e' prevedibile).
    public static BigInteger NewSecret()
    {
        return new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true);
    }

    // Chiave pubblica: A = g^a mod p (oppure B = g^b mod p). Questa si puo' inviare in rete.
    // ModPow calcola (base ^ esponente) mod modulo senza costruire il numero enorme base^esponente.
    public static BigInteger PublicKey(BigInteger secret)
    {
        return BigInteger.ModPow(G, secret, P);
    }

    // Segreto condiviso: K = B^a mod p (oppure K = A^b mod p).
    // K e' lungo 2048 bit, ma AES-256 vuole una chiave di 32 byte: la ricavo con SHA-256(K).
    public static byte[] SharedKey(BigInteger otherPublicKey, BigInteger mySecret)
    {
        BigInteger K = BigInteger.ModPow(otherPublicKey, mySecret, P);
        return SHA256.HashData(K.ToByteArray());
    }

    // I numeri grandi viaggiano nel JSON come testo esadecimale (es. "1F3A..."), perche' un
    // numero JSON normale perderebbe precisione oltre le 15 cifre circa.
    // TrimStart('0') toglie lo zero iniziale che .NET a volte aggiunge: cosi' p e' scritto sempre
    // allo stesso modo e lo schema handshake-request puo' confrontarlo con "const".
    public static string ToHex(BigInteger n) { return n.ToString("X").TrimStart('0'); }

    // Il "0" davanti evita che BigInteger legga il numero come negativo.
    public static BigInteger FromHex(string hex) { return BigInteger.Parse("0" + hex, NumberStyles.HexNumber); }

    // ---------------------------------------------------------------------------------
    //  AES-GCM
    //  Cifratura simmetrica (la stessa chiave per cifrare e decifrare) e "autenticata":
    //  oltre al testo cifrato produce un TAG di 16 byte. Se qualcuno modifica anche un
    //  solo bit del messaggio in rete, alla decifratura il tag non torna e si scopre.
    // ---------------------------------------------------------------------------------

    // Cifra un JSON e lo mette nella busta che viaggia in rete:
    //   { "session_id": "...", "ciphertext": "...", "tag": "..." }
    // Il nonce (12 byte casuali) deve essere DIVERSO per ogni messaggio: lo metto davanti
    // al testo cifrato, cosi' chi riceve lo ritrova. Il nonce non e' segreto.
    // Base64 serve per scrivere dei byte dentro un JSON, che contiene solo testo.
    public static string Seal(string sessionId, byte[] key, string json)
    {
        byte[] plain = Encoding.UTF8.GetBytes(json);         // testo in chiaro -> byte
        byte[] nonce = RandomNumberGenerator.GetBytes(12);   // nuovo a ogni messaggio
        byte[] cipher = new byte[plain.Length];              // qui finisce il testo cifrato
        byte[] tag = new byte[16];                           // qui finisce il tag
        using (AesGcm aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plain, cipher, tag);

        JsonObject envelope = new JsonObject();
        envelope["session_id"] = sessionId;                                             // unico dato in chiaro
        envelope["ciphertext"] = Convert.ToBase64String(nonce.Concat(cipher).ToArray()); // nonce + testo cifrato
        envelope["tag"] = Convert.ToBase64String(tag);
        return envelope.ToJsonString(Readable);
    }

    // Apre la busta e restituisce il JSON in chiaro.
    // Restituisce null se la busta e' stata manomessa (il tag non torna), se la chiave
    // e' sbagliata o se il Base64 non e' valido: in tutti questi casi Decrypt lancia
    // un'eccezione, che qui viene catturata.
    public static string Open(byte[] key, JsonNode envelope)
    {
        try
        {
            byte[] data = Convert.FromBase64String((string)envelope["ciphertext"]);
            byte[] tag = Convert.FromBase64String((string)envelope["tag"]);
            byte[] nonce = data.Take(12).ToArray();    // i primi 12 byte sono il nonce
            byte[] cipher = data.Skip(12).ToArray();   // il resto e' il testo cifrato
            byte[] plain = new byte[cipher.Length];
            using (AesGcm aes = new AesGcm(key, 16)) aes.Decrypt(nonce, cipher, tag, plain);   // controlla il tag
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return null;
        }
    }

    // Opzioni per scrivere la busta senza trasformare il "+" del Base64 in "+"
    // (sarebbe JSON valido lo stesso, ma meno leggibile).
    static readonly JsonSerializerOptions Readable = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
}
