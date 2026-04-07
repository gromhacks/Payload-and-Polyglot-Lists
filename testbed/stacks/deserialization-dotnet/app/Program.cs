using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Serialization;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ---------------------------------------------------------------------------
// Helper: build the standard JSON response envelope
// ---------------------------------------------------------------------------
static IResult MakeResult(string? output, string? error, double timeMs)
{
    return Results.Json(new { output = output ?? "", error = error ?? "", time_ms = timeMs });
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------
app.MapGet("/health", () => Results.Text("ok"));

// ---------------------------------------------------------------------------
// POST /jsonnet  -  Newtonsoft.Json with TypeNameHandling.All
// ---------------------------------------------------------------------------
app.MapPost("/jsonnet", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["input"].ToString();

    var sw = Stopwatch.StartNew();
    try
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        var obj = JsonConvert.DeserializeObject(input, settings);
        sw.Stop();
        return MakeResult(obj?.ToString(), null, sw.Elapsed.TotalMilliseconds);
    }
    catch (Exception ex)
    {
        sw.Stop();
        return MakeResult(null, ex.ToString(), sw.Elapsed.TotalMilliseconds);
    }
});

// ---------------------------------------------------------------------------
// POST /binaryformatter  -  base64 → BinaryFormatter.Deserialize
// ---------------------------------------------------------------------------
#pragma warning disable SYSLIB0011
app.MapPost("/binaryformatter", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["input"].ToString();

    var sw = Stopwatch.StartNew();
    try
    {
        var bytes = Convert.FromBase64String(input);
        using var ms = new MemoryStream(bytes);
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(ms);
        sw.Stop();
        return MakeResult(obj?.ToString(), null, sw.Elapsed.TotalMilliseconds);
    }
    catch (Exception ex)
    {
        sw.Stop();
        return MakeResult(null, ex.ToString(), sw.Elapsed.TotalMilliseconds);
    }
});
#pragma warning restore SYSLIB0011

// ---------------------------------------------------------------------------
// POST /xmlserializer  -  raw XML from form field → XmlSerializer
// ---------------------------------------------------------------------------
app.MapPost("/xmlserializer", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["input"].ToString();

    var sw = Stopwatch.StartNew();
    try
    {
        using var reader = new StringReader(input);
        using var xmlReader = XmlReader.Create(reader, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        });

        // Load into XmlDocument to inspect the root element
        var doc = new XmlDocument();
        doc.Load(xmlReader);
        var rootName = doc.DocumentElement?.Name ?? "string";

        // Try to resolve type from the root element name (assembly-qualified ok)
        var type = Type.GetType(rootName) ?? typeof(object);
        var serializer = new XmlSerializer(type);

        using var reader2 = new StringReader(input);
        var obj = serializer.Deserialize(reader2);
        sw.Stop();
        return MakeResult(obj?.ToString(), null, sw.Elapsed.TotalMilliseconds);
    }
    catch (Exception ex)
    {
        sw.Stop();
        return MakeResult(null, ex.ToString(), sw.Elapsed.TotalMilliseconds);
    }
});

// ---------------------------------------------------------------------------
// POST /losformatter  -  base64 → LosFormatter-style deserialization
//
// LosFormatter (System.Web.UI.LosFormatter) is a .NET Framework class that
// wraps ObjectStateFormatter, which internally uses BinaryFormatter for
// arbitrary object graphs. In .NET 8 on Linux it is unavailable, so this
// endpoint replicates the insecure pipeline: base64 → BinaryFormatter.
// ---------------------------------------------------------------------------
#pragma warning disable SYSLIB0011
app.MapPost("/losformatter", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["input"].ToString();

    var sw = Stopwatch.StartNew();
    try
    {
        var bytes = Convert.FromBase64String(input);
        using var ms = new MemoryStream(bytes);
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(ms);
        sw.Stop();
        return MakeResult(obj?.ToString(), null, sw.Elapsed.TotalMilliseconds);
    }
    catch (Exception ex)
    {
        sw.Stop();
        return MakeResult(null, ex.ToString(), sw.Elapsed.TotalMilliseconds);
    }
});
#pragma warning restore SYSLIB0011

// ---------------------------------------------------------------------------
// POST /javascriptserializer  -  JSON → type-resolving deserialization
//
// JavaScriptSerializer (System.Web.Script.Serialization) is .NET Framework
// only. This endpoint replicates its insecure behavior: when the JSON
// contains a "__type" field, the specified type is instantiated. On .NET 8
// we use Newtonsoft with TypeNameHandling to achieve the same attack surface.
// ---------------------------------------------------------------------------
app.MapPost("/javascriptserializer", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["input"].ToString();

    var sw = Stopwatch.StartNew();
    try
    {
        // JavaScriptSerializer uses "__type" for type discrimination.
        // Newtonsoft uses "$type". Rewrite so payloads targeting either work.
        var patched = input.Replace("\"__type\"", "\"$type\"");

        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        var obj = JsonConvert.DeserializeObject(patched, settings);
        sw.Stop();
        return MakeResult(obj?.ToString(), null, sw.Elapsed.TotalMilliseconds);
    }
    catch (Exception ex)
    {
        sw.Stop();
        return MakeResult(null, ex.ToString(), sw.Elapsed.TotalMilliseconds);
    }
});

app.Run();
