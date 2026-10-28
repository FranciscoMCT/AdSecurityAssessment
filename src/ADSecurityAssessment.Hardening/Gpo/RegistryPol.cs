using System.Text;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Gpo;

/// <summary>Formato PReg (registry.pol) versão 1: "PReg" + versão, depois [chave;valor;tipo;tamanho;dados] em UTF-16LE.</summary>
public static class RegistryPol
{
    public const string DeletePrefix = "**del.";
    private const uint RegSz = 1, RegDword = 4, RegMultiSz = 7;

    public static byte[] Build(IEnumerable<PolEntry> entries)
    {
        using var ms = new MemoryStream();
        ms.Write(new byte[] { 0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00 });   // "PReg" + versão 1
        foreach (var e in entries)
        {
            Char(ms, '[');
            Str(ms, e.Key); Char(ms, ';');
            Str(ms, e.Delete ? DeletePrefix + e.Name : e.Name); Char(ms, ';');
            byte[] data;
            uint type;
            if (e.Delete)
            {
                type = RegSz;
                data = new byte[] { 0x20, 0x00, 0x00, 0x00 };   // " " + NUL (convenção do GP para **del.)
            }
            else
            {
                switch (e.Type)
                {
                    case RegType.Dword: type = RegDword; data = BitConverter.GetBytes(Convert.ToUInt32(e.Data)); break;
                    case RegType.String: type = RegSz; data = Encoding.Unicode.GetBytes((string)e.Data! + "\0"); break;
                    default: type = RegMultiSz; data = Encoding.Unicode.GetBytes(string.Concat(((string[])e.Data!).Select(s => s + "\0")) + "\0"); break;
                }
            }
            ms.Write(BitConverter.GetBytes(type)); Char(ms, ';');
            ms.Write(BitConverter.GetBytes((uint)data.Length)); Char(ms, ';');
            ms.Write(data);
            Char(ms, ']');
        }
        return ms.ToArray();
    }

    /// <summary>Leitura (usada na verificação e nos testes): devolve exatamente o que Build gravou.</summary>
    public static IReadOnlyList<PolEntry> Parse(byte[] bytes)
    {
        if (bytes.Length < 8 || bytes[0] != 0x50 || bytes[1] != 0x52 || bytes[2] != 0x65 || bytes[3] != 0x67 || BitConverter.ToUInt32(bytes, 4) != 1)
            throw new InvalidDataException("registry.pol inválido (assinatura/versão).");
        var list = new List<PolEntry>();
        var p = 8;
        while (p < bytes.Length)
        {
            Expect(bytes, ref p, '[');
            var key = ReadString(bytes, ref p); Expect(bytes, ref p, ';');
            var name = ReadString(bytes, ref p); Expect(bytes, ref p, ';');
            var type = BitConverter.ToUInt32(bytes, p); p += 4; Expect(bytes, ref p, ';');
            var size = (int)BitConverter.ToUInt32(bytes, p); p += 4; Expect(bytes, ref p, ';');
            var data = bytes.AsSpan(p, size).ToArray(); p += size;
            Expect(bytes, ref p, ']');
            if (name.StartsWith(DeletePrefix, StringComparison.Ordinal))
            { list.Add(new PolEntry("", key, name[DeletePrefix.Length..], RegType.String, null, true)); continue; }
            switch (type)
            {
                case RegDword: list.Add(new PolEntry("", key, name, RegType.Dword, BitConverter.ToUInt32(data, 0), false)); break;
                case RegSz: list.Add(new PolEntry("", key, name, RegType.String, Encoding.Unicode.GetString(data).TrimEnd('\0'), false)); break;
                case RegMultiSz:
                    var parts = Encoding.Unicode.GetString(data).Split('\0').Where(s => s.Length > 0).ToArray();
                    list.Add(new PolEntry("", key, name, RegType.MultiString, parts, false)); break;
                default: throw new InvalidDataException($"Tipo de registro não suportado: {type}.");
            }
        }
        return list;
    }

    private static void Char(Stream s, char c) { s.WriteByte((byte)c); s.WriteByte((byte)(c >> 8)); }
    private static void Str(Stream s, string v) { var b = Encoding.Unicode.GetBytes(v); s.Write(b); Char(s, '\0'); }

    private static void Expect(byte[] b, ref int p, char c)
    {
        if (p + 2 > b.Length || b[p] != (byte)c || b[p + 1] != (byte)(c >> 8)) throw new InvalidDataException($"registry.pol corrompido: esperado '{c}' em {p}.");
        p += 2;
    }

    private static string ReadString(byte[] b, ref int p)
    {
        var start = p;
        while (p + 1 < b.Length && !(b[p] == 0 && b[p + 1] == 0)) p += 2;
        if (p + 1 >= b.Length) throw new InvalidDataException("registry.pol corrompido: texto sem terminador.");
        var s = Encoding.Unicode.GetString(b, start, p - start);
        p += 2;
        return s;
    }
}
