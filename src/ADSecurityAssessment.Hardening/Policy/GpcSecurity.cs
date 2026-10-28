namespace ADSecurityAssessment.Hardening.Policy;

/// <summary>
/// Lógica pura (portátil, sem APIs de ACL do Windows) sobre o descritor de segurança binário do objeto GPC.
/// Uma GPO só se aplica a quem tem "Read" + "Apply group policy" nela; o padrão do esquema concede isso a Authenticated Users.
/// Se o direito faltar, a GPO vinculada não se aplicaria a ninguém — a ferramenta avisa em vez de deixar passar em silêncio.
/// </summary>
public static class GpcSecurity
{
    /// <summary>Direito estendido "Apply Group Policy" (edacfd8f-ffb3-11d1-b41d-00a0c968f939).</summary>
    public static readonly Guid ApplyGroupPolicy = new("edacfd8f-ffb3-11d1-b41d-00a0c968f939");
    private const uint ControlAccess = 0x100;       // ADS_RIGHT_DS_CONTROL_ACCESS
    private const ushort DaclPresent = 0x0004;
    private static readonly byte[] AuthenticatedUsersSid = { 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0 };   // S-1-5-11

    /// <summary>true se Authenticated Users tem o direito Apply Group Policy (ou controle de acesso genérico) e não há negação.</summary>
    public static bool AuthenticatedUsersCanApply(byte[] sd)
    {
        if (sd.Length < 20) throw new InvalidDataException("Descritor de segurança curto demais.");
        var control = BitConverter.ToUInt16(sd, 2);
        var daclOffset = (int)BitConverter.ToUInt32(sd, 16);
        if ((control & DaclPresent) == 0 || daclOffset == 0) return true;   // sem DACL = acesso total

        var aceCount = BitConverter.ToUInt16(sd, daclOffset + 4);
        var p = daclOffset + 8;
        var granted = false;
        for (var i = 0; i < aceCount; i++)
        {
            if (p + 8 > sd.Length) throw new InvalidDataException("ACL truncada.");
            var type = sd[p];
            var size = BitConverter.ToUInt16(sd, p + 2);
            if (size < 8 || p + size > sd.Length) throw new InvalidDataException("ACE inválida.");
            var mask = BitConverter.ToUInt32(sd, p + 4);
            var isObject = type is 0x05 or 0x06;
            var allow = type is 0x00 or 0x05;
            var deny = type is 0x01 or 0x06;
            if (allow || deny)
            {
                var q = p + 8;
                var appliesToApplyRight = (mask & ControlAccess) != 0;
                if (isObject)
                {
                    var flags = BitConverter.ToUInt32(sd, q); q += 4;
                    if ((flags & 1) != 0)
                    {
                        var objectType = new Guid(sd.AsSpan(q, 16)); q += 16;
                        if (objectType != ApplyGroupPolicy) appliesToApplyRight = false;
                    }
                    if ((flags & 2) != 0) q += 16;
                }
                if (appliesToApplyRight && SidEquals(sd, q, p + size))
                {
                    if (deny) return false;
                    granted = true;
                }
            }
            p += size;
        }
        return granted;
    }

    private static bool SidEquals(byte[] sd, int offset, int end) =>
        end - offset >= AuthenticatedUsersSid.Length && sd.AsSpan(offset, AuthenticatedUsersSid.Length).SequenceEqual(AuthenticatedUsersSid);
}
