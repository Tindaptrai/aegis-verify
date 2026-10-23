using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Aegis.Connection;

internal static class Certificates
{
    internal static X509Certificate2 PublicPem(string pem)
    {
        if (pem.Length > 8192 || pem.Any(c => c > 127) || !PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "CERTIFICATE" || !string.IsNullOrWhiteSpace(pem[..fields.Location.Start.Value]) || !string.IsNullOrWhiteSpace(pem[fields.Location.End.Value..])) throw new CryptographicException();
        return X509Certificate2.CreateFromPem(pem);
    }
    internal static void RequireCa(X509Certificate2 certificate, DateTimeOffset? verificationTime = null)
    {
        var now = (verificationTime ?? DateTimeOffset.UtcNow).UtcDateTime;
        if (!certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority) || !certificate.Extensions.OfType<X509KeyUsageExtension>().Any(e => e.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)) || now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) throw new CryptographicException();
    }
    internal static bool HasEku(X509Certificate2 certificate, string oid) => certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == oid));
    internal static bool Trusted(X509Certificate2 certificate, X509Certificate2 issuer, string eku, DateTimeOffset? verificationTime = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(issuer);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = (verificationTime ?? DateTimeOffset.UtcNow).UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(eku));
        return HasEku(certificate, eku) && chain.Build(certificate) && chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(issuer.RawData);
    }
    internal static void ValidateIdentity(IdentityState state, EnrollmentResponse response, bool allowExpired = false)
    {
        try
        {
            Protocol.ValidateEnrollmentFields(response, "identity_invalid");
            using var key = RSA.Create(); key.ImportFromPem(state.PrivateKeyPem);
            using var certificate = PublicPem(response.CertificatePem);
            var verificationTime = allowExpired ? new DateTimeOffset(certificate.NotBefore.ToUniversalTime()).AddSeconds(1) : DateTimeOffset.UtcNow;
            using var issuer = PublicPem(response.IssuerPem); RequireCa(issuer, verificationTime);
            using var publicKey = certificate.GetRSAPublicKey();
            if (publicKey == null || !publicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()) || !Trusted(certificate, issuer, "1.3.6.1.5.5.7.3.2", verificationTime) || certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault() is not { CertificateAuthority: false } || !certificate.Extensions.OfType<X509KeyUsageExtension>().Any(e => e.KeyUsages == X509KeyUsageFlags.DigitalSignature) || certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData) == false || certificate.Extensions.Cast<X509Extension>().GroupBy(e => e.Oid!.Value).Any(g => g.Count() > 1)) throw new CryptographicException();
            var san = certificate.Extensions.SingleOrDefault(e => e.Oid?.Value == "2.5.29.17") ?? throw new CryptographicException();
            var reader = new AsnReader(san.RawData, AsnEncodingRules.DER); var sequence = reader.ReadSequence(); reader.ThrowIfNotEmpty();
            var uri = sequence.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)); sequence.ThrowIfNotEmpty();
            if (uri != "urn:aegis:agent:" + response.DeviceId || !Protocol.Timestamp(response.ExpiresAt, out var expires) || expires != new DateTimeOffset(certificate.NotAfter.ToUniversalTime()) || !allowExpired && (expires <= DateTimeOffset.UtcNow || expires > DateTimeOffset.UtcNow.AddDays(31))) throw new CryptographicException();
        }
        catch (Exception e) when (e is CryptographicException or AsnContentException or InvalidOperationException or ArgumentException) { throw new ConnectionException("identity_invalid"); }
    }
}
