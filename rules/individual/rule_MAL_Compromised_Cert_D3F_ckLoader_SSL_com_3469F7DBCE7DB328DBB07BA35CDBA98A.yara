import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_3469F7DBCE7DB328DBB07BA35CDBA98A {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-30"
      version             = "1.0"

      hash                = "9b85aaf4d8e2945d735235615611c7bc5215dcb1358565fa2f38c75375cb81b0"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Aheli Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "34:69:f7:db:ce:7d:b3:28:db:b0:7b:a3:5c:db:a9:8a"
      cert_thumbprint     = "BF238E703FDE9EBA42A6BE99974C53A47F587F8A"
      cert_valid_from     = "2024-03-30"
      cert_valid_to       = "2025-03-30"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "1267891-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "34:69:f7:db:ce:7d:b3:28:db:b0:7b:a3:5c:db:a9:8a"
      )
}
