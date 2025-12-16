import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_54BFAC4E3C2EA108E9CE1E0C10DA8B5A {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-02"
      version             = "1.0"

      hash                = "420a4e1575bdbc22b947155465046eab0fefa4ab3490b1b63270b198fabaf8ad"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RASYS Software AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "54:bf:ac:4e:3c:2e:a1:08:e9:ce:1e:0c:10:da:8b:5a"
      cert_thumbprint     = "62309F28C2DC95B3BFC41B652923DEC475396321"
      cert_valid_from     = "2025-06-02"
      cert_valid_to       = "2026-06-02"

      country             = "SE"
      state               = "Dalarna County"
      locality            = "Mora"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "54:bf:ac:4e:3c:2e:a1:08:e9:ce:1e:0c:10:da:8b:5a"
      )
}
