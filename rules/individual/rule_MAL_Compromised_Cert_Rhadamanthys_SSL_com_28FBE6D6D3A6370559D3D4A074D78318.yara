import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_28FBE6D6D3A6370559D3D4A074D78318 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-28"
      version             = "1.0"

      hash                = "a451cbfe093830cd4d907d10bc0f27ea51da53ece5456af2fe6b3b24d3df163e"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "IT HR SYSTEMS SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:fb:e6:d6:d3:a6:37:05:59:d3:d4:a0:74:d7:83:18"
      cert_thumbprint     = "7BE3F3210CFD173ED35F584F17B8CA76196433AA"
      cert_valid_from     = "2025-08-28"
      cert_valid_to       = "2026-08-28"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:fb:e6:d6:d3:a6:37:05:59:d3:d4:a0:74:d7:83:18"
      )
}
