import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_73E6959668279CF575807965749DCCED {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-04"
      version             = "1.0"

      hash                = "230f4de7b92166c695ad4f8bc469e2a39a31d0640ceb994d4f46f1afdabea90b"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BNY Holding Aps"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "73:e6:95:96:68:27:9c:f5:75:80:79:65:74:9d:cc:ed"
      cert_thumbprint     = "7f6e28324e79521078ab3a06e3b7a6d8be8df4fcb21fabbb3549a9a18f31d4ea"
      cert_valid_from     = "2025-06-04"
      cert_valid_to       = "2026-06-04"

      country             = "DK"
      state               = "Region of Southern Denmark"
      locality            = "Odense"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "73:e6:95:96:68:27:9c:f5:75:80:79:65:74:9d:cc:ed"
      )
}
