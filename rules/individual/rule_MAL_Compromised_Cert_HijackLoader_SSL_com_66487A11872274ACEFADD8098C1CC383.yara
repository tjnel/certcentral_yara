import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_66487A11872274ACEFADD8098C1CC383 {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-25"
      version             = "1.0"

      hash                = "ea73818d5c96294381ea56af0bdda98a987704ee478d8ab374e53e2bafec892b"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AR DIGITAL SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:48:7a:11:87:22:74:ac:ef:ad:d8:09:8c:1c:c3:83"
      cert_thumbprint     = "66368BDD4E4E52DA17107DE96E1EF57E9DAEF7B6"
      cert_valid_from     = "2025-04-25"
      cert_valid_to       = "2026-04-25"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "0000771777"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:48:7a:11:87:22:74:ac:ef:ad:d8:09:8c:1c:c3:83"
      )
}
