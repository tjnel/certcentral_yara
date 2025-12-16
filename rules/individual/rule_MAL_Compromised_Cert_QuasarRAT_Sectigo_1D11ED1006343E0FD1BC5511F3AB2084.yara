import "pe"

rule MAL_Compromised_Cert_QuasarRAT_Sectigo_1D11ED1006343E0FD1BC5511F3AB2084 {
   meta:
      description         = "Detects QuasarRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-31"
      version             = "1.0"

      hash                = "28efc53ff3f91f47ca7a83789330c7b1d7f86acbe510b3a58a497f388ce368a1"
      malware             = "QuasarRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "12980215 Canada Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "1d:11:ed:10:06:34:3e:0f:d1:bc:55:11:f3:ab:20:84"
      cert_thumbprint     = "1373BA6C061866EF7DA2A7592237642DD8C672D5"
      cert_valid_from     = "2022-08-31"
      cert_valid_to       = "2023-08-31"

      country             = "CA"
      state               = "Ontario"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "1d:11:ed:10:06:34:3e:0f:d1:bc:55:11:f3:ab:20:84"
      )
}
