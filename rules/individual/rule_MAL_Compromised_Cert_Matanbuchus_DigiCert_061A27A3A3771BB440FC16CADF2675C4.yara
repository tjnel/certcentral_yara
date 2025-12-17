import "pe"

rule MAL_Compromised_Cert_Matanbuchus_DigiCert_061A27A3A3771BB440FC16CADF2675C4 {
   meta:
      description         = "Detects Matanbuchus with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-18"
      version             = "1.0"

      hash                = "face46e6593206867da39e47001f134a00385898a36b8142a21ad54954682666"
      malware             = "Matanbuchus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Westeast Tech Consulting, Corp."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:1a:27:a3:a3:77:1b:b4:40:fc:16:ca:df:26:75:c4"
      cert_thumbprint     = "2A40875C895B648C9583925C7DAD694A2A11D7DD"
      cert_valid_from     = "2022-05-18"
      cert_valid_to       = "2023-05-11"

      country             = "US"
      state               = "California"
      locality            = "NORTHRIDGE"
      email               = "???"
      rdn_serial_number   = "4088386"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:1a:27:a3:a3:77:1b:b4:40:fc:16:ca:df:26:75:c4"
      )
}
