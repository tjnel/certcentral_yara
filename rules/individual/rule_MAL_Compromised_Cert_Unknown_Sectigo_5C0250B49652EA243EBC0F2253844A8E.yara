import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_5C0250B49652EA243EBC0F2253844A8E {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-26"
      version             = "1.0"

      hash                = "05eed8d83fbcba33734cf113ee97cca5d760fc66052c32b3e7c791cda6e44865"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hibernation Holdings, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5c:02:50:b4:96:52:ea:24:3e:bc:0f:22:53:84:4a:8e"
      cert_thumbprint     = "257A074A90E6243B65EF49C092AE9CCE61EBEE19"
      cert_valid_from     = "2024-08-26"
      cert_valid_to       = "2025-08-26"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5c:02:50:b4:96:52:ea:24:3e:bc:0f:22:53:84:4a:8e"
      )
}
