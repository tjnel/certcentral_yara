import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_3D1ED9CE0D8A81789EF479DE {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-17"
      version             = "1.0"

      hash                = "5ea9507196400edee8e287f66dd84e9345908d9dc5757e625ed18e89cfb2d40c"
      malware             = "Unknown"
      malware_type        = "Infostealer"
      malware_notes       = "Fake WeChat Installer that launches the Windows App store as a decoy."

      signer              = "ООО СТРОЙСЕРВИС"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3d:1e:d9:ce:0d:8a:81:78:9e:f4:79:de"
      cert_thumbprint     = "F6ECE321CDBBE3EA598A53C473D76D6F59ED1C60"
      cert_valid_from     = "2025-06-17"
      cert_valid_to       = "2026-03-25"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3d:1e:d9:ce:0d:8a:81:78:9e:f4:79:de"
      )
}
