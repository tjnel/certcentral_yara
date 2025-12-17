import "pe"

rule MAL_Compromised_Cert_Github_Loader_GlobalSign_616B166E814736AA88A96A53 {
   meta:
      description         = "Detects Github Loader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "0e5b342033b68fd3f79404fd90356f48e6473a025d5f74a8d1ba6754f1fbfa99"
      malware             = "Github Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RAJLAXMI PVT LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "61:6b:16:6e:81:47:36:aa:88:a9:6a:53"
      cert_thumbprint     = "7018B57F4947E57388E24F2D27D2D262252F52CB"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-11"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "sunilgautamjpr90@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "61:6b:16:6e:81:47:36:aa:88:a9:6a:53"
      )
}
