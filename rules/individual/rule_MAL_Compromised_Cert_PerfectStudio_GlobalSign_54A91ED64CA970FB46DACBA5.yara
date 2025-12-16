import "pe"

rule MAL_Compromised_Cert_PerfectStudio_GlobalSign_54A91ED64CA970FB46DACBA5 {
   meta:
      description         = "Detects PerfectStudio with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "e1b9dce593374af5d44bf62350c5ba44c01416d73514557e03a228de46fafab3"
      malware             = "PerfectStudio"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SUNDARAM FOOTWEAR MARKETING PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:a9:1e:d6:4c:a9:70:fb:46:da:cb:a5"
      cert_thumbprint     = "EBF1B938F9B831B58F1571D798CBEFF84F02DF4C"
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2026-04-16"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:a9:1e:d6:4c:a9:70:fb:46:da:cb:a5"
      )
}
