import "pe"

rule MAL_Compromised_Cert_OysterLoader_GlobalSign_0E937B1ED66ECC467E3A3714 {
   meta:
      description         = "Detects OysterLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-01"
      version             = "1.0"

      hash                = "abb0e6628c891bcd8ed54bf08790718eeb0c7a44f157d28ced18adfebe4dce21"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Pili-Sverli"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0e:93:7b:1e:d6:6e:cc:46:7e:3a:37:14"
      cert_thumbprint     = "C834CA98AC7C7B848EEEC6A633E0F54B87B6E286"
      cert_valid_from     = "2025-10-01"
      cert_valid_to       = "2026-05-31"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Elitny"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0e:93:7b:1e:d6:6e:cc:46:7e:3a:37:14"
      )
}
