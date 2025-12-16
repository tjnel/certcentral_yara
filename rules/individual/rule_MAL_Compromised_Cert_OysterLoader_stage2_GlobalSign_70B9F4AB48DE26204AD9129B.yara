import "pe"

rule MAL_Compromised_Cert_OysterLoader_stage2_GlobalSign_70B9F4AB48DE26204AD9129B {
   meta:
      description         = "Detects OysterLoader_stage2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-29"
      version             = "1.0"

      hash                = "8339392bded530e54115016e1a78b2f692a9c15a42f5f9c956de51f3f4aa1278"
      malware             = "OysterLoader_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Antek"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "70:b9:f4:ab:48:de:26:20:4a:d9:12:9b"
      cert_thumbprint     = "8EEA8EC2B67C2E0E5E79ABA355935DD69ED75E37"
      cert_valid_from     = "2025-09-29"
      cert_valid_to       = "2026-06-06"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "70:b9:f4:ab:48:de:26:20:4a:d9:12:9b"
      )
}
