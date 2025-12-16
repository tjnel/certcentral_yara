import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330005700A78B0BEC32F1C809F00000005700A {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-25"
      version             = "1.0"

      hash                = "c4f0350f6f55708fbb52cb853b1f9951856b1e1579e9a67f9dff11361f64b2f4"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:70:0a:78:b0:be:c3:2f:1c:80:9f:00:00:00:05:70:0a"
      cert_thumbprint     = "5029EEA156DDEE45A62209311B7C8CB71CB1EE58"
      cert_valid_from     = "2025-11-25"
      cert_valid_to       = "2025-11-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:70:0a:78:b0:be:c3:2f:1c:80:9f:00:00:00:05:70:0a"
      )
}
