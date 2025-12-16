import "pe"

rule MAL_Compromised_Cert_OysterLoader_GoGetSSL_0CD398F0C19E99E5A5CD1CCB63D49059 {
   meta:
      description         = "Detects OysterLoader with compromised cert (GoGetSSL)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-13"
      version             = "1.0"

      hash                = "4631309051a5943e92656a421a01f79132f47b0367462ee1b9c50f56ab38e04f"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Soft Furniture OÜ"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0c:d3:98:f0:c1:9e:99:e5:a5:cd:1c:cb:63:d4:90:59"
      cert_thumbprint     = "B67606F36E62A50B04422AE9BDE3F2E24D57726B"
      cert_valid_from     = "2025-02-13"
      cert_valid_to       = "2026-02-12"

      country             = "EE"
      state               = "???"
      locality            = "Tallinn"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0c:d3:98:f0:c1:9e:99:e5:a5:cd:1c:cb:63:d4:90:59"
      )
}
