import "pe"

rule MAL_Compromised_Cert_OysterLoader_SSL_com_5EC13F23067D4BC6F01883A00B32553B {
   meta:
      description         = "Detects OysterLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "ada8654dcc9b01811e2e902e857d2b1960b5b58ac4f86b0b67147f5d8c6ca3a5"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Internet Hotspot"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:c1:3f:23:06:7d:4b:c6:f0:18:83:a0:0b:32:55:3b"
      cert_thumbprint     = "900F213D296D59E663C2474638C5E7E061124058"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:c1:3f:23:06:7d:4b:c6:f0:18:83:a0:0b:32:55:3b"
      )
}
